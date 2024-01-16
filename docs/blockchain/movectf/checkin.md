---
title: Blockchain - Checkin
description: 2024 | MoveCTF
tags:
    - move
---

## 题目

??? note "checkin.move"

    ```rs
    module movectf::checkin {
        use sui::event;
        use sui::tx_context::{Self, TxContext};

        const ESTRING:u64 = 0;

        struct Flag has copy, drop {
            sender: address,
            flag: bool,
        }

        public entry fun get_flag(string: vector<u8>, ctx: &mut TxContext) {
            assert!(string == b"MoveBitCTF",ESTRING);
            event::emit(Flag {
                sender: tx_context::sender(ctx),
                flag: true,
            });
        }
    }
    ```

??? note "Move.toml"

    ```toml
    [package]
    name = "movectf"
    version = "0.0.1"

    [dependencies]
    Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "framework/testnet" }

    [addresses]
    movectf = "0x0"
    ```

## 解题思路

- 切换网络

    ```bash
    $ sui client new-env --alias movectf --rpc http://8.217.173.179:9001
    $ sui client switch --env movectf
    ```

- 调用 `get_flag()` 函数以触发 `Flag` 事件

    ```bash
    $ sui client call --function get_flag --args MoveBitCTF --module checkin --package <packageId> --gas-budget 10000000
    ```

### Flag

> flag{31pSrCCf7pjK}_CHECKINNEW

## References

- [Sui Client CLI](https://docs.sui.io/references/cli/client)