---
title: Blockchain - EasyGame
description: 2024 | MoveCTF
tags:
    - move
---

## 题目

??? note "easy_game.move"

    ```rs
    module movectf::easy_game {
        use std::vector;
        use sui::math;
        use sui::transfer;
        use sui::tx_context::TxContext;
        use sui::object::{Self,UID};
        use sui::event;

        struct Challenge has key, store {
            id: UID,
            initial_part: vector<u64>, 
            target_amount: u64, 
        }

        struct Flag has copy, drop {
            user: address,
            flag: bool
        }

        fun init( ctx: &mut sui::tx_context::TxContext) {
            let initial_part = vector::empty<u64>();
            vector::push_back(&mut initial_part, 1);
            vector::push_back(&mut initial_part, 2);
            vector::push_back(&mut initial_part, 4);
            vector::push_back(&mut initial_part, 5);
            vector::push_back(&mut initial_part, 1);
            vector::push_back(&mut initial_part, 3);
            vector::push_back(&mut initial_part, 6);
            vector::push_back(&mut initial_part, 7);

            let challenge = Challenge {
                id: object::new(ctx),
                initial_part: initial_part,
                target_amount: 22,
            };
            transfer::share_object(challenge);
        
        }

        public fun submit_solution(user_input: vector<u64>,rc: &mut Challenge,ctx: &mut TxContext ){
            let sender = sui::tx_context::sender(ctx);
        
            let houses = rc.initial_part;
            vector::append(&mut houses, user_input);

            let amount_robbed = rob(&houses);

            let result = amount_robbed == rc.target_amount;
            if  (result) {
                event::emit(Flag { user: sender, flag: true });
            };
        }
        public fun rob(houses: &vector<u64>):u64{
            let n = vector::length(houses);
            if (n ==0){
                0;
            };
            let v = vector::empty<u64>();
            vector::push_back(&mut v, *vector::borrow(houses, 0));
            if (n>1){
                vector::push_back(&mut v, math::max(*vector::borrow(houses, 0), *vector::borrow(houses, 1)));
            };
            let i = 2;
            while (i < n) {
                let dp_i_1 = *vector::borrow(&v, i - 1);
                let dp_i_2_plus_house = *vector::borrow(&v, i - 2) + *vector::borrow(houses, i);
                vector::push_back(&mut v, math::max(dp_i_1, dp_i_2_plus_house));
                i = i + 1;
            }
            ;
            *vector::borrow(&v, n - 1)
        }
    }
    ```

??? note "Move.toml"

    ```toml
    [package]
    name = "easy_game"
    version = "0.0.1"

    [dependencies]
    Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "framework/testnet" }

    [addresses]
    movectf =  "0x0"
    sui =  "0x0000000000000000000000000000000000000002"
    ```

## 解题思路

- 为触发 `Flag` 事件需要 `amount_robbed` 为 $22$，即 `rob()` 的返回值
- 对于给定的数组 `houses`，`rob()` 将新建数组 `v` 并添加元素 `houses[0]` 和 `max(houses[0], houses[1])`。随后依次计算 `max(v[i-1], v[i-2] + houses[i]) (2 <= i < n)` 并加入到数组 `v` 中，最终返回数组 `v` 的最后一个值

    ```rs
    public fun rob(houses: &vector<u64>):u64{
        let n = vector::length(houses);
        if (n == 0) {
            0;
        };
        let v = vector::empty<u64>();
        vector::push_back(&mut v, *vector::borrow(houses, 0));
        if (n > 1) {
            vector::push_back(&mut v, math::max(*vector::borrow(houses, 0), *vector::borrow(houses, 1)));
        };
        let i = 2;
        while (i < n) {
            let dp_i_1 = *vector::borrow(&v, i - 1);
            let dp_i_2_plus_house = *vector::borrow(&v, i - 2) + *vector::borrow(houses, i);
            vector::push_back(&mut v, math::max(dp_i_1, dp_i_2_plus_house));
            i = i + 1;
        };
        *vector::borrow(&v, n - 1)
    }
    ```

- 根据 `init()`，`houses` 数组为 `[1, 2, 4, 5, 1, 3, 6, 7, user_input]`，可以推出数组 `v` 需要满足 `[1, 2, 5, 7, 7, 10, 13, 17, 22]`，由此可知 `user_input` 为 $22-13=9$

### Exploitation

```bash
$ sui client tx-block <digest>    # get Challenge objectID
$ sui client call --function submit_solution --args [9] <objectId> --module easy_game --package <packageId> --gas-budget 300000000
```

### Flag

> flag{yUH6yansnMpi}_EasyGame
