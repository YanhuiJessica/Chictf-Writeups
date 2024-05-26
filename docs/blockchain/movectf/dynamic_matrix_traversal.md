---
title: Blockchain - DynamicMatrixTraversal
description: 2024 | MoveCTF
tags:
    - move
    - pascal's triangle
---

## 题目

??? note "matrix.move"

    ```rs
    module dynamic_matrix_traversal::matrix {

        use std::vector;
        use sui::event;
        use sui::object::{Self, UID};
        use sui::transfer;
        use sui::tx_context::{Self, TxContext};

        const TARGET_VALUE_1: u64 = 2794155;
        const TARGET_VALUE_2: u64 = 14365;

        const ERROR_RESULT_1: u64 = 1;
        const ERROR_RESULT_2: u64 = 2;
        const ERROR_PARAM_1: u64 = 3;
        const ERROR_PARAM_2: u64 = 4;

        struct Flag has copy, drop {
            user: address,
            flag: bool
        }

        struct Record has key {
            id: UID,
            count_1: u64,
            count_2: u64,
            count_3: u64,
            count_4: u64
        }


        fun init(ctx: &mut sui::tx_context::TxContext) {
            let record = Record {
                id: object::new(ctx),
                count_1: 0,
                count_2: 0,
                count_3: 0,
                count_4: 0
            };

            transfer::share_object(record);
        }

        fun up(m: u64, n: u64): u64 {
            let f: vector<vector<u64>> = vector::empty();
            let i: u64 = 0;
            while (i < m) {
                let row: vector<u64> = vector::empty();
                let j: u64 = 0;
                while (j < n) {
                    if (j == 0 || i == 0) {
                        vector::push_back(&mut row, 1);
                    } else {
                        let f1 = *vector::borrow(&f, i - 1);
                        let j1 = *vector::borrow(&row, j - 1);
                        let val = *vector::borrow(&f1, j) + j1;
                        vector::push_back(&mut row, val);
                    };
                    j = j + 1;
                };
                vector::push_back(&mut f, row);
                i = i + 1;
            };
            let fr = *vector::borrow(&f, m - 1);
            let result = *vector::borrow(&fr, n-1);
            result
        }

        public entry fun execute(record: &mut Record, m: u64, n: u64) {
            if (record.count_1 == 0) {
                let result: u64 = up(m, n);
                assert!(result == TARGET_VALUE_1, ERROR_RESULT_1);
                record.count_1 = m;
                record.count_2 = n;
            } else if (record.count_3 == 0) {
                let result: u64 = up(m, n);
                assert!(result == TARGET_VALUE_2, ERROR_RESULT_2);
                record.count_3 = m;
                record.count_4 = n;
            }
        }

        public entry fun get_flag(record: &Record, ctx: &mut TxContext) {
            assert!(record.count_1 < record.count_3, ERROR_PARAM_1);
            assert!(record.count_2 > record.count_4, ERROR_PARAM_2);
            event::emit(Flag { user: tx_context::sender(ctx), flag: true });
        }

        #[test_only]
        public fun init2(ctx: &mut sui::tx_context::TxContext) {
            init(ctx)
        }
    }
    ```

??? note "Move.toml"

    ```rs
    [package]
    name = "dynamic_matrix_traversal"
    version = "0.0.1"

    [dependencies]
    Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "framework/testnet" }

    [addresses]
    dynamic_matrix_traversal = "0x0"
    ```

## 解题思路

- `count_1`、`count_2`、`count_3` 和 `count_4` 初始值为 $0$，最终需要满足 `count_1 < count_3` 且 `count_2 > count_4`
- 通过 `execute()` 可以分别设置 `count_1 & count_2` 以及 `count_3 & count_4`，但 `up(m, n)` 的执行结果应等于特定的 `TARGET_VALUE`

    ```rs
    public entry fun execute(record: &mut Record, m: u64, n: u64) {
        if (record.count_1 == 0) {
            let result: u64 = up(m, n);
            assert!(result == TARGET_VALUE_1, ERROR_RESULT_1);
            record.count_1 = m;
            record.count_2 = n;
        } else if (record.count_3 == 0) {
            let result: u64 = up(m, n);
            assert!(result == TARGET_VALUE_2, ERROR_RESULT_2);
            record.count_3 = m;
            record.count_4 = n;
        }
    }
    ```

- 函数 `up()` 输出矩阵第 `m` 行第 `n` 列的结果，其中第 1 行第 1 列所有元素均为 $1$，随后第 `i` 行第 `j` 列的元素为第 `i-1` 行第 `j` 列和第 `i` 行第 `j-1` 列元素相加的结果

    ```rs
    fun up(m: u64, n: u64): u64 {
        let f: vector<vector<u64>> = vector::empty();
        let i: u64 = 0;
        while (i < m) {
            let row: vector<u64> = vector::empty();
            let j: u64 = 0;
            while (j < n) {
                if (j == 0 || i == 0) {
                    vector::push_back(&mut row, 1);
                } else {
                    let f1 = *vector::borrow(&f, i - 1);
                    let j1 = *vector::borrow(&row, j - 1);
                    let val = *vector::borrow(&f1, j) + j1;
                    vector::push_back(&mut row, val);
                };
                j = j + 1;
            };
            vector::push_back(&mut f, row);
            i = i + 1;
        };
        let fr = *vector::borrow(&f, m - 1);
        let result = *vector::borrow(&fr, n-1);
        result
    }
    ```

- 可以通过暴力求解得到两组 `m`、`n`，分别为 `m=5,n=89` 和 `m=169,n=3`，恰好能满足题目需求

    ```py
    def up(m, n):
        if n > m:
            return 0
        f, i = None, 0
        while i < m:
            row = []
            j = 0
            while j < n:
                if j == 0 or i == 0:
                    row.append(1)
                else:
                    row.append(f[j] + row[j - 1])
                j += 1
            f = row
            i += 1
        return row[n - 1]

    for m in range(1, 200):
        for n in range(1, 200):
            if n > m:
                break
            ret = up(m, n)
            if ret in [2794155, 14365]:
                print(m, n)
    ```

### Exploitation

```bash
$ sui client tx-block <digest>  # get Record objectID
$ sui client call --function execute --args <objectId> 5 89 --module matrix --package <packageId> --gas-budget 300000000
$ sui client call --function execute --args <objectId> 169 3 --module matrix --package <packageId> --gas-budget 300000000
$ sui client call --function get_flag --args <objectId> --module matrix --package <packageId> --gas-budget 300000000
```

### Flag

> flag{0FhsM2AMrlt9}_DynamicMatrixTraversal
