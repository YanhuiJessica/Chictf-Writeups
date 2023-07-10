---
title: Blockchain - positive
description: 2023 | CrewCTF | Web3
tags:
    - smart contract
    - fuzzing
---

## Description

Stay positive.

> nc positive.chal.crewc.tf 60003

??? note "Setup.sol"

    ```js
    pragma solidity =0.7.6;

    import "./Positive.sol";

    contract Setup {
        Positive public immutable TARGET;

        constructor() payable {
            TARGET = new Positive(); 
        }

        function isSolved() public view returns (bool) {
            return TARGET.solved();
        }
    }
    ```

??? note "Positive.sol"

    ```js
    // SPDX-License-Identifier: MIT
    pragma solidity =0.7.6;

    contract Positive{
        bool public solved;

        constructor() {
            solved = false;
        }

        function stayPositive(int64 _num) public returns(int64){
            int64 num;
            if(_num<0){
                num = -_num;
                if(num<0){
                    solved = true;
                }
                return num;
            }
            num = _num;
            return num;
        }

    }
    ```

## Solution

- We need to find a number of type int64 that is less than 0, and its opposite is also negative

    ```js
    function stayPositive(int64 _num) public returns(int64){
        int64 num;
        if(_num<0){
            num = -_num;
            if(num<0){
                solved = true;
            }
            return num;
        }
        num = _num;
        return num;
    }
    ```

> If you have `int x = type(int).min;`, then `-x` does not fit the positive range. This means that `unchecked { assert(-x == x); }` works [^1]

- As int64 type values range from -9223372036854775808 to 9223372036854775807, the answer will be -9223372036854775808
- During the competition, I used fuzzing to get the answer uwu

    ```js
    contract PositiveTest is Test {
        Setup setup;
        Positive target;

        function setUp() public {
            setup = new Setup();
            target = setup.TARGET();
        }

        function testSolve(int64 a) public {
            target.stayPositive(a);
            assert(!target.solved());
        }
    }
    ```

    ```bash
    Failing tests:
    Encountered 1 failing test in test/Positive.t.sol:PositiveTest
    [FAIL. Reason: EvmError: InvalidFEOpcode Counterexample: calldata=0xecd6eb4fffffffffffffffffffffffffffffffffffffffffffffffff8000000000000000, args=[-9223372036854775808]] testSolve(int64) (runs: 66, μ: 8924, ~: 8925)
    ```

### Flag

> crew{9o5it1v1ty1sth3k3y}

[^1]: [Addition, Subtraction and Multiplication](https://docs.soliditylang.org/en/latest/types.html#addition-subtraction-and-multiplication)