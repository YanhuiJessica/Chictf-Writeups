---
title: Blockchain - deception
description: 2023 | CrewCTF | Web3
tags:
    - smart contract
---

## Description

Tate doesn't want you to know the truth. Find the secret.

> nc deception.chal.crewc.tf 60002

??? note "Setup.sol"

    ```js
    pragma solidity ^0.8.13;

    import "./Deception.sol";

    contract Setup {
        deception public immutable TARGET;

        constructor() payable {
            TARGET = new deception(); 
        }

        function isSolved() public view returns (bool) {
            return TARGET.solved();
        }
    }
    ```

??? note "Deception.sol"

    ```js
    // Contract that has to be displayed for challenge

    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.10;

    contract deception{
        address private owner;
        bool public solved;

        constructor() {
        owner = msg.sender;
        solved = false;
        }

        modifier onlyOwner() {
        require(msg.sender==owner, "Only owner can access");
        _;
        }

        function changeOwner(address newOwner) onlyOwner public{
        owner = newOwner;
        }

        function password() onlyOwner public view returns(string memory){
            return "secret";
        }

        function solve(string memory secret) public {
            require(keccak256(abi.encodePacked(secret))==0x65462b0520ef7d3df61b9992ed3bea0c56ead753be7c8b3614e0ce01e4cac41b, "invalid");
            solved = true;
        }
    }
    ```

## Solution

- From the source code, if we are able to provide a secret whose keccak256 hash is equal to `0x65462b0520ef7d3df61b9992ed3bea0c56ead753be7c8b3614e0ce01e4cac41b`, then the challenge can be solved. And, the keccak256 hash of "secret" is exactly what we want XD
- However, when I called the `solve()` function with the argument "secret", the transaction kept reverting :(
- I suddenly realized that the secret provided in the source code is not the actual value. So, I got the bytecode and attempted to extract the password from it
- It's not easy to get the secret even with decompiled bytecode

    ```js
    function password() public payable { 
        require(msg.sender == _changeOwner, Error('Only owner can access'));
        v0 = _SafeExp(stor_1, stor_4);
        require(stor_2, Panic(18)); // division by zero
        if (76 - v0 % stor_2) {
            MEM[MEM[64] + 32] = v0 % stor_2;
            v1 = v2 = MEM[64] + 64;
        } else {
            require((stor_3 == stor_3 * (v0 % stor_2) / (v0 % stor_2)) | !(v0 % stor_2), Panic(17)); // arithmetic overflow or underflow
            require(v0 % stor_2, Panic(18)); // division by zero
            MEM[32 + MEM[64]] = stor_3 * (v0 % stor_2) / (v0 % stor_2);
            v3 = 0x18e(64 + MEM[64], 32, 30);
            v4 = _SafeAdd(0x616263, stor_3);
            v5 = _SafeSub(v4, stor_3);
            MEM[32 + MEM[64]] = v5;
            v6 = 0x18e(64 + MEM[64], 32, 30);
            v7 = v8 = 0;
            while (v7 < v3.length) {
                MEM[v7 + (32 + MEM[64])] = v3[v7];
                v7 += 32;
            }
            MEM[v3.length + (32 + MEM[64])] = 0;
            v9 = v10 = 0;
            while (v9 < v6.length) {
                MEM[v9 + (32 + MEM[64] + v3.length)] = v6[v9];
                v9 += 32;
            }
            MEM[v6.length + (32 + MEM[64] + v3.length)] = 0;
            v1 = v11 = v6.length + (32 + MEM[64] + v3.length);
        }
        v12 = new array[](v1 - MEM[64] - 32);
        v13 = v14 = 0;
        while (v13 < v1 - MEM[64] - 32) {
            MEM[v13 + v12.data] = MEM[v13 + (MEM[64] + 32)];
            v13 += 32;
        }
        MEM[v1 - MEM[64] - 32 + v12.data] = 0;
        return v12;
    }
    ```

- Why not just fork the chain and impersonate the owner to call the `password()` function?

    ```js
    contract DeceptionTest is Test {
        Setup setup;
        deception target;

        function setUp() public {
            vm.createSelectFork(vm.envString("RPC_URL"));
            setup = Setup(vm.envAddress("INSTANCE_ADDR"));
            target = setup.TARGET();
        }

        function testSolve() public {
            // address private owner;
            bytes32 slotValue = vm.load(address(target), 0);
            vm.prank(address(uint160(uint256(slotValue))));
            console.log("%s", target.password());
        }
    }
    ```

- Call the `solve()` function to complete the challenge after getting the actual secret :D

### Flag

> crew{d0nt_tru5t_wh4t_y0u_s3e_4s5_50urc3!}