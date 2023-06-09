---
title: QuillCTF - assertEqual
description: 2023 | Hard | EVM
tags:
    - smart contract
    - evm
    - bytecode
    - opcode
    - huff
---

## Objective of CTF

> You need to write a smart contract that accepts two unsigned integers as inputs. The contract should return 1 if the input numbers are equal; otherwise, it should return a different number.

[QuillCTF Challenges - assertEqual](https://quillctf.super.site/challenges/assertequal)

## Vulnerability Description

- Most arithmetic opcodes are banned
  - We can not simply push `0x04` onto the stack in order to load the first parameter
  - We can not use opcode EQ to compare the two numbers
- As an alternative, ISZERO can be used to compare
- 4 wei is send for each call
- Since v0.8.7 does not support PUSH0, we can use RETURNDATASIZE as an alternative

## Attack Steps

- We can leverage CALLVALUE to get the first parameter
- Using the first parameter as the key, store any value that is greater than 0 in that storage slot
- Using the second parameter as the key, load the value of that storage slot. If the value is not 0, the two numbers are equal

## Proof of Concept

```
// isNumbersEQContract.huff

#define macro MAIN() = takes (0) returns (0) {
    callvalue callvalue calldataload
    sstore
    
    0x24 calldataload sload
    iszero
    iszero

    returndatasize callvalue calldataload
    sstore  // restore to 0

    returndatasize
    mstore

    0x20
    returndatasize
    return
}

// EIP 1167 creation code: 3d60<code-size>80600a3d3981f3
// huffc isNumbersEQContract.huff -r
```

```js
// SPDX-License-Identifier: MIT
pragma solidity 0.8.7;

import "forge-std/Test.sol";

contract EQ is Test {
    address isNumbersEQContract;
    bytes1[] badOpcodes;

    function setUp() public {
        badOpcodes.push(hex"01"); // ADD
        badOpcodes.push(hex"02"); // MUL
        badOpcodes.push(hex"03"); // SUB
        badOpcodes.push(hex"04"); // DIV
        badOpcodes.push(hex"05"); // SDIV
        badOpcodes.push(hex"06"); // MOD
        badOpcodes.push(hex"07"); // SMOD
        badOpcodes.push(hex"08"); // ADDMOD
        badOpcodes.push(hex"09"); // MULLMOD
        badOpcodes.push(hex"18"); // XOR
        badOpcodes.push(hex"10"); // LT
        badOpcodes.push(hex"11"); // GT
        badOpcodes.push(hex"12"); // SLT
        badOpcodes.push(hex"13"); // SGT
        badOpcodes.push(hex"14"); // EQ
        badOpcodes.push(hex"f0"); // create
        badOpcodes.push(hex"f5"); // create2
        badOpcodes.push(hex"19"); // NOT
        badOpcodes.push(hex"1b"); // SHL
        badOpcodes.push(hex"1c"); // SHR
        badOpcodes.push(hex"1d"); // SAR
        vm.createSelectFork(
            "https://eth-mainnet.g.alchemy.com/v2/..."
        );
        address isNumbersEQContractTemp;
        // solution - your bytecode
        // The code size is changed slightly to bypass the check (14 -> 15)
        bytes
            memory bytecode = hex"3d601580600a3d3981f3343435556024355415153d3435553d5260203df3";
        //
        require(bytecode.length < 40, "try harder!");
        for (uint i; i < bytecode.length; i++) {
            for (uint a; a < badOpcodes.length; a++) {
                if (bytecode[i] == badOpcodes[a]) revert();
            }
        }

        assembly {
            isNumbersEQContractTemp := create(
                0,
                add(bytecode, 0x20),
                mload(bytecode)
            )
            if iszero(extcodesize(isNumbersEQContractTemp)) {
                revert(0, 0)
            }
        }
        isNumbersEQContract = isNumbersEQContractTemp;
    }

    // fuzzing test
    function test_isNumbersEq(uint8 a, uint8 b) public {
        (bool success, bytes memory data) = isNumbersEQContract.call{value: 4}(
            abi.encodeWithSignature("isEq(uint256, uint256)", a, b)
        );
        require(success, "!success");
        uint result = abi.decode(data, (uint));
        a == b ? assert(result == 1) : assert(result != 1);

        // additional tests
        // 1 - equal numbers
        (, data) = isNumbersEQContract.call{value: 4}(
            abi.encodeWithSignature("isEq(uint256, uint256)", 57204, 57204)
        );
        require(abi.decode(data, (uint)) == 1, "1 test fail");
        // 2 - different numbers
        (, data) = isNumbersEQContract.call{value: 4}(
            abi.encodeWithSignature("isEq(uint256, uint256)", 0, 3568)
        );
        require(abi.decode(data, (uint)) != 1, "2 test fail");
    }
}
```