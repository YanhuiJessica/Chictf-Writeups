---
title: Blockchain - Restricted Proxy
description: 2025 | REMEDY CTF | Solidity | EVM
tags:
    - smart contract
    - solidity
    - abi coder
---

## Description

Long, long ago (like... Block 42), a wizard has sealed 1 ETH inside a mystical Proxy Contract. You get one shot to proxy upgrade it—but under these very strict rules:

No Messing with the Family Tree The inheritance structure stays exactly as is. No new parents, no secret children.

No Rewriting the Magic You can’t alter existing functions or their visibility, and you can’t add or remove any functions. No new spells, no banished spells.

No Rearranging the Royal Closet. The storage layout cannot change. Touch a single uint256, and you might awaken the alignment demon.

No Upgrading the Wizard’s Quill Keep the same Solidity version. The wizard likes his dusty old version—deal with it.

Obey these ancient laws, upgrade the contract once, and claim the 1 ETH prize. But break them and face the dreaded 'Gasless Abyss!'

> nc 167.99.129.101 1337

??? note "Challenge.sol"

    ```js
    // SPDX-License-Identifier: MIT
    pragma solidity 0.8.26;

    import "src/CTF.sol";

    contract Challenge {
        address public immutable PLAYER;
        address public immutable ctf;

        constructor(address player) payable {
            PLAYER = player;
            ctf = address(new CTF{value: 100 ether}());
        }

        function isSolved() external view returns (bool) {
            return PLAYER.balance >= 100 ether
                && ctf.balance == 0 ether;
        }
    }
    ```

??? note "CTF.sol"

    ```js
    // SPDX-License-Identifier: MIT
    pragma solidity 0.8.26;

    contract CTF {

        bool public ownerWithdrawn;
        uint256 public withdrawRate;
        address public owner;
        uint256 public constant WITHDRAW_DENOMINATOR = 10000;

        constructor() payable {
            withdrawRate = 100;
            ownerWithdrawn = true;
        }

        function becomeOwner(uint256) external {
            assembly {
                sstore(owner.slot, calldataload(4))
            }
        }

        function changeWithdrawRate(uint8) external {
            assembly {
                sstore(withdrawRate.slot, calldataload(4))
            }
        }

        function withdrawFunds() external {
            assembly {
                let ownerWithdrawnSlot := sload(ownerWithdrawn.slot)
                let ownerSlot := sload(owner.slot)
                let withdrawRateSlot := sload(withdrawRate.slot)

                if iszero(ownerWithdrawnSlot) {
                    revert(0, 0)
                }

                if iszero(eq(ownerSlot, caller())) {
                    revert(0, 0)
                }

                sstore(ownerWithdrawn.slot, 0)

                let contractBalance := selfbalance()
                let amount := div(
                    mul(contractBalance, withdrawRateSlot),
                    WITHDRAW_DENOMINATOR
                )

                let success := call(gas(), caller(), amount, 0, 0, 0, 0)
                if iszero(success) {
                    revert(0, 0)
                }
            }
        }
    }
    ```

??? note "challenge.py"

    ```py
    from typing import Dict
    from web3 import Web3
    from base64 import b64decode
    import requests
    import secrets

    from eth_abi import abi
    from ctf_launchers.launcher import Action, pprint
    from ctf_launchers.pwn_launcher import PwnChallengeLauncher
    from ctf_launchers.utils import deploy
    from ctf_server.types import LaunchAnvilInstanceArgs, UserData, get_privileged_web3, get_system_account
    from foundry.anvil import check_error
    from foundry.anvil import anvil_autoImpersonateAccount, anvil_setCode

    class Challenge(PwnChallengeLauncher):
        def after_init(self):
            self._actions.append(Action(
                name="Upgrade the CTF contract", handler=self.upgrade_contract
            ))

        def get_anvil_instances(self) -> Dict[str, LaunchAnvilInstanceArgs]:
            return {
                "main": self.get_anvil_instance(fork_url=None, balance=1)
            }
        
        def upgrade_contract(self):
            user_data = self.get_user_data()
            pprint('Please input the new full source code in Base64.')
            pprint('Terminal has a 1024 character limit on copy paste, so you can paste it in batches and finish with an empty one.')
            total_txt = ''
            next_txt = '1337'
            while next_txt != '':
                next_txt = input('Input:\n')
                total_txt += next_txt
            try:
                upgrade_contract = b64decode(total_txt).decode()
            except Exception as e:
                return
            with open('challenge/project/src/CTF.sol', 'r') as f:
                original_contract = f.read()
            try:
                res = requests.post('http://restricted-proxy-backend:3000/api/compare', json={
                    'originalContract': original_contract,
                    'upgradeContract': upgrade_contract
                }).json()
            except Exception as e:
                return
            
            if 'error' in res or not res['areEqual']:
                pprint('Nope, sorry, that contract violates the upgrade rules.')
                return
            web3 = get_privileged_web3(user_data, "main")
            (ctf_addr,) = abi.decode(
                ["address"],
                web3.eth.call(
                    {
                        "to": user_data['metadata']["challenge_address"],
                        "data": web3.keccak(text="ctf()")[:4],
                    }
                ),
            )
            anvil_setCode(web3, ctf_addr, res['bytecode'])

            pprint('All okay! The CTF contract has been upgraded.')

    Challenge().run()
    ```

## Solution

- The contract `CTF` has 100 ether. The function `withdrawFunds` can be called once by the owner, and the withdraw amount is related to the `withdrawRate`.
- The first parameter of the function `becomeOwner` is of type `uint256`, and the function uses `calldataload(4)` to read the data, so we can just convert the address to a number and set the owner to ourselves.

    ```js
    function becomeOwner(uint256) external {
        assembly {
            sstore(owner.slot, calldataload(4))
        }
    }
    ```

- If we want to withdraw all ETH in the contract, we have to set the `withdrawRate` to 10000. Although the function `changeWithdrawRate` also uses `calldataload(4)` to read the data, its first parameter is of type `uint8`.

    ```js
    function changeWithdrawRate(uint8) external {
        assembly {
            sstore(withdrawRate.slot, calldataload(4))
        }
    }
    ```

- Since Solidity v0.8.0, ABI coder v2 is activated by default. It performs more sanity checks on the inputs than v1. Due to the limitation of the parameter type, we can not set `withdrawRate` to 10000.

    ```js
    // Decompiled
    function 0xff853d0b(uint256 varg0) public payable { 
        require(msg.data.length - 4 >= 32);
        require(varg0 == uint8(varg0));
        _withdrawRate = varg0;
    }
    ```

- This challenge supports upgrading the code of the contract `CTF`, but it will determine whether it follows the rules based on the source code. We can not change the ABI, storage layout, etc.
- However, we can choose to use ABI coder v1 by adding `pragma abicoder v1;`. Therefore, the sanity check on the input is removed, then we can easily update the `withdrawRate` to 10000.

    ```js
    // Decompiled
    function 0xff853d0b(uint256 varg0) public payable { 
        require(msg.data.length - 4 >= 32);
        _withdrawRate = varg0;
    }
    ```

## References

- [Silent Changes of the Semantics](https://docs.soliditylang.org/en/stable/080-breaking-changes.html#silent-changes-of-the-semantics)
- [ABI Coder Pragma](https://docs.soliditylang.org/en/stable/layout-of-source-files.html#abi-coder-pragma)
