---
title: Crypto - Code is Law
description: 2022 | BSidesTLV CTF | Blockchain
---

## 题目

Download the **zip** file and follow the instructions in the **README.md** file to solve the solidity challenge.

[:material-download: `code-is-law-1.zip`](static/code-is-law-1.zip)
[:material-download: `code-is-law-2.zip`](static/code-is-law-2.zip)

??? note "OnlyICanHazToken.sol"

    ```js
    // SPDX-License-Identifier: Unlicense
    pragma solidity ^0.8.0;

    contract OnlyICanHazToken {
        function bye() public {
            selfdestruct(payable(msg.sender));
        }
    }
    ```

??? note "index.ts"

    ```js
    import { expect } from "chai";
    import { ethers } from "hardhat";
    import { ChallengeToken } from "../typechain";

    // This "Challenge Setup" block must be left as-is
    describe("Challenge Setup", function () {
        it("Should deploy ChallengeToken", async function () {
            const ChallengeTokenFactory = await ethers.getContractFactory("ChallengeToken", (await ethers.getSigners()).pop());
            const challengeToken = await ChallengeTokenFactory.deploy();
            await challengeToken.deployed();
        });
    });

    // Try to solve the challenge below this line
    // Run `npx hardhat ctf-try` to test your solution locally
    // Run `npx hardhat ctf-try --submit` to submit your solution to the remote CTF node and get the real flag
    describe("Solve Challenge", function () {
        let challengeToken: ChallengeToken;

        it("Should return the winning flag", async function () {
            challengeToken = await ethers.getContractAt("ChallengeToken", "0x73511669fd4dE447feD18BB79bAFeAC93aB7F31f");

            const returnedFlag = await challengeToken.did_i_win()

            console.log(`\tThe returned flag is: "${returnedFlag}"`)
        });
    });
    ```

### Code is Law 1

??? note "ChallengeToken.sol"

    ```js
    // SPDX-License-Identifier: Unlicense
    pragma solidity ^0.8.0;

    import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
    import "hardhat/console.sol";

    contract ChallengeToken is ERC20 {
        bytes32 private onlyICanHazTokenContractCodeHash =
            0x1431A52467B8E0B496D710A30B897A6EB093CD9137FBF9B34B47441FD5E868F3;

        constructor() ERC20("ChallengeToken", "BSIDES2022") {}

        function did_i_win() public view returns (string memory) {
            if (balanceOf(msg.sender) == 0) {
                revert("you shall not pass");
            }

            return "BSidesTLV2022{PLACEHOLDER}";
        }

        function can_i_haz_token(address receiver) public {
            require(
                receiver == calculateAddressOfTheFirstContractDeployedBy(tx.origin),
                "receiver is ineligible for a token because they are not the first contract deployed by the EOA who initiated this transaction"
            );
            require(
                getContractCodeHash(receiver) == onlyICanHazTokenContractCodeHash,
                "receiver is ineligible for a token because their codehash does not match the specific contract codehash required"
            );

            if (balanceOf(receiver) == 0) {
                _mint(receiver, 1);
            }
        }

        function getContractCodeHash(address contractAddress)
            private
            view
            returns (bytes32 callerContractCodeHash)
        {
            assembly {
                callerContractCodeHash := extcodehash(contractAddress)
            }
        }

        // Copied from https://ethereum.stackexchange.com/a/87840
        function calculateAddressOfTheFirstContractDeployedBy(address deployer)
            private
            pure
            returns (address _address)
        {
            bytes32 hash = keccak256(
                abi.encodePacked(bytes1(0xd6), bytes1(0x94), deployer, bytes1(0x80))
            );

            assembly {
                mstore(0, hash)
                _address := mload(0)
            }
        }
    }
    ```

### Code is Law 2

??? note "ChallengeToken.sol"

    ```js
    //SPDX-License-Identifier: Unlicense
    pragma solidity ^0.8.0;

    import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
    import "hardhat/console.sol";

    contract ChallengeToken is ERC20 {
        bytes32 private onlyICanHazTokenContractCodeHash =
            0x1431A52467B8E0B496D710A30B897A6EB093CD9137FBF9B34B47441FD5E868F3;

        constructor() ERC20("ChallengeToken", "BSIDES2022") {}

        function did_i_win() public view returns (string memory) {
            if (balanceOf(msg.sender) == 0) {
                revert("you shall not pass");
            }

            return "BSidesTLV2022{PLACEHOLDER}";
        }

        function can_i_haz_token(address receiver) public {
            require(
                getContractCodeHash(receiver) == onlyICanHazTokenContractCodeHash,
                "receiver is ineligible for a token because their codehash does not match the specific contract codehash required"
            );

            if (balanceOf(receiver) == 0) {
                _mint(receiver, 1);
            }
        }

        function getContractCodeHash(address contractAddress)
            private
            view
            returns (bytes32 callerContractCodeHash)
        {
            assembly {
                callerContractCodeHash := extcodehash(contractAddress)
            }
        }

        function approve(address spender, uint256 amount) public override returns (bool) {
            return false;
        }
    }
    ```

## 解题思路

- 当 `ChallengeToken.did_i_win()` 的 `msg.sender` 所在地址持有 `token` 时就能获得 flag
- 首先分析 `Code is Law 1` 的 `ChallengeToken` 合约
    - `ChallengeToken` 通过函数 `can_i_haz_token` 发放 `token`，但只有合约 `receiver` 在 `tx.origin` 初次部署合约的地址上，且合约代码的哈希值与 `onlyICanHazTokenContractCodeHash` 相等时才能获得
- 那么，先让合约 `OnlyICanHazToken` 获得 `token` 再转移呢？但 `selfdestruct(payable(msg.sender))` 只能转移以太币，无法转移 `token`
- 再回头看看 `ChallengeToken` 的 `getContractCodeHash` 和 `calculateAddressOfTheFirstContractDeployedBy` 似乎也没有什么问题，`ERC20` 就更不可能了 uwu
- 最后把注意力转移到了 `hardhat` 上，发现了能修改合约存储的 `hardhat_setStorageAt`[^1]（是神 (╥ω╥)），结合合约变量的存储位置、方式直接修改余额就好了！

    ```ts
    it("Should return the winning flag", async function () {
        challengeToken = await ethers.getContractAt("ChallengeToken", "0x73511669fd4dE447feD18BB79bAFeAC93aB7F31f");
        
        let [player] = await ethers.getSigners();
        let playerHash = await ethers.utils.solidityKeccak256(["uint256", "uint"], [player.address, 0]);
        await ethers.provider.send("hardhat_setStorageAt", [challengeToken.address, playerHash, ethers.utils.hexZeroPad(ethers.utils.hexlify(1), 32)]);

        const returnedFlag = await challengeToken.did_i_win()
        console.log(`\tThe returned flag is: "${returnedFlag}"`)
    });
    ```

    - `ChallengeToken` 继承自 `ERC20`，变量 `_balances` 用于存储各个账户地址对应的余额
    - `_balances` 为 `mapping` 类型，占用 `slot 0`，那么地址 `A` 的余额存储位置在 `keccak256(A | 0)`，`|` 表示连接

- `Code is Law 2` 与 `Code is Law 1` 相比，只修改了 `ChallengeToken` 发放 `token` 的规则并禁用了 `approve`，因而修改存储的方法仍然适用 =）

### Flag

#### Code is Law 1

> BSidesTLV2022{c0nstUct!v3_m@g!3_ind3ed}

#### Code is Law 2

> BSidesTLV2022{W!L3_M@g!3_in_the_w3rld}

[^1]: [Local ERC20 Balance Manipulation (with HardHat)](https://kndrck.co/posts/local_erc20_bal_mani_w_hh/)