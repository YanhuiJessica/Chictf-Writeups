---
title: OpenZeppelin：Ethernaut
---

## 0. Hello Ethernaut

- 登录 MetaMask，将 MetaMask 切换到 Rinkeby 测试网络
  - 若没有则需要在 `设置->高级` 中开启「Show test networks」
- 在浏览器的控制台可以收到一些消息，其中一条为玩家地址
  - 可以使用 `player` 命令随时查看玩家地址，MetaMask 也可以直接复制
- 查看当前余额：`getBalance(player)`
  - 如果显示 `pending`，可改用 `await getBalance(player)` 来获得清晰的结果

    ```js
    >> await getBalance(player)
    "0"
    ```

- 在控制台输入 `ethernaut` 查看游戏的主要合约
  - 合约的 ABI（Application Binary Interfaces）提供了所有 Ethernaut.sol 的公开方法，如所有者，可通过 `ethernaut.owner()` 查看
  - 并不需要直接与 Ethernaut.sol 合约交互，而是通过关卡实例
- 获取测试用以太币用于支付汽油费：[1](https://faucet.rinkeby.io/) / [2](https://faucets.chain.link/rinkeby) / [3](https://faucet.paradigm.xyz/)
- 点击「Get new instance」并在 MetaMask 授权交易
- 查看合约信息并根据提示交互

  ```js
  >> await contract.info()
  "You will find what you need in info1()."
  >> await contract.info1()
  "Try info2(), but with \"hello\" as a parameter."
  >> await contract.info2("hello")
  "The property infoNum holds the number of the next info method to call."
  >> await contract.infoNum()
  {
    "negative": 0,
    "words": [
      42,
      null
    ],
    "length": 1,
    "red": null
  }
  >> await contract.info42()
  "theMethodName is the name of the next method."
  >> await contract.theMethodName()
  "The method name is method7123949."
  >> await contract.method7123949()
  "If you know the password, submit it to authenticate()."
  >> await contract.password()
  "ethernaut0"
  >> await contract.authenticate("ethernaut0")
  // MetaMask 授权交易，等待确认
  ```

- 完成后点击「Submit instance」验证