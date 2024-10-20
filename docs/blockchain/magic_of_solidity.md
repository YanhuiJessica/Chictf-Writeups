---
title: Blockchain - Magic of solidity
description: 2023 | QuillCTF Dubai | MultiConcept
tags:
    - ethereum
    - evm
    - access list
---

## 题目

Are you a sorcerer? Cast your magic and retrieve the flag.

??? note "Challenge.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity 0.8.9;

    /**
     *                                                          
     *               ,          /)           /) ,   /) ,       
     *   ___   _   _      _    ___//    _   ___//    _(/   _/_    
     *   // (_(_(_(_/__(_(__  (_)/(_   /_)_(_)(/__(_(_(__(_(__(_/_
     *           .-/            /)                           .-/  
     *       (_/            (/                           (_/   
     *
     * @author jinu.eth < https://twitter.com/lj1nu >
     */

    import {CrackMe} from "./CrackMe.sol";

    contract Challenge {
        bool public isSolved;

        constructor () {
            isSolved = false;
        }

        function solve() public { 
            bytes32 salt = keccak256(abi.encodePacked(block.number));
            uint gasInput = gasleft() / 1500;

            uint sum = 1;
            
            for(uint i=1;i<=11;i++){
                salt = keccak256(abi.encodePacked(salt, sum));
                CrackMe answ = new CrackMe{salt: salt}();
                try answ.getValue{gas: gasInput}( i ) returns(uint256 value) {
                    sum *= (sum + value);
                } catch (bytes memory) {
                } 
            }

            require(sum == 0x997fecf7193572c88c27ea9af4653249258);
            
            isSolved = true;
        }
    }
    ```

??? note "CrackMe.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity 0.8.9;

    contract CrackMe {
        uint a0;
        uint a1;

        mapping(uint=>uint) public c;

        constructor () {
            a0 = block.number;
            a1 = block.chainid;
        }

        function getValue(uint n) public view returns(uint) {
            return n + a0 * a1 * c[a0] * c[a1] * c[a0+a1] + c[a0/a1];
        }

        function setValue(uint offset, uint value) public {
            c[offset] = value;
        }
    }
    ```

## 解题思路

- 在函数 `solve()` 的执行期间，没有受控函数，因此无法调用 `CrackMe` 的 `setValue()` 函数，映射 `c` 中的值将始终为 0
- 但 `0x997fecf7193572c88c27ea9af4653249258` 恰好是仅 $2,3,5,6,7,9,11$ 参与计算能够取得的结果，因此，不需要设置 `CrackMe` 中映射 `c` 的值，而是需要调节 gas 使得 `answ.getValue()`
- 而函数 `solve()` 中，每次调用 `answ.getValue()` 设置的 gas 值都是固定的 `gasInput`
- 为了减轻 EIP-2929 导致的 gas 费用增加所可能带来的风险，EIP-2930 介绍了访问列表。访问列表能够将指定的地址和存储槽加入到 `accessed_addresses` 和 `accessed_storage_keys` 集合中，并预付冷地址和冷存储的附加 gas，从而减少执行所需的 gas
- 通过访问列表改变 `answ.getValue()` 执行所需的 gas，并利用 Out of Gas 和 try-catch 结构来控制 `sum` 的计算

### 解题脚本

```js
contract MagicOfSolidityHack {
    MagicOfSolidity magic;
    bool[11] checkList = [false, true, true, false, true, true, true, false, true, false, true];

    constructor(address _magic) {
        magic = MagicOfSolidity(_magic);
    }

    function isSolved() external view returns (bool) {
        return magic.isSolved();
    }

    function _getAddress(bytes32 salt, uint256 sum) internal view returns (bytes32, address) {
        salt = keccak256(abi.encodePacked(salt, sum));
        // @note It'll compile to different bytecode in different environments, use the creationCode in the MagicOfSolidity contract bytecode to get this code hash
        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), address(magic), salt, bytes32(0x3c8add5ea685c69ff7292af8f866aba3ab2f5cb76a93d58837ba938ed8456b54)));
        return (salt, address(uint160(uint256(h))));
    }

    function getCrackAddress(uint bn) external view returns (address[] memory cracks) {
        cracks = new address[](11);
        bytes32 salt = keccak256(abi.encodePacked(bn));
        uint sum = 1;
        for (uint i = 1; i <= 11; i++) {
            (salt, cracks[i - 1]) = _getAddress(salt, sum);
            if (checkList[i - 1]) {
                sum *= (sum + i);
            }
        }
    }

    function exploit(uint256 bn) external {
        require(bn == block.number);
        magic.solve{gas: 15000000}();
    }
}
```

```py
import os
from dotenv import load_dotenv
from web3 import Web3
from cheb3 import Connection
from cheb3.utils import compile_file

load_dotenv("../.env")

def get_slot(key):
    return Web3.solidity_keccak(['uint256', 'uint256'], [key, 2]).hex()

check_list = [False, True, True, False, True, True, True, False, True, False, True]

conn = Connection('http://challA0.quillctf.kalos.xyz:8545')
account = conn.account(os.getenv("PRIVATE_KEY"))
magic_addr = "0xc64e9De7D3809074EEFf0d22B058623e047475B9"

hack_abi, hack_bin = compile_file(
    "MagicOfSolidityHack.sol",
    solc_version="0.8.9",
    base_path="../"
)['MagicOfSolidityHack']
hack = conn.contract(account, abi=hack_abi, bytecode=hack_bin)
hack.deploy(magic_addr)

chain_id = conn.w3.eth.chain_id
block_number = conn.w3.eth.block_number + 2
addresses = hack.functions.getCrackAddress(block_number).call()
slots = [
    get_slot(block_number),
    get_slot(chain_id),
    get_slot(block_number + chain_id),
    get_slot(block_number // chain_id),
]
access_list = []
for i in range(11):
    if check_list[i]:
        access_list.append({
            'address': addresses[i],
            'storageKeys': slots
        })
while conn.w3.eth.block_number < block_number:
    try:
        hack.functions.exploit(block_number).send_transaction(gas_limit=18 * 10 ** 6, access_list=access_list)
    except Exception as e:
        print(e)
        continue

print(hack.functions.isSolved().call())
```

### Flag

> flag{451c55fb18d8a00027721f45dff19112c52725534465cde0f956fe2e74be7647}

## 参考资料

- [EIP-2930: Optional access lists](https://eips.ethereum.org/EIPS/eip-2930)
- [EIP-2930 - Ethereum access list saving gas on cross-contract](https://www.rareskills.io/post/eip-2930-optional-access-list-ethereum)
