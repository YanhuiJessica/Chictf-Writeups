---
title: Blockchain - 链上记忆大师
description: 2022 | 中国科学技术大学第九届信息安全大赛 | General
tags:
    - smart contract
---

## 题目

听说你在区块链上部署的智能合约有过目不忘的能力。

??? note "main.py"

    ```py
    from web3 import Web3
    from web3.middleware import geth_poa_middleware
    import os
    import json
    import time
    import shutil

    challenge_id = int(input('The challenge you want to play (1 or 2 or 3): '))
    assert challenge_id == 1 or challenge_id == 2 or challenge_id == 3

    player_bytecode = bytes.fromhex(input('Player bytecode: '))

    print('Launching geth...')
    shutil.copytree('/data', '/dev/shm/geth')
    os.system('geth --datadir /dev/shm/geth --nodiscover --mine --unlock 0x2022af4DCbb9dA7F41cBD3dD8CdB4134D4e6DDe6 --password password.txt --verbosity 0 --datadir.minfreedisk 0 &')
    time.sleep(2)
    w3 = Web3(Web3.IPCProvider('/dev/shm/geth/geth.ipc'))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    w3.eth.default_account = w3.eth.accounts[0]
    w3.geth.personal.unlock_account(w3.eth.default_account, open('password.txt').read().strip())
    print('Deploying challenge contract...')
    bytecode, abi = json.load(open(f'contract{challenge_id}.json'))
    Challenge = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Challenge.constructor().transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print('Challenge contract address:', tx_receipt.contractAddress)
    challenge = w3.eth.contract(address=tx_receipt.contractAddress, abi=abi)
    print('Deploying player contract...')
    tx_hash = w3.eth.send_transaction({'to': None, 'data': player_bytecode})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print('Player contract address:', tx_receipt.contractAddress)
    for i in range(10):
        print(f'Testing {i + 1}/10...')
        if challenge_id == 2:
            n = int.from_bytes(os.urandom(2), 'big')
        else:
            n = int.from_bytes(os.urandom(32), 'big')
        print(f'n = {n}')
        if challenge.functions.test(tx_receipt.contractAddress, n).call():
            print('Test passed!')
        else:
            print('Test failed!')
            exit(-1)
    print(open(f'flag{challenge_id}').read())
    ```

??? note "compile.py"

    ```py
    from solcx import compile_source
    import json

    for i in 1, 2, 3:
        compiled_sol = compile_source(open(f'challenge{i}.sol').read(), output_values=['abi', 'bin'])
        contract_interface = compiled_sol['<stdin>:Challenge']
        bytecode = contract_interface['bin']
        abi = contract_interface['abi']
        json.dump((bytecode, abi), open(f'contract{i}.json', 'w'))
    ```

??? note "genesis.json"

    ```json
    {
        "config": {
            "chainId": 2022,
            "homesteadBlock": 0,
            "eip150Block": 0,
            "eip155Block": 0,
            "eip158Block": 0,
            "byzantiumBlock": 0,
            "constantinopleBlock": 0,
            "petersburgBlock": 0,
            "istanbulBlock": 0,
            "muirGlacierBlock": 0,
            "berlinBlock": 0,
            "londonBlock": 0,
            "arrowGlacierBlock": 0,
            "grayGlacierBlock": 0,
            "clique": {
                "period": 0,
                "epoch": 30000
            }
        },
        "alloc": {
            "0x2022af4DCbb9dA7F41cBD3dD8CdB4134D4e6DDe6": {"balance": "0x56bc75e2d63100000"}
        },
        "coinbase": "0x0000000000000000000000000000000000000000",
        "difficulty": "0x1",
        "gasLimit": "0x1c9c380",
        "extraData": "0x00000000000000000000000000000000000000000000000000000000000000002022af4dcbb9da7f41cbd3dd8cdb4134d4e6dde60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "nonce": "0x0000000000000042",
        "mixhash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "timestamp": "0x00"
    }
    ```

??? note "Dockerfile"

    ```dockerfile
    FROM ubuntu:22.04
    RUN apt update && apt install -y software-properties-common && add-apt-repository -y ppa:ethereum/ethereum && apt update && apt install -y ethereum python3-pip
    RUN python3 -m pip install web3 py-solc-x
    RUN python3 -c "from solcx import install_solc; install_solc(version='latest')"
    COPY genesis.json privatekey.txt password.txt main.py challenge1.sol challenge2.sol challenge3.sol compile.py /
    RUN geth init --datadir data genesis.json
    RUN geth --datadir data account import --password password.txt privatekey.txt
    RUN python3 compile.py
    CMD ["/usr/bin/python3", "-u", "/main.py"]
    ```

### 记忆练习

```js
pragma solidity =0.8.17;

interface MemoryMaster {
    function memorize(uint256 n) external;
    function recall() external view returns (uint256);
}

contract Challenge {
    function test(MemoryMaster m, uint256 n) external returns (bool) {
        m.memorize(n);
        uint256 recalled = m.recall();
        return recalled == n;
    }
}
```

### 牛刀小试

```js
pragma solidity =0.8.17;

interface MemoryMaster {
    function memorize(uint16 n) external;
    function recall() external view returns (uint16);
}

contract Challenge {
    function test(MemoryMaster m, uint16 n) external returns (bool) {
        try this.memorize_revert(m, n) {
        } catch (bytes memory) {
        }

        uint16 recalled = m.recall();
        return recalled == n;
    }

    function memorize_revert(MemoryMaster m, uint16 n) external {
        m.memorize(n);
        revert();
    }
}
```

### 终极挑战

```js
pragma solidity =0.8.17;

interface MemoryMaster {
    function memorize(uint256 n) external view;
    function recall() external view returns (uint256);
}

contract Challenge {
    function test(MemoryMaster m, uint256 n) external returns (bool) {
        m.memorize(n);
        uint256 recalled = m.recall();
        return recalled == n;
    }
}
```

## 解题思路

需要编写包含函数 `memorize` 和函数 `recall` 的合约 `MemoryMaster`，合约 `Challenge` 将首先调用函数 `memorize` 并传入参数 `n`，随后调用函数 `recall` 并期望返回 `n`。

### 记忆练习

本题没有对函数 `memorize` 和函数 `recall` 进行任何限制，因而可以直接借助状态变量。

```js
pragma solidity 0.8.17;

contract MemoryMaster {
    uint256 n;
    function memorize(uint256 _n) public {
        n = _n;
    }

    function recall() public view returns (uint256) {
        return n;
    }
}
```

#### Flag

> flag{Y0u_Ar3_n0w_f4M1l1ar_W1th_S0l1dity_st0rage_dd0d6977ef}

### 牛刀小试

- 函数 `memorize` 被调用后即 `revert`，尽管由于 `try/catch` 的存在，不影响后续操作，但无法再使用状态变量来传递 `n` 值
- 便想到可以借助 `gasleft()`，汽油的消耗不受回滚的影响，并且 `n` 的类型也由 `uint256` 调整为了 `uint16`，不过实施起来就没那么简单了 :(
- 梳理一下已知的信息
    - 交易的初始汽油量受 `geth` 的 `--rpc.gascap` 控制，默认为 $50000000$[^gascap]
    - 每次函数调用会传入剩余汽油的 63/64
- 若函数 `memorize` 故意消耗掉 `x` 汽油，那么传入 `recall` 的汽油量为 `(50000000 - k - x) * 63 / 64`。$50000000$ 映射到 $2^{16}$，每个区间约 $763$ 汽油，考虑到 `63/64`，可以以 $720$ 为一个单位
    - `gasleft()` 包含 `GAS` 操作码，获取该操作执行结束后剩余的汽油量[^gas]
- 首先可利用 `revert` 获得执行到函数 `recall` 的剩余汽油量，并计算出 `k`

    ```js
    pragma solidity 0.8.17;

    import "@openzeppelin/contracts/utils/Strings.sol";

    contract MemoryMaster {
        function memorize(uint16 n) public {
            uint256 g = gasleft();
            while (gasleft() > g - 720 * uint256(n)) gasleft();
        }

        function recall() public view returns (uint16) {
            uint256 n = gasleft();
            revert(Strings.toString(n));
            return uint16(n);
        }
    }
    ```

- 提交字节码到服务器，由此可大致算出 `k = 30040` (`(50000000 - k - 27688 * 720) * 63 / 64 = 29565309`)

    ```bash
    Testing 1/10...
    n = 27688
    ...
    web3.exceptions.ContractLogicError: execution reverted: 29565309
    ```

#### Exploit

```js
pragma solidity 0.8.17;

contract MemoryMaster {
    function memorize(uint16 n) public {
        uint256 g = gasleft();
        while (gasleft() > g - 720 * uint256(n)) gasleft();
    }

    function recall() public view returns (uint16) {
        return uint16((50000000 - 30040 - gasleft() * 64 / 63) / 720);
    }
}
```

#### Flag

> flag{Gas_gAs_gaS_c4n_b3_us3d_aS_s1de_ChaNNel_5a01148fd5}

### 终极挑战

- 函数 `memorize` 添加了 `view` 修饰符，因而不能修改状态变量，而 `n` 的类型又恢复为 `uint256`，上一题的策略也不能再使用
- 一部分操作码，如 `SSTORE`、`SLOAD`，消耗的汽油量与访问的位置是否是初次访问有关，冷访问要消耗更多的汽油
- 可以通过故意访问一些特定的位置来向 `recall` 传递 `n` 的值，可以使用 `SLOAD`，访问冷/热存储位置的开销分别为 `2100`/`100`，或借助于其它 `ADDRESS_TOUCHING_OPCODES`、`STORAGE_TOUCHING_OPCODES`

    ```js
    pragma solidity 0.8.17;

    contract MemoryMaster {

        mapping(uint16 => bool) access;

        function memorize(uint256 n) external view {
            for (uint16 i = 0; i < 256; i ++) {
                if ((n >> i) & 1 != 0) access[i];
            }
        }

        function recall() external view returns (uint256) {
            uint256 n = 0;
            for (uint16 i = 256; i > 0; i --) { // i 减到 -1 会导致 revert
                n <<= 1;
                uint256 g = gasleft();
                access[i - 1];
                if (g - gasleft() < 1000) n += 1;
            }
            return n;
        }
    }
    ```

- 状态回滚包括地址和存储位置的冷热状态

#### Flag

> flag{EVM_1s_c0mPl1c4ted_bUt_Rea11y_FuN_T0_d1g_Deeper_9d3b7f6932}

#### 参考资料

- [EIP-2929: Gas cost increases for state access opcodes](https://eips.ethereum.org/EIPS/eip-2929)
- [Appendix - Dynamic Gas Costs](https://github.com/wolflo/evm-opcodes/blob/main/gas.md)

[^gascap]: [Command-line Options | Go Ethereum](https://geth.ethereum.org/docs/interface/command-line-options)
[^gas]: [EVM Codes - An Ethereum Virtual Machine Opcodes Interactive Reference](https://www.evm.codes/#5a?fork=merge)