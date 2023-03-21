---
title: Blockchain - TealyMan
description: 2023 | WolvCTF | Crypto
tags:
    - smart contract
    - algorand
    - teal
    - beginner
---

## 题目

Use the TestNet. Submit by sending enough testnet algos to cover the current transaction fee to the CTF_Address.

<table>
<tbody>
  <tr>
    <td>CTF_Address</td>
    <td>OH4YZ4QXWOWLHIUKPQAOMPBZBELCANRPRX3NI7SQFL2OFASHLBW5DTLDZQ</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>AppID</td>
    <td>163726037</td>
  </tr>
</tbody>
</table>

## 解题思路

- 看地址首先排除 Ethereum uwu 根据 `TestNet` 和 `algos` 锁定 Algorand 生态 owo
- [OH4YZ4QXWOWLHIUKPQAOMPBZBELCANRPRX3NI7SQFL2OFASHLBW5DTLDZQ](https://testnet.algoexplorer.io/address/OH4YZ4QXWOWLHIUKPQAOMPBZBELCANRPRX3NI7SQFL2OFASHLBW5DTLDZQ) 为普通账户，[163726037](https://testnet.algoexplorer.io/application/163726037) 对应需要交互的智能合约账户
- Algorand 智能合约包含两部分，`ApprovalProgram` 和 `ClearStateProgram`。`ApprovalProgram` 负责处理主应用逻辑，`ClearStateProgram` 负责将对应智能合约从账户记录中移除，执行成功返回 $1$

> the flag will be sent to u once ur done with the app and provide the address enough to cover current transaction fees

- 目标是与应用进行完整交互。与合约交互的方法包括 Opt-in、Call(NoOp)、Read state、Update、Close out、Delete 以及 Clear state
    - 在开始与使用本地状态的应用交互前，账户需要 Opt in
- 分析 `ApprovalProgram`，根据 `OnCompletion` 的类型执行相关操作，重点关注 `OnCompletion == 0`，即 NoOp。目标应用支持 `setup` 和 `buy`
    - 首先通过 `setup` 向应用注册 asset，并向应用转移一部分 asset 以便后续购买操作
    - 再进行 `buy`，需要发送一个交易组，其中第一个交易为 Payment（向应用支付购买 asset 的 algo），第二个是 Application Call

	??? note "Approval Program"

		```
		#pragma version 5
			intcblock 1 0 4 9223372036854775808 // prepare block of uint64 constants for use by intc
			bytecblock 0x7374617274 0x656e64 0x61646d696e5f6b6579 0x6e66745f6964 // prepare block of byte-array constants for use by bytec

			// Deploy or Call?
			txn ApplicationID
			intc_1 // 0
			==
			bnz label1

			txn OnCompletion
			intc_1 // 0, NoOp, only execute the ApprovalProgram associated with this application ID, with no additional effects.
			==
			bnz label2

			txn OnCompletion
			intc_0 // 1, OptIn, before executing the ApprovalProgram, allocate local state for this application into the sender's account data
			==
			bnz label3

			txn OnCompletion
			pushint 2 // CloseOut, after executing the ApprovalProgram, clear any local state for this application out of the sender's account data.
			==
			bnz label4

			txn OnCompletion
			pushint 5 // DeleteApplication
			==
			bnz label5

			txn OnCompletion
			intc_2 // 4, UpdateApplication
			==
			bnz label6

			err
		label6:
			intc_1 // 0
			return
		label5:
			txn Sender
			global CreatorAddress
			==
			assert

			bytec_2 // "admin_key"
			app_global_get
			callsub label7

			intc_0 // 1
			return
		label4:
			intc_0 // 1
			return
		label3:
			intc_0 // 1
			return
		label2:
			txna ApplicationArgs 0 // 0-th value of the ApplicationArgs array of the current transaction
			pushbytes 0x7365747570 // "setup"
			==
			bnz label8

			txna ApplicationArgs 0
			pushbytes 0x627579 // "buy"
			==
			bnz label9

			err
		label9:
			global CurrentApplicationAddress // Address that the current application controls
			txna Assets 0 // Foreign Assets listed in the ApplicationCall transaction
			asset_holding_get AssetBalance
			store 1	// store is_opted_in to the 1-th scratch space
			store 0 // store asset balance to the 0-th scratch space
			load 1	// load is_opted_in from the 1-th scratch space
			intc_1 // 0
			load 0
			callsub label10
			&&	// if is_opted_in and asset balance > 0

			txn Sender
			bytec_0 // "start"
			app_local_get
			global LatestTimestamp
			callsub label10
			&&

			global LatestTimestamp
			txn Sender
			bytec_1 // "end"
			app_local_get
			callsub label10
			&&

			txn GroupIndex // index=1
			intc_0 // 1
			- // GroupIndex - 1
			gtxns TypeEnum // field F of the (GroupIndex - 1)-th transaction in the current group

			intc_0 // 1
			==
			&&

			txn GroupIndex // index=1
			intc_0 // 1
			-
			gtxns Sender

			txn Sender
			==
			&&

			txn GroupIndex // index=1
			intc_0 // 1
			-
			gtxns Receiver

			global CurrentApplicationAddress
			==
			&&

			global MinTxnFee

			txn GroupIndex // index=1
			intc_0 // 1
			-
			gtxns Amount

			callsub label10
			&&
			assert

			txna ApplicationArgs 1
			btoi
			global LatestTimestamp
			+

			txn Sender
			bytec_0 // "start"
			app_local_get
			callsub label10
			bnz label11

			intc_1 // 0
			return
		label11:
			txn Sender
			bytec_3 // "nft_id"
			app_local_get

			txn Sender
			callsub label12

			intc_0 // 1
			return
		label8:
			itxn_begin // begin preparation of a new inner transaction in a new transaction group
			
			intc_2 // 4
			itxn_field TypeEnum // set field of the current inner transaction to AssetTransfer
			
			txna Assets 0
			itxn_field XferAsset
			
			global CurrentApplicationAddress
			itxn_field AssetReceiver
			itxn_submit	// execute the current inner transaction group
			
			txn Sender
			bytec_3 // "nft_id"
			txna Assets 0
			app_local_put // store the nft_id in the sender's local state
			
			txn Sender
			pushbytes 0x73656c6c6572 // "seller"
			txn Sender
			app_local_put // store the seller address in the sender's local state

			txn Sender
			bytec_0 // "start"
			global LatestTimestamp
			app_local_put

			txn Sender
			bytec_1 // "end"
			txna ApplicationArgs 1
			btoi
			app_local_put

			txn Sender
			bytec_0 // "start"
			app_local_get
			txn Sender
			bytec_1 // "end"
			app_local_get
			<
			assert	// require start < end

			intc_0 // 1, approval
			return
		label1:
			bytec_2 // "admin_key"
			txn Sender
			app_global_put

			intc_0 // 1
			return
		label12:
			store 3
			store 2
			global CurrentApplicationAddress
			load 2
			asset_holding_get AssetBalance
			store 5
			store 4
			load 5
			bz label13

			itxn_begin
			intc_2 // 4
			itxn_field TypeEnum
			load 2
			itxn_field XferAsset
			load 3
			itxn_field AssetCloseTo
			itxn_submit
		label13:
			retsub
		label7:
			store 6
			global CurrentApplicationAddress
			balance
			intc_1 // 0
			!=
			bz label14

			itxn_begin
			intc_0 // 1
			itxn_field TypeEnum
			load 6
			itxn_field CloseRemainderTo
			itxn_submit
		label14:
			retsub
		label10:
			store 8
			store 7
			intc_3 // 9223372036854775808
			load 7
			&
			bnz label15

			intc_3 // 9223372036854775808, 0x8000000000000000
			load 8
			&
			bnz label16

			load 7
			load 8
			<
			bnz label17

			intc_1 // 0
			retsub
		label17:
			intc_0 // 1
			retsub
		label16:
			intc_1 // 0
			retsub
		label15:
			intc_3 // 9223372036854775808
			load 8
			&
			bnz label18

			intc_0 // 1
			retsub
		label18:
			load 7
			load 8
			>
			bnz label19

			intc_1 // 0
			retsub
		label19:
			intc_0 // 1
			retsub
		```

- CTF_Address 会向完成交易的账户发起 Transfer 交易，其中包含使用 AlgoSMS 加密的 Flag

### Exploit

```py
from algosdk.v2client import algod
from algosdk import transaction, account, constants
from Crypto.Util.number import long_to_bytes
from datetime import datetime
import json

def transact(txn):
    if not isinstance(txn, list):
        signed_txn = txn.sign(private_key)
        txid = algod_client.send_transaction(signed_txn)
    else:
        signed_txns = [t.sign(private_key) for t in txn]
        txid = algod_client.send_transactions(signed_txns)
    confirmed_txn = transaction.wait_for_confirmation(algod_client, txid, 4)
    print(f"Transaction information: {json.dumps(confirmed_txn, indent=4)}")
    return confirmed_txn

private_key = '<private>'
sender = account.address_from_private_key(private_key)

app_id = 163726037
app_address = "5K7JP6324NOEPDB5THIZY3FWHUKF4FBPJFYKIUX2SBNG264NUY6E3AI3BM"

algod_address = "https://testnet-algorand.api.purestake.io/ps2"
algod_token = "<api-key>"
headers = {
    "X-API-Key": algod_token,
}
algod_client = algod.AlgodClient(algod_token, algod_address, headers)

params = algod_client.suggested_params()

# OptIn
optin_txn = transaction.ApplicationOptInTxn(sender, params, app_id)
transact(optin_txn)

# Create asset
create_txn = transaction.AssetCreateTxn(
    sender,
    params,
    100,
    decimals=2,
    default_frozen=False,
    unit_name="CC",
    asset_name="Chicken Coin",
    manager=sender,
)
res = transact(create_txn)
asset_id = res['asset-index']

setup_txn = transaction.ApplicationNoOpTxn(
    sender,
    params,
    app_id,
    [b'setup', long_to_bytes(int(datetime.now().timestamp() * 1000) + 0x80000000)],
    foreign_assets=[asset_id],
    foreign_apps=[asset_id],
    )
transact(setup_txn)

transfer_txn = transaction.AssetTransferTxn(
    sender,
    params,
    app_address,
    1,
    asset_id,
)
transact(transfer_txn)

payment_txn = transaction.PaymentTxn(
    sender,
    params,
    app_address,
    constants.MIN_TXN_FEE * 10,
)
noop_txn = transaction.ApplicationNoOpTxn(
    sender,
    params,
    app_id,
    [b'buy', long_to_bytes(9223372036854775808)],
    foreign_assets=[asset_id],
    foreign_apps=[asset_id],
)
gid = transaction.calculate_group_id([payment_txn, noop_txn])
payment_txn.group = gid
noop_txn.group = gid
transact([payment_txn, noop_txn])

close_txn = transaction.ApplicationCloseOutTxn(
    sender,
    params,
    app_id,
)
transact(close_txn)
```

```js
const algosdk = require('algosdk');
const { unsealMessageFromNote } = require('algosms');

async function main() {
    const baseServer = 'https://testnet-algorand.api.purestake.io/idx2'
    const port = '';
    const token = {
        'X-API-Key': '<api-key>'
    }

    let indexerClient = new algosdk.Indexer(token, baseServer, port);

    const accRcpt = algosdk.mnemonicToSecretKey('<mnemonic>');

    /* get the TXN with encrypted note from indexer */
    let SmsTXID = "DPHCQMJZ7BKJZHZO674VWGUO3J7JJAIKFKGSAEDHBSQBVYGV4I7A";
    const txn = await indexerClient.lookupTransactionByID(SmsTXID).do();

    /* convert base64 to bytes */
    const note = Buffer.from(txn.transaction.note, 'base64');
    const senderAddr = txn.transaction.sender;

    /* decrypt the note with recipient secret key */
    const msg = unsealMessageFromNote(note, senderAddr, accRcpt);
    console.log(msg);
}

main();
```

### Flag

> wctf{1_h0p3_y0u_d0nt_4cc1dent4lly_4get_t0_r3m0ve_th3_4pp}

### 参考资料

- [Interact with smart contracts - Algorand Developer Portal](https://developer.algorand.org/docs/get-details/dapps/smart-contracts/frontend/apps)
- [Opcodes - Algorand Developer Portal](https://developer.algorand.org/docs/get-details/dapps/avm/teal/opcodes)
- [PureStake Developer Portal](https://developer.purestake.io/code-samples)
- [algosms - npm](https://www.npmjs.com/package/algosms)