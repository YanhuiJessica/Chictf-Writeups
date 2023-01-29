---
title: Figment Learn：Solana Pathway
tags:
    - web3
    - blockchain
    - smart contract
    - solana
    - rust
---

## Connect to Solana

> Implement connect by creating a Connection instance and getting the API version

```ts
// pages/api/solana/connect.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { getNodeURL } from '@figment-solana/lib';
import { Connection } from '@solana/web3.js';

export default async function connect(
  req: NextApiRequest,
  res: NextApiResponse<string>,
) {
  try {
    const {network} = req.body;
    const url = getNodeURL(network);
    /***** START *****/
    const connection = new Connection(url);
    const version = await connection.getVersion();
    /***** END *****/
    res.status(200).json(version['solana-core']);
  } catch (error) {
    let errorMessage = error instanceof Error ? error.message : 'Unknown Error';
    res.status(500).json(errorMessage);
  }
}
```

## Create an account

> Implement `keypair` and parse the keypair to extract the address as a string

```ts
// pages/api/solana/keypair.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { Keypair } from '@solana/web3.js';

type ResponseT = {
  secret: string;
  address: string;
};
export default function keypair(
  _req: NextApiRequest,
  res: NextApiResponse<string | ResponseT>,
) {
  try {
    /***** START *****/
    const keypair = Keypair.generate();
    // or
    //const keypair = new Keypair();
    const address = keypair?.publicKey.toString();
    /***** END *****/
    const secret = JSON.stringify(Array.from(keypair.secretKey));
    res.status(200).json({
      secret,
      address,
    });
  } catch (error) {
    let errorMessage = error instanceof Error ? error.message : 'Unknown Error';
    res.status(500).json(errorMessage);
  }
}
```

## Fund the account with SOL

> Convert the address passed in the request body to a public key and use `requestAirdrop` to get 1 SOL

1 **SOL** is equal to 1,000,000,000 **lamports**.

```ts
// pages/api/solana/fund.ts
import { Connection, PublicKey, LAMPORTS_PER_SOL } from '@solana/web3.js';
import type { NextApiRequest, NextApiResponse } from 'next';
import { getNodeURL } from '@figment-solana/lib';

export default async function fund(
  req: NextApiRequest,
  res: NextApiResponse<string>,
) {
  try {
    const { network, address } = req.body;
    const url = getNodeURL(network);
    // confirmed 即当块已通过 cluster 达到 1 个确认时可查询到
    const connection = new Connection(url, 'confirmed');
    /***** START *****/
    const publicKey = new PublicKey(address);
    const hash = await connection.requestAirdrop(publicKey, LAMPORTS_PER_SOL);
    await connection.confirmTransaction(hash);
    /***** END *****/
    res.status(200).json(hash);
  } catch (error) {
    let errorMessage = error instanceof Error ? error.message : 'Unknown Error';
    res.status(500).json(errorMessage);
  }
}
```

### Anatomy of [an Explorer page](https://explorer.solana.com/tx/E6eDJJTx7VDtYgscTquRguaPPGc1hidiNxPK1qPCnbDvWeWVM64ZsytMkysiHoXtdbHu1tQBSFy9Z8WvW8AZm5y?cluster=devnet#ix-1)

- `Overview`
- `Account Input(s)` 参与交易的账户
- `Instruction` 交易中使用的程序指令
- `Program Instruction Logs` 程序执行中的日志输出

## Get the balance

> Implement `publicKey` & `balance`

```ts
// pages/api/solana/balance.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { Connection, PublicKey } from '@solana/web3.js';
import { getNodeURL } from '@figment-solana/lib';

export default async function balance(
  req: NextApiRequest,
  res: NextApiResponse<string | number>,
) {
  try {
    const {network, address} = req.body;
    const url = getNodeURL(network);
    const connection = new Connection(url, 'confirmed');
    /***** START *****/
    const publicKey = new PublicKey(address);
    // The balance is denominated in LAMPORTS
    const balance = await connection.getBalance(publicKey);
    /***** END *****/
    if (balance === 0 || balance === undefined) {
      throw new Error('Account not funded');
    }
    res.status(200).json(balance);
  } catch (error) {
    let errorMessage = error instanceof Error ? error.message : 'Unknown Error';
    res.status(500).json(errorMessage);
  }
}
```

## Transfer some SOL

> Finish implementing the `transfer()` function

- 若一个账户持有至少两年的租金，则免租
- 所有新账户都需要持有至少两年的租金，若交易使得账户余额小于最小值将失败
- 若账户余额为 0，将被清除

```ts
// pages/api/solana/transfer.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { getNodeURL } from '@figment-solana/lib';
import { Connection, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction, Keypair } from '@solana/web3.js';

export default async function transfer(
  req: NextApiRequest,
  res: NextApiResponse<string>,
) {
  try {
    const { address, secret, recipient, lamports, network } = req.body;
    const url = getNodeURL(network);
    const connection = new Connection(url, 'confirmed');

    const fromPubkey = new PublicKey(address);
    const toPubkey = new PublicKey(recipient);
    // The secret key is stored in our state as a stringified array
    const secretKey = Uint8Array.from(JSON.parse(secret as string));

    /***** START *****/
    //... let's skip the beginning as it should be familiar for you by now!
    // Find the parameter to pass
    const instructions = SystemProgram.transfer({ fromPubkey, toPubkey, lamports });

    // How could you construct a signer array's
    const signers = [Keypair.fromSecretKey(secretKey)];
    //const signers = [{publicKey: fromPubkey, secretKey}];
    // 当属性名与变量名相同时，e.g. name:name, 可简写为 name

    // Maybe adding something to a Transaction could be interesting ?
    const transaction = new Transaction().add(instructions);

    // We can send and confirm a transaction in one row.
    const hash = await sendAndConfirmTransaction(
      connection,
      transaction,
      signers
    );
    /***** END *****/

    res.status(200).json(hash);
  } catch (error) {
    let errorMessage = error instanceof Error ? error.message : 'Unknown Error';
    res.status(500).json(errorMessage);
  }
}
```

### 参考资料

- [Accounts | Solana Docs](https://docs.solana.com/developing/programming-model/accounts#rent)
- [Objects | Property value shorthand](https://javascript.info/object#property-value-shorthand)

## Deploy a program

### Smart contract review

> a simple program, incrementing a number every time it's called

- `use` 类似于 `import`

    ```rust
    // The Rust source code for the program
    // contracts/solana/program/src/lib.rs
    use borsh::{BorshDeserialize, BorshSerialize};  // borsh: Binary Object Representation Serializer for Hashing
    use solana_program::{
        account_info::{next_account_info, AccountInfo},
        entrypoint,
        entrypoint::ProgramResult,
        msg,    // for low-impact logging on the blockchain
        program_error::ProgramError,
        pubkey::Pubkey,
    };
    ```

- 利用派生（`derive`）宏在编译时生成结构体 `GreetingAccount` 必需的样板代码

    ```rust
    /// Define the type of state stored in accounts
    #[derive(BorshSerialize, BorshDeserialize, Debug)]
    pub struct GreetingAccount {
        /// number of greetings
        pub counter: u32,
    }
    ```

- 定义程序的入口点
    - `?` 只能用于返回 `Result` 的函数

    ```rust
    // Declare and export the program's entrypoint
    entrypoint!(process_instruction);

    // Program entrypoint's implementation
    pub fn process_instruction(
        program_id: &Pubkey, // Public key of the account the hello world program was loaded into
        accounts: &[AccountInfo], // The account to say hello to
        _instruction_data: &[u8], // Ignored, all helloworld instructions are hellos
    ) -> ProgramResult {
        // print messages to the Program Log with the msg!() macro
        // rather than use println!() which would be prohibitive in terms of computational cost for the network.
        msg!("Hello World Rust program entrypoint");

        // Iterating accounts is safer than indexing
        let accounts_iter = &mut accounts.iter();
        // accounts_iter takes a mutable reference of each values in accounts

        // Get the account to say hello to
        let account = next_account_info(accounts_iter)?;    // Will return the next AccountInfo or a NotEnoughAccountKeys error
        // ? is a shortcut expression for error propagation

        // The account must be owned by the program in order to modify its data
        // 除所有者外，其他人无权修改数据账户的状态
        if account.owner != program_id {
            msg!("Greeted account does not have the correct program id");
            return Err(ProgramError::IncorrectProgramId);
        }

        // Increment and store the number of times the account has been greeted
        let mut greeting_account = GreetingAccount::try_from_slice(&account.data.borrow())?; // borrow operator &
        // shared borrow &: the place may not be mutated, but it may be read or shared again
        // mutable borrow &mut: the place may not be accessed in any way until the borrow expires
        // try_from_slice will mutably reference and deserialize the account.data
        greeting_account.counter += 1;
        greeting_account.serialize(&mut &mut account.data.borrow_mut()[..])?;
        // with the serialize(), the new counter value is sent back to Solana

        msg!("Greeted {} time(s)!", greeting_account.counter);

        Ok(())
    }
    ```

- 关于 `greeting_account.serialize(&mut &mut account.data.borrow_mut()[..])?;`
    - `serialize` 需要类型为 `&mut W` 的参数，`W` 实现了 `Write` 特征，而 `Write` 需要 `&mut [u8]`
    - `borrow_mut()` 返回 `RefMut<&mut [u8]>`，接下来取可变切片
    - `account.data.borrow_mut()[..]` 是 `*(account.data.borrow_mut().index_mut(..))`（`*` 执行解引用）的语法糖，`..` 是 `RangeFull` 的简写，而 `fn index_mut(&mut self, index: RangeFull) -> &mut Self::Output`，得到 `[u8]`
    - 在查询方法调用时，接收者可能会自动解引用或借用变量来调用一个方法[^deref]，使用 `greeting_account.serialize(&mut *account.data.borrow_mut())?` 是等价的

### Set up the Solana CLI

```bash
$ solana config set --url https://api.devnet.solana.com
$ mkdir solana-wallet
$ solana-keygen new --outfile solana-wallet/keypair.json
$ solana airdrop 1 $(solana-keygen pubkey solana-wallet/keypair.json)
$ solana account $(solana-keygen pubkey solana-wallet/keypair.json) # check balance
```

### Deploy a Solana program

```bash
# Build the program, running the following command from the project root directory
$ yarn run solana:build:program
# Deploy the program
$ solana deploy -v --keypair solana-wallet/keypair.json dist/solana/program/helloworld.so
```

当部署一直处在等待状态时，注意检查集群的版本是否与 CLI 的版本匹配[^version]

```bash
$ solana cluster-version
```

### Challenge

> Get the publicKey of the programId and get its account info

```ts
// pages/api/solana/deploy.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { Connection, PublicKey } from '@solana/web3.js';
import { getNodeURL } from '@figment-solana/lib';
import path from 'path';
import fs from 'mz/fs';

const PROGRAM_PATH = path.resolve('dist/solana/program');
const PROGRAM_SO_PATH = path.join(PROGRAM_PATH, 'helloworld.so');

export default async function deploy(
  req: NextApiRequest,
  res: NextApiResponse<string | boolean>,
) {
  try {
    const {network, programId} = req.body;
    const url = getNodeURL(network);
    const connection = new Connection(url, 'confirmed');
    /***** START *****/
    const publicKey = new PublicKey(programId);
    const programInfo = await connection.getAccountInfo(publicKey);
    /***** END *****/

    if (programInfo === null) {
      if (fs.existsSync(PROGRAM_SO_PATH)) {
        throw new Error(
          'Program needs to be deployed with `solana program deploy`',
        );
      } else {
        throw new Error('Program needs to be built and deployed');
      }
    } else if (!programInfo.executable) {
      throw new Error(`Program is not executable`);
    }

    res.status(200).json(true);
  } catch (error) {
    let errorMessage = error instanceof Error ? error.message : 'Unknown Error';
    res.status(500).json(errorMessage);
  }
}
```

### 参考资料

- [Cargo, crates and basic project structure - Learning Rust](https://learning-rust.github.io/docs/cargo-crates-and-basic-project-structure/)
- [The question mark operator, ?](https://doc.rust-lang.org/std/result/#the-question-mark-operator-)
- [Borrow operators](https://doc.rust-lang.org/reference/expressions/operator-expr.html#borrow-operators)
- [rust - Trouble understanding &mut &mut reference - Stack Overflow](https://stackoverflow.com/questions/69670357/trouble-understanding-mut-mut-reference)

## Create storage for the program

> First, derive the **greeter** address from some values. Then create a transaction which instructs the blockchain to create the **greeter** account

```ts
// pages/api/solana/greeter.ts
import {
  Connection,
  PublicKey,
  Keypair,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from '@solana/web3.js';
import type { NextApiRequest, NextApiResponse } from 'next';
import { getNodeURL } from '@figment-solana/lib';
import * as borsh from 'borsh';

// The state of a greeting account managed by the hello world program
class GreetingAccount {
  counter = 0;
  constructor(fields: {counter: number} | undefined = undefined) {
    if (fields) {
      this.counter = fields.counter;
    }
  }
}

// Borsh schema definition for greeting accounts
const GreetingSchema = new Map([
  [GreetingAccount, {kind: 'struct', fields: [['counter', 'u32']]}],
]);

// The expected size of each greeting account.
const GREETING_SIZE = borsh.serialize(
  GreetingSchema,
  new GreetingAccount(),
).length;

type ResponseT = {
  hash: string;
  greeter: string;
};
export default async function greeter(
  req: NextApiRequest,
  res: NextApiResponse<string | ResponseT>,
) {
  try {
    const {network, secret, programId: programAddress} = req.body;
    const url = getNodeURL(network);
    const connection = new Connection(url, 'confirmed');

    const programId = new PublicKey(programAddress);
    const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(secret)));
    const GREETING_SEED = 'hello';

    /***** START *****/
    // Are there any methods from PublicKey to derive a public key from a seed?
    const greetedPubkey = await PublicKey.createWithSeed(payer.publicKey, GREETING_SEED, programId);

    // This function calculates the fees we have to pay to keep the newly
    // created account alive on the blockchain. We're naming it lamports because
    // that is the denomination of the amount being returned by the function.
    const lamports = await connection.getMinimumBalanceForRentExemption(
      GREETING_SIZE,
    );

    // Find which instructions are expected and complete SystemProgram with
    // the required arguments.
    const transaction = new Transaction().add(SystemProgram.createAccountWithSeed({
      basePubkey: payer.publicKey,  // Base public key to use to derive the address of the created account
      fromPubkey: payer.publicKey,  // The payer
      lamports,
      newAccountPubkey: greetedPubkey,  // The created account
      programId,
      seed: GREETING_SEED,
      space: GREETING_SIZE
    }));

    // Complete this function call with the expected arguments.
    const hash = await sendAndConfirmTransaction(connection, transaction, [payer]);
    /***** END *****/
    res.status(200).json({
      hash: hash,
      greeter: greetedPubkey.toBase58(),
    });
  } catch (error) {
    let errorMessage = error instanceof Error ? error.message : 'Unknown Error';
    res.status(500).json(errorMessage);
  }
}
```

## Get data from the program

> First deserialize the greeter data to a TypeScript class, then access the counter value and pass it to the response object using the `.json()` method as in all previous tutorials

```ts
// pages/api/solana/getter.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { Connection, PublicKey } from '@solana/web3.js';
import { getNodeURL } from '@figment-solana/lib';
import * as borsh from 'borsh';

// The state of a greeting account managed by the hello world program
class GreetingAccount {
  counter = 0;
  constructor(fields: {counter: number} | undefined = undefined) {
    if (fields) {
      this.counter = fields.counter;
    }
  }
}

// Borsh schema definition for greeting accounts
const GreetingSchema = new Map([
  [GreetingAccount, {kind: 'struct', fields: [['counter', 'u32']]}],
]);

export default async function getter(
  req: NextApiRequest,
  res: NextApiResponse<string | number>,
) {
  try {
    const {network, greeter} = req.body;
    const url = getNodeURL(network);
    const connection = new Connection(url, 'confirmed');
    const greeterPublicKey = new PublicKey(greeter);

    const accountInfo = await connection.getAccountInfo(greeterPublicKey);

    if (accountInfo === null) {
      throw new Error('Error: cannot find the greeted account');
    }

    /***** START *****/
    // Find the expected parameters.
    const greeting = borsh.deserialize(GreetingSchema, GreetingAccount, accountInfo.data);

    // A little helper
    console.log(greeting);

    // Pass the counter to the client-side as JSON
    res.status(200).json(greeting.counter);
    /***** END *****/
  } catch (error) {
    let errorMessage = error instanceof Error ? error.message : 'Unknown Error';
    console.log(errorMessage);
    res.status(500).json(errorMessage);
  }
}
```

## Send data to the program

> First you'll have to create an instruction, then you'll have to send and confirm a transaction to store the data from

```ts
// pages/api/solana/setter.ts
import {
  Connection,
  PublicKey,
  Keypair,
  TransactionInstruction,
  Transaction,
  sendAndConfirmTransaction,
} from '@solana/web3.js';
import type { NextApiRequest, NextApiResponse } from 'next';
import { getNodeURL } from '@figment-solana/lib';

export default async function setter(
  req: NextApiRequest,
  res: NextApiResponse<string>,
) {
  try {
    const {greeter, secret, programId, network} = req.body;
    const url = getNodeURL(network);
    const connection = new Connection(url, 'confirmed');

    const greeterPublicKey = new PublicKey(greeter);
    const programKey = new PublicKey(programId);

    const payerSecretKey = new Uint8Array(JSON.parse(secret));
    const payerKeypair = Keypair.fromSecretKey(payerSecretKey);

    /***** START *****/
    const instruction = new TransactionInstruction({
      programId,
      keys: [{pubkey: greeterPublicKey, isWritable: true, isSigner: false}]
    });

    const hash = await sendAndConfirmTransaction(connection, new Transaction().add(instruction), [payerKeypair]);
    /***** END *****/

    res.status(200).json(hash);
  } catch (error) {
    console.error(error);
    res.status(500).json('Get balance failed');
  }
}
```

[^deref]: [Method call expressions - The Rust Reference](https://doc.rust-lang.org/reference/expressions/method-call-expr.html)
[^version]: [Ensure Versions Match](https://docs.solana.com/cli/choose-a-cluster#ensure-versions-match)