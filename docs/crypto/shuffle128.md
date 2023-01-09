---
title: Crypto - shuffle128
description: 2023 | TetCTF | CRYPTO
tags:
    - rc4
---

## 题目

A weak version of RC4.

??? note "shuffle128.py"

    ```py
    import sys
    from typing import List, Iterator
    from bitarray import bitarray  # https://pypi.org/project/bitarray/
    import random

    State = List[int]

    def swap(arr: State, i: int, j: int):
        arr[i] ^= arr[j]
        arr[j] ^= arr[i]
        arr[i] ^= arr[j]

    def rc4_key_scheduling(key: bytes) -> State:
        S = list(range(128))
        j = 0
        for i in range(128):
            j = (j + S[i] + key[i % len(key)]) % 128
            swap(S, i, j)
        return S

    def rc4_pseudo_random_generator(S: State) -> Iterator[int]:
        i = j = 0
        while True:
            i = (i + 1) % 128
            j = (j + S[i]) % 128
            swap(S, i, j)
            yield S[(S[i] + S[j]) % 128]

    def shuffle(s: bytes) -> bytes:
        bits = bitarray()
        bits.frombytes(s)
        random.shuffle(bits)
        return bits.tobytes()

    def xor(s1: bytes, s2: bytes) -> bytes:
        assert len(s1) == len(s2)
        return bytes(c1 ^ c2 for c1, c2 in zip(s1, s2))

    if __name__ == '__main__':
        from secret import FLAG

        random.seed(2023)
        print(sys.version)
        prg = rc4_pseudo_random_generator(rc4_key_scheduling(FLAG))
        for _ in range(64):
            shuffled = shuffle(FLAG)
            key = bytes(next(prg) for _ in range(len(FLAG)))
            print(xor(shuffled, key).hex())

    # Output
    # 3.10.7 (main, Nov 24 2022, 19:45:47) [GCC 12.2.0]
    # 7dfdf6eba4da43bf7ca6eb64d3fbaac5e764b2c8e66e1f2a30e3b9e95b2ef48b28f105cdfc
    # 3353e19ed6a3ecad7716831b8cc149ad3a1990c8f4682c434d1b7f417e7df9e9ca0743fc3a
    # 2e15e68721c7773a920d9622cbad21b2d48e00358b1107b300ba19c3a48291dc1579eaf4f4
    # e0f6b4e61390ce8d1eab002af797eb022c58a6576ef55c78b917268b9fe4d3f45dfc7d5dc3
    # de11f01e825a69e5b1e004db1f79974ca9e42a2b0c0197dcb322f5a0e43cf7ddfdb529699d
    # 976dbf67bf2f67fd947c69696c5ef5bb9186b8031d279165a5fcd1f6ac9d7f668b847ecfc0
    # 01f123b89f75d3ab5f744caa4dd892eac598a0b1413cc0abf93509b2bc254a5714fd979f7a
    # 488b3d4d110f2dca864f6589a58033cc23ca3618db8ce59f398b7b9a6dfd93220e1cd02538
    # 6b92f7e54e6406b2d7d1176f5604e22cf4c6710ff35fa4cf7d33a7d1855a7f868da8713faa
    # f9302dccf5c000ef69c2440fbe22b7eaeb5a95483dda09a0b0414e297ad81fb64fabc60025
    # c9b5dcf6031051d3433ddc358f7e18b3f7cec58b37bace17f2fd1e39b1cac64fbfcdbff2aa
    # bddac6c00310a5c80cb73d640a1b0592ed5d99984971a085941e7ea8e2fd0e86aaa1b7098f
    # 2ac7cdeb9e7eeb5abad2b4ed1238de39cb17aa4f4d8827ebd36d4a99acb9fb4e44cd365186
    # b38ed3a76f5751faaca88fbae7ef53a6a4baa4f29b4bca0ef782b373969d3df62d9c276d69
    # 20f40b4267ae37f994dac8fccbb652d29abce709dc9f52223ddebe441899edfb8dc3a31a5d
    # c9116855c08f1d04cbe6d86d0e9523c564fd3dd8bb79f7898ea7e624aba832e6530ad1231c
    # b388f35a0f2009326bf66170156e57a36eea83285698fcdf2ba1fbbad199dc9d7860158d5e
    # 1f8c81249a0428cd781494ada971c49e1cd7121af374ecc70d902ad0f4f736e4ef23f61fc9
    # b70d877d5ff8c38096faecb1de2df31ce467372c09c66c54b8e122123b539966937bb94d52
    # 72951dcfda3601c762b4ea5119e40e93bbe7a595a35db985cb990f3bbcc74ddc7157f0baff
    # ca0532f7df0239d0fe60e9a62852384f6cce737884808134fb1960e84803fb6ddc144df3c9
    # 78f35e7e26df365e213787a3885ca11c76d14fb998d4a440826b2d8adaa5fe85065c9e9c0d
    # f3110f509bd39e5ead882e85ccb31906809a0c29e33a79f0b3229e671dba1353c89968c4a4
    # 2ac15e7a5dcc821c58ac08d526e5a350ef994bb485fc1c916f59e366e6f7e7ddc76b4a0cae
    # 381a2afbc6aa95643248d8dd39c44fd7090746af9fa3f3c4f70ba56298d6ca1b36b7d19ec8
    # b098dfffe1cd19019ba9c472f6f966964352a958eda8707553021870ba51c9a0b573a59f99
    # 02578a8b58c1e9c9d5f4321e0b8eb66922905ec2dfd3bf1a6ef583fcce8846243cf6c609d9
    # 93efb1acf6b268c5a79746a28c64adbbbc81924991e13aa971d64f4087c87650ebb6309daa
    # 9fcbff37a9919d676e6ce86d9bae8f75376b1a7a76de304c622fe163ea7549a8dcccb095f7
    # ad25c09cdcc768b53a519daf6f1a0861b4c9530cc9d0cf82fbf7c9f5a9acc2346d611a21d0
    # 08aee3c019e664d88f3f1147c4f52d33f2f4ab9fea176625f24a14d517a1d59d338e5bf0aa
    # 479de7e5e8e7841382bb7c9c844f7f8d900979bd360c6d84dc69bd17e7f4ced202afce5964
    # 65c43c740e68be4ac64c559f09b461904be78fe5f5eaa6f78afb23a1d9c12ecf1d14a287a3
    # 90063ef6a3b48091f514f1b87dc3ef40942989648043df1dda7d1221c0efea863f69f2fba6
    # e4c2976ec29fec9cc3d04ec5f4dde4e282886be0c5ee471ccb8cd201558adb759375c27d78
    # 1ec9458af0857b6f437ee5d72de707eb6d38df96a830bb53775667f9722a46869e0954b5ad
    # 5de6f6df232cc29f3fcaac177f323ecfd99732e7559f9d6ffdd706e387bcc23127891be4e1
    # 7df2884288490b19fd7d20c746508c3ee8e77706c549ba5a07bf9cc183ede90e5cdd6cc59b
    # 6ebc5d2caff2d0fc8afb538ea990f4289f716375834a67966dc6eba35b7559726826c23bd4
    # e6bdfbfe7f094d6ecfdf76433cfc3c64c5041ad8aeaf84ba5c8473b24d836f332e8e41eabe
    # 6b845fefb8e5fe2253600c137047ee029a1bab28e9b45eda71597169148593938049092ee2
    # 1172b4a57311da2ff968e1071c4eff0bd22a333cfdc8a6fdef41a4b98f69620152bbeb60b5
    # 5a788ee6a476eaaa3f581eaebc2589efa640ac37fc5faa4f3591b7db58234dd8fb9743192d
    # 07d49bf8af3cf3ac77db932a41b81d61736b7e8f5bb656b2a9637f57b7871c1297bf5e3b14
    # 94d1d09e9c3d024538c4e5fedafbf5aed564d9998dec700647f704115f281efe74aefc0231
    # b11b4ff19b77cd69f1881e5401c6e56a9bbf2e88bb443b3340de8d01c4768c6efa34233b35
    # dfc7edc0fa6232d7df18717c9dec7631295a035afdeeea7e2dfaec3518e58c8189f65dd52f
    # 5490e892fca7f4be4312ad69b1eed46e11cb94bf8bafd2ef725e77fd9620ba980fa1d46563
    # b9066eb49cb42ecfdcd9f7713e0feddb920043908df127cf35386df3b4bce6fab3c6a3e89f
    # 8c51507ea79ffb2914436f8c9fa39501d89b8f9446cbe2fcfb0bada4886ff76b20ce1e29f3
    # 6df94fc313b82da575073aeb54c35e5d3ff0c9dc7032cbffcc92b47b2fead75610d6157bca
    # b92cf23e538fc6b3d1c0e28dd81f3c2a58d890bf323da321a39c9fb601caee4bcc1ccc9abd
    # 0cc0985f966eb484c5f26b9bb8821dabf3b88d3471b55c6351a43fde32428519241a0ddd76
    # 78cf7e7bf1ffa53812d1c9b47fc23852b2fcd318f7ea21dba12ad3a1d4f38e2ba1a5116aa9
    # e35e377f7972b49fbb82a42f90443ca77adb678fa278bf93046c8ec2bc05cb2155d5b506d6
    # 3bc4ffa6eb16c6da6c40d78b132131092bc8f0696a81e14deca5018daea56c6678befbc1f8
    # 138d167661180fc7b7c52fa821c518a29d41c5a73aee9969f74b096cff8fca7ead4f5affe9
    # 3784f8b584545b1ef09aa3815182776966eb9d4758f25ae89550aee3916dce6f40d29c79ee
    # 09913e8ed1778c95cbac302c86cc4ba5ad8b5fe113c78352d00979e84dcd10c3ecd036fba0
    # d1ed85304ea4a3e03233544efb85017c9cd1d3259d959acc0f0dbdaece9ed668d937d52309
    # e6b89393cfd0e888c8dce582495d216760eb1a8032103351d15c8033a46aae338a11ac99ee
    # 92683cb1cb9f24a7925395f54be8b0e520ffd5afbc80c11256e33324bf2509a1c9b64f46dc
    # 0b7e5204fba4ceec74ee7b35417ecb88fa8a74c6575bb6de8f15f1257b6e02a42e4b56dff0
    # 49d609e06cb04aa787ebe99d741d4b60b909a00c0de6faecbf4c6d21559495a7c67060625d
    ```

## 解题思路

RC4 在实现上没有什么问题，重点在 S 数组的范围在 $[0, 127]$，所以每次异或都会泄漏 Flag 字节的最高有效位。

```py
import random

cts = ['7dfdf6eba4da43bf7ca6eb64d3fbaac5e764b2c8e66e1f2a30e3b9e95b2ef48b28f105cdfc', 
...
'49d609e06cb04aa787ebe99d741d4b60b909a00c0de6faecbf4c6d21559495a7c67060625d']

flag_bits = [0] * 37 * 8
random.seed(2023)
for ct in cts:
    a = list(range(37 * 8))
    random.shuffle(a)
    for i, c in zip(a[::8], bytes.fromhex(ct)):
        flag_bits[i] = c >> 7
print(int(''.join(map(str, flag_bits)), 2).to_bytes(37, 'big'))
```

### Flag

> TetCTF{____1nsuff1c13nt_3ntr0py_____}