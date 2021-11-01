---
title: Crypto - Alkaloid Stream
description: 2021 | PBCTF | Crypto
---

## 题目

I found a weird stream cipher scheme. Can you break this?

[CTFtime.org / pbctf 2021 / Alkaloid Stream](https://ctftime.org/task/17577)

## 解题思路

- 加密程序 `gen.py` 和输出文件 `output.txt`
- 先看看加密程序执行的函数
    ```py
    flag = bytes_to_bits(flag) 

    key = keygen(len(flag)) # 根据 flag 的长度产生密钥
    keystream, public = gen_keystream(key)
    assert keystream == recover_keystream(key, public) # 判断是否能由 key 和 public 还原出 keystream
    enc = bits_to_bytes(xor(flag, keystream)) # flag、enc 和 keystream 三者长度一致
    # 异或，已知 enc 和 keystream 可求 flag

    print(enc.hex())
    print(public)
    ```
- 现在已知 `enc` 和 `public`，需要获得 `key` 或者 `keystream` 才能得到 `flag`
- `keygen` 函数只要提供长度就可以输出密钥！于是愉快地看了看，结果发现用到了随机数 (╥ω╥) 【爆破当然是不现实的！】
    ```py
    def keygen(ln):
        # Generate a linearly independent key
        arr = [ 1 << i for i in range(ln) ]

        for i in range(ln):
            for j in range(i):
                if random.getrandbits(1):
                    arr[j] ^= arr[i]
        for i in range(ln):
            for j in range(i):
                if random.getrandbits(1):
                    arr[ln - 1 - j] ^= arr[ln - 1 - i]

        return arr
    ```
- 因为没有 `key`，`recover_keystream` 函数也没有什么用了，`gen_keystream` 函数成为了重点关注对象
    ```py
    def gen_keystream(key):
        ln = len(key)
        
        # Generate some fake values based on the given key...
        fake = [0] * ln
        for i in range(ln):
            for j in range(ln // 3):
                if i + j + 1 >= ln:
                    break
                fake[i] ^= key[i + j + 1]

        # Generate the keystream
        res = []
        for i in range(ln):
            t = random.getrandbits(1)
            if t:
                res.append((t, [fake[i], key[i]]))
            else:
                res.append((t, [key[i], fake[i]]))

        # Shuffle!
        random.shuffle(res)

        keystream = [v[0] for v in res]
        public = [v[1] for v in res] # 由 key 和 fake 数组组成
        return keystream, public
    ```
- 其中，`fake` 数组的产生过程为突破点。当且仅当 $i = ln - 1$ 时，$fake[ln - 1]$ 不与 `key` 数组中的值异或，且 `fake` 数组初始值为全 $0$，因此 $fake[ln - 1] = 0$。在 `output.txt` 中搜索，只有一个 $0$ \\(ΦωΦ)/
- 由此结合 `public` 数组可以依次推出 `key` 数组和 `keystream`

    <div style="text-align: center">

    $fake[ln - 1] => key[ln - 1]$

    $key[ln - 1] = fake[ln - 2] => key[ln - 2]$

    $key[ln - 2] \oplus key[ln - 1] = fake[ln - 3] => key[ln - 3]$

    $... ...$

    </div>

- 使用 `recover_keystream` 函数或直接用 `keystream` 异或 `enc` 就可以得到 Flag 啦！(ΦˋωˊΦ)
    ```py
    ln = len(enc)
    key = [0] * ln
    keystream = [0] * ln
    fake = [0] * ln
    # 先根据 fake[ln - 1] 找到 key[ln - 1]
    for p in range(len(public)):
        if public[p][0] == 0:
            key[ln - 1] = public[p][1]
            keystream[p] = 1
            break
        elif public[p][1] == 0:
            key[ln - 1] = public[p][0]
            keystream[p] = 0
            break

    # 依次求解
    for i in range(ln - 2, -1, -1):
        for j in range(ln // 3):
            if i + j + 1 >= ln:
                break
            fake[i] ^= key[i + j + 1]
        for p in range(len(public)):
            # output.txt 中有两个值一样，其中一对是 ln - 1
            if fake[i] == public[p][0] and public[p][1] != 0:
                key[i] = public[p][1]
                keystream[p] = 1
            elif fake[i] == public[p][1]:
                key[i] = public[p][0]
                keystream[p] = 0

    print(bits_to_bytes(xor(enc, keystream)))
    ```
- Flag：`pbctf{super_duper_easy_brute_forcing_actually_this_one_was_made_by_mistake}`