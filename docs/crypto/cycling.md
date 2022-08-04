---
title: Crypto - Cycling
description: 2022 | Google CTF | crypto
---

## 题目

It is well known that any RSA encryption can be undone by just encrypting the ciphertext over and over again.<br>
If the RSA modulus has been chosen badly then the number of encryptions necessary to undo an encryption is small.<br>
However, if the modulus is well chosen then a cycle attack can take much longer. This property can be used for a timed release of a message.<br>
We have confirmed that it takes a whopping 2^1025-3 encryptions to decrypt the flag.<br>
Pack out your quantum computer and perform 2^1025-3 encryptions to solve this challenge. Good luck doing this in 48h.

??? note "chall.py"

    ```py
    #!/usr/bin/python3

    # Copyright 2022 Google LLC

    """
    It is well known that any RSA encryption can be undone by just encrypting the
    ciphertext over and over again. If the RSA modulus has been chosen badly then
    the number of encryptions necessary to undo an encryption is small.
    If n = 0x112b00148621 then only 209 encryptions are necessary as the following
    example demonstrates:

    >>> e = 65537
    >>> n = 0x112b00148621
    >>> pt = 0xdeadbeef
    >>> # Encryption
    >>> ct = pow(pt, e, n)
    >>> # Decryption via cycling:
    >>> pt = ct
    >>> for _ in range(209):
    >>>   pt = pow(pt, e, n)
    >>> # Assert decryption worked:
    >>> assert ct == pow(pt, e, n)

    However, if the modulus is well chosen then a cycle attack can take much longer.
    This property can be used for a timed release of a message. We have confirmed
    that it takes a whopping 2^1025-3 encryptions to decrypt the flag. Pack out
    your quantum computer and perform 2^1025-3 encryptions to solve this
    challenge. Good luck doing this in 48h.
    """

    e = 65537
    n = 0x99efa9177387907eb3f74dc09a4d7a93abf6ceb7ee102c689ecd0998975cede29f3ca951feb5adfb9282879cc666e22dcafc07d7f89d762b9ad5532042c79060cdb022703d790421a7f6a76a50cceb635ad1b5d78510adf8c6ff9645a1b179e965358e10fe3dd5f82744773360270b6fa62d972d196a810e152f1285e0b8b26f5d54991d0539a13e655d752bd71963f822affc7a03e946cea2c4ef65bf94706f20b79d672e64e8faac45172c4130bfeca9bef71ed8c0c9e2aa0a1d6d47239960f90ef25b337255bac9c452cb019a44115b0437726a9adef10a028f1e1263c97c14a1d7cd58a8994832e764ffbfcc05ec8ed3269bb0569278eea0550548b552b1
    ct = 0x339be515121dab503106cd190897382149e032a76a1ca0eec74f2c8c74560b00dffc0ad65ee4df4f47b2c9810d93e8579517692268c821c6724946438a9744a2a95510d529f0e0195a2660abd057d3f6a59df3a1c9a116f76d53900e2a715dfe5525228e832c02fd07b8dac0d488cca269e0dbb74047cf7a5e64a06a443f7d580ee28c5d41d5ede3604825eba31985e96575df2bcc2fefd0c77f2033c04008be9746a0935338434c16d5a68d1338eabdcf0170ac19a27ec832bf0a353934570abd48b1fe31bc9a4bb99428d1fbab726b284aec27522efb9527ddce1106ba6a480c65f9332c5b2a3c727a2cca6d6951b09c7c28ed0474fdc6a945076524877680
    # Decryption via cycling:
    pt = ct
    for _ in range(2**1025 - 3):
    pt = pow(pt, e, n)
    # Assert decryption worked:
    assert ct == pow(pt, e, n)

    # Print flag:
    print(pt.to_bytes((pt.bit_length() + 7)//8, 'big').decode())
    ```

## 解题思路

- 已知目标密文必须再经过 $2^{1025}-3$ 次加密后才能获得明文。令 $R=2^{1025}-2$（梅森数的 $2$ 倍），那么有 $x^{e^{R}}\equiv x\ (mod\ n)$
- 欧拉函数 $\varphi(n)$ 能够求出满足 $a^m\equiv 1\ (mod\ n)$（$a$ 小于 $n$ 且与 $n$ 互质） 的正整数，但不一定是最小的，卡迈克尔函数 $\lambda(n)$ 的结果才是。那么有 $x^{\lambda(n)}\equiv 1\ (mod\ n),\ x^{e^R}\equiv x\equiv (x^{\lambda(n)})^k x\ (mod\ n)$，能够推出 $e^R\equiv 1\ mod\ \lambda(n)$，由此可知 $\lambda(\lambda(n))|R$
- 设 $\lambda(n)=\prod_{i=1}^k s_i^{r_i}$，那么 $\lambda(\lambda(n))=lcm(\lambda(s_1^{r_1}),\lambda(s_2^{r_2}),\dotsb,\lambda(s_k^{r_k}))=lcm(s_1^{r_1-1}(s_1-1),s_2^{r_2-1}(s_2-1),\dotsb,s_k^{r_k-1}(s_k-1))$，根据 $R$ 的质因数分解结果推测所有质因数指数不大于 $1$，则 $\lambda(\lambda(n))=lcm(s_1-1,s_2-1,\dotsb,s_k-1)$
- 根据 Pollard 的 $p-1$ 质因数分解算法，可以选择与 $n$ 互质的任意整数 $a$，计算 $g=gcd((a^{M}-1\ mod\ n), n)$ 来分解 $n$
    - $p$ 是 $n$ 的一个质因数，若 $p-1$ 的每一个因数 $s$ 都满足 $s\le B$（$B$ 人为选定），显然有 $(p-1)|B!$，$M$ 定义为 $\prod_{primes\ s\le B}s^{\lfloor log_s B\rfloor}$，若 $g=1$ 或 $g=n$ 则重新选择 $B$ 进行计算
    - 根据费马小定理有 $a^{k(p-1)}\equiv 1\ (mod\ p)$
    - 若一个数 $x$ 模 $p$ 余 $1$，那么 $p|gcd(x-1,n)$
- $\lambda(\lambda(n))=\lambda(lcm(p-1,q-1))=\lambda(s_1s_2\dotsb s_k)=lcm(s_1-1,s_2-1,\dotsb,s_k-1)$，显然，$(s_i-1)|R$，那么可由 $R$ 质因数分解结果得出 $s_i$ 的候选集，即 $p-1$ 和 $q-1$ 的质因数候选集，结合 Pollard 的 $p-1$ 质因数分解算法进行求解

    ```py
    from factordb.factordb import FactorDB
    from sympy import isprime
    from math import gcd
    from Crypto.Util.number import long_to_bytes

    def factor_n(primes):
        m = 2
        for p in primes:
            m = pow(m, p, n)
            g = gcd(m - 1, n)
            if 1 < g < n:
                return g, n // g

    e = 65537
    n = 0x99efa9177387907eb3f74dc09a4d7a93abf6ceb7ee102c689ecd0998975cede29f3ca951feb5adfb9282879cc666e22dcafc07d7f89d762b9ad5532042c79060cdb022703d790421a7f6a76a50cceb635ad1b5d78510adf8c6ff9645a1b179e965358e10fe3dd5f82744773360270b6fa62d972d196a810e152f1285e0b8b26f5d54991d0539a13e655d752bd71963f822affc7a03e946cea2c4ef65bf94706f20b79d672e64e8faac45172c4130bfeca9bef71ed8c0c9e2aa0a1d6d47239960f90ef25b337255bac9c452cb019a44115b0437726a9adef10a028f1e1263c97c14a1d7cd58a8994832e764ffbfcc05ec8ed3269bb0569278eea0550548b552b1
    ct = 0x339be515121dab503106cd190897382149e032a76a1ca0eec74f2c8c74560b00dffc0ad65ee4df4f47b2c9810d93e8579517692268c821c6724946438a9744a2a95510d529f0e0195a2660abd057d3f6a59df3a1c9a116f76d53900e2a715dfe5525228e832c02fd07b8dac0d488cca269e0dbb74047cf7a5e64a06a443f7d580ee28c5d41d5ede3604825eba31985e96575df2bcc2fefd0c77f2033c04008be9746a0935338434c16d5a68d1338eabdcf0170ac19a27ec832bf0a353934570abd48b1fe31bc9a4bb99428d1fbab726b284aec27522efb9527ddce1106ba6a480c65f9332c5b2a3c727a2cca6d6951b09c7c28ed0474fdc6a945076524877680

    R = 2 * (2**1024 - 1)

    f = FactorDB(R)
    f.connect()
    factors = f.get_factor_list()

    prods = {1}
    for f in factors:
        prods |= {f * x for x in prods}
    primes = [p + 1 for p in prods if isprime(p + 1)]

    p, q = factor_n(primes)
    d = pow(e, -1, (p - 1) * (q - 1))
    m = pow(ct, d, n)
    print(long_to_bytes(m))
    ```

### Flag

> CTF{Recycling_Is_Great}

## 参考资料

- [Intended Solution](https://github.com/google/google-ctf/blob/fee84ec9663910627dd037b7c053ef0b6cfa03b1/2022/crypto-cycling/src/solve.py#L107)
- [Carmichael function - Wikipedia](https://en.wikipedia.org/wiki/Carmichael_function)
- [Pollard's p − 1 algorithm - Wikipedia](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm)