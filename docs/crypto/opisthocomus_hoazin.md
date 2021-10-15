---
title: Crypto - opisthocomus-hoazin
description: 2021 | HSCTF | Crypto
---

## 题目

The plural of calculus is calculi.

## 解题思路

- 已知 `n`、`e` 和 `flag` 每一位 ASCII 值与 `e` 异或模 `n` 的结果数组

    ```py
    from Crypto.Util.number import *
    flag = open('flag.txt','r').read()
    p = getPrime(1024)
    q = getPrime(1024)
    e = 2**16+1
    n=p*q
    ct=[]
    for ch in flag:
        ct.append((ord(ch)^e)%n)
    print(n)
    print(e)
    print(ct)
    ```

- 看到 `n` 和 `e` 感觉很 RSA，然而由于 ASCII 码取值范围为 $[0,127]$，直接暴力就可以了！

    ```py
    for i in ct:
        for j in range(128):
            if (j ^ e) % n == i:
                print(chr(j),end="")
    ```