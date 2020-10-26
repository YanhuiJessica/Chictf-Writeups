---
title: Crypto - easy_RSA
description: 攻防世界 | 新手练习区 | Crypto
---

## 题目

在一次 RSA 密钥对生成中，假设 p = 473398607161，q = 4511491，e = 17<br>
求解出 d

## 解题思路

主要是记录一下求逆元的板子(ΦˋωˊΦ)
```py
def exgcd(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, m = exgcd(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, m

def modinv(x, p):
	return exgcd(x, p)[0] % p

p = 473398607161
q = 4511491
e = 17

fn = (p - 1)*(q - 1)
print(modinv(e, fn))
```