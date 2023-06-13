---
title: Crypto - badkey1
description: 2023 | 第十六届全国大学生信息安全竞赛 | 初赛 | Crypto
tags:
    - rsa
    - pycryptodome
    - invalid key
---

## 题目

我认真检查了一下我的 RSA 参数，似乎没有任何问题，但是为什么会……

??? note "test.py"

    ```py
    from Crypto.Util.number import *
    from Crypto.PublicKey import RSA
    from hashlib import sha256
    import random, os, signal, string

    def proof_of_work():
        random.seed(os.urandom(8))
        proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])
        _hexdigest = sha256(proof.encode()).hexdigest()
        print(f"sha256(XXXX+{proof[4:]}) == {_hexdigest}")
        print('Give me XXXX: ')
        x = input()
        if len(x) != 4 or sha256(x.encode()+proof[4:].encode()).hexdigest() != _hexdigest:
            print('Wrong PoW')
            return False
        return True

    if not proof_of_work():
        exit(1)
        
    signal.alarm(10)
    print("Give me a bad RSA keypair.")

    try:
        p = int(input('p = '))
        q = int(input('q = '))
        assert p > 0
        assert q > 0
        assert p != q
        assert p.bit_length() == 512
        assert q.bit_length() == 512
        assert isPrime(p)
        assert isPrime(q)
        n = p * q
        e = 65537
        assert p % e != 1
        assert q % e != 1
        d = inverse(e, (p-1)*(q-1))
    except:
        print("Invalid params")
        exit(2)

    try:
        key = RSA.construct([n,e,d,p,q])
        print("This is not a bad RSA keypair.")
        exit(3)
    except KeyboardInterrupt:
        print("Hacker detected.")
        exit(4)
    except ValueError:
        print("How could this happen?")
        from secret import flag
        print(flag)
    ```

## 解题思路

- 需要输入满足一定条件的 $p,q$，并最终使 `RSA.construct` 根据提供的参数执行失败
- 排除调用 `RSA.construct` 前已进行的检查，最有可能导致失败的检查是

    ```py
    if Integer(n).gcd(d) != 1:
        raise ValueError("RSA private exponent is not coprime to modulus")
    ```

- 令 $d = k_1p$，需要求 $q$
- 根据 $ed\equiv 1\ (mod\ \phi)$，有 $ek_1\equiv 1\ (mod\ p-1)$，求得 $k_1$
- 接下来由 $ek_1p=k_2(p-1)(q-1)+1$ 得 $q=\frac{ek_1p-1}{k_2(p-1)}+1$，可在 $[1, e+1]$ 的范围内爆破 $k_2$

### Exploit

```py
from Crypto.Util.number import getPrime, isPrime, inverse

e = 65537
while True:
    p = getPrime(512)
    k1 = inverse(e, p - 1)
    t = (e * k1 * p - 1) // (p - 1)
    for k2 in range(1, e + 1):
        if t % k2 == 0:
            q = t // k2 + 1
            if isPrime(q) and q.bit_length() == 512:
                print(p, q)
                exit()
```