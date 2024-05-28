---
title: Crypto - random rabin
description: 2024 | ångstromCTF | crypto
tags:
    - rabin cryptosystem
---

## 题目

I heard that the [Rabin cryptosystem](https://en.wikipedia.org/wiki/Rabin_cryptosystem) has four decryptions per ciphertext. So why not choose one randomly?

??? note "random_rabin.py"

    ```py
    from random import SystemRandom
    from Crypto.Util.number import getPrime
    from libnum import xgcd

    random = SystemRandom()

    def primegen():
        while True:
            p = getPrime(512)
            if p % 4 == 3:
                return p

    def keygen():
        p = primegen()
        q = primegen()
        n = p * q
        return n, (n, p, q)

    def encrypt(pk, m):
        n = pk
        return pow(m, 2, n)

    def decrypt(sk, c):
        n, p, q = sk
        yp, yq, _ = xgcd(p, q)
        mp = pow(c, (p + 1)//4, p)
        mq = pow(c, (q + 1)//4, q)
        s = yp * p * mq % n
        t = yq * q * mp % n
        rs = [(s + t) % n, (-s - t) % n, (s - t) % n, (-s + t) % n]
        r = random.choice(rs)
        return r

    def game():
        pk, sk = keygen()
        print(f'pubkey: {pk}')
        secret = random.randbytes(16)
        m = int.from_bytes(secret, 'big')
        print(f'plaintext: {decrypt(sk, encrypt(pk, m))}')
        guess = bytes.fromhex(input('gimme the secret: '))
        return guess == secret

    if __name__ == '__main__':
        for _ in range(64):
            success = game()
            if not success:
                exit()

        with open('flag.txt') as f:
            flag = f.read().strip()
            print(flag)
    ```

## 解题思路

- 已知公钥和密文的任一解密结果，需要连续猜对 64 次明文
- 由 `secret` 加密得到密文的任一解密结果再加密的结果相同
- 而 `secret` 相对于公钥较小，其平方仍然小于公钥，因此获得密文后直接开方的结果即为 `secret`

    ```py
    import pwn
    from Crypto.Util.number import long_to_bytes
    from gmpy2 import isqrt
    from tqdm import tqdm

    io = pwn.remote("challs.actf.co", 31300)

    for _ in tqdm(range(64)):
        pk = int(io.recvline().split(b':')[-1])
        pt = int(io.recvline().split(b':')[-1])
        guess = isqrt(pow(pt, 2, pk))
        io.sendlineafter(b"secret: ", long_to_bytes(guess).hex().encode())

    io.interactive()
    ```

### Flag

> actf{f4ncy_squ4re_r00ts_53a370c33f192973}
