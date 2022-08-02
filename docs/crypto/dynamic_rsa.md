---
title: Crypto - Dynamic RSA
description: 2022 | LITCTF | crypto
tags:
    - rsa
    - gcd
    - crt
---

## 题目

Nowadays, clients just keep changing their requirements! They said e=65537 is too boring for RSA and that they wanted a dynamic encryption system instead. Oh, I'll give it to them!

> Connect with nc litctf.live 31792

https://drive.google.com/uc?export=download&id=1JY3LfzcoIWUEhC0C8NuwO-fOwZnp3tKt

## 解题思路

- 已知经过 RSA 加密的 Flag 的密文及随机数种子/加密指数 $e$

    ```py
    flag = open('flag.txt','rb').read();

    m = bytes_to_long(flag);
    e = 65537;
    p = getPrime(200);
    q = getPrime(200);
    random.seed(e);
    phi = (p-1) * (q-1);
    n = p * q;
    ct = pow(m, e, n)
    print("My secret flag is " + str(ct));
    ```

- 可以与服务器进行两种交互
    - 提供私钥，获得 Flag 密文的解密结果
    - 提供任意消息，获得「消息+盐值」的加密结果

    ```py
    while True:
        inp = input("Guess Private Key (1) or Encrypt Message (2): ");
        if (inp == "1"):
            d = int(input("Enter Private Key: "));
            print(long_to_bytes(pow(ct, d, n)));
            exit()
            
        elif (inp == "2"):
            test_e = e_gen()
            # Oh great they made me change the algorithm again
            # They said its "TOO BLAND"
            # FINE I'll add more seasoning
            salt = get_random_bytes(8).hex();
            inp = bytes_to_long((input("Enter Message: ") + salt).encode());
            test_ct = pow(inp, test_e, n);
            print("Your Message (remember to convert): " + str(test_ct));
            
        else:
            print("BAD OPTION");
            exit();
    ```

- 不过重点在函数 `e_gen` 以及 `gcd`。随机数种子已知，则可以求出 `test_e`。因为 `test_e` 是质数，所以 `gcd(test_e, phi)` 只有两种结果，要么是 $1$，要么是 `test_e`。当 `gcd(test_e, phi)` 的结果为 `test_e` 时，`new_e = 1`，此时密文与明文相同，可以确定 `phi` 的其中一个因数。但显然，结果 `gcd(test_e, phi)` 为 $1$ 的情况更多

    ```py
    def gcd(a,b):
        # Client said the loading screen is too boring
        # So they want something with more flair and movement while they wait
        if(a == 0):
            return b;
        if(b == 0):
            return a;
        print(".,"[(b // a) & 1], end = "");

        return gcd(b % a,a);

    # Clients keep complaining that making e always 65537 is too boring
    # So they changed their requirements and wanted a "dynamic encryption system"
    # I literally can't
    def e_gen():
        print("Loading", end = "")
        test_e = nextprime(random.randint(1, 100000));
        # Okay but I literally can't use a random e if gcd is not 1
        # It's like most fundamental part of RSA!!!
        new_e = test_e // gcd(test_e, phi);
        print()
        return new_e
    ```

- 重写的函数 `gcd` 给出了每一步 `b // a` 结果的奇偶性，因为第一步 `phi` 的值未知，所以从第二步开始考虑，即 `gcd(phi % test_e, test_e)`。`test_e` 已知，`phi % test_e` 是小于 `test_e` 的自然数，仅根据每一步 `b // a` 结果的奇偶性是有一定概率能够确定 `phi % test_e` 的。以 $13$ 为例 `gcd` 的计算结果如下，可见部分 `b // a` 奇偶性结果序列与 `phi % test_e` 有一对一映射关系

    ```
    gcd(1, 13) ,
    gcd(2, 13) ..
    gcd(3, 13) .,
    gcd(4, 13) ,.
    gcd(5, 13) .,,.
    gcd(6, 13) ..
    gcd(7, 13) ,,.
    gcd(8, 13) ,,,,.
    gcd(9, 13) ,..
    gcd(10, 13) ,,,
    gcd(11, 13) ,,.
    gcd(12, 13) ,.
    ```

- 由此可利用中国剩余定理计算出 `phi`，从而得出私钥 `d`

    ```py
    import random, pwn
    from sympy import nextprime
    from sage.all import crt, Integer
    from Crypto.Util.number import inverse

    def gcd(a, b):
        if a == 0 or b == 0:
            return ''
        return '.,'[(b // a) & 1] + gcd(b % a, a)

    e = 65537

    random.seed(e)
    state = random.getstate()

    gcd_res = dict()
    for i in set(nextprime(random.randint(1, 100000)) for _ in range(750)):
        gcd_res[i] = ['']
        for j in range(1, i):
            gcd_res[i].append(gcd(j, i))

    conn = pwn.remote('litctf.live', 31792)
    random.setstate(state)

    mo, rem = [], []
    pre_crt = 0
    while True:
        conn.sendafter('Encrypt Message (2): ', '2\n')
        test_e = nextprime(random.randint(1, 100000))
        res = conn.recvline().decode().strip()[7:]
        conn.sendafter('Enter Message:', '0\n')
        if len(res) == 1 and test_e not in mo:
            mo.append(Integer(test_e))
            rem.append(Integer(0))
            cur = crt(rem, mo)
            if cur == pre_crt:
                break
            pre_crt = cur
        if test_e in gcd_res and test_e not in mo and gcd_res[test_e].count(res[1:]) == 1:
            mo.append(Integer(test_e))
            rem.append(Integer(gcd_res[test_e].index(res[1:])))
            cur = crt(rem, mo)
            if cur == pre_crt:
                break
            pre_crt = cur
        print(pre_crt)

    d = inverse(e, pre_crt)
    conn.sendafter('Encrypt Message (2): ', '1\n')
    conn.sendafter('Enter Private Key:', f'{d}\n')
    conn.interactive()
    ```

### Flag

> LITCTF{0op5i3_dyn4m1c_n0t_gr3at_1t_s33m5}