---
title: Crypto - leapfrog
description: 2022 | corCTF | crypto
tags:
    - algebra
---

## 题目

??? note "leapfrog.py"

    ```py
    from Crypto.Util.number import long_to_bytes, getPrime
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from hashlib import sha256
    from secrets import randbelow
    from random import sample

    p = getPrime(256)
    a = randbelow(p)
    b = randbelow(p)
    s = randbelow(p)

    def f(s):
        return (a * s + b) % p

    jumps = sample(range(3, 25), 12)
    output = [s]
    for jump in jumps:
        for _ in range(jump):
            s = f(s)
        output.append(s)

    print(jumps)
    print(output)

    flag = open("flag.txt", "rb").read()
    key = sha256(b"".join([long_to_bytes(x) for x in [a, b, p]])).digest()[:16]
    iv = long_to_bytes(randbelow(2**128))

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    print(iv.hex() + cipher.encrypt(pad(flag, 16)).hex())
    ```

??? "output.txt"

    ```
    [5, 3, 23, 13, 24, 6, 10, 9, 7, 4, 19, 16]
    [26242498579536691811055981149948736081413123636643477706015419836101346754443, 30320412755241177141099565765265147075632060183801443609889236855980299685595, 65684356693401962957802832810273549345608027337432965824937963429120291339333, 15025547765549333168957368149177848577882555487889680742466312084547650972663, 46764069432060214735440855620792051531943268335710103593983788232446614161424, 71575544531523096893697176151110271985899529970263634996534766185719951232899, 8149547548198503668415702507621754973088994278880874813606458793607866713778, 12081871161483608517505346339140143493132928051760353815508503241747142024697, 65627056932006241674763356339068429188278123434638526706264676467885955099667, 23413741607307309476964696379608864503970503243566103692132654387385869400762, 56014408298982744092873649879675961526790332954773022900206888891912862484806, 77000766146189604405769394813422399327596415228762086351262010618717119973525, 14589246063765426640159853561271509992635998018136452450026806673980229327448]
    05ac5b17c67bcfbf5c43fa9d319cfc4c62ee1ce1ab2130846f776e783e5797ac1c02a34045e4130f3b8111e57397df344bd0e14f3df4f1a822c43c7a89fd4113f9a7702b0b0e0b0473a2cbac25e1dd9c
    ```

## 解题思路

- 与 [exchanged](exchanged.md) 类似，同样使用到了函数 $f(x)$，不过 $p,a,b$ 没有直接给出
- 已知初始值 $s$、每次迭代的次数及结果
- 设 $B$ 是 $A$ 经过 $n$ 次 $f$ 迭代后的结果，那么有 $B + t = a^n(A + t)$。注意到数组 `jumps` 存在多个子数组集合，满足同一集合内子数组的和相同
    - 设存在中间迭代结果 $A,B,C,D$ 满足以下条件

        <div style="text-align: center">

        $$\begin{equation}
            \begin{split}
                B+t \equiv a^n(A+t)\ (mod\ p) \\
                C+t \equiv a^n(B+t)\ (mod\ p)  \\
                D+t \equiv a^n(C+t)\ (mod\ p)  \\
            \end{split}
        \end{equation}$$

        </div>

    - 那么有 $(B-C)\equiv a^n(A-B)\ (mod\ p)$ 以及 $(C-D)\equiv a^n(B-C)\ (mod\ p)$，两式相除消去 $a$ 可得 $(B-C)(C-D)^{-1}\equiv (A-B)(B-C)^{-1}\ (mod\ p)$，即 $(B-C)(B-C)-(A-B)(C-D)\equiv 0\ (mod\ p)$（与 $(B-D)(B-C)-(A-C)(C-D)\equiv 0\ (mod\ p)$ 是等价）
- 结合多个子数组集合，通过 GCD 求出 $p$，随后再求出 $a,b$ 即可

### Exploit

```py
from math import gcd
from sympy import nthroot_mod
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.number import inverse, long_to_bytes

def f(s):
    return (a * s + b) % p

jumps, opt, enc = open('output.txt').readlines()
jumps, opt = eval(jumps), eval(opt)
s, *opt = opt

same_sum = dict()
for l in range(1, len(jumps)):
    for i in range(len(jumps) - l + 1):
        if (sm := sum(jumps[i: i + l])) not in same_sum:
            same_sum[sm] = [(i - 1, i + l - 1)]
        else:
            same_sum[sm].append((i - 1, i + l - 1))

p, mn = 0, None
for k, v in same_sum.items():
    if len(v) == 3:
        if mn is None:  # 记录最小满足条件的子数组和及相应的子数组集合
            mn = (k, v)
        A, B, C = [[opt[i[0]], opt[i[1]]] for i in v]
        res = (A[1] - B[1]) * (B[0] - C[0]) - (A[0] - B[0]) * (B[1] - C[1])
        p = gcd(res, p)

A, B, C = [[opt[i[0]], opt[i[1]]] for i in mn[1]]
a_s = nthroot_mod((A[1] - B[1]) * inverse(A[0] - B[0], p), mn[0], p, all_roots=True)
for a in a_s:
    try:
        # f(x) = a^n*s + b*(a^(n-1)+a^(n-2)+...+a+1)
        b = (opt[0] - a ** jumps[0] * s) * inverse(sum(a ** i for i in range(jumps[0])), p) % p
        test = s
        for _ in range(sum(jumps[:2])):
            test = f(test)
        assert test == opt[1]
        break
    except:
        continue

key = sha256(b"".join([long_to_bytes(x) for x in [a, b, p]])).digest()[:16]
iv = bytes.fromhex(enc[:32])
flag = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(bytes.fromhex(enc[32:]))
print(flag)
```

### Flag

> corctf{:msfrog:_is_pr0ud_0f_y0ur_l34pfr0gg1ng_4b1lit135}