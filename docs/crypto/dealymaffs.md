---
title: Crypto - Dealymaffs
description: 2022 | Crypto
---

## 题目

```py
#!sage

from Crypto.Util.number import inverse, bytes_to_long, getPrime

FLAG = b"[REDACTED]"
step = len(FLAG) // 3
parts = []
for i in range(0, len(FLAG), step):
    parts.append(bytes_to_long(FLAG[i:i+step]))

P = 71438829955248006563930557910994159568699947908111673792342752884287610505363
ZmodP = Zmod(P)
x, y, z = parts
x, y, z = ZmodP(x), ZmodP(y), ZmodP(z)

assert x^3 + z^2 + y == 66394136981860516361851354749859612266004193813290269649537881228428968257460
assert y^3 + x^2 + z == 56417157666649050976546805407267029231007861216965940838682304201229073647799
assert z^3 + y^2 + x == 58104989704612501066634459111657336494541502098206428113992326325857090556559
assert x   + y   + z == 1575390570296234165094105579834233267605062475793
```

## 解题思路

通过 Gröbner 基解多项式方程组 📌

```py
#!sage

from Crypto.Util.number import long_to_bytes

P = 71438829955248006563930557910994159568699947908111673792342752884287610505363
a = [66394136981860516361851354749859612266004193813290269649537881228428968257460, 56417157666649050976546805407267029231007861216965940838682304201229073647799, 58104989704612501066634459111657336494541502098206428113992326325857090556559, 1575390570296234165094105579834233267605062475793,4726171710888702495282316739502699802815187427379]

R.<x,y,z> = PolynomialRing(FiniteField(P))
# 方程等号右侧为 0
I = Ideal([x**3 + z**2 + y - a[0], y**3 + x**2 + z - a[1], z**3 + y**2 + x - a[2], x + y + z - a[3]])
ans = I.variety()

flag = b''
for _, v in ans[0].items():
    flag += long_to_bytes(int(v))
print(flag)
# b"flag{___Groebner_B45iS_!s_an_Id3aL_R3aL_D34L_Isn't_IT?!#___}"
```

## 参考资料

[Groebner basis to solve linear system of equations](https://ask.sagemath.org/question/37156/groebner-basis-to-solve-linear-system-of-equations/?answer=37167#post-id-37167)