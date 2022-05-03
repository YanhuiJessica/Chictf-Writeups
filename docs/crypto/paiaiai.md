---
title: Crypto - P(ai)^3
description: 2022 | HackPack CTF | Cryptography
---

## 题目

Pai-ai-ai… My Paillier scheme seems to be broken and I stored my favourite flag in it. Please help me get it back, will you? Who could have guessed this would ever happen? … Me… I- I wrote it… yeah.

```bash
nc cha.hackpack.club 10997 # or 20997
```

??? note "paiaiai.py"

    ```py
    #!/usr/bin/env python3
    #
    # Polymero
    #

    # Imports
    from Crypto.Util.number import getPrime, inverse
    from secrets import randbelow

    # Local imports
    with open("flag.txt",'rb') as f:
        FLAG = f.read().decode()
        f.close()

    # Just for you sanity
    assert len(FLAG) > 64

    MENU = r"""|
    |  MENU:
    |   [E]ncrypt
    |   [D]ecrypt
    |   [Q]uit
    |"""

    class Paiaiai:
        """ My first Paillier implementation! So proud of it. ^ w ^ """

        def __init__(self):
            # Key generation
            p, q = [getPrime(512) for _ in range(2)]
            n = p * q
            # Public key
            self.pub = {
                'n'  : n,
                'gp' : pow(randbelow(n**2), p, n**2),
                'gq' : pow(randbelow(n**2), q, n**2)
            }
            # Private key
            self.priv = {
                'la' : (p - 1)*(q - 1),
                'mu' : inverse((pow(self.pub['gp'] * self.pub['gq'], (p-1)*(q-1), n**2) - 1) // n, n)
            }
            
        def encrypt(self, m: str):
            m_int = int.from_bytes(m.encode(), 'big')
            g = pow([self.pub['gp'],self.pub['gq']][randbelow(2)], m_int, self.pub['n']**2)
            r = pow(randbelow(self.pub['n']), self.pub['n'], self.pub['n']**2)
            return (g * r) % self.pub['n']**2
        
        def decrypt(self, c: int):
            cl = (pow(c, self.priv['la'], self.pub['n']**2) - 1) // self.pub['n']
            return (cl * self.priv['mu']) % self.pub['n']

    pai = Paiaiai()

    while True:
        
        try:
            
            print(MENU)
            choice = input("|  >>> ").lower().strip()
            
            if choice == 'e':
                print("|\n|  ENCRYPT:")
                print("|   [F]lag")
                print("|   [M]essage")
                subchoice = input("|\n|  >>> ").lower().strip()
                
                if subchoice == 'f':
                    enc_flag = pai.encrypt(FLAG)
                    print("|\n|  FLAG:", enc_flag)
                    
                elif subchoice == 'm':
                    msg = input("|\n|  MSG: str\n|   > ")
                    cip = pai.encrypt(msg)
                    print("|\n|  CIP:", cip)
                
            elif choice == 'd':
                cip = input("|\n|  CIP: int\n|   > ")
                msg = pai.decrypt(int(cip))
                print("|\n|  MSG:", msg)
                
            elif choice == 'q':
                print("|\n|  Bai ~ \n|")
                break
                
            else:
                print("|\n|  Trai again ~ \n|")
            
        except (KeyboardInterrupt, EOFError):
            print("\n|\n|  Bai ~ \n|")
            break
            
        except:
            print("|\n|  Aiaiai ~ \n|")
    ```

## 解题思路

- `server` 同时提供了加密和解密的功能，但是解密结果显然是不对的 (╥ω╥)
    - 如果我们加密 `test` 并将得到的密文交给服务器解密，那么会收到一串乱码（以下结果经过 `long_to_bytes` 处理）

        ```bash
        b"6\xa2\x15\x816\x12'\x8f\xdc[v\xb6\xe4]2\xfc\xfc\x13_\xc3\xe3\xc7A\xddF:f\x1d\xd4\xe8A\x92`V\xf8\xfe)4\xb1DS\xcc\xe7\xf6&\x93\x8b\xee()/7\xd4\xb9=`\xc80\x95\xb5\x00\xc1h\x1f\xc5\xab\xb7\x9b\x03\x8c\xbd[\xd8\xf8\x81\x8ek\x00\xd0\xe0v\x03l\xfa\x872h\xd0.C\xa1D\xa8\xc8\xc7a\xe5\xd5_\xd0\x91\xe8\x8b\xeb\xb8\x17Zd\xb8\xe7j\x14\xc6^\xdd\xa1\x80\xb4kT$j\xc9\xe6e`\x8e\x00"
        ```

- 分析 `paiaiai.py` 中 `Paillier` 的实现 `Paiaiai`

### Paiaiai

- `Paiaiai` 加解密过程与原 `Paillier` 算法基本一致，但修改了公私钥的生成方式
- 公钥为 $(n,g_p,g_q)$
- 私钥为 $(\lambda, \mu)$，其中 $\lambda=(p-1)(q-1),\mu=(L((g_p\times g_q)^\lambda\ mod\ n^2))^{-1}(mod\ n)$

#### 加密

- 随机选择 $g_p$ 和 $g_q$ 作为 $g$
- 两种可能的密文
    - $c_p=g_p^m\cdot r^n\ mod\ n^2$
    - $c_q=g_q^m\cdot r^n\ mod\ n^2$

#### 解密

- $D(c)=L(c^\lambda\ mod\ n^2)\cdot\mu$ $=\frac{L(c^\lambda\ mod\ n^2)}{L((g_p\times g_q)^\lambda\ mod\ n^2)}\ mod\ n$

    $\because \lambda=(p-1)(q-1)=\varphi(n)$

    $\therefore g^\lambda\equiv 1(mod\ n),g^\lambda(mod\, n^2)\equiv 1(mod\, n)$

    $\therefore g^\lambda(mod\, n^2)=nk_g+1,k_g<n$

    $\therefore L(g^\lambda(mod\, n^2))=k_g$

    设 $L(g_p^\lambda(mod\ n^2))=k_p,L(g_q^\lambda(mod\ n^2))=k_q$

    $\therefore L(c_p^{\lambda}\, mod\, n^2)=mk_p,L(c_q^{\lambda}\, mod\, n^2)=mk_q$

    $\because$
    $\begin{equation}
        \begin{split}
            (g_p\times g_q)^\lambda\ mod\ n^2 & =(nk_p+1)(nk_q+1) \\
            & = n^2k_pk_q+nk_p+nk_q+1 \\
            & \equiv nk_p+nk_q+1(mod\ n^2)
        \end{split}
    \end{equation}$

    $\therefore L((g_p\times g_q)^\lambda\ mod\ n^2)=k_p+k_q$

    $\therefore m(k_p+k_q)=L((c_p\times c_q)^\lambda mod\ n^2)$

    $\therefore m=D(c_p)+D(c_q)=\frac{mk_p}{k_p+k_q}+\frac{mk_q}{k_p+k_q}=\frac{m(k_p+k_q)}{k_p+k_q}=D(c_p\times c_q)(mod\ n)$

- 虽然 $n$ 是 `Paillier` 公钥的一部分，但 `Paiaiai` 没有提供获取接口，因而将 $D(c_p)+D(c_q)$ 根据加法同态性转化为 $D(c_p\times c_q)$ 并交由服务器解密

### Exploitation

- 首先获取 Flag 分别使用 $g_p$ 和 $g_q$ 加密的结果 $c_p,c_q$（由于加密时随机数 $r$ 的存在，需要解密后才能判断）
- 解密 $c_p\times c_q$ 即可获得 Flag

```py
from Crypto.Util.number import long_to_bytes
import pwn

conn = pwn.remote("cha.hackpack.club", 10997)

cipher = dict()
for _ in range(5):
    conn.sendafter('>>> ', 'e\n')
    conn.sendafter('>>> ', 'f\n')
    c = conn.recvline_contains('FLAG: ').decode()
    c = c[c.find(': ') + 2:]

    conn.sendafter('>>> ', 'd\n')
    conn.sendafter('> ', c + '\n')
    x = conn.recvline_contains('MSG: ').decode()
    x = int(x[x.find(': ') + 2:])
    cipher[x] = int(c)
    if len(cipher) == 2: # got 2 different ciphertexts
        break
cipher = cipher.values()

conn.sendafter('>>> ', 'd\n')
conn.sendafter('> ', str(cipher[0] * cipher[1]) + '\n')
m = conn.recvline_contains('MSG: ').decode()
m = int(m[m.find(': ') + 2:])
print(long_to_bytes(m))
# b'________flag{p41_41_41_1_d0nt_th1nk_th1s_1s_wh4t_p41ll13r_1nt3nd3d_3h}________'
```

### Flag

> flag{p41_41_41_1_d0nt_th1nk_th1s_1s_wh4t_p41ll13r_1nt3nd3d_3h}

## Paillier

### 密钥生成

- 随机选择两个大素数 $p,q$，保证 $gcd(pq,(p-1)(q-1))=1$
- 计算 $n=pq$，$\lambda=lcm(p-1,q-1)$
- 随机选择一个小于 $n^2$ 的正整数 $g$，且存在 $\mu=(L(g^{\lambda}\ mod\ n^2))^{-1}mod\, n$
    - 其中，$L(x)=\frac{x-1}{n}$（此处分式为除法）
- 公钥为 $(n,g)$，私钥为 $(\lambda,\mu)$

#### 简单变种

- 在 $p,q$ 长度一致的情况下，可以快速生成密钥
- $g=n+1,\lambda=\varphi(n),\mu=\varphi(n)^{-1}$

### 加密

- 明文 $m$ 是小于 $n$ 的自然数，随机数 $r$ 是小于 $n$ 的正整数
- $c=g^m\cdot r^n\, mod\ n^2$

### 解密

- $m=L(c^{\lambda}\ mod\ n^2)\cdot \mu\ mod\ n=\frac{L(c^\lambda\ mod\ n^2)}{L(g^\lambda\ mod\ n^2)}\ mod\ n$

#### 原理

- 根据二项式定理，$(1+n)^x=\sum^x_{k=0}{x\choose k}n^k=1+xn+{x\choose 2}n^2+\dotsb$，易得 $(1+n)^x\equiv 1+nx\, (mod\, n^2)$

    $\because (p-1)|\lambda,(q-1)|\lambda$

    $\therefore \lambda=k_1(p-1)=k_2(q-1)$

    由费马小定理可得 $g^\lambda=g^{k_1(p-1)}\equiv 1(mod\,p),(g^\lambda-1)|p$
    ，同理有 $(g^\lambda-1)|q$

    $\therefore (g^\lambda-1)|pq$，可得 $g^\lambda\equiv 1(mod\, n),g^\lambda(mod\, n^2)\equiv 1(mod\, n)$

    $\therefore g^\lambda(mod\, n^2)=nk_g+1,k_g<n$

    $\therefore L(g^\lambda(mod\, n^2))=k_g$

    $\because c^{\lambda}=g^{m\lambda}\cdot r^{n\lambda}\, mod\, n^2$

    又 $\because g^{m\lambda} = (nk_g+1)^m\equiv mnk_g+1(mod\, n^2),r^{n\lambda}\equiv n^2k_r+1\equiv 1(mod\, n^2)$

    $\therefore L(c^{\lambda}\, mod\, n^2)=L(mnk_g+1)=mk_g$

    $\therefore \frac{L(c^\lambda\, mod\, n^2)}{L(g^\lambda\, mod\, n^2)}=\frac{mk_g}{k_g}=m(mod\, n)$

### 同态性

#### 加法同态性

- $\begin{equation}
    \begin{split}
        D(E(m_1,r_1)\cdot E(m_2,r_2)\, mod\, n^2)&=D(g^{m_1}\cdot r_1^n\cdot g^{m_2}\cdot r_2^n\, mod\, n^2)\\
        &=D(g^{m_1+m_2}\cdot(r_1\cdot r_2)^n\, mod\, n^2)\\
        &=m_1+m_2\, (mod\, n)
    \end{split}
\end{equation}$
- $D(E(m_1,r_1)\cdot g^{m_2}\, mod\, n^2)=m_1+m_2\, (mod\, n)$

#### 乘法同态性

- $D(E(m_1,r_1)^k\, mod\, n^2)=D(g^{km_1}\cdot (r_1^k)^n\, mod\, n^2)=km_1\,(mod\,n)$

## 参考资料

- Paillier P. [Public-key cryptosystems based on composite degree residuosity classes](https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_16.pdf)[C]//International conference on the theory and applications of cryptographic techniques. Springer, Berlin, Heidelberg, 1999: 223-238.
- [Paillier cryptosystem - Wikipedia](https://en.wikipedia.org/wiki/Paillier_cryptosystem)