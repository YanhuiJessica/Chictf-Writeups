---
title: Misc - last digit
description: 2022 | DownUnderCTF | misc
tags:
    - binary search
---

## 题目

Can you get the flag given its last digit?

> nc 2022.ductf.dev 30003

??? note "last-digit.py"

    ```py
    with open('/flag.txt', 'rb') as f:
        FLAG = int.from_bytes(f.read().strip(), byteorder='big')

    assert FLAG < 2**1024

    while True:
        print("Enter your number:")
        
        try:
            n = FLAG * int(input("> "))
            print("Your digit is:", str(n)[-1])
        except ValueError:
            print("Not a valid number! >:(")
    ```

??? note "Dockerfile"

    ```dockerfile
    FROM python:3.10.7

    RUN /usr/sbin/useradd --no-create-home -u 1000 ctf

    COPY flag.txt /
    COPY last-digit.py /home/ctf/

    RUN chmod a+x /home/ctf/last-digit.py

    RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

    USER ctf

    CMD socat \
            TCP-LISTEN:1337,reuseaddr,fork \
            EXEC:"python -u /home/ctf/last-digit.py"
    ```

## 解题思路

- Python 3.10.7 新增了 [integer string conversion length limitation](https://docs.python.org/3/library/stdtypes.html#integer-string-conversion-length-limitation)，在默认设置下，十进制数在 `int` 和 `str` 间相互转换，位数不能超过 $4300$ 位，否则会触发 `ValueError` 异常
- `str(n)` 可能触发 `ValueError` 异常，结合输入来二分求出 Flag
- 参考 Manger's Attack 进行二分，边界 $B$ 为 $10^{4300}$
    - 通过 $10^x$ 确定 Flag 的位数，若 $10^{x-1} \times$ FLAG 的位数小于 $4300$ 而 $10^x \times$ FLAG 的位数大于 $4300$，那么 $10^x \times$ FLAG $\in [B, 10B)$，由此可初步确定 FLAG $\in [\frac{B}{10^x}, \frac{B}{10^{x-1}})$
    - 设当前 FLAG 的最小值 $mn=\lfloor\frac{B}{10^x}\rfloor$，当前 FLAG 的最大值 $mx=\lfloor\frac{B}{10^{x-1} }\rfloor$，$y=\lfloor\frac{2B}{mx+mn}\rfloor$，则 $y \times \lfloor\frac{mx+mn}{2}\rfloor \approx B$
    - 向服务器发送 $y$，若触发 `ValueError` 说明 $y \times$ FLAG $\ge B$，则设 $mn=\lceil\frac{B}{y}\rceil$，否则设 $mx=\lfloor\frac{B}{y}\rfloor$

    ```py
    import pwn
    from Crypto.Util.number import long_to_bytes

    B = 10 ** 4300

    conn = pwn.remote('2022.ductf.dev', 30003)
    l, r = 4000, 4300
    while l < r:
        mid = (l + r) // 2
        conn.sendafter('>', f'{10 ** mid}\n')
        ret = conn.recvline().decode()
        if '>:(' in ret:
            r = mid - 1
        else:
            l = mid + 1

    mn = B // 10 ** l
    mx = B // 10 ** (l - 1)

    while mx > mn:
        tmp = 2 * B // (mx + mn)
        conn.sendafter('>', str(tmp) + '\n')
        ret = conn.recvline().decode()
        if '>:(' in ret:
            mn = (B + tmp) // tmp
        else:
            mx = B // tmp

    print(long_to_bytes(mn))
    ```

- 官方 WP 直接二分输入，最后根据边界求得 FLAG

    ```py
    import pwn
    from Crypto.Util.number import long_to_bytes

    def oracle(x):
        conn.sendlineafter(b'> ', str(x).encode())
        o = conn.recvline().decode()
        return '>:(' in o

    conn = pwn.remote('192.168.56.104', 30003)

    U = 10 ** 4300
    FLAG_BITS = 1024

    lower = U // 2 ** FLAG_BITS
    upper = U
    # FLAG 有 1024 位，至多需要二分 1024 次
    for _ in range(1024):
        middle = (upper + lower) // 2
        if oracle(middle):
            upper = middle - 1
        else:
            lower = middle + 1

    f = (U + middle) // middle

    print(long_to_bytes(f))
    ```

- 虽然没有随机算法，但是实际交互时不同连接 limitation 时有时无 (ŏωŏ) 原因不明...

### Flag

> CTF{14288_bits_should_be_enough_for_anybody_:)}