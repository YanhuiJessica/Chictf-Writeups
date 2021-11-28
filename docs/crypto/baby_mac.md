---
title: Crypto - Baby MAC
description: 2021 | DragonCTF | Cryptography
---

## 题目

We implemented a simple signing service. Can you sign a flag request?

nc babymac.hackable.software 1337

??? note "task.py"

```py
#!/usr/bin/env python3
import os
try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES

def split_by(data, cnt):
    return [data[i : i+cnt] for i in range(0, len(data), cnt)]

def pad(data, bsize):
    b = bsize - len(data) % bsize
    return data + bytes([b] * b)

def xor(a, b):
    return bytes(aa ^ bb for aa, bb in zip(a, b))

def sign(data, key):
    data = pad(data, 16)
    blocks = split_by(data, 16)
    mac = b'\0' * 16
    aes = AES.new(key, AES.MODE_ECB)
    for block in blocks:
        mac = xor(mac, block)
        mac = aes.encrypt(mac)
    mac = aes.encrypt(mac)
    return mac

def verify(data, key):
    if len(data) < 16:
        return False, ''
    tag, data = data[:16], data[16:]
    correct_tag = sign(data, key)
    if tag != correct_tag:
        return False, ''
    return True, data

def main():
    key = os.urandom(16)
    while True:
        print('What to do?')
        opt = input('> ').strip()
        if opt == 'sign':
            data = input('> ').strip()
            data = bytes.fromhex(data)
            if b'gimme flag' in data:
                print('That\'s not gonna happen')
                break
            print((sign(data, key) + data).hex())
        elif opt == 'verify':
            data = input('> ').strip()
            data = bytes.fromhex(data)
            ok, data = verify(data, key)
            if ok:
                if b'gimme flag' in data:
                    with open('flag.txt', 'r') as f:
                        print(f.read())
                else:
                    print('looks ok!')
            else:
                print('hacker detected!')
        else:
            print('??')
            break
    return 0

if __name__ == '__main__':
    exit(main())
```

## 解题思路

- 需要在不输入包含 `gimme flag` 字符串的情况下，获得包含 `gimme flag` 字符串的 MAC
- 分析 `sign()` 函数，发现实际是 CBC-MAC
    ```py
    def sign(data, key):
        data = pad(data, 16)
        blocks = split_by(data, 16)
        mac = b'\0' * 16
        aes = AES.new(key, AES.MODE_ECB)
        for block in blocks:
            mac = xor(mac, block)
            mac = aes.encrypt(mac)
        # 结果再加密，可以认为实际加密的消息为 blocks + (b'\0' * 16)
        mac = aes.encrypt(mac)
        return mac
    ```
- 当明文长度刚好为 16 字节时，将填充 `b'\x10' * 16`，用 $pad$ 表示，$iv$ 表示 `b'\x00' * 16`
- 可以利用异或取得目标字符串的 MAC（加密过程简单表示为顺序块的形式，如 $pad, iv$ 等价于 $MAC_k(MAC_k(pad) \oplus iv)$）

    <div style="text-align: center">

    $pad, iv = C_0$

    $P=hex(gimme\,flag123456)$

    $x=C_0 \oplus P$

    $pad, iv, x, pad, iv = C_1 => P, pad, iv = C_1$

    </div>

- 实际只要知道 $pad+iv$ 和 $pad+iv+x+pad+iv$ 的 MAC 就可以了 XD

    ```py
    #!/usr/bin/python

    import pwn
    from Crypto.Util.number import bytes_to_long, long_to_bytes

    conn = pwn.remote("babymac.hackable.software", 1337)

    conn.sendafter('> ', 'sign\n')
    conn.sendafter('> ', '\n')
    c0 = bytes.fromhex(conn.recvline().decode().strip())

    P = b'gimme flag123456'
    x = long_to_bytes(bytes_to_long(P) ^ bytes_to_long(c0)).hex()   

    conn.sendafter('> ', 'sign\n')
    conn.sendafter('> ', '10' * 16 + '00' * 16 + x + '\n')
    c1 = conn.recvline().decode()[:32]

    conn.sendafter('> ', 'verify\n')
    conn.sendafter('> ', c1 + P.hex() + '\n')
    conn.interactive()
    ```