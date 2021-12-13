---
title: Crypto - Compress The Flag
description: 2021 | DragonCTF | Miscellaneous
---

## 题目

Technically this isn't a good compression benchmark, but it's the only one we have.

nc compresstheflag.hackable.software 1337

??? note "server.py"

    ```py
    #!/usr/bin/env python3
    import threading
    import socket
    import random
    import codecs
    import lzma as lz


    with open("flag.txt", "rb") as f:
    FLAG = f.read().strip()

    def none(v):
    return len(v)

    def zlib(v):
    return len(codecs.encode(v, "zlib"))

    def bzip2(v):
    return len(codecs.encode(v, "bz2"))

    def lzma(v):
    return len(lz.compress(v))

    COMPRESSION_FUNCS = [
    none,
    zlib,
    bzip2,
    lzma
    ]

    def handle_connection(s, addr):
    s.sendall(
        ("Please send: seed:string\\n\n"
        "I'll then show you the compression benchmark results!\n"
        "Note: Flag has format DrgnS{[A-Z]+}\n").encode())

    data = b''
    while True:
        idx = data.find(b'\n')
        if idx == -1:
        if len(data) > 128:
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            return

        d = s.recv(1024)
        if not d:
            s.close()
            return
        data += d
        continue

        line = data[:idx]
        data = data[idx+1:]

        seed, string = line.split(b':', 1)

        flag = bytearray(FLAG)
        random.seed(int(seed))
        random.shuffle(flag)
        test_string = string + bytes(flag)

        response = []
        for cfunc in COMPRESSION_FUNCS:
        res = cfunc(test_string)
        response.append(f"{cfunc.__name__:>8} {res:>4}")

        response.append('')
        response.append('')
        s.sendall('\n'.join(response).encode())

    s.shutdown(socket.SHUT_RDWR)
    s.close()


    def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', 1337))
        s.listen(256)

        while True:
        conn, addr = s.accept()
        print(f"Connection from: {addr}")

        th = threading.Thread(
            target=handle_connection,
            args=(conn, addr),
            daemon=True
        )
        th.start()

    if __name__ == "__main__":
    main()
    ```

## 解题思路

- 提供一个随机数种子和字符串，服务器使用随机数种子打乱 Flag 字符的顺序，再拼接上提供的字符串，返回最后生成字符串的原长度以及不同压缩算法压缩后的长度

    ```bash
    Please send: seed:string\n
    I'll then show you the compression benchmark results!
    Note: Flag has format DrgnS{[A-Z]+}
    1:A
        none   26
        zlib   34
       bzip2   63
        lzma   84
    ```

- `none` 即不进行压缩，除去输入的字符串和 Flag 头，需要求解的部分的长度为 $26 - 1 - 7 = 18$
- 指定随机数种子，也就是说可以知道 Flag 打乱之后每一个字符原先的位置
- 先在本地用 `DrgnS{ABCDEFGHIJKLMNOPQR}` 观察一下
    - 当种子为 1 时，字母 `E` 开头
    - 观察发现，当输入字符串为 4 个相同字符时，`EEEE` 和打乱的 Flag 字符串使用 zlib 和 bzip2 （均含 Huffman 编码）压缩的长度会小于其他字符

        ```bash
        1:EEEE
            none   29
            zlib   35
           bzip2   69
            lzma   88
        1:AAAA
            none   29
            zlib   37
           bzip2   70
            lzma   88
        1:SSSS
            none   29
            zlib   37
           bzip2   70
            lzma   88
        ```

- 先找到使每个字母打乱后作为开头的随机数种子

    ```py
    import random

    flag_pos = b'DrgnS{ABCTEFGHIJKLMNOPQR}' # 为方便查找，每个字符均不相同
    d = {}
    for i in range(10000):
        random.seed(i)
        tflag = bytearray(flag_pos)
        random.shuffle(tflag)
        if tflag[0] in b'ABCTEFGHIJKLMNOPQR' and tflag[0] not in d:
            d[tflag[0]] = i
        if len(d) == 18:
            break
    ```

- 随后爆破每一个字母（有一定的运气成分，如果随机数种子没选好，导致打乱的 Flag 开头是连续字母就难以直接根据长度判断了）

    ```py
    import pwn

    conn = pwn.remote("compresstheflag.hackable.software", 1337)
    conn.recvline_contains('Note')

    flag_pos = 'DrgnS{ABCTEFGHIJKLMNOPQR}'
    flag = list('DrgnS{xxxxxxxxxxxxxxxxxx}')
    for k in d:
        min, mic = 0xffff, 'A'
        for c in range(ord('A'), ord('Z') + 1):
            conn.send(f'{d[k]}:{chr(c) * 4}\n')
            l = int(conn.recvline_contains('zlib').split(b' ')[-1])
            if l < min:
                min, mic = l, chr(c)
        flag[flag_pos.find(chr(k))] = mic

    print(''.join(flag))
    # DrgnS{THISISACRIMEIGUESS}
    ```

## 参考资料

- [bzip2 - Wikipedia](https://en.wikipedia.org/wiki/Bzip2)
- [zlib - Wikipedia](https://en.wikipedia.org/wiki/Zlib)