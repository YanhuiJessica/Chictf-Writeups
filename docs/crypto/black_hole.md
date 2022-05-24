---
title: Crypto - Black Hole
description: 2022 | Hack-A-Sat | Crypto Category Placeholder Name
---

## 题目

We found a satellite but we can't speak its language. It changes its ~~encryption~~ encoding every time we open a connection...

We've got an open connection to the satellite.

It sent us this encoded message. Decode it and send it back to get the flag.

### Connecting

```bash
nc black_hole.satellitesabove.me 5300
```

## 解题思路

- 没有给源码，直接连服务器分析 ~~密文~~ 编码结果 ΣΣΣ(Φ ωΦ||¡)
- 既然是编码，应该有一定规律可循。就先试试最小的两个吧...等等！它们有什么区别么？！-ω- 十六进制字符串差了一个字符

    ```bash
    Generating black hole...

    Encoded msg is: e7a1977d3bce40b06475a6f44ca13535a345397224a927fc2f59633f66d7272bd45c1c8c9030755cf4e05fbd20ed995480e198b52498b0dcdfde8f027dd58c0c836f50045463ee0846df632a4c4b8bc7a7978290820441649b13760ee645d2f36af7571206d66b45b5eea1e0b13de2b84505a1b85c09d032f206f12b1179ca347eaecc6344af06e8c34bfe93072a5c0c6587a7e1c6c6bd1cd37a8868da78ecd103ce8d4f8e48d38369f669feb2ebf8ec9a74f70dbf22e84028b9290665ff2822fc4311047e68f02b24a5661cea07b42ec2dbfed36c964785cee1d70818aa2bdeece7680ef144c6e1797f695d2681a1210be06cd9e9d65487bbda4c5bba402030
    We can stream 18909 bytes of data before the sat kills the connection. Please help. (Send your message in hex.)
    (18909) Msg: 00
    9844ce7e63ee946ac1b2572627e46fa2309f6bc2a10dd9f0062f23d826884f20ab56eeaec99490ff8694fc8b8e5097177a0deb5345212e9eb52ac7e90edfecafedc8e1ef9b3c7c9018581ca238ea246705b9185af5d748df08563e45d0e64b642743d826bcd7257c8e126193f0bc15682027a2c7d7611d9327c0779808e2c82f3f0cea10192127ff0ce72091f9d42b576180e18a0e3b5d159df3e4c30c07a59d98756abc68a009cdf125282757a1e7a9d1792cb0d8664007af41ba1fc625562ebbf2601018899aa22a1c27e30fd43e368d40d39f4e8b962c42e24c9d0ecedf0681bdab587f5c7a2950658e141175b5c1e358fdc765b6d6ff187f7fc8a3757eb9
    # 9844ce7e63ee946ac1b2572627e46fa2309f6bc2a10dd9f0062f23d826884f20ab56eeaec99490ff8694fc8b8e5097177a0deb5345212e9eb52ac7e90edfecafedc8e1ef9b3c7c9018581ca238ea246705b9185af5d748df08563e45d0e64b642743d826bcd7257c8e126193f0bc15682027a2c7d7611d9327c0779808e2c82f3f0cea10192127ff0ce72091f9d42b576180e18a0e3b5d159df3e4c30c0_7_a59d98756abc68a009cdf125282757a1e7a9d1792cb0d8664007af41ba1fc625562ebbf2601018899aa22a1c27e30fd43e368d40d39f4e8b962c42e24c9d0ecedf0681bdab587f5c7a2950658e141175b5c1e358fdc765b6d6ff187f7fc8a3757eb9
    (18908) Msg: 01
    9844ce7e63ee946ac1b2572627e46fa2309f6bc2a10dd9f0062f23d826884f20ab56eeaec99490ff8694fc8b8e5097177a0deb5345212e9eb52ac7e90edfecafedc8e1ef9b3c7c9018581ca238ea246705b9185af5d748df08563e45d0e64b642743d826bcd7257c8e126193f0bc15682027a2c7d7611d9327c0779808e2c82f3f0cea10192127ff0ce72091f9d42b576180e18a0e3b5d159df3e4c30c06a59d98756abc68a009cdf125282757a1e7a9d1792cb0d8664007af41ba1fc625562ebbf2601018899aa22a1c27e30fd43e368d40d39f4e8b962c42e24c9d0ecedf0681bdab587f5c7a2950658e141175b5c1e358fdc765b6d6ff187f7fc8a3757eb9
    # 9844ce7e63ee946ac1b2572627e46fa2309f6bc2a10dd9f0062f23d826884f20ab56eeaec99490ff8694fc8b8e5097177a0deb5345212e9eb52ac7e90edfecafedc8e1ef9b3c7c9018581ca238ea246705b9185af5d748df08563e45d0e64b642743d826bcd7257c8e126193f0bc15682027a2c7d7611d9327c0779808e2c82f3f0cea10192127ff0ce72091f9d42b576180e18a0e3b5d159df3e4c30c0_6_a59d98756abc68a009cdf125282757a1e7a9d1792cb0d8664007af41ba1fc625562ebbf2601018899aa22a1c27e30fd43e368d40d39f4e8b962c42e24c9d0ecedf0681bdab587f5c7a2950658e141175b5c1e358fdc765b6d6ff187f7fc8a3757eb9
    ```

- 随后试了一些 `00`，发现长度大于等于 $2$ 的消息不能包含 `00`（看上去 `0100` 是个例外）

    ```bash
    (18909) Msg: 0000
    Must provide message with no NULL bytes (00)
    (18907) Msg: 0001
    Must provide message with no NULL bytes (00)
    (18905) Msg: 0100
    78c407e05c297ed2de6ebb9f4741be52a234e5519a0e4bd9be2e835dfd41ffbef0db1c87ea62db03f2711b96bb843afa3eadf6730996abbad539dba2cb433a02a877febfe8799e75e9170382c3c13238a4db876a691593e95a28267b3cedfa694f1a211fefa834a4bd41d670b3ad2f1dc8175c9716f136287c1c0c175914762d68069003215bc32fbc9dda8c01fc072eb379ecec40d2138e5f70b0b6e3af62bd1dbc1980227d5cf3475b979e5a19bf8069ad2f407f4e9edd109214bb70a2fcd343a5be3c8e408831a2482d0bf926b5322a521eb6158163419fb79a08802e052026e9bf9a20e2b7a8b5c50b1b36f0a6ea89f037a96a1f80784d2a2af4c7954aa2
    (18903) Msg: 010000
    Must provide message with no NULL bytes (00)
    (18900) Msg: 000001
    Must provide message with no NULL bytes (00)
    (18897) Msg: 010001
    Must provide message with no NULL bytes (00)
    ```

- （省略打表找规律的过程）通过观察可以确定
    - 相同长度的消息，编码结果的相似度高
    - 在一次通信中，对于相同长度的消息，明文的每个位置与编码结果有固定且唯一的映射
    - 对于明文的每一个位置可以分别考虑值的高八位和低八位，其编码结果由高八位与低八位的映射结果组合而成，如明文 `10` 对应编码结果 `45`，明文 `0a` 对应编码结果 `e3`，那么可推出明文 `1a` 对应编码结果 `43`
    - 明文不同位置与编码结果值的映射不同
- 因为还限制了发送消息字节的总数，所以一次查询应尽可能多获得信息

    ```py
    from pwn import *
    from Crypto.Util.number import long_to_bytes

    def compare(a, b):
        a, b = bytes.fromhex(a), bytes.fromhex(b)
        diff = 0
        for i, j in zip(a, b):
            if i != j:
                diff += 1
        return diff

    def index_diff(a, b):
        a, b = bytes.fromhex(a), bytes.fromhex(b)
        pos = []
        for i in range(len(a)):
            if a[i] != b[i]:
                pos.append(i)
        return pos

    ticket = 'ticket{foxtrot294921delta3:GD1KWFvlJJN0ge3qaEddP9Olmir30Q5z7V67AmZ_e1b8RtSz61E8uIlvDpuCSGS6pw}'

    conn = connect('black_hole.satellitesabove.me', 5300)
    conn.sendafter('Ticket please:' , f'{ticket}\n')

    enc = conn.recvline_contains('Encoded msg is: ').decode().split(' ')[-1]

    # 获取编码消息的长度
    enc_len = 0
    for i in range(140, 0x100): # 经过测试，待求消息的长度基本在 140 及以上
        conn.sendafter('Msg:', f'{"01" * i}\n')
        res = conn.recvline().decode().strip()
        if compare(enc, res) <= i:
            enc_len = i
            print(f'Length: {i}')
            break

    # pre: 消息 b'\x01' * enc_len 的编码结果，便于确定明文各个位在编码结果的位置
    # pos_map: 明文各个位置与十六进制字符串的位置映射
    # first_map: 明文各个位置高八位的编码映射表 0x0_ - 0xf_
    # second_map: 明文各个位置低八位的编码映射表 0x_0 - 0x_f
    pre, pos_map, first_map, second_map = res, [-1] * enc_len, {}, {}
    for i in [0x02, 0x10, 0x21, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]:
        s = long_to_bytes(i) * enc_len
        conn.sendafter('Msg:', f'{s.hex()}\n')
        res = conn.recvline().decode().strip()
        pd = index_diff(res, pre)
        for j in pd:
            p = j * 2
            if p in first_map:
                first_map[p][res[p]] = (i & 0xf0) // 0x10
            else:
                first_map[p] = {res[p]: 0}
            if p in second_map:
                second_map[p][res[p + 1]] = i & 0xf
            else:
                second_map[p] = {res[p + 1]: 2}

    # 获得编码结果各个位置与明文值的映射关系后，就可以构造明文来确定位置的映射关系
    for i in range(0, enc_len, 0x10):
        s = bytearray(b'\x01') * enc_len
        for j in range(min(0x10, enc_len - i)):
            s[i + j] = 0x10 + j
        conn.sendafter('Msg:', f'{s.hex()}\n')
        res = conn.recvline().decode().strip()
        pd = index_diff(res, pre)
        pos, sm = [], []
        for j in pd:
            p = j * 2
            pos.append(p)
            sm.append(second_map[p][res[p + 1]])
        for j, k in zip(sm, pos):
            pos_map[i + j] = k

    s = bytearray(b'\x00') * enc_len
    for i in range(enc_len):
        s[i] = first_map[pos_map[i]][enc[pos_map[i]]] * 0x10 + second_map[pos_map[i]][enc[pos_map[i] + 1]]
    conn.sendafter('Msg:', f'{s.hex()}\n')
    conn.interactive()
    # Satellite-link synced! Flag: flag{foxtrot294921delta3:GEPzPQGVu-6MW0Ly8t6rSDotRhMZUOVCgnp-lcMPJbIiuvNwfH2MeDjkChz6vPvg8Hn6sGWG2i_8XroCUhRsIE4}
    ```

### Flag

> flag{foxtrot294921delta3:GEPzPQGVu-6MW0Ly8t6rSDotRhMZUOVCgnp-lcMPJbIiuvNwfH2MeDjkChz6vPvg8Hn6sGWG2i_8XroCUhRsIE4}