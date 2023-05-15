---
title: Misc - Chm0d
description: 2023 | HeroCTF | System
tags:
    - dd
    - chmod
---

## 题目

Catch-22: a problematic situation for which the only solution is denied by a circumstance inherent in the problem.

Credentials: `user:password123`

## 解题思路

- `flag.txt` 位于根目录下，但不可读

    ```bash
    $ ls -l
    total 76
    ...
    ----------   1 user user   40 May 12 11:44 flag.txt
    ...
    ```

- `chmod` 命令不可用，且 `user` 不是所有者

    ```bash
    $ ls /bin/chmod -l
    ---------- 1 root root 64448 Sep 24  2020 /bin/chmod
    ```

- 可以在家目录创建一个文件，再用原始文件覆盖它，这样能够保留可读权限

    ```bash
    $ touch flag.txt
    $ dd if=/flag.txt of=flag.txt
    $ cat flag.txt 
    Hero{chmod_1337_would_have_been_easier}
    ```

## 参考资料

- [permissions - How to chmod without /usr/bin/chmod? - Unix & Linux Stack Exchange](https://unix.stackexchange.com/a/83873)