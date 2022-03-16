---
title: Pwn - Amnesia
description: 2021 | 中国科学技术大学第八届信息安全大赛 | Binary
---

## 题目

你的程序只需要输出字符串 `Hello, world!`（结尾有无换行均可）并正常结束。

编译指令：`gcc -O file.c -m32`

运行指令：`./a.out`

编译器版本：Docker 镜像 `ustclug/debian:10` 中 `apt update && apt -y upgrade && apt install -y gcc=4:8.3.0-1 gcc-multilib=4:8.3.0-1` 的版本

### 轻度失忆

编译后 ELF 文件的 `.data` 和 `.rodata` 段会被清零。

## 解题思路

### 轻度失忆

- `.data` 段存储全部的全局变量和所有被 `static` 修饰的变量，`.rodata` 段存储未被作为初始化使用的 **字符串常量** 和被 `const` 修饰的全局变量
- 当字符串常量被用来为数组初始化时，该字符串常量将放入对应数组中（局部变量在栈区）
- 由于使用 `printf` 仍然会包含字符串常量，使用 `puts` 直接输出

    ```c
    #include <stdio.h>

    int main(){
        char str[14] = "Hello, world!";
        puts(str);
    }
    ```

## 参考资料

- [浅谈C语言的数据存储（一）](http://emb.hqyj.com/Column/Column540.htm)