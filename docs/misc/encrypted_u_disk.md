---
title: Misc - 加密的 U 盘
description: 2021 | 中国科学技术大学第八届信息安全大赛 | General
---

## 题目

这是一个关于 LUKS (Linux Unified Key Setup) 的故事。

第一天

小 T：「你要的随机过程的课件我帮你拷好了，在这个 U 盘里，LUKS 加密的密码是 `suijiguocheng123123`。」

小 Z：「啊，你又搞了 Linux 文件系统加密，真拿你没办法。我现在不方便用 Linux，我直接把这块盘做成磁盘镜像文件再回去处理吧。」

第二天

小 Z：「谢谢你昨天帮我拷的课件。你每次都搞这个加密，它真的安全吗？」

小 T：「当然了！你看，你还给我之后，我已经把这块盘的弱密码改掉了，现在是随机生成的强密码，这样除了我自己，世界上任何人都无法解密它了。」

小 Z：「我可不信。」

小 T：「你不信？你看，我现在往 U 盘里放一个 flag 文件，然后这个 U 盘就给你了，你绝对解密不出来这个文件的内容。当初搞 LUKS 的时候我可研究了好几天，班上可没人比我更懂加密！」

## LUKS - 技术特点

- 采用一种数据分割技术保存加密密钥，保证密钥的安全性 
- 支持多用户/密码对同一个设备的访问，用户密码加密主密钥
    - 由 Split Master Key 可以得到 Master Key
- 数据加密密钥，即主密钥，不依赖密码，**改变密码无需重新加密数据**

## 解题思路

- 第一天和第二天分别对应镜像 `day1.img` 和 `day2.img`
- 由题意可知，从 `day1.img` 到 `day2.img` 只有用户密码发生了变更，加密数据使用的主密钥并没有变化
- Ubuntu 双击后输入密码，直接挂载 `day1.img`，这里并没有 Flag (ŏωŏ)，快进到下一步
    - 或者通过命令行的方式挂载
        ```bash
        sudo losetup -P /dev/loop23 day1.img
        # -P：强制内核扫描新建回环设备上的分区表，否则 cryptsetup 无法识别为有效的 LUKS 设备
        sudo cryptsetup luksOpen /dev/loop23p1 day1
        ```
- 获取 LUKS 加密镜像挂载的位置
    ```bash
    $ lsblk | grep luks -B 2
    loop23                                          7:23   0    20M  1 loop  
    └─loop23p1                                    259:10   0    19M  1 part  
      └─luks-e9a660d5-4a91-4dca-bda5-3f6a49eea998   253:0    0     3M  1 crypt /media/yanhui/My Disk
    ```
- 获取主密钥并保存为二进制文件
    ```bash
    $ sudo cryptsetup luksDump --dump-master-key /dev/loop23p1

    WARNING!
    ========
    Header dump with volume key is sensitive information
    which allows access to an encrypted partition without a passphrase.
    This dump should be always stored encrypted in a safe place.

    Are you sure? (Type uppercase yes): YES
    Enter passphrase for /dev/loop23p1: 
    LUKS header information for /dev/loop23p1
    Cipher name:   	aes
    Cipher mode:   	xts-plain64
    Payload offset:	32768
    UUID:          	e9a660d5-4a91-4dca-bda5-3f6a49eea998
    MK bits:       	512
    MK dump:	be 97 db 91 5c 30 47 ce 1c 59 c5 c0 8c 75 3c 40 
                72 35 85 9d fe 49 c0 52 c4 f5 26 60 af 3e d4 2c 
                ec a3 60 53 aa 96 70 4d f3 f2 ff 56 8f 49 a1 82 
                60 18 7c 58 d7 6a ec e8 00 c1 90 c1 88 43 f8 9a

    $ echo "be 97 db 91 5c 30 47 ce 1c 59 c5 c0 8c 75 3c 40 72 35 85 9d fe 49 c0 52 c4 f5 26 60 af 3e d4 2c ec a3 60 53 aa 96 70 4d f3 f2 ff 56 8f 49 a1 82 60 18 7c 58 d7 6a ec e8 00 c1 90 c1 88 43 f8 9a" | tr -d " " | xxd -r -p > masterkey
    ```
- 使用主密钥解密 `day2.img`
    ```bash
    sudo losetup -P /dev/loop24 day2.img
    sudo cryptsetup luksOpen /dev/loop24p1 day2 --master-key-file masterkey
    ```
- 进入磁盘，就能看到 `flag.txt` 了

### Flag

> flag{changing_Pa55w0rD_d0esNot_ChangE_Luk5_ma5ter_key}

## 参考资料

- 钱镜洁，魏鹏，沈长达. [LUKS加密卷的离线解密技术分析](http://netinfo-security.org/CN/10.3969/j.issn.1671-1122.2014.09.051)[J]. 信息网络安全, 2014, 14(9): 217-219. 
- [losetup(8) — Linux manual page](https://man7.org/linux/man-pages/man8/losetup.8.html)
- [cryptsetup(8) — Linux manual page](https://man7.org/linux/man-pages/man8/cryptsetup.8.html)