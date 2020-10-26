---
title: Crypto - Normal_RSA
description: 攻防世界 | 新手练习区 | Crypto
---

## 解题思路

- 附件为一个公钥文件 *pubkey.pem* 和一个经过加密的文件 *flag.enc*
- 直接使用工具 [Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) 解密
    ```bash
    # factordb 在线分解 N
    $ ./RsaCtfTool.py --publickey pubkey.pem --uncipherfile flag.enc --attack factordb
    private argument is not set, the private key will not be displayed, even if recovered.

    [*] Testing key pubkey.pem.
    [*] Performing factordb attack on pubkey.pem.

    Results for pubkey.pem:

    Unciphered data :
    HEX : 0x0002c0fe04e3260e5b8700504354467b323536625f69355f6d336469756d7d0a
    INT (big endian) : 4865677769286717240419296208145914517832094464845949055035370987525602570
    INT (little endian) : 4744739824694533032519230312074638919149793854447671791679980959756701401600
    STR : b'\x00\x02\xc0\xfe\x04\xe3&\x0e[\x87\x00PCTF{256b_i5_m3dium}\n'
    ```
- Flag 为`PCTF{256b_i5_m3dium}`