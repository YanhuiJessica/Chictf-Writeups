---
title: Crypto - fanfie
description: 2017 | BITSCTF | Crypto
---

## 解题思路

- 观察字符串`MZYVMIWLGBL7CIJOGJQVOA3IN5BLYC3NHI`，仅由大写字母和数字 *3、5、7* 组成，推测经过 Base32 编码
  > Base32：32 个可打印字符，*A-Z* 和 *2-7*，等号填充
- `BITSCTF{`经过 Base32 编码后得到：`IJEVIU2DKRDHW===`
- 将两个字符串一一对应，发现两个`M`都对应`I`，两个`L`也都对应`D`，为单表代换
    ```
    MZYVMIWLGBL7CIJOGJQVOA3IN5BLYC3NHI
    IJEVIU2DKRDHW===
    ```
- 注意到`W`对应的是数字`2`，不是普通的字母表代换，推测是 Base32 对应的 32 个可打印字符。`M`与`I`的距离和`L`与`D`的距离不同，不是单纯的移位加密，而是仿射密码
- 计算方程组$\begin{cases}12a+b\equiv8&(mod&32)\\ 11a+b\equiv3&(mod&32)\end{cases}$，解得$\begin{cases}a=5\\b=12\end{cases}$
- 先使用仿射密码解密，得到`IJEVIU2DKRDHWUZSKZ4VSMTUN5RDEWTNPU`，再经过 Base32 解码，即可获得 Flag：`BITSCTF{S2VyY2tob2Zm}`