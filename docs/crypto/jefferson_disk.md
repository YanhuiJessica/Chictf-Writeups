---
title: Crypto - 转轮机加密
description: 2017 | ISCC | Crypto
---

## 题目

<div style="font-family:Lucida Console;">
01:  < ZWAXJGDLUBVIQHKYPNTCRMOSFE <<br>
02:  < KPBELNACZDTRXMJQOYHGVSFUWI <<br>
03:  < BDMAIZVRNSJUWFHTEQGYXPLOCK <<br>
04:  < RPLNDVHGFCUKTEBSXQYIZMJWAO <<br>
05:  < IHFRLABEUOTSGJVDKCPMNZQWXY <<br>
06:  < AMKGHIWPNYCJBFZDRUSLOQXVET <<br>
07:  < GWTHSPYBXIZULVKMRAFDCEONJQ <<br>
08:  < NOZUTWDCVRJLXKISEFAPMYGHBQ <<br>
09:  < XPLTDSRFHENYVUBMCQWAOIKZGJ <<br>
10: < UDNAJFBOWTGVRSCZQKELMXYIHP <<br>
11: < MNBVCXZQWERTPOIUYALSKDJFHG <<br>
12: < LVNCMXZPQOWEIURYTASBKJDFHG <<br>
13: < JZQAWSXCDERFVBGTYHNUMKILOP <<br>
</div>

密钥为: 2, 3, 7, 5, 13, 12, 9, 1, 8, 10, 4, 11, 6<br>
密文为: NFQKSEVOQOFNP

## 解题思路

- 先按密钥顺序对行进行排序，对每一行，滚动字母表使密文字符位于同一列（如首列）

    Line | Alphabets
    -|-
    2 |  <div style="font-family:Lucida Console;">NACZDTRXMJQOYHGVS**F**UWIKPBEL
    3 |  <div style="font-family:Lucida Console;">FHTEQGYXPLOCKBDMA**I**ZVRNSJUW
    7 |  <div style="font-family:Lucida Console;">QGWTHSPYBXIZULVKM**R**AFDCEONJ
    5 |  <div style="font-family:Lucida Console;">KCPMNZQWXYIHFRLAB**E**UOTSGJVD
    13| <div style="font-family:Lucida Console;">SXCDERFVBGTYHNUMK**I**LOPJZQAW
    12| <div style="font-family:Lucida Console;">EIURYTASBKJDFHGLV**N**CMXZPQOW
    9 |  <div style="font-family:Lucida Console;">VUBMCQWAOIKZGJXPL**T**DSRFHENY
    1 |  <div style="font-family:Lucida Console;">OSFEZWAXJGDLUBVIQ**H**KYPNTCRM
    8 |  <div style="font-family:Lucida Console;">QNOZUTWDCVRJLXKIS**E**FAPMYGHB
    10|  <div style="font-family:Lucida Console;">OWTGVRSCZQKELMXYI**H**PUDNAJFB
    4 |  <div style="font-family:Lucida Console;">FCUKTEBSXQYIZMJWA**O**RPLNDVHG
    11| <div style="font-family:Lucida Console;">NBVCXZQWERTPOIUYA**L**SKDJFHGM
    6 |  <div style="font-family:Lucida Console;">PNYCJBFZDRUSLOQXV**E**TAMKGHIW

- 依次查看每一列，找到有实际意义的即为 Flag：`FIREINTHEHOLE`

## 参考资料

[Jefferson disk - Wikipedia](https://en.wikipedia.org/wiki/Jefferson_disk)