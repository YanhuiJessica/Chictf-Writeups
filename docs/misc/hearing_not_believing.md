---
title: Misc - HearingNotBelieving
description: 2021 | ByteCTF | Misc
---

## 题目

Hearing is not believing

## 解题思路

- 查看 `hearing.wav` 频谱图，有三段被切分的二维码<br>
![清晰的二维码](img/hearing_not_believing01.jpg)
- 拼接扫码后获得一部分 Flag：`m4yB3_`<br>
![不太整齐，但也能扫 :)](img/hearing_not_believing02.jpg)
- 剩下就是一段看上去很整齐的音频 (ŏωŏ)<br>
![看上去能用工具的样子](img/hearing_not_believing03.jpg)
- 本来还以为会和中间的小竖线有关，因为刚好是 $8$ 的倍数，又有明显的二元区别，还能解出来 `IR` 🤧 结果跑偏了……
- 最后是 SSTV，慢扫描电视（Slow-scan television）
- Linux 下用 `qsstv` 就可以，能得到 $16$ 张图片，拼起来是一个二维码

    <img src="img/hearing_not_believing04.png" width=100px style="margin:-4px">
    <img src="img/hearing_not_believing08.png" width=100px style="margin:-4px">
    <img src="img/hearing_not_believing12.png" width=100px style="margin:-4px">
    <img src="img/hearing_not_believing16.png" width=100px style="margin:-4px">
    <br>
    <img src="img/hearing_not_believing05.png" width=100px style="margin:-4px">
    <img src="img/hearing_not_believing09.png" width=100px style="margin:-4px">
    <img src="img/hearing_not_believing13.png" width=100px style="margin:-4px">
    <img src="img/hearing_not_believing17.png" width=100px style="margin:-4px">
    <br>
    <img src="img/hearing_not_believing06.png" width=100px style="margin:-4px">
    <img src="img/hearing_not_believing10.png" width=100px style="margin:-4px">
    <img src="img/hearing_not_believing14.png" width=100px style="margin:-4px">
    <img src="img/hearing_not_believing18.png" width=100px style="margin:-4px">
    <br>
    <img src="img/hearing_not_believing07.png" width=100px style="margin:-4px">
    <img src="img/hearing_not_believing11.png" width=100px style="margin:-4px">
    <img src="img/hearing_not_believing15.png" width=100px style="margin:-4px">
    <img src="img/hearing_not_believing19.png" width=100px style="margin:-4px">

- 由于没法直接扫出来，还要再手工描一下图 (╥ω╥) 获得另一部分 Flag：`U_kn0W_S57V}`<br>
![流下眼泪](img/hearing_not_believing20.jpg)
- 拼一下：`ByteCTF{m4yB3_U_kn0W_S57V}`
 
## 参考链接

- [Decoding SSTV from a file using Linux](https://www.chonky.net/hamradio/decoding-sstv-from-a-file-on-a-linux-system)