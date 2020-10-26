---
title: Eggs - 首页
description: CTFHub | 技能树 | 彩蛋
---

## 题目

听说在首页的某个地方隐藏了一个 flag，可能在 *.ctfhub.com 中，不妨先找到 flag 再来开题

## 解题思路

- 直接看首页并没有什么特别的发现(╮ŏωŏ)╭
- 题目提示 flag 可能在 *.ctfhub.com 中，说明不一定是 www.ctfhub.com
- 观察访问首页时的网络通信，共发现三个域名：www.ctfhub.com、api.ctfhub.com、static.ctfhub.com<br>
![发向三个域名的请求](img/ctfhub_index01.jpg)
- 访问 api.ctfhub.com 就可以发现 flag 了<br>
![使用开发者查看器](img/ctfhub_index02.jpg)
- static.ctfhub.com 并不能访问 XD