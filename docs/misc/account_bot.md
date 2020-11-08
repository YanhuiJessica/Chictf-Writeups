---
title: Misc - 从零开始的记账工具人
description: 2020 | 中国科学技术大学第七届信息安全大赛 | General
---

## 题目

如同往常一样，你的 npy 突然丢给你一个购物账单：“我今天买了几个小玩意，你能帮我算一下一共花了多少钱吗？”

你心想：~~又双叒叕要开始吃土了~~ 这不是很简单吗？电子表格里面一拖动就算出来了

只不过拿到账单之后你才注意到，似乎是为了剁手时更加的安心，这次的账单上面的金额全使用了中文大写数字

## 解题思路

主要是将中文大写金额转化为数字金额，求和交给 EXCEL 就好啦~w
```py
digit = ['零','壹','贰','叁','肆','伍','陆','柒','捌','玖']
tens = ['拾','佰','仟','万']
yuan = ['元','角','分']

l = []
while True:
    try:
        l.append(input())
    except EOFError:
        break

for s in l:
    tmp, cnt, total = 0, 0, 0
    for i in s:
        if i in digit:
            tmp += digit.index(i)
        elif i in tens:
            if tmp == 0:
                tmp = 1
            cnt += tmp * 10 ** (tens.index(i) + 1)
            tmp = 0
        elif i in yuan:
            if tmp:
                cnt += tmp
                tmp = 0
            total += cnt * 10 ** (-yuan.index(i))
            cnt = 0
    print("%.2f" % total)
```
