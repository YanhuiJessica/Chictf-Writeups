---
title: Reverse - re_signin
description: 2021 | NEWSCTF | Reverse
---

## 题目

count is times

## Hint

冒泡排序的次数

## 解题思路

- 题目包含两个文件`flag.pyc`和`flag.txt`，`flag.txt` 是若干一维数组
- 反编译 PYC 文件获得 PY 源代码
    ```bash
    uncompyle6 flag.pyc > flag.py
    ```
- 分析代码，发现冒泡排序，结合题目 `count is times` 可以推测 `c` 数组每一位的值是对应数组冒泡排序的总交换次数（本来没有 Hint）
    ```py
    flag = 'xxxx{xxxxxxxxxxxxxxxxxx}'
    import random
    c = [0] * len(flag)
    for i in range(len(flag)):
        c[i] = ord(flag[i])
    else:
        print(c)
        t = 0
        for i in range(2000):
            num = range(0, 100)
            nums = random.sample(num, 22)
            numss = nums.copy()

        # 冒泡排序
        for i in range(len(nums) - 1):
            for j in range(len(nums) - i - 1):
                if nums[j] > nums[(j + 1)]:
                    nums[j], nums[j + 1] = nums[(j + 1)], nums[j]

            if count == c[t]:
                print(numss)
                t += 1
                if t == 24: # 共输出 24 次
                    break
    ```
- 计算得 `synt{jrypbzr_gb_arjfpgs}`
- ROT13 可得 Flag：`flag{welcome_to_newsctf}`