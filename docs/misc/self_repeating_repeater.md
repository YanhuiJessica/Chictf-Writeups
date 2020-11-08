---
title: Misc - 自复读的复读机
description: 2020 | 中国科学技术大学第七届信息安全大赛 | General
---

## 题目

能够复读其他程序输出的程序只是普通的复读机。

顶尖的复读机还应该能复读出自己的源代码。

什么是国际复读机啊（战术后仰）

你现在需要编写两个只有一行 Python 代码的顶尖复读机：

- 其中一个要输出代码本身的逆序（即所有字符从后向前依次输出）
- 另一个是输出代码本身的 sha256 哈希值，十六进制小写

## Quine

自产生程序，指的是无输入且输出结果为程序自身源码的程序

### 原理

- 程序包含两个部分：用于执行输出的代码 A 和表示代码文本的数据 B
- 代码 A 打印输出数据 B，数据 B 中也包含代码 A

### Quine in Python

- `repr()`：返回描述对象的字符串。在格式化字符串中，转换说明符`%r`代表`repr()`
  ```py
  >>> s = 'Hello'
  >>> repr(s)
  "'Hello'"
  >>> l = [1, 2, 'a']
  >>> repr(l)
  "[1, 2, 'a']"
  ```
- 最短的 Python 自产生程序（未考虑回车）
    ```py
    s = 's=%r;print(s%%s)';print(s%s)
    ```

### 参考资料

- [自产生程序 - 维基百科，自由的百科全书](https://zh.wikipedia.org/wiki/%E8%87%AA%E7%94%A2%E7%94%9F%E7%A8%8B%E5%BC%8F)
- [How to write your first Quine program | by David Bertoldi | Towards Data Science](https://towardsdatascience.com/how-to-write-your-first-quine-program-947f2b7e4a6f)

## 输出代码本身的逆序

注意要考虑回车
```py
s="s=%r;print((s%%s)[::-1],end='')";print((s%s)[::-1],end='')
```

## 输出代码本身的 SHA256 哈希值

字符串`s`的内容参考执行输出的代码
```py
s="s=%r;import hashlib;print(hashlib.sha256((s%%s).encode()).hexdigest(),end='')";import hashlib;print(hashlib.sha256((s%s).encode()).hexdigest(),end='')
```