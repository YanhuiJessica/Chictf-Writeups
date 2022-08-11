---
title: Misc - Lighthouse
description: 2022 | UACTF | Misc
tags:
    - modular equation
---

## 题目

Hey, could you help us? It's dark in here.

The flag is of the form `UACTF{the minimum amount of turns required per dial for the check to be successful.}`

There is a custom character encoding to convert the number of turns for each dial to the character representation.

```
0 -> A
1 -> B
2 -> C
3 -> D
4 -> E
5 -> F
6 -> G
7 -> H
8 -> I
9 -> J
10 -> K
11 -> L
12 -> M
13 -> N
14 -> O
15 -> P
16 -> Q
17 -> R
18 -> S
19 -> T
20 -> U
21 -> V
22 -> W
23 -> X
24 -> Y
25 -> Z
26 -> _
27 -> !
28 -> *
```

For example:

```
0 Turns to dial 1
13 Turns to Dial 2 etc...
UACTF{0 13 10 11 8 3 4 9}
UACTF{ANKLIDEJ}
```

[:material-download: `lighthouse.zip`](static/lighthouse.zip)

## 解题思路

- `index.html` 有 $8$ 个转盘，点击任意转盘会改变所有转盘指向的数字，求满足要求每个转盘最少点击的次数
- `setup.js` 指出每个转盘为通过检查应指向的数字为 `8, 11, 22, 4, 14, 26, 3, 21`，`ki.js` 分别对应每个转盘点击后对自己及其它转盘的影响，其中 `k2.js` 给出了每个转盘初始指向的数字
- 类似 [灯，等灯等灯 - Level 0](https://github.com/USTC-Hackergame/hackergame2021-writeups/blob/master/official/%E7%81%AF%EF%BC%8C%E7%AD%89%E7%81%AF%E7%AD%89%E7%81%AF/README.md)，解一个模 $29$ 的线性方程组
- 矩阵乘法的结果矩阵第 $i$ 行第 $j$ 列元素等于前一个矩阵第 $i$ 行元素和后一矩阵第 $j$ 列相应元素乘积的和，因而矩阵乘法的前后顺序很重要

    ```py
    import numpy as np

    N, F = 8, Zmod(29)
    k = [
        [1, 6, 28, 40, 16, 42, 46, 37],
        [46, 1, 14, 25, 44, 17, 27, 27],
        [48, 30, 1, 47, 46, 27, 20, 25],
        [40, 11, 16, 1, 50, 12, 27, 26],
        [48, 49, 26, 16, 1, 6, 16, 2],
        [11, 9, 13, 3, 11, 1, 10, 35],
        [19, 34, 23, 10, 31, 27, 1, 32],
        [12, 10, 36, 6, 19, 24, 8, 1]
    ]
    init = [18, 12, 4, 8, 17, 2, 15, 8]
    target = [8, 11, 22, 4, 14, 26, 3, 21]

    L = Matrix(F, N, N)
    for i in range(N):
        for j in range(N):
            L[i, j] = k[i][j]
    d = [chr(ord('A') + i) for i in range(26)]
    d.extend(['_', '!', '*'])
    # use A.solve_left(Y) to solve for X in XA = Y
    for i in L.solve_left(vector(F, np.subtract(target, init))):
        print(d[i], end='')
    ```

- 也可以使用 [Modular Arithmetic Solver - Congruence Calculator - Online](https://www.dcode.fr/modular-equation-solver) 来解 =ω=

### Flag

> UACTF{Y_Z*MB!E}

## 参考资料

- [Base class for matrices, part 2 — Matrices and Spaces of Matrices](https://doc.sagemath.org/html/en/reference/matrices/sage/matrix/matrix2.html?highlight=solve_left)