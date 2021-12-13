---
title: Crypto - Steroid Stream
description: 2021 | PBCTF | Crypto
---

## 题目

I found a weird stream cipher scheme. Can you break this?

[CTFtime.org / pbctf 2021 / Steroid Stream](https://ctftime.org/task/17579)

## 解题思路

- [Alkaloid Stream](alkaloid_stream.md) 进阶版，除了 `fake` 数组的产生方式有所差异，其他部分都是一样的
    ```py
    fake = [0] * ln
    for i in range(ln - ln // 3):
        arr = list(range(i + 1, ln))
        random.shuffle(arr)
        for j in arr[:ln // 3]: # 在 [i + 1, ln) 中随机选取 ln // 3 个 key 异或
            fake[i] ^= key[j]
    ```
    - 对于 `fake` 数组中下标为 $[ln - ln // 3, ln)$ 的元素值均为 $0$
- 异或等同于 $GF(2)$ 中的加法，可以把 `fake` 数组中的值看作是已知 `keys` 的线性组合，而 `keys` 数组中的值相互间线性无关，从而可以区分 `fake` 和 `keys`
- 使用已知 `keys` 构建一个以 `keys` 为行的 $GF(2)$ 矩阵，假设 `keys` 的数量为 $k$，那么有 $k$ 行相互独立，矩阵的秩（rank）为 $k$。添加值 $v$ 到 $k + 1$ 行，如果 $v$ 是 `keys` 的线性组合，那么矩阵的秩仍为 $k$，否则是 $k + 1$
    ```py
    def gf2_rank(rows):
        """
        Find rank of a matrix over GF2.

        The rows of the matrix are given as nonnegative integers, thought
        of as bit-strings.

        This function modifies the input list. Use gf2_rank(rows.copy())
        instead of gf2_rank(rows) to avoid modifying rows.
        """
        rank = 0
        while rows:
            pivot_row = rows.pop()
            if pivot_row:
                rank += 1
                lsb = pivot_row & -pivot_row
                for index, row in enumerate(rows):
                    if row & lsb:
                        rows[index] = row ^ pivot_row
        return rank

    def is_linear_combination(keys, test):
        rows = keys.copy()
        rows.append(test)
        return len(rows) > gf2_rank(rows)

    keys, remain = [], []
    for p in public:
        if 0 in p:
            keys.append(p[0] + p[1])
        else:
            remain.append(p)

    while remain:
        cur_remain = []
        for p in remain:
            if is_linear_combination(keys, p[0]):
                keys.append(p[1])
            elif is_linear_combination(keys, p[1]):
                keys.append(p[0])
            else:
                cur_remain.append(p)
        remain = cur_remain

    keystream = recover_keystream(keys, public)
    print(bits_to_bytes(xor(enc, keystream)))

    # b'pbctf{I_hope_you_enjoyed_this_challenge_now_how_about_playing_Metroid_Dread?}'
    ```

## 参考资料

- [另一种世界观——有限域](https://www.bilibili.com/read/cv2922069)
- [GF(2) - Wikipedia](https://en.wikipedia.org/wiki/GF(2))
- [Linear combination - Wikipedia](https://en.wikipedia.org/wiki/Linear_combination)
- [Rank (linear algebra) - Wikipedia](https://en.wikipedia.org/wiki/Rank_(linear_algebra))
- [Fast computation of matrix rank over GF(2)](https://stackoverflow.com/questions/56856378/fast-computation-of-matrix-rank-over-gf2)

### 拓展阅读

<!-- 如果能懂的话... -->

- [[Tutorial] Matroid intersection in simple words - Codeforces](https://codeforces.com/blog/entry/69287)