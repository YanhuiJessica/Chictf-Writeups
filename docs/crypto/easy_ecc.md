---
title: Crypto - easy_ECC
description: 2016 | XUSTCTF | Crypto
---

## 解题思路

- 已知椭圆群 $E_p(a,b)$ 、生成原点 $G$ 和私钥 $k$，公钥为 $kG$
- 使用工具 *SageMath*，编写脚本`ecc_calc`
    ```sh
    #!/usr/bin/env sage

    from sage.all import *

    p, a, b = 15424654874903, 16546484, 4548674875
    G = (6478678675, 5636379357093)
    k = 546768

    F = GF(p)   # 有限域
    E = EllipticCurve(F, [a, b])
    G = E.point(G) # 得到在有限域椭圆曲线上对应点类的对象
    Pub = k * G
    print(Pub)
    ```
- 运行脚本得到点的坐标，Flag 为 $x、y$ 的和
  ```bash
  $ ./ecc_calc
  (13957031351290 : 5520194834100 : 1)
  ```

## 参考资料

- [Points on elliptic curves — Sage 9.1 Reference Manual: Curves](https://doc.sagemath.org/html/en/reference/curves/sage/schemes/elliptic_curves/ell_point.html)
- [Points — Sage 9.1 Reference Manual: 2D Graphics](https://doc.sagemath.org/html/en/reference/plotting/sage/plot/point.html)