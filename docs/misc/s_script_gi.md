---
title: Misc - s/<script>//gi
description: 2021 | SECCON | Misc
---

## 题目

Can you figure out why `s/<script>//gi` is insufficient for sanitizing? This can be bypassed with `<scr<script>ipt>`.

Remove `<script>` (case insensitive) from the input until the input contains no `<script>`.

Note that flag format is `SECCON{[\x20-\x7e]+}`, which means that the flag may contains < or > as the following examples.

Sample Input 1:

`S3CC0N{dum<scr<script>ipt>my}`

Sample Output 1:

`S3CC0N{dummy}`

Sample Input 2 (small.txt):

`S3CC0N{dumm<scrIpT>y_flag>_<_pt>>PT><<SCr<S<<SC<SCRIpT><scRiPT>Ript>sCr<Scri<...`

Sample Output 2:

`S3CC0N{dummy_flag>_<_pt>>PT><sCRIp<scr<scr<scr!pt>ipt>ipt>}`

## 解题思路

- 不断移除 `<script>`（大小写不敏感） 标签，直到没有为止
- 然而 `flag.txt` 大小高达 67M
- 先用 `sed` 替换几下，能砍掉 20 M

    ```bash
    for i in {1..10};do sed -i 's/<[sS][cC][rR][iI][pP][tT]>//g' flag.txt; done
    ```

- 然后，进入瓶颈阶段 -_- 「用啥都不会太快」（Python 和 C++ 都跑了两小时左右）

    ```py
    s = open('flag.bak', 'r').read()
    l = len(s)

    res, p = '', 0

    for i in range(l):
        if s[i] == '>':
            res += s[p:i+1]
            while '<script>' == res[-8:].lower():
                res = res[:-8]
            p = i + 1
            
    if p != l:
        res += s[p:l]        

    print(res)
    ```

    ```cpp
    #include<iostream>
    #include<fstream>
    #include<algorithm>
    using namespace std;

    int main()
    {
        ifstream infile;
        infile.open("flag.txt");
        string s, r = "";
        infile >> s;
        infile.close();

        int l = s.length(), p = 0;
        for (int i = 0; i < l; i++) {
            if (s[i] == '>') {
                r += s.substr(p, i - p + 1);
                int tl = r.length();
                string tmp = r.substr(tl - 8);
                transform(tmp.begin(), tmp.end(), tmp.begin(), ::tolower);
                if ("<script>" == tmp) {
                    r = r.substr(0, tl - 8);
                }
                p = i + 1;
            }
        }

        if (p != l) {
            r += s.substr(p, l - p + 1);
        }

        cout << r << endl;
        return 0;
    }
    ```

- 最终结果：`SECCON{sanitizing_is_not_so_good><_escaping_is_better_iPt><SCript<ScrIpT<scRIp<scRI<Sc<scr!pt>}`