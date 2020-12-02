---
title: OverTheWire：Leviathan
---

## Level 0

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>leviathan0</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>leviathan0</td>
  </tr>
</tbody>
</table>

```bash
$ ssh leviathan0@leviathan.labs.overthewire.org -p 2223

$ ls
$ ls -la
total 24
drwxr-xr-x  3 root       root       4096 Aug 26  2019 .
drwxr-xr-x 10 root       root       4096 Aug 26  2019 ..
drwxr-x---  2 leviathan1 leviathan0 4096 Aug 26  2019 .backup
-rw-r--r--  1 root       root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root       root       3526 May 15  2017 .bashrc
-rw-r--r--  1 root       root        675 May 15  2017 .profile
$ ls .backup/
bookmarks.html
$ cat .backup/bookmarks.html | grep leviathan
<DT><A HREF="http://leviathan.labs.overthewire.org/passwordus.html | This will be fixed later, the password for leviathan1 is rioGegei8m" ADD_DATE="1155384634" LAST_CHARSET="ISO-8859-1" ID="rdf:#$2wIU71">password to leviathan1</A>
```

## Level 1

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>leviathan1</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>rioGegei8m</td>
  </tr>
</tbody>
</table>

利用`ltrace`

```bash
$ ssh leviathan1@leviathan.labs.overthewire.org -p 2223

$ ls -l
total 8
-r-sr-x--- 1 leviathan2 leviathan1 7452 Aug 26  2019 check

$ ./check
password: 123
Wrong password, Good Bye ...

# strace - Troubleshooting tool for tracing system calls
# ltrace - Display dynamic library calls of a process
$ ltrace ./check
__libc_start_main(0x804853b, 1, 0xffffd784, 0x8048610 <unfinished ...>
printf("password: ")                                    = 10
getchar(1, 0, 0x65766f6c, 0x646f6700password:
)                   = 10
getchar(1, 0, 0x65766f6c, 0x646f6700
)                   = 10
getchar(1, 0, 0x65766f6c, 0x646f6700
)                   = 10
strcmp("\n\n\n", "sex")                                 = -1
puts("Wrong password, Good Bye ..."Wrong password, Good Bye ...
)                    = 29
+++ exited (status 0) +++

$ ./check
password: sex
$ whoami
leviathan2
$ cat /etc/leviathan_pass/leviathan2
ougahZi8Ta
```

## Level 2

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>leviathan2</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>ougahZi8Ta</td>
  </tr>
</tbody>
</table>

```bash
$ ssh leviathan2@leviathan.labs.overthewire.org -p 2223

$ ls -l
total 8
-r-sr-x--- 1 leviathan3 leviathan2 7436 Aug 26  2019 printfile
# 设置了 Setuid

$ ./printfile
*** File Printer ***
Usage: ./printfile filename

$ ltrace ./printfile /etc/leviathan_pass/leviathan3
__libc_start_main(0x804852b, 2, 0xffffd764, 0x8048610 <unfinished ...>
# access 检查调用它的实际用户（在这里是 leviathan2）是否能访问指定文件
access("/etc/leviathan_pass/leviathan3", 4)             = -1
puts("You cant have that file..."You cant have that file...
)                      = 27
+++ exited (status 1) +++
$ ltrace ./printfile /etc/leviathan_pass/leviathan2
__libc_start_main(0x804852b, 2, 0xffffd764, 0x8048610 <unfinished ...>
access("/etc/leviathan_pass/leviathan2", 4)             = 0
# 使用 snprintf 直接拼接输入的『文件路径』字符串
snprintf("/bin/cat /etc/leviathan_pass/lev"..., 511, "/bin/cat %s", "/etc/leviathan_pass/leviathan2") = 39
geteuid()                                               = 12002
geteuid()                                               = 12002
setreuid(12002, 12002)                                  = 0
# 因为设置了 Setuid，cat 只能查看 leviathan3 能查看的文件
system("/bin/cat /etc/leviathan_pass/lev"...ougahZi8Ta
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                  = 0
+++ exited (status 0) +++

$ mkdir /tmp/chicken

# 解法一：利用分号
$ touch "/tmp/chicken/tmp;sh"
$ ./printfile "/tmp/chicken/tmp;sh"
/bin/cat: /tmp/chicken/tmp: No such file or directory
$ cat /etc/leviathan_pass/leviathan3
Ahdiemoo1j

# 解法二：利用 cat 查看多个文件 + 符号链接
$ touch /tmp/chicken/fi
$ touch "/tmp/chicken/fi le"
$ ln -s /etc/leviathan_pass/leviathan3 /tmp/chicken/le
$ cd /tmp/chicken
# access 将 fi le 看成一个文件，cat 则看作两个文件
$ ~/printfile "fi le"
Ahdiemoo1j

$ cd
$ rm -r /tmp/chicken
```

### 参考资料

[access(2) — Linux manual page](https://man7.org/linux/man-pages/man2/access.2.html)

## Level 3

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>leviathan3</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>Ahdiemoo1j</td>
  </tr>
</tbody>
</table>

```bash
$ ssh leviathan3@leviathan.labs.overthewire.org -p 2223

$ ls -l
total 12
-r-sr-x--- 1 leviathan4 leviathan3 10288 Aug 26  2019 level3
$ ltrace ./level3
__libc_start_main(0x8048618, 1, 0xffffd784, 0x80486d0 <unfinished ...>
strcmp("h0no33", "kakaka")                              = -1
printf("Enter the password> ")                          = 20
fgets(Enter the password> 123
"123\n", 256, 0xf7fc55a0)                         = 0xffffd590
strcmp("123\n", "snlprintf\n")                          = -1
puts("bzzzzzzzzap. WRONG"bzzzzzzzzap. WRONG
)                              = 19
+++ exited (status 0) +++

$ ./level3
Enter the password> snlprintf
[You've got shell]!
$ cat /etc/leviathan_pass/leviathan4
vuH0coox6m
```

## Level 4

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>leviathan4</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>vuH0coox6m</td>
  </tr>
</tbody>
</table>

```bash
$ ssh leviathan4@leviathan.labs.overthewire.org -p 2223

$ ls -l
total 0
$ ls -la
total 24
drwxr-xr-x  3 root root       4096 Aug 26  2019 .
drwxr-xr-x 10 root root       4096 Aug 26  2019 ..
-rw-r--r--  1 root root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root root       3526 May 15  2017 .bashrc
-rw-r--r--  1 root root        675 May 15  2017 .profile
dr-xr-x---  2 root leviathan4 4096 Aug 26  2019 .trash
$ cd .trash/
$ ls -l
total 8
-r-sr-x--- 1 leviathan5 leviathan4 7352 Aug 26  2019 bin
$ ./bin
01010100 01101001 01110100 01101000 00110100 01100011 01101111 01101011 01100101 01101001 00001010
$ ./bin | perl -lape '$_=pack"(B8)*",@F'
Tith4cokei

# -a: autosplit mode with -n or -p (splits $_ into @F)
# The array @F contains the fields of each line read in when autosplit mode is turned on
```

### 参考资料

[bash - ASCII to Binary and Binary to ASCII conversion tools? - Unix & Linux Stack Exchange](https://unix.stackexchange.com/questions/98948/ascii-to-binary-and-binary-to-ascii-conversion-tools)

## Level 5

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>leviathan5</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>Tith4cokei</td>
  </tr>
</tbody>
</table>

```bash
$ ssh leviathan5@leviathan.labs.overthewire.org -p 2223

$ ls -l
total 8
-r-sr-x--- 1 leviathan6 leviathan5 7560 Aug 26  2019 leviathan5
$ ./leviathan5
Cannot find /tmp/file.log
$ ltrace ./leviathan5
__libc_start_main(0x80485db, 1, 0xffffd784, 0x80486a0 <unfinished ...>
fopen("/tmp/file.log", "r")                             = 0
puts("Cannot find /tmp/file.log"Cannot find /tmp/file.log
)                       = 26
exit(-1 <no return ...>
+++ exited (status 255) +++

$ ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log
$ ./leviathan5
UgaoFee4li
```

## Level 6

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>leviathan6</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>UgaoFee4li</td>
  </tr>
</tbody>
</table>

```bash
$ ssh leviathan6@leviathan.labs.overthewire.org -p 2223

$ ls -l
total 8
-r-sr-x--- 1 leviathan7 leviathan6 7452 Aug 26  2019 leviathan6
$ ./leviathan6
usage: ./leviathan6 <4 digit code>
# Nothing found...
$ ltrace ./leviathan6 1234
__libc_start_main(0x804853b, 2, 0xffffd774, 0x80485e0 <unfinished ...>
atoi(0xffffd8a9, 0, 0xf7e40890, 0x804862b)              = 1234
puts("Wrong"Wrong
)                                           = 6
+++ exited (status 0) +++

# 可以暴力破解
$ mkdir /tmp/chicken
$ cd /tmp/chicken
$ vi brute.sh
#!/usr/bin/env bash
for i in $(seq -w 0 9999)
do
  /home/leviathan6/leviathan6 "$i"
done

$ chmod +x brute.sh
$ ./brute.sh
# Wait for a while
$ whoami
leviathan7
$ cat /etc/leviathan_pass/leviathan7
ahy7MaeBo9

$ cd
$ rm -r /tmp/chicken
```

也可以使用`gdb`调试

```bash
$ gdb -q ./leviathan6
Reading symbols from ./leviathan6...(no debugging symbols found)...done.
(gdb) disas main  # 显示 main 函数的汇编
Dump of assembler code for function main:
   0x0804853b <+0>:     lea    0x4(%esp),%ecx
   0x0804853f <+4>:     and    $0xfffffff0,%esp
   0x08048542 <+7>:     pushl  -0x4(%ecx)
   0x08048545 <+10>:    push   %ebp
   0x08048546 <+11>:    mov    %esp,%ebp
   0x08048548 <+13>:    push   %ebx
   0x08048549 <+14>:    push   %ecx
   0x0804854a <+15>:    sub    $0x10,%esp
   0x0804854d <+18>:    mov    %ecx,%eax
   0x0804854f <+20>:    movl   $0x1bd3,-0xc(%ebp) # 这里将 0x1bd3(7123) 放入了 $ebp-0xc
   0x08048556 <+27>:    cmpl   $0x2,(%eax)
   0x08048559 <+30>:    je     0x804857b <main+64>
   ...
   0x08048587 <+76>:    call   0x8048420 <atoi@plt>
---Type <return> to continue, or q <return> to quit---
   0x0804858c <+81>:    add    $0x10,%esp
   0x0804858f <+84>:    cmp    -0xc(%ebp),%eax  # 这里出现了一个比较
   0x08048592 <+87>:    jne    0x80485bf <main+132>
   ...
   0x080485d7 <+156>:   pop    %ecx
   0x080485d8 <+157>:   pop    %ebx
   0x080485d9 <+158>:   pop    %ebp
   0x080485da <+159>:   lea    -0x4(%ecx),%esp
   0x080485dd <+162>:   ret
End of assembler dump.
# 除了下断点还可以直接观察汇编源码
(gdb) b *main+84  # 将断点下在 0x0804858f <+84>:    cmp    -0xc(%ebp),%eax
Breakpoint 1 at 0x804858f
(gdb) r 1234
Starting program: /home/leviathan6/leviathan6 1234

Breakpoint 1, 0x0804858f in main ()
(gdb) x /w $ebp-0xc # 查看内存单元
0xffffd68c:     7123
(gdb) c
Continuing.
Wrong
[Inferior 1 (process 26843) exited normally]
(gdb) q

$ ./leviathan6 7123
$ whoami
leviathan7
$ cat /etc/leviathan_pass/leviathan7
ahy7MaeBo9
```