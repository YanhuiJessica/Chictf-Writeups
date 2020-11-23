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

```bash
$ ssh leviathan1@leviathan.labs.overthewire.org -p 2223

$ ls -l
total 8
-r-sr-x--- 1 leviathan2 leviathan1 7452 Aug 26  2019 check

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