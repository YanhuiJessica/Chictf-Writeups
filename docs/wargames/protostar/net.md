---
title: Exploit Education：Protostar - Net
---

> The levels to be exploited can be found in the /opt/protostar/bin directory.

## Net 0

> converting strings to little endian integers

```c
#include "../common/common.c"

#define NAME "net0"
#define UID 999
#define GID 999
#define PORT 2999

void run()
{
  unsigned int i;
  unsigned int wanted;

  wanted = random();

  printf("Please send '%d' as a little endian 32bit int\n", wanted);

  if(fread(&i, sizeof(i), 1, stdin) == NULL) {  // fread from stdin
      errx(1, ":(\n");
  }

  if(i == wanted) {
      printf("Thank you sir/madam\n");
  } else {
      printf("I'm sorry, you sent %d instead\n", i);
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID);   // deamonizes by cloning itself and killing the parent
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT); // listen on port 2999 for TCP connections

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  /* Don't do this :> */
  srandom(time(NULL));

  run();
}
```

- 在开始做之前，注意到 `net0` 已在运行中

    ```bash
    $ ps aux | grep net0
    999       1503  0.0  0.0   1532   272 ?        Ss   Sep02   0:00 /opt/protostar/bin/net0
    user     17387  0.0  0.0   3272   644 pts/0    S+   01:16   0:00 grep net0
    ```

- 可以切换到 `root` 以便重新启动 `net0`，用户名密码 `root:godmode`
- 杀掉原先的 `net0` 进程，通过 `strace` 启动，注意到最后调用了函数 `clone()`

    ```bash
    # kill 1503
    # strace ./net0
    execve("./net0", ["./net0"], [/* 24 vars */]) = 0
    brk(0)                                  = 0x804b000
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7fe0000
    access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
    open("/etc/ld.so.cache", O_RDONLY)      = 3
    fstat64(3, {st_mode=S_IFREG|0644, st_size=13796, ...}) = 0
    mmap2(NULL, 13796, PROT_READ, MAP_PRIVATE, 3, 0) = 0xb7fdc000
    close(3)                                = 0
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libc.so.6", O_RDONLY)        = 3
    read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\320m\1\0004\0\0\0"..., 512) = 512
    fstat64(3, {st_mode=S_IFREG|0755, st_size=1319176, ...}) = 0
    mmap2(NULL, 1329480, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xb7e97000
    mprotect(0xb7fd5000, 4096, PROT_NONE)   = 0
    mmap2(0xb7fd6000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x13e) = 0xb7fd6000
    mmap2(0xb7fd9000, 10568, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xb7fd9000
    close(3)                                = 0
    mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7e96000
    set_thread_area({entry_number:-1 -> 6, base_addr:0xb7e966c0, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0
    mprotect(0xb7fd6000, 8192, PROT_READ)   = 0
    mprotect(0xb7ffe000, 4096, PROT_READ)   = 0
    munmap(0xb7fdc000, 13796)               = 0
    rt_sigaction(SIGCHLD, {0x8048dc4, [CHLD], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
    rt_sigaction(SIGPIPE, {SIG_IGN, [PIPE], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
    open("/opt/protostar/run/net0.pid", O_RDWR|O_CREAT|O_TRUNC, 0700) = 3
    setgroups32(1, [999])                   = 0
    setresgid32(999, 999, 999)              = 0
    setresuid32(999, 999, 999)              = 0
    clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xb7e96728) = 17420
    # clone() 将创建一个新的进程，是自身的克隆
    # 返回值 17420 为新进程的 PID
    exit_group(0)                           = ?
    # 父进程退出，留下子进程 net0
    ```

- 通过 `-f` 来跟踪子进程，因为没有杀掉刚创建的进程，所以提示 `Address already in use`

    ```bash
    # -f -- follow forks
    # strace -f ./net0
    execve("./net0", ["./net0"], [/* 24 vars */]) = 0
    brk(0)                                  = 0x804b000
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7fe0000
    access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
    open("/etc/ld.so.cache", O_RDONLY)      = 3
    fstat64(3, {st_mode=S_IFREG|0644, st_size=13796, ...}) = 0
    mmap2(NULL, 13796, PROT_READ, MAP_PRIVATE, 3, 0) = 0xb7fdc000
    close(3)                                = 0
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libc.so.6", O_RDONLY)        = 3
    read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\320m\1\0004\0\0\0"..., 512) = 512
    fstat64(3, {st_mode=S_IFREG|0755, st_size=1319176, ...}) = 0
    mmap2(NULL, 1329480, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xb7e97000
    mprotect(0xb7fd5000, 4096, PROT_NONE)   = 0
    mmap2(0xb7fd6000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x13e) = 0xb7fd6000
    mmap2(0xb7fd9000, 10568, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xb7fd9000
    close(3)                                = 0
    mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7e96000
    set_thread_area({entry_number:-1 -> 6, base_addr:0xb7e966c0, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0
    mprotect(0xb7fd6000, 8192, PROT_READ)   = 0
    mprotect(0xb7ffe000, 4096, PROT_READ)   = 0
    munmap(0xb7fdc000, 13796)               = 0
    rt_sigaction(SIGCHLD, {0x8048dc4, [CHLD], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
    rt_sigaction(SIGPIPE, {SIG_IGN, [PIPE], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
    open("/opt/protostar/run/net0.pid", O_RDWR|O_CREAT|O_TRUNC, 0700) = 3   # 3 for filedescriptor
    setgroups32(1, [999])                   = 0
    setresgid32(999, 999, 999)              = 0
    setresuid32(999, 999, 999)              = 0
    clone(Process 17423 attached
    child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xb7e96728) = 17423
    [pid 17422] exit_group(0)               = ? # parent exit
    setsid()                                = 17423 # attached to the new process
    chdir("/")                              = 0
    open("/dev/null", O_RDWR)               = 4
    fstat64(4, {st_mode=S_IFCHR|0666, st_rdev=makedev(1, 3), ...}) = 0
    dup2(4, 0)                              = 0 # stdin
    dup2(4, 1)                              = 1 # stdout
    dup2(4, 2)                              = 2 # stderr
    # bend all standard streams to /dev/null
    close(4)                                = 0
    write(3, "17423\n", 6)                  = 6 # write child's process id to net0.pid
    close(3)                                = 0
    socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
    setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
    bind(3, {sa_family=AF_INET, sin_port=htons(2999), sin_addr=inet_addr("0.0.0.0")}, 16) = -1 EADDRINUSE (Address already in use)
    # bind this process to port 2999
    write(2, "serve_forever: unable to bind():"..., 56) = 56
    exit_group(6)                           = ?
    Process 17423 detached
    ```

- 重新启动 `net0` 并跟踪

    ```bash
    # killall net0
    # strace -f ./net0
    execve("./net0", ["./net0"], [/* 24 vars */]) = 0
    ...
    socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
    setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
    bind(3, {sa_family=AF_INET, sin_port=htons(2999), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
    listen(3, 10)                           = 0 # listen on the port
    accept(3,   # waiting for a packet to arrive
    ```

- 另起一个终端，通过 `netstat` 查找监听进程

    ```bash
    # netstat -plant
    # -p, --programs - display PID/Program name for sockets
    # -l, --listening - display listening server sockets
    # -a, --all, --listening - display all sockets (default: connected)
    # -n, --numeric - don't resolve names
    # <Socket>={-t|--tcp}
    Active Internet connections (servers and established)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    ...       
    tcp        0      0 0.0.0.0:2998            0.0.0.0:*               LISTEN      1507/net1       
    tcp        0      0 0.0.0.0:2999            0.0.0.0:*               LISTEN      17964/net0      
    tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      1479/exim4      
    ...
    ```

- `nc` 建立连接后，函数 `accept` 返回

    ```bash
    accept(3, {sa_family=AF_INET, sin_port=htons(36218), sin_addr=inet_addr("127.0.0.1")}, [16]) = 4
    clone(Process 18005 attached    # 再次调用 clone，从而能支持多用户并发
    child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xb7e96728) = 18005
    [pid 17964] close(4)                    = 0
    [pid 17964] accept(3,  <unfinished ...>
    [pid 18005] close(3)                    = 0
    [pid 18005] dup2(4, 0)                  = 0
    [pid 18005] dup2(4, 1)                  = 1
    [pid 18005] dup2(4, 2)                  = 2
    [pid 18005] time(NULL)                  = 1662378390
    [pid 18005] write(1, "Please send '1923281790' as a li"..., 54) = 54    # printf
    [pid 18005] read(0, 
    ```

- 存在不可打印字符，需要借助于 `echo` 或 `python`，但由于数字随机生成，不能直接硬编码，可以借助于 `cat`

### Exploit

```bash
$ echo -e "`cat | python -c "import struct; print(struct.pack('I', int(input())))"`" | nc localhost 2999
Please send '2035797908' as a little endian 32bit int
2035797908  # Enter + Ctrl_D, which will closes cat and echo
Thank you sir/madam
```

## Net 1

> convert binary integers into ascii representation

```c
#include "../common/common.c"

#define NAME "net1"
#define UID 998
#define GID 998
#define PORT 2998

void run()
{
  char buf[12];
  char fub[12];
  char *q;

  unsigned int wanted;

  wanted = random();

  sprintf(fub, "%d", wanted);

  // the binary string is sent
  if(write(0, &wanted, sizeof(wanted)) != sizeof(wanted)) {
      errx(1, ":(\n");
  }

  if(fgets(buf, sizeof(buf)-1, stdin) == NULL) {
      errx(1, ":(\n");
  }

  // strchr - locate character in string
  q = strchr(buf, '\r'); if(q) *q = 0;
  q = strchr(buf, '\n'); if(q) *q = 0;

  if(strcmp(fub, buf) == 0) {
      printf("you correctly sent the data\n");
  } else {
      printf("you didn't send the data properly\n");
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  /* Don't do this :> */
  srandom(time(NULL));
  // If we send fast enough, the seconds will be the same
  // thus produce the same pseudo random number

  run();
}
```

### Exploit

```py
import socket, struct

# 可以与 strace nc -l <port> 对比
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 2998))
wanted = s.recv(4)    # 4 bytes
num_wanted = str(struct.unpack('I', wanted)[0])
s.sendall(num_wanted)
print 'Receive: ' + wanted
print 'Send: ' + num_wanted
print s.recv(1024)
```

```bash
$ python /tmp/net.py 
Receive: ��W
Send: 1473381877
you correctly sent the data
```

### References

- [socket - Example](https://docs.python.org/3/library/socket.html#example)

## Net 2

> add up 4 unsigned 32-bit integers

```c
#include "../common/common.c"

#define NAME "net2"
#define UID 997
#define GID 997
#define PORT 2997

void run()
{
  unsigned int quad[4];
  int i;
  unsigned int result, wanted;

  result = 0;
  for(i = 0; i < 4; i++) {
      quad[i] = random();
      result += quad[i];    // 可能有溢出

      if(write(0, &(quad[i]), sizeof(result)) != sizeof(result)) {
          errx(1, ":(\n");
      }
  }

  if(read(0, &wanted, sizeof(result)) != sizeof(result)) {
      errx(1, ":<\n");
  }


  if(result == wanted) {
      printf("you added them correctly\n");
  } else {
      printf("sorry, try again. invalid\n");
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  /* Don't do this :> */
  srandom(time(NULL));

  run();
}
```

### Exploit

```py
import socket, struct

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 2997))
result = ''
for i in range(4):
    result += s.recv(4)
nums = struct.unpack('IIII', result)
sm = 0
for num in nums:
    sm += num
ans = struct.pack('I', sm & 0xffffffff)
s.sendall(ans)
print 'Receive: ' + result
print 'Send: ' + ans
print s.recv(1024)
```

```bash
$ python /tmp/net.py 
Receive: ��iv�c��>
z�P
Send: ���
you added them correctly
```