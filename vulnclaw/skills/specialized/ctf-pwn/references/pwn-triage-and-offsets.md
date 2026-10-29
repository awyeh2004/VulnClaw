# Pwn 判定流程、偏移求解与常见坑

配套 `ctf-pwn` SKILL.md 使用。这里只放**能直接照做**的东西：命令、判据、失败时的下一步。

## 1. 开局三分钟

```bash
file ./chal                    # 架构 / 静态或动态
checksec --file=./chal         # 或者 pwntools: ELF('./chal').checksec()
readelf -h ./chal | grep Type  # EXEC(无 PIE) / DYN(有 PIE)
readelf -lW ./chal | grep GNU_STACK   # RW = NX 关，可执行栈
python3 -c "from pwn import *; e=ELF('./chal'); print(e.symbols.get('win'), e.got.get('puts'))"
```

无 `checksec` 时用 pwntools 的 `ELF().checksec()`，判据一样。

## 2. 偏移怎么求（不要手数）

```python
from pwn import *
io = process('./chal')
io.sendline(cyclic(200))            # 或用 cyclic(0x100)
io.wait()
core = io.corefile                  # 崩了就有 core
offset = cyclic_find(core.read(core.rsp, 8))
print('rip offset =', offset)
```

没有 core 时：二分或者用 `cyclic_find(0x6161616c)` 这类回显里的值反查。
**要点**：`read` 读满 N 字节才继续，`sendline` 多的那个 `\n` 会占位置，导致差 1 字节——
远端表现为"本地通、远程不通"的最常见原因。

## 3. 栈题的三条路

1. **ret2win**：有直接读 flag 的函数 → `b'A'*off + p64(win)`。
   若触发时 `movaps` 报错（Ubuntu 18.04+ 的栈对齐），中间垫一个 `ret` gadget。
2. **ret2libc**：泄漏 `puts`/`printf` 的 GOT → 算 libc 基址 → 第二次回到 `main` 再打 `system("/bin/sh")`。
   用 `libc_lookup` 工具按泄漏值低 12 位查版本，别套版本号。
3. **ret2csu / 无 pop rdi**：64 位程序里 `__libc_csu_init` 的 `pop rbx;pop rbp;pop r12..r15;ret` +
   间接调用，能凑出三个参数；或者找 `leave; ret` 做栈迁移（原栈不够放 rop 链时）。

## 4. 格式化字符串

```python
io.sendline(b'%p.%p.%p.%p.%p.%p.%p.%p')
```
先数到自己的缓冲区在参数第几位（amd64 前 6 个在寄存器，第 7 个起在栈上）。
写地址时注意 `%n` 一次写 4 字节，`%hn` 写 2 字节——大数值分两次 `%hn` 更快。
**坑**：payload 里不能出现 `\x00`（`printf` 截断），所以地址通常放在 payload 末尾而不是开头。

## 5. 堆题的最小流程

1. 先确认 glibc 版本（`strings libc.so.6 | grep 'GNU C Library'`，或泄漏 malloc 地址后反查）。
2. **tcache**（2.26+）：`free` 同一 size 两次 → 第二个 chunk 的 `fd` 可控 → 申请回来写任意地址。
   2.29+ 有 safe-linking：`fd = target ^ (chunk_addr >> 12)`，**必须先拿 heap 泄漏**。
3. **fastbin dup**：`free(A); free(B); free(A)` 绕过"连续 free 同一 chunk"检查，再申请出 A 两次。
4. **unsorted bin**：free 一个大于 tcache 上限的 chunk，`fd/bk` 指向 `main_arena` → 泄漏 libc。
5. 写哪里：`__free_hook` / `__malloc_hook`（2.34 前）、`exit_funcs`、或直接 GOT（部分 RELRO）。

## 6. seccomp / 静态链接

```bash
seccomp-tools dump ./chal      # 有工具时，确认哪些 syscall 允许
```
不能 `execve` → ORW：`open('/flag',0)` → `read(fd,buf,0x100)` → `write(1,buf,0x100)`，
需要 `pop rdi; pop rsi; pop rdx` 三个 gadget；没有 `pop rdx` 时用 `__libc_csu_init` 凑。

## 7. 常见"本地通、远程不通"

| 现象 | 原因 | 处置 |
|---|---|---|
| 差 1 字节错位 | `sendline` 的换行占了缓冲 | 用 `send(...)` 精确控制 |
| 段错误在 `do_system` | 栈未 16 字节对齐 | 链里垫一个 `ret` |
| 远程偏移全错 | 远程 libc 与本地不同 | 泄漏后反查 libc，不要用本地文件 |
| 交互超时 | 远程有短 alarm / 单连接 | 先把本地跑通，一次打准；`pwn_local_replay` 反复调 |
| 拿到 shell 但读不到 flag | 容器内 flag 路径不同 | `ls / ; ls /home/*`，或用 ORW 直接读已知路径 |
