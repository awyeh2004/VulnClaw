---
name: ctf-pwn
description: CTF 二进制利用知识库 — 判题型与保护面（PIE/NX/Canary/RELRO）→ 栈溢出与 ROP、格式化字符串、堆利用（tcache/fastbin/unsorted）、libc 版本定位、seccomp 下的 ORW、静态链接的 syscall 链；强调先本地复现再打远程
routing:
  target_types: [ctf]
  task_types: [ctf]
---

# CTF Pwn 二进制利用知识库

针对 CTF Pwn 题的实战知识库，给的是**判据与顺序**，不是 payload 大全——具体 payload 先用
`lookup_playbook` 查本库沉淀的同类配方（栈/ROP 有 60+ 篇）。

## 先判四件事，再写一个字节的 payload

1. **保护面**：`checksec` — PIE / NX / Canary / RELRO / FORTIFY。这四项直接决定哪条路可行：
   - 无 PIE → 可以直接用程序内地址（`.bss`、GOT、`pop rdi` gadget）；
   - 有 PIE 无泄漏 → 只能打部分覆写（只改低 2 字节）或先拿泄漏；
   - 有 Canary 无泄漏 → 先找格式化字符串 / 越界读 / `__stack_chk_fail` 绕过路径，别硬堆溢出；
   - 部分/全 RELRO → 决定能不能写 GOT。
2. **架构与链接方式**：`file` — amd64/i386/arm/mips，静态还是动态。静态链接没有 libc 可用，
   走纯 syscall ROP（`execve` / `open-read-write`）；动态的要定 libc 版本。
3. **libc 版本**：有泄漏（`puts`/`printf` 打 GOT）→ 用 `libc_lookup` 工具或 libc-database 按低 12 位匹配；
   题目给了 libc 文件就直接用。**不要凭感觉套 Ubuntu 版本号**，差一个 build 就偏移全错。
4. **输入面**：`scanf`/`read`/`gets` 的长度和缓冲区位置，`strlen`/`strcpy` 的截断行为。
   `read(0, buf, N)` 里 N 与 `buf` 大小的差就是溢出长度。

## 分型处置

| 观察到的形状 | 走法 |
|---|---|
| 无 Canary 的栈上 `read`/`gets` | `cyclic` 定偏移 → ret2win / ret2libc / ret2csu（无 `pop rdi` 时） |
| `printf(user_input)` | 格式化字符串：先 `%p` 定位自己的栈偏移，再 `%n` 写 GOT 或返回地址 |
| 有 Canary 的栈溢出 | 先找泄漏（越界读 / 未初始化 / 格式化字符串），拿到 canary 再溢出 |
| 有 `malloc/free` 且体积可控 | 堆：tcache poisoning（2.29+ 要 heap leak，safe-linking 会异或）、fastbin dup、unsorted bin 泄漏 libc |
| 开了 seccomp | 不能 `execve`，改 ORW：`open("/flag")` → `read` → `write(1,…)` |
| 静态链接 | 自己拼 syscall gadget，别找 libc |
| 一次只能改一两个字节 | 部分覆写返回地址低字节（ASLR 页对齐 → 12 位不变）；必要时爆破 |

## 纪律：本地先跑通，再打远程

远程服务通常是单连接 + 短 alarm，盲试会烧掉机会。用 `pwn_local_replay` 对本地二进制反复调，
跑通再发远程；打完 `pwn_local_stop` 释放容器（`solver` 里有 pwn-local-first 提醒，是刻意的）。

调试要点：向程序要回显（`print` 泄漏值、`/proc/self/maps`、`elf.symbols`），不要靠猜偏移；
`pwntools` 的 `cyclic`/`cyclic_find` 求偏移比手数可靠。

## 与其它 skill 的边界

- `ctf-reverse`/`client-reverse` → 目标是"看懂算法并逆出输入"，不涉及内存破坏；
- 本 skill → 目标是"控制执行流"，需要二进制、保护面、libc 三个坐标。

## 参考

- `references/pwn-triage-and-offsets.md` — 判定流程、偏移求解、常见坑（含 pwntools 片段）
- 本库 playbook：`lookup_playbook` 搜「栈溢出 ROP canary libc」「格式化字符串」「tcache」等
