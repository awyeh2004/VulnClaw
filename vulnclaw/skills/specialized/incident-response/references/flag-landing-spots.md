# 活体找 flag 落点清单（经跳板机远程排查）

> 适用：**赛题要求"在被入侵服务器上找隐藏的 flag"**（2026-10-08 赛方材料原文：
> "选手需通过跳板机访问被入侵服务器，利用工具与思路寻找隐藏的 flag"）。
> 这是**解题交付**路径，不是"写一份处置报告"——目标是把 `flag{...}` 抓到手并带证据。
>
> 与其它参考文档的关系：`10`~`60` 各篇解决"**入侵痕迹在哪、是什么**"，
> 本篇解决"**出题人把 flag 放哪了、怎么最快捞出来**"。两者共用同一套痕迹知识，
> 但检索策略不同：痕迹按**面**扫，flag 按**内容 + 时间 + 进程**扫。

## 〇、先做三件事（顺序不能反）

1. **读题面提示**：给的线索（现象、路径片段、账号、时间）优先于任何全盘扫描。
2. **确认 flag 格式**：`flag{...}` / `DASCTF{...}` / 自定义前缀，**以题面为准**。
   格式决定了搜索关键字——搜错前缀等于没搜。
3. **`id` + `hostname` + `pwd`**：经跳板机进来的 shell 未必是 root；
   权限拿不到时**明说拿不到**，不要脑补内容。

> 纪律：**只读优先**。要改状态（删文件/停进程）前先留证（hash、进程内存、原始日志）。
> 每条命令的输出都可能成为证据——别用管道把原文吃掉（`| tail` 会截断）。

## 一、五步作业顺序（从最省时间到最费时间）

| 步 | 动作 | 命令骨架 | 为什么排这个位置 |
|---|---|---|---|
| 1 | **按内容全盘搜前缀** | `grep -a -rIl --exclude-dir={proc,sys,dev} "flag{" / 2>/dev/null` | 出题人最常直接把 flag 写进文件；一遍就能覆盖 80% 的静态落点 |
| 2 | **按时间圈定** | `find / -xdev -type f -newermt '2026-10-01' 2>/dev/null \| head -200` | flag 文件的 mtime 往往集中在镜像制作/赛前，时间比路径更可靠 |
| 3 | **进程 / 环境 / 历史** | `ps auxww`、`cat /proc/*/environ`（去重）、`history`、`cat ~/.bash_history` | flag 常是**命令行参数**或环境变量，静态搜文件搜不到 |
| 4 | **服务侧** | cron、systemd、Web 根目录、数据库、日志 | "数据即 flag"（落库型）与"服务配置即 flag"（ExecStart/Arguments）很常见 |
| 5 | **变形解码** | base64 / hex / rot13 / 反转 / UTF-16LE | 找到的是"像 flag 但不是"的东西时用，**不要一上来就解码** |

> ⚠️ 第 1 步是**全盘 grep**：一定要
> ①排除 `/proc` `/sys` `/dev`；②给足超时（慢盘 + 大目录会跑很久）；
> ③先 `-l` 只列文件名，再对命中文件看内容——否则输出会把上下文冲爆。

## 二、Linux 静态落点（按命中概率排序）

| 落点 | 为什么在这 | 命令 |
|---|---|---|
| `/tmp` `/var/tmp` `/dev/shm` `/run` | 易写、重启即清，出题人最爱 | `ls -alh /tmp /dev/shm; find /tmp /dev/shm -type f -newermt '-7 days'` |
| **`.` 开头的隐藏文件/目录** | `ls -l` 看不见 | `ls -al / /root /home/*; find / -xdev -name '.*' -type f 2>/dev/null` |
| **shell 历史** | 被执行的命令里可能直接带 flag | `cat ~/.bash_history; find / -xdev -name '*history*' -o -name '.viminfo' 2>/dev/null` |
| **cron** | 定时任务的命令行里常藏 flag | `crontab -l; ls -al /etc/cron*; cat /var/spool/cron/crontabs/* 2>/dev/null` |
| **systemd unit / timer** | `ExecStart` / `Environment=` 里藏 | `grep -rn "" /etc/systemd/system/*.service 2>/dev/null \| grep -i -E 'flag\|exec\|environ'` |
| **环境变量** | 进程环境比文件更隐蔽 | `cat /proc/*/environ 2>/dev/null \| tr '\0' '\n' \| sort -u; grep -rn "flag" /etc/environment /etc/profile.d/ ~/.bashrc 2>/dev/null` |
| **Web 根目录** | webshell 内容、上传目录、图片马、备份包 | `grep -a -rn "flag" /var/www /usr/share/nginx /opt 2>/dev/null; find / -xdev \( -name '*.bak' -o -name '*.zip' -o -name '*.sql' -o -name '*.tar*' \) 2>/dev/null` |
| **数据库** | 落库型后门 / 直接把 flag 存表里 | `mysql -uroot -p -e 'show databases;'` → 逐库 `select` 可疑表；`redis-cli keys '*'`、`get <key>` |
| **日志** | 请求里带 flag、或攻击者操作留痕 | `grep -a -rn "flag" /var/log 2>/dev/null`（含 `access.log`/`auth.log`/`syslog`/`*.log.1`） |
| **伪装成系统文件** | 与系统同名但路径不对、mtime 新 | `ls -al /usr/bin /usr/local/bin \| head -50`；按时间圈定；`find / -perm -4000 -type f 2>/dev/null`（SUID） |
| **邮件 / 队列 / 缓存** | 少见但存在 | `/var/mail/*`、`/var/spool/*`、`/var/cache/*` |
| **容器层** | 题目跑在容器里 | `docker ps -a; docker history <img>`；`/var/lib/docker/overlay2/*/diff/...` |
| **已删除但仍被持有** | 攻击者/出题人删了文件、进程还开着 | `ls -l /proc/*/exe \| grep deleted` → `cp /proc/<PID>/exe /tmp/x`；`lsof +L1` |
| **磁盘未分配 / 块设备** | 进阶：文件删了内容还在 | `strings /dev/<root-dev> \| grep -a 'flag{'`（**只读**，别写盘） |
| **swap / 内存** | 进程内存里的明文 | `strings /swap.img \| grep -a 'flag{'`；见第三节 |

## 三、进程 / 内存落点（静态搜完再来）

```bash
ps auxww                                   # ⭐ 完整命令行，flag 常是参数
ls -l /proc/*/exe | grep '(deleted)'        # 自删除二进制 = 高价值
cat /proc/<PID>/cmdline | tr '\0' ' '; echo
cat /proc/<PID>/environ | tr '\0' '\n'      # 环境变量
grep -a 'flag{' /proc/<PID>/maps 2>/dev/null
lsof -p <PID> | head -40                    # 打开的文件/套接字
```

- **内存字符串**（有权限时）：`gcore <PID>` 或 `dd if=/proc/<PID>/mem`（多半受限）；
  拿到 dump 后 `strings -a dump | grep -a 'flag{'`。
- **镜像/流量**：走 `50-memory-traffic.md`（volatility3 插件 `linux.pslist` / `malfind`；
  Windows 用 `windows.pslist` / `windows.malfind` / `windows.cmdline`），或 tshark 搜包内容
  （`tshark -r x.pcap -Y 'frame contains "flag{"'`）。

## 四、Windows 落点（对照速查）

| 落点 | 命令 |
|---|---|
| Temp / AppData / ProgramData | `dir /a /s %TEMP%`、`dir /a /s %APPDATA%` |
| 隐藏文件 / 系统属性 | `dir /a /s`；`.\\` 隐藏+系统 |
| **ADS 交换数据流** | `dir /r` → 看到 `file:stream` 后 `more < file:stream` |
| 注册表 | `reg query HKLM\\Software /s /f flag`、Run 键、Uninstall 键 |
| 计划任务 | `schtasks /query /fo LIST /v`（看 **Task To Run** 参数） |
| WMI 事件订阅 | `Get-WmiObject -Namespace root\\subscription -Class __EventFilter` |
| IIS 站点目录 / 日志 | `%SystemDrive%\\inetpub\\wwwroot`、`C:\\Windows\\System32\\LogFiles` |
| 回收站 / pagefile | `$Recycle.Bin`、`pagefile.sys`（`strings` 搜） |
| 事件日志内容 | `wevtutil qe Security /f:text /rd:true /c:50` |

## 五、变形与编码（找到"像但不像"时）

| 形态 | 判据 | 还原 |
|---|---|---|
| base64 | `ZmxhZ3s` / `R0lG` 之类前缀 | `echo '<s>' \| base64 -d` |
| hex | 全是 `[0-9a-f]` 偶数长度 | `xxd -r -p` |
| rot13 | 字母整体位移 | `tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
| 反转 | 尾部是 `}` 反转成头部 | `rev` |
| UTF-16LE（Windows） | 字节间夹 `\x00` | `iconv -f UTF-16LE -t UTF-8` |
| JS/转义 | 源码里 `\\x66\\x6c\\x61\\x67` | 交给 `crypto_decode` 工具或本地 python |
| 双编码 | `%25` / `%2520` 层层套 | 迭代解码直到稳定（**最多 3 层**，见 `enforce_host_path_constraints` 的同款教训） |

> `crypto_decode` 工具就是为这一步准备的；**别名还原后仍要在输出里逐字符看到 flag**
> 才算证据（见 `state`/evidence 的取证纪律）。

## 六、常见坑（实测与教材都踩过）

1. **搜错前缀**：题面写 `flag{`，你却搜 `FLAG{`（`grep` 默认区分大小写）→ 加 `-i`。
2. **二进制文件被跳过**：`grep` 对二进制只回 "Binary file matches" → 用 **`grep -a`**。
3. **全盘 grep 卡死**：不排除 `/proc` `/sys` `/dev`、不给超时 → 现场浪费几分钟。
4. **`grep -r` 跟随符号链接**成环（`/proc` 自引用）→ 用 `-r` 且排除，或 `find -xdev`。
5. **改了现场**：为了看内容 `>` 覆盖、`touch` 改时间 → 破坏证据；一律只读。
6. **路径脑补**：URL 路径 ≠ 文件系统路径（见 `SKILL.md` 的路径证据纪律）。
7. **权限幻觉**：不是 root 时读不到的目录就说读不到，别把"没搜到"写成"不存在"。
8. **flag 在另一台机器上**：经跳板机时容易只盯一台；题目可能是多台（`remote_hosts` 逐个看）。

## 七、拿不到 flag 时的收尾（体面退出）

- 交付**已经排除的落点清单** + **每条命令的原始输出**（证据 id），而不是空手说"没找到"。
- 说明**权限边界**（哪些目录没权限）与**时间边界**（日志保留期）。
- 留下**下一步最小验证动作**（例如"若给 root，`strings /dev/sda1 | grep -a flag{` 是下一步"）。
