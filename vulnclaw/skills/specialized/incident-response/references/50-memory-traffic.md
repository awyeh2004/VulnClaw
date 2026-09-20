# 内存取证 / 流量分析

> **这篇的每个命令和输出都在本机实测过**（volatility3 2.28.2、tshark 3.2.1、dpkt 1.9.8）。
> 标 `[知识]` 的是没法在本机验证的（要靠真实镜像 / 现场环境），标 `[实测]` 的可以直接抄。
>
> 最后验证：2026-09-20。

---

## 〇、先做判断：这两个能力**什么时候用得上**

⚠️ **这是最容易白忙的地方。** 内存取证和流量分析门槛高、耗时长，
**只有当磁盘上没有痕迹时才值得做**。

| 场景 | 该做什么 | 为什么 |
|---|---|---|
| 磁盘上有日志、有落地文件、有 crontab | **别做内存取证** | `ps`/`ls`/`crontab`/日志 20 分钟能出结论 |
| 进程已退出、文件已自删除、日志被清 | ⭐ **内存取证** | 只剩内存里可能还有残留 |
| 隐藏进程 / 内核态 Rootkit | ⭐ **内存取证** | 用户态工具会被 rootkit 骗过 |
| 不知道攻击者怎么进来的、走了什么协议 | ⭐ **流量分析** | 日志只记结果，流量记全过程 |
| 要确认有没有数据外传、外传了什么 | ⭐ **流量分析** | 日志通常不记响应体 |
| 内存马（无文件 webshell） | ⭐ **两者都要** | 内存里有类、流量里有特征 |

### ⚠️ 现实中最大的约束：**符号表和网络**

`[实测]` volatility3 **真正分析镜像时需要 OS 符号表**：

- **Windows**：从微软符号服务器（`msdl.microsoft.com`）下载
- **Linux**：`[知识]` 需要**自己生成 ISF** —— volatility3 不提供 Linux 符号下载。
  要用 `dwarf2json` 把目标内核（须带 DWARF 调试信息）转成 ISF

**`[实测]` 网络可达性（2026-09-20，决定要不要翻墙）**：

| 目标 | 结果 |
|---|---|
| `http://msdl.microsoft.com`（Windows 符号） | ✅ **HTTP 200 可达** |
| `ddebs.ubuntu.com` / `debug.mirrors.debian.org`（Linux dbgsym） | ✅ HTTP 200 |
| `goproxy.cn`（dwarf2json 国内路径，有 v0.8.0/v0.9.0） | ✅ 可达 |
| `github.com` / `raw.githubusercontent.com` | ❌ **超时** |
| `proxy.golang.org` | ❌ 超时 |

⭐ **结论：微软符号服务器与发行版镜像都是 `http` 且国内直连可达 —— 不需要翻墙。**
⚠️ 但 **GitHub 不可靠**，别把"从 GitHub 下工具"写进现场流程。

**本机现状（重要）**：

| 项 | 状态 |
|---|---|
| vol 能分析 Linux 镜像吗 | ❌ **不能**——没有 `dwarf2json`（且未装 Go），也没有任何 ISF |
| vol 能分析 Windows 镜像吗 | ✅ 代码就绪 + 符号服务器可达（首次分析时联网下符号） |
| 有没有预置符号缓存 | ❌ `.ir-tools/_volcache` 里只有 NVIDIA shader 缓存，**没有任何符号表** |

> ⭐ **赛前值得问赛方**：*"内存取证题给的是镜像文件还是需要自己抓？镜像是什么系统？"*
> 如果给的是 **Windows 镜像** → 现在就能做，符号服务器可达。
> 如果是 **Linux 镜像** → 需要目标内核版本的 ISF，要提前准备（见 2.5），
> 或者退回到第四节 `/proc` 实时取证。

---

## 一、内存取证：采集

### 1.1 ⭐ 最高性价比：直接从 `/proc` 捞（不需要镜像、不需要符号表）

**活着的 Linux 系统上，这比做内存镜像快 100 倍。** 攻击者二进制自删除后，
`/proc/<PID>/exe` 仍指向已被删除的 inode —— 这是最常捞到样本的地方。

```bash
# 找到可疑 PID 后（进程还在）
PID=1337
cp /proc/$PID/exe /tmp/evidence/pid$PID.exe     # ⭐ 自删除的二进制在这里
cat /proc/$PID/maps                              # 内存映射，看加载了哪些 .so / 匿名段
ls -l /proc/$PID/cwd /proc/$PID/root             # 进程的工作目录与根
tr '\0' '\n' < /proc/$PID/environ                # 环境变量（常藏 C2 地址）
ls -l /proc/$PID/fd/ | head -30                  # 打开的文件/套接字（看连接）
cat /proc/$PID/cmdline | tr '\0' ' '; echo       # 完整命令行
ls -l /proc/$PID/exe                             # 带 " (deleted)" 就是自删除
```

> ⭐ `ls -l /proc/<PID>/exe` 显示 `... (deleted)` = **二进制已被删除但仍在运行**，
> 必须立刻 `cp` 出来，进程一死就没了。

### 1.2 `[知识]` 完整内存镜像采集

| 系统 | 工具 | 备注 |
|---|---|---|
| Linux | `avml`（微软，静态单文件）/ LiME | AVML 不需要装内核模块，推荐 |
| Windows | `winpmem` / DumpIt / Magnet RAM Capture | 现场直接跑 exe |
| VMware 虚拟机 | **挂起**后直接拷 `.vmem` / `.vmsn` | 最干净——VM 挂起时内存未变 |
| VirtualBox | `.sav` 文件（挂起后） | 同上 |
| Hyper-V | `.bin`（检查点） | 同上 |

> ⭐ **虚拟机靶机是最省事的场景**：`挂起` → 直接拷 `.vmem`，
> 不需要在靶机里跑任何采集工具（也就不会污染内存）。

⚠️ **内存采集会污染内存**（工具本身要加载）。顺序上：**先照相，再动手**。

---

## 二、volatility3 用法

### 2.1 启动方式

```powershell
. .ir-tools\env.ps1          # 让 vol 进 PATH
vol --help                   # 应输出 Volatility 3 Framework 2.28.2
```

或直接：`.ir-tools\bin\vol.cmd <参数>`

### 2.2 ⚠️ 一个已经踩过并修好的大坑：Anaconda 的 pyOpenSSL

`[实测]`**修复前**：`vol --help` 完全正常，但**任何真实插件都崩**：

```
AttributeError: module 'lib' has no attribute 'GEN_EMAIL'
```

原因不是 volatility3，而是本机 `python` 是 **Anaconda**（`D:\anacond_1`）：
它的 win32com `lib` 与已装的 `cryptography 50.0.0` 不兼容，导入 `pyOpenSSL` 必炸。
volatility3 自己**不 import requests**，但全量解释器下任何传递依赖都可能走到
`urllib3 → pyopenssl`，而崩溃发生在命令行的 `--help` **之后** ——
所以自检脚本只测 `--help` 时**完全看不出来**。

**修法**（已做进 `.ir-tools/bin/_vol_entry.py`）：脚本自动 `re-exec` 到 `python -S`
（禁用 site-packages），只让工具箱自带的 `pylib/` 可导入 ——
`pefile.py`、`peutils.py`、`ordlookup/`、`colorama/`、`yara` 都在里面，依赖齐全。

> ⚠️ 写这个守卫时踩过一个坑：**`import site` 在 `-S` 下仍然成功**
> （只是不自动调用 `site.main()`），所以不能用它当"已隔离"的判据，
> 否则会**无限自我 exec**。正确判据是 `sys.flags.no_site`。

### 2.3 `[实测]` 验证可用性：`banners`

`banners` 是**唯一不需要 OS 符号表**的实用插件，所以它是"vol 到底活没活"的判据：

```powershell
vol -f <镜像或PE> banners
```

`[实测]` 对 `C:\Windows\System32\ntoskrnl.exe` 的输出（3.3 秒）：

```
Volatility 3 Framework 2.28.2
Offset	Banner
0x4d8e0	ntkrnlmp.pdb|9A3533F8CCC878F8F791BADD952A6EC8|1
```

⭐ 这行的价值：**`ntkrnlmp.pdb` + GUID 就是符号表请求键**。
把它记下来，就能判断该下哪个符号、也能解释"为什么符号下载失败"。

`[实测]` 对非内存镜像跑需要符号的插件会被正确拒绝（不是崩溃，是明确报错）：

```
vol -f ntoskrnl.exe windows.info
→ Unable to validate the plugin requirements:
  ['plugins.Info.kernel.layer_name', 'plugins.Info.kernel.symbol_table_name']
```

看到这个报错 = **vol 本身是好的**，只是缺符号表或文件不是内存镜像。别误判成工具坏了。

### 2.4 `[知识]` 常用插件

**Windows**

| 插件 | 用途 |
|---|---|
| `windows.info` | ⭐ 先跑这个：版本、时间、CPU、`IsF` 关键信息 |
| `windows.pslist` | 进程列表（类似 `tasklist`） |
| `windows.psscan` | ⭐ **扫内存里的进程池**——能发现 `pslist` 看不到的已退出/隐藏进程 |
| `windows.pstree` | 进程树（看父子关系，找异常的 services.exe 子进程） |
| `windows.netscan` | ⭐ 网络连接（含已关闭的） |
| `windows.malfind` | ⭐⭐ **找注入代码**——无文件恶意代码的主战场 |
| `windows.cmdline` | 命令行参数 |
| `windows.dlllist` | 进程加载的 DLL（找异常路径的 DLL） |
| `windows.handles` | 句柄（找被删文件的句柄，类似 Linux `/proc/PID/fd`） |
| `windows.registry.userassist` | 用户执行痕迹（补磁盘上可能被删的） |
| `windows.svcscan` | 服务（找恶意服务） |
| `windows.vadyarascan` | ⭐ 内存 YARA 扫描（工具箱已带 yara） |

**Linux**

| 插件 | 用途 |
|---|---|
| `linux.pslist` / `linux.pstree` | 进程 / 进程树 |
| `linux.bash` | ⭐ 从内存恢复 bash 历史（磁盘上的 `.bash_history` 可能被删/被改） |
| `linux.check_creds` | 凭据异常 |
| `linux.check_modules` | ⭐ 内核模块（对比磁盘上的 `lsmod`，找隐藏模块） |
| `linux.check_syscall` | ⭐ **syscall 表劫持**（rootkit 的典型手法） |
| `linux.check_afinfo` | 网络协议钩子劫持 |
| `linux.lsmod` / `linux.kallsyms` | 模块 / 内核符号 |
| `linux.malfind` | 可执行匿名内存映射 |
| `linux.sockstat` | 套接字 |
| `linux.vmayarascan` | 内存 YARA 扫描 |

> ⭐ 常用组合（怀疑 Rootkit 时）：
> `linux.check_modules` + `linux.check_syscall` + `linux.check_afinfo`
> 三者任一与磁盘状态不一致 → 高度可疑。

### 2.5 `[知识]` Linux 符号表：怎么把不可能变成可能

如果现场确实要做 Linux 内存取证，**赛前**准备好：

```bash
# 目标内核必须带调试信息（Ubuntu 需装 linux-image-*-dbgsym）
sudo apt install linux-image-$(uname -r)-dbgsym   # 或从 ddebs.ubuntu.com 下
# 用 dwarf2json 生成 ISF
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > <banner>.json.xz
```

> ⚠️ 必须在**与靶机同版本内核**上生成。不同内核的 ISF 不能混用。
> 时间成本很高 —— **赛前问清楚再决定做不做**。

---

## 三、流量分析

### 3.1 工具

| 工具 | 版本 | 用途 |
|---|---|---|
| ⭐ **tshark** | 3.2.1 | 命令行分析主力（`C:\Program Files\Wireshark\tshark.exe`） |
| capinfos | 3.2.1 | 看 pcap 概况 |
| editcap / mergecap | 3.2.1 | 切分 / 合并（按时间、按包数） |
| dpkt | 1.9.8 | Python 编程式解析（tshark 不够用时） |
| ⚠️ `-z export-objects` | ❌ | **3.2.1 没有这个功能**（3.4+ 才有），用 field 导出替代 |

> ⚠️ **tshark 不在 PATH 里**，且 Wireshark 3.2.1 比较老。
> 现场要升级的话注意 `-z export-objects` 是 3.4+ 才有的。

### 3.2 `[实测]` 最常用的 5 条命令

先用**自造样本**（下一节）验证过，全部可直接抄：

```powershell
$W='C:\Program Files\Wireshark'
$P='synthetic-webshell.pcap'

# ① 概况：先看规模，决定怎么切
& "$W\capinfos.exe" -c -a -e $P

# ② ⭐ HTTP 请求一览（IR 第一命令）
& "$W\tshark.exe" -r $P -Y http.request -T fields `
    -e frame.time_relative -e ip.src -e http.request.method -e http.request.uri

# ③ ⭐ 响应码分布（找"失败尝试→成功"的转折点）
& "$W\tshark.exe" -r $P -Y 'http.response.code >= 400' -T fields -e ip.src -e http.response.code

# ④ ⭐ 上传/请求体（找 webshell 内容）
& "$W\tshark.exe" -r $P -Y 'http.request.method == "POST"' -T fields -e http.file_data

# ⑤ 会话统计（谁跟谁通信、多少流量）
& "$W\tshark.exe" -r $P -q -z conv,tcp
```

`[实测]` 对自造样本 ②③④ 的真实输出：

```
0.200000000	203.0.113.47	GET	/upload.php
20.200000000	203.0.113.47	POST	/upload.php
22.200000000	203.0.113.47	GET	/uploads/a7f3c1.jpg.php
31.200000000	203.0.113.47	POST	/uploads/a7f3c1.jpg.php
39.200000000	203.0.113.47	GET	/uploads/.cache_update.sh
40.200000000	203.0.113.47	GET	/uploads/a7f3c1.jpg.php?c=Y2F0IC9ldGMvcGFzc3dk
```

```
# ③ 400 只有 1 个（被拦的那次）
10.0.0.5	400
```

```
# ④ 请求体原文 —— 直接看到图片马文件名和命令
[filename=shell.php\r\nPOST, /upload.php HTTP/1.1\r\n...filename="a7f3c1.jpg.php"...GIF89a...]
[c=system('id',)\r\n]
```

⭐ 注意最后一条：**URI 里的 `c=Y2F0IC9ldGMvcGFzc3dk` 是 `cat /etc/passwd` 的 base64**。
这是 webshell 的典型流量特征 —— URI 参数里塞 base64/长随机串（见 `events/webshell.md`）。

### 3.3 `[实测]` 其他好用的过滤器与统计

```powershell
# 协议分层（先摸清 pcap 里有什么协议）
& "$W\tshark.exe" -r $P -q -z io,phs

# 明文凭据（HTTP Basic / FTP / telnet 等）
& "$W\tshark.exe" -r $P -q -z credentials

# DNS 查询与解析结果（C2 / DGA / DNS 隧道）
& "$W\tshark.exe" -r $P -Y dns -T fields -e ip.src -e dns.flags.response -e dns.qry.name -e dns.a

# DNS 统计树
& "$W\tshark.exe" -r $P -q -z dns,tree

# UDP 会话
& "$W\tshark.exe" -r $P -q -z conv,udp
```

`[实测]` DNS 输出（能直接看出 beacon 目标 + 解析出的 IP）：

```
10.0.0.5	0	c2.example.net	
8.8.8.8	1	c2.example.net	203.0.113.99
```

### 3.4 ⚠️ `[实测]` Windows 上 `-Y` 表达式的两个解析坑

**这两个我实际撞到了，会让人误以为工具坏了：**

| 写法 | 结果 |
|---|---|
| `-Y 'http.request.method = "POST"'` | ❌ `tshark: "=" was unexpected in this context.` |
| `-Y 'http.request.method == "POST"'` | ✅ 2 个包 |
| `-Y 'http.response.code >= 400'` | ✅ 1 个包 |
| `-Y 'http.request.uri contains "upload"'` | ✅ 6 个包 |
| `-Y 'http.request.method == "POST" and http.request.uri contains "upload"'` | ✅ 2 个包 |
| `-Y 'http.request.uri matches "\?c="'` | ❌ `"?" was unexpected` |

**规律**：**裸 `=` 和裸 `?` 过不去**（Windows 命令行把它当特殊字符）。
`==`、`contains`、`>=`、`matches`（不带 `?`）都正常。

**兜底写法（最稳，绝不踩解析坑）**：让 tshark 出全量字段，用 `Select-String` 过滤：

```powershell
& "$W\tshark.exe" -r $P -T fields -e http.request.uri | Select-String -Pattern 'c='
# → /uploads/a7f3c1.jpg.php?c=Y2F0IC9ldGMvcGFzc3dk
```

> ⭐ 另一个坑：**3.2.1 的 `dns.qry.name contains "c2"` 返回 0 个包**，
> 但 `matches "c2"` 和 `== "c2.example.net"` 都正常。
> 所以**短子串匹配别用 `contains`**，用 `matches`。

### 3.5 `[实测]` 用 dpkt 编程解析（tshark 不够用时）

tshark 擅长"筛+出字段"，但**关联分析**（跨包算状态、解码自定义协议）用 Python 更顺。

⭐ 工具箱里有一个**可直接运行的完整示例**：`.ir-tools/pcap/make_pcap.py`
（造一个含"探测→被拦→绕过→webshell 回连→DNS beacon"的合成 pcap，
用来验证本文命令，也可当写解析脚本的模板）：

```powershell
. .ir-tools\env.ps1
cd .ir-tools\pcap
python make_pcap.py sample-webshell.pcap     # 需 PYTHONPATH 指向 pylib，env.ps1 已设
```

`[实测]` dpkt 1.9.8 有个**必踩的坑**：

```python
import dpkt, socket
# ❌ 错：IP(src="1.2.3.4") —— IP.__init__ 默认 unpack=False，字符串不会被转换
#    会报 PackError: argument for 's' must be a bytes object
ip = dpkt.ip.IP(src="203.0.113.47", dst="10.0.0.5")   # 打包时炸

# ✅ 对：自己 inet_aton
ip = dpkt.ip.IP(src=socket.inet_aton("203.0.113.47"),
                dst=socket.inet_aton("10.0.0.5"), p=dpkt.ip.IP_PROTO_TCP)
```

第二个坑：**`UDP(data=...)` 不会自动算 length**。不显式赋值的话
tshark 会显示 `Len=0` 并且**完全不解析成 DNS**：

```python
u = dpkt.udp.UDP(sport=40001, dport=53, data=payload)
u.ulen = 8 + len(payload)      # ⭐ 必须手动设
```

---

## 四、⭐ 实时取证优先于内存取证（活着的机器）

**活着的 Linux 靶机上，第四节这一套 5 分钟能出结论，且不需要任何符号表。**
真要用 vol 之前先问自己：**这些是不是已经能回答问题了？**

```bash
# 1) 反查"磁盘上没有但正在跑"的进程
ls -l /proc/[0-9]*/exe 2>/dev/null | grep -i deleted
ls -l /proc/[0-9]*/exe 2>/dev/null | grep -vE '/usr/|/bin/|/sbin/|/lib'

# 2) 隐藏进程：对比 /proc 与 ps 的输出（rootkit 常藏 ps）
ls /proc | grep -E '^[0-9]+$' | sort -n > /tmp/p1
ps -eo pid --no-headers | tr -d ' ' | sort -n > /tmp/p2
diff /tmp/p1 /tmp/p2          # ⭐ 只在 /proc 里有 = 有进程从 ps 里被藏了

# 3) 看进程打开的网络连接（比 netstat 更底层）
ls -l /proc/[0-9]*/fd 2>/dev/null | grep socket
cat /proc/net/tcp /proc/net/tcp6 | head            # 16 进制端口要自己转

# 4) 内核模块一致性
lsmod > /tmp/m1
cat /proc/modules > /tmp/m2
# 对比 /lib/modules/$(uname -r)/ 下的实际文件
find /lib/modules/$(uname -r) -name '*.ko*' | sed 's|.*/||;s|\.ko.*||' | tr - _ | sort > /tmp/m3
awk '{print $1}' /tmp/m1 | sort > /tmp/m4
comm -13 /tmp/m3 /tmp/m4      # ⭐ 加载了但磁盘上没有的模块 = 可疑

# 5) 内核符号表被改？(rootkit hook)
grep -E ' (sys_call_table|do_sys_open|tcp4_seq_show)$' /proc/kallsyms

# 6) 反弹 shell 特征：bash 连着 socket
ls -l /proc/[0-9]*/fd 2>/dev/null | grep -E 'socket:' | head
for p in $(pgrep -f 'bash|sh$'); do
  echo "--- $p: $(tr '\0' ' ' < /proc/$p/cmdline)"
done
```

> ⭐ **`ls -l /proc/*/exe` 和 `/proc/*/fd` 是最有产出的两条命令。**
> 攻击者最常做的是"删掉自己 + 保持运行"，这两个位置正好暴露它。

---

## 五、报告写法：把"内存/流量"证据讲清楚

内存和流量证据**比磁盘证据更弱**（不可复现、易被质疑），所以标注要更严：

| 说法 | 该标什么 |
|---|---|
| `vol windows.pslist` 输出里有 `evil.exe` | `[观测]` — 有插件原始输出 |
| 该进程是恶意的 | `[推断]` — 需要配合 hash / 路径 / 行为 |
| 内存里有 MZ 头说明有注入代码 | `[知识]` — 工具判据，不是本次观测 |
| tshark 显示 09:22:51 有一次 200 | `[观测]` — 时间戳来自 pcap |
| 这就是入侵时刻 | `[推断]` — 需与磁盘日志交叉验证 |

⚠️ **别犯的错**（`SKILL.md` 铁律）：

- `[知识]` 说成 `[观测]`（例如"内存马一定有特征 X"→ 写成"我在内存里发现了 X"）
- 从 pcap 的 IP 反推"这是攻击者的机器" —— IP 可能是跳板/NAT
- 把 vol 的插件名当证据（`malfind` 报可疑 **≠** 已确认恶意）

---

## 六、速查：该用哪套

```
有磁盘痕迹？ ──是──> 先用 10/20/25/30/40 那几篇，别碰内存
     │
     否
     ↓
机器还活着？ ──是──> ⭐ 第四节 /proc 实时取证（最快，无需符号表）
     │
     否（只有镜像文件）
     ↓
是 Windows 镜像？ ──是──> vol + 符号（msdl 国内直连可达，不需翻墙）
     │
     否（Linux 镜像）
     ↓
有该内核的 ISF 吗？ ──有──> vol linux.*
     │
     无 ──> ❌ vol 用不了；转流量分析 + 承认内存这块做不了（写进报告）
```

**有任何 pcap 就一定要跑第 3.2 节那 5 条命令** —— 成本极低，产出极高，
而且能补磁盘日志看不到的响应体和协议细节。
