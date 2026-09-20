# 工具清单与落点

**先读这条**：工具分两类，**别搞混使用场景**。

| 类别 | 在哪用 | 说明 |
|---|---|---|
| **CLI / 原生命令** | ⭐ **靶机现场** | 通过 shell 直接在受害主机上跑。**这是比赛主力**——靶机上不会给你装 GUI 工具 |
| **GUI / 便携工具** | **本机分析工作台** | 分析离线证据（导出的日志、内存镜像、样本）、或靶机恰好是 Windows 且有远程桌面时用 |

> ⚠️ **比赛现实**：`shell_command` 只在你本机执行，远端靶机靠 SSH / webshell 型 RCE 间接操作。
> **不要把手册写成"打开 D盾点扫描"**——那是离线分析姿势，不是现场排查姿势。

---

## 一、CLI 主力（靶机现场，无需安装）

这些是**每个靶机都有**的，也是 `25-process-service.md` / `30-file-artifacts.md` / `40-log-analysis.md` 里命令的来源。

| 排查面 | Windows | Linux |
|---|---|---|
| 系统信息 | `systeminfo` `msinfo32` `hostname` `wmic`(可能缺失) | `uname -a` `lscpu` `lsmod` `uptime` `hostnamectl` |
| 账号 | `net user` `lusrmgr.msc` `wmic useraccount` `reg query`(SAM) | `awk -F: '$3==0' /etc/passwd` `awk` on shadow `last` `lastb` `lastlog` `who -a` |
| 进程 | `tasklist` `tasklist /svc` | `ps aux` `ps -ef` `top -c` `/proc/<PID>/exe` |
| 网络 | `netstat -ano` `netstat -anob` | `ss -antp` `netstat -anp` `lsof -i:<port>` |
| 服务 | `sc query` `sc qc <name>` `services.msc` | `systemctl cat` `systemctl list-unit-files` `chkconfig --list` |
| 启动项 | `msconfig` `reg query`(Run 键) `shell:startup` | `ls -la /etc/rc*.d/` `cat /etc/rc.local` `ls /etc/profile.d/` |
| 计划任务 | `schtasks /query /fo LIST /v` `C:\WINDOWS\System32\Tasks` | `crontab -l` `cat /etc/crontab` `ls -la /etc/cron*` |
| 文件痕迹 | `dir /od /s` `forfiles` `attrib` `dir /r`(ADS) | `find -ctime/-mtime/-atime` `ls -alt` `stat` `lsattr` |
| 日志 | `wevtutil` `eventvwr` `Get-WinEvent` | `grep` on `/var/log/*` `journalctl` |
| 完整性 | `sigcheck`(需工具) / 手工 hash | ⭐ `rpm -Va` `debsums` |
| Rootkit | （无原生） | ⭐ `chkrootkit` `rkhunter` `unhide` |

### Linux 侧的"临时装工具"可行性

有些工具值得现装（靶机有外网或你有本地包）：

```bash
# Rootkit 查杀
yum -y install epel-release && yum -y install unhide    # 查隐藏进程
yum -y install chkrootkit rkhunter
yum -y install clamav && freshclam && clamscan -r /home

# 没有包管理时的替代
# 隐藏进程 → 手工对比 /proc 与 ps
ls -d /proc/[0-9]* | wc -l ; ps -e --no-headers | wc -l
```

> ⚠️ **比赛里慎装**：装工具会产生网络流量和磁盘变动，可能被视为"异常操作"。
> **优先用原生命令**，确有必要再装，并记录你装了什么。

---

## 二、已就位的工具箱（本机分析工作台）

**位置**：`D:\GitClone\VulnClaw\VulnClaw\.ir-tools`（移动硬盘副本 `G:\tool\ir-toolkit`）

启用：`. .\.ir-tools\env.ps1` 或 `.\.ir-tools\env.cmd`

### ⭐ D盾_Web查杀

`bin/D盾_Web查杀/D_Safe_Manage.exe`（绿色便携，双击运行）

《指南》第 6 章**指定的 Windows 查杀工具**。

| 功能 | 对应排查面 |
|---|---|
| Webshell 查杀 + 可疑文件隔离 | `events/webshell.md` |
| **克隆用户检测** | ⭐ `20-accounts.md` —— 补上手工查注册表 F 值的麻烦 |
| 端口进程查看 | `25-process-service.md` |
| base64 解码 | 看混淆代码 |
| 文件监控 | 实时抓文件变动 |

> ⚠️ 大概率被火绒/Defender 误杀，先加白名单。

### Sysinternals Suite（164 工具）

`bin/SysinternalsSuite/`

| 工具 | 用在哪 |
|---|---|
| **Process Explorer** `procexp64.exe` | 进程树/句柄/签名/命令行 → 判定"无签名进程" |
| **Process Monitor** `Procmon64.exe` | 文件·注册表·网络实时监控 → 抓"谁改了这个文件" |
| **Autoruns** `autoruns64.exe` | 全自启动项。⚠️ **COM 劫持能绕过它**，别只信它 |
| **TCPView** `Tcpview64.exe` | 连接实时视图（绿=新 红=已结束）→ 对应 `10-system-basics` 的网络连接面 |
| **Sigcheck** `sigcheck64.exe` | 签名校验 → 批量验文件签名 |
| **Strings** `strings64.exe` | 二进制字符串提取 → 样本判读 |
| **Sysmon** `Sysmon64.exe` | 需装驱动。比赛靶机通常装不了，**本机分析时才用** |

### NirSoft 八件套

免费便携单文件，**替代需付费注册的 Event Log Explorer**。

| 工具 | 对应《指南》 |
|---|---|
| **FullEventLogView** | ⭐ 2.5 节 日志分析 —— 全量 evtx 浏览筛选（配合 `40-log-analysis.md` 的事件 ID 表） |
| **WinPrefetchView** | ⭐ 2.4 节 预读取文件夹 |
| **UserAssistView** | ⭐ 2.6 节 userassist |
| **ShellBagsView** | ShellBags 文件夹访问痕迹 |
| **LastActivityView** | 最近活动时间线 |
| **BrowsingHistoryView** | 2.4 节 浏览器历史记录 |
| **WifiHistoryView** | 无线连接历史 |
| **DNSDataView** | DNS 记录 |

### volatility3（内存取证）

```powershell
. .\.ir-tools\env.ps1
vol -f memory.raw windows.info         # 先看镜像信息
vol -f memory.raw windows.pslist       # 进程列表
vol -f memory.raw windows.psscan       # ⭐ 找隐藏/未链接进程
vol -f memory.raw windows.netscan      # 网络连接
vol -f memory.raw windows.malfind      # ⭐ 找注入代码（PAGE_EXECUTE_READWRITE、MZ 头）
vol -f memory.raw windows.dumpfiles --pid <PID>
# Linux 镜像
vol -f memory.raw linux.pslist
vol -f memory.raw linux.bash           # ⭐ 恢复 bash 命令历史
```

详见 `50-memory-traffic.md`。

### 其他 Python 包（`pylib/`）

| 包 | 用途 |
|---|---|
| yara-python | 样本特征匹配（已实测） |
| oletools | Office 宏 / OLE 分析 |
| dpkt | 抓包解析 |
| pefile / capstone / lief | PE 解析、反汇编、格式解析 |

### Log Parser 2.2（需手动安装）

`logparser/LogParser.msi` —— 安装要点见 `.ir-tools/README.md`。
**只有 32 位版**，装完要 `regsvr32 logparser.dll` 注册 COM。
> 批量查事件日志用 PowerShell `Get-WinEvent` 更可靠，且**靶机上不会有它**。

---

## 三、第 3 章工具落点对照

对照《网络安全应急响应技术实战指南》第 3 章：

| 书中工具 | 状态 | 说明 |
|---|---|---|
| 3.1 SysinternalsSuite | ✅ | `bin/SysinternalsSuite/`（164 工具） |
| 3.2 PCHunter / 火绒剑 / PowerTool | ⚠️ 部分 | 本机有**火绒安全软件本体**（`C:\Program Files\Huorong\Sysdiag\`），自带 `Autoruns.exe`、`SecAnalysis.exe`、`NetFlow.exe`；**PCHunter 需手动下**（内核级，无替代） |
| 3.3 Process Monitor | ✅ | `bin/SysinternalsSuite/Procmon64.exe` |
| 3.4 Event Log Explorer | ❌ 替代 | 需付费注册 → 用 **FullEventLogView** |
| 3.5 FullEventLogView | ✅ | `bin/FullEventLogView/` |
| 3.6 Log Parser | ⚠️ 待装 | `logparser/LogParser.msi` |
| 3.7 ThreatHunting | ❌ 跳过 | 书里是推广 |
| 3.8 WinPrefetchView | ✅ | `bin/WinPrefetchView/` |
| 3.9 WifiHistoryView | ✅ | `bin/WifiHistoryView/` |
| 3.10 奇安信应急响应工具箱 | ❌ 跳过 | 需申请 |

**另需手动补**：河马 HWS（`shellpub.com`）、PCHunter / PowerTool（`xuetr.com`）。

---

## 三点五、⭐ 外部攻击工具（本机已装，但不在系统 PATH）

**本机装了 sqlmap / hashcat / ffuf / gobuster / john / exiftool / binwalk**，
但**默认不在系统 PATH 里**。清单（含确切路径与调用方式）：

```
D:\GitClone\VulnClaw\VulnClaw\.ir-tools\TOOL-INVENTORY.md
```

**要先把会话环境激活，命令名才能直接用**：

```powershell
. .ir-tools\env.ps1          # PowerShell
.ir-tools\env.cmd            # cmd
where.exe sqlmap hashcat ffuf gobuster john exiftool
```

### ⚠️ 找不到工具时怎么办（重要，实测踩过）

**不要反复全盘搜索。** 实测行为：agent 想用 sqlmap → `where sqlmap` 找不到 →
`Get-ChildItem -Path C:\ -Recurse` **60 秒超时** → 又扫 D 盘浪费 20 秒 →
最后转去 `pip install sqlmap`。**总计浪费约 40 秒 + 一次超时。**

**正确做法**：

1. 先读上面那份 `TOOL-INVENTORY.md`（一步到位拿到路径）
2. 或先 `. .ir-tools\env.ps1` 再 `where <tool>`
3. **两条都不行就直接判定"该工具不可用"**，改用内置工具或原生命令，
   **不要 pip install、不要全盘搜**

| 任务 | 用哪个 | 备选 |
|---|---|---|
| SQL 注入检测 | `sqlmap` | 内置 `http_probe_batch` 手写 payload |
| 目录爆破 | `ffuf` | `gobuster` / 内置 `dir_enum` |
| hash 破解（GPU） | `hashcat` | — |
| hash 破解（CPU / 压缩包） | `john` + `zip2john` 等 | — |
| 端口扫描 | **内置 `nmap_scan`** | `nmap` |
| 图片元数据 | `exiftool` | — |
| 固件解包 | `binwalk` | — |

### ⚠️ 三个调用约束

| 工具 | 约束 |
|---|---|
| **hashcat** | **必须走 `wrappers/hashcat.cmd`**。① CUDA 后端在本机坏了（`nvrtc: invalid value for --gpu-architecture`），需 `--backend-ignore-cuda`；② 工作目录必须是它自己那层（它用相对路径找 `./OpenCL/`） |
| **sqlmap / exiftool** | 必须走包装器：sqlmap 只有 `.py`、exiftool 文件名是 `exiftool(-k).exe` |
| **john** | Cygwin 构建，受限沙箱里报 `signal pipe` 错；普通终端正常 |

> **主机应急取证时优先用原生命令**（`ps`/`ls -al`/`grep`/`find`/`ss` 等，见本文档第一、二节）。
> 上面这些攻击工具是**打漏洞/破解**用的，不是取证主力。

---

## 四、工具 ↔ 排查面速查矩阵

**按题面找工具**：

| 要回答什么 | CLI（靶机） | GUI（本机） |
|---|---|---|
| 有哪些账号 | `net user` + `lusrmgr.msc` | **D盾**（克隆用户检测） |
| 有没有隐藏进程 | 对比 `/proc` 与 `ps`、`unhide proc` | **Process Explorer** |
| 进程的可执行文件在哪 | `/proc/<PID>/exe`、`lsof -p` | **Process Explorer**（属性→映像路径） |
| 谁在联网 | `ss -antp` / `netstat -ano` | **TCPView** |
| 有哪些自启动 | `schtasks /query`、`reg query`、`/etc/rc*.d` | **Autoruns** |
| 谁改了文件 | `find -ctime`、`ls -alt`、`stat` | **Process Monitor** |
| 被改了哪些文件 | `rpm -Va` / 手工 hash 对比 / `diff -r` | **Sigcheck** + Beyond Compare |
| 事件日志里的可疑记录 | `wevtutil` / `Get-WinEvent` | **FullEventLogView** |
| 某个程序什么时候跑过 | `/proc`、`.bash_history` | **WinPrefetchView** / **UserAssistView** / **LastActivityView** |
| 日志在哪个目录 | `/var/log/*`、`nginx.conf` | 见 `40-log-analysis.md` 位置表 |
| 内存里有什么 | （无原生） | ⭐ **volatility3** |
| 这个文件是不是恶意的 | `strings` `file` `md5sum` | **Strings** + **YARA** + **D盾** |
| 有没有 rootkit | `chkrootkit` `rkhunter` `rpm -Va` | **PCHunter**（被挂钩函数） |
| 网页被改成什么了 | `grep -r` 页面目录、查 `nginx.conf` | **D盾** 查暗链 |
| 数据库被改了吗 | `mysql` 查 `general_log`、查表记录 | — |

---

## 五、取证操作的顺序原则

**1. 先只读，后修改**

排查阶段能只读就只读。需要停进程 / 删文件时，**先保存证据**：

```bash
cp /proc/<PID>/exe /tmp/evidence/          # 进程内存副本（文件可能已自删除）
md5sum <suspect_file> >> evidence/hashes.txt
cp /var/log/secure /tmp/evidence/          # 原始日志副本
stat <suspect_file> > evidence/stat.txt    # 时间戳
```

**2. 易失性数据的优先序**（RFC 3227 原则）

```
寄存器/缓存 > 内存 > 网络连接 > 运行进程 > 磁盘 > 日志/归档 > 备份
        ↑ 最易失，先取                      ↑ 最不易失，后取
```

**3. 不要污染时间戳**

读文件时**用 `cp -p` 保留时间戳**，避免 `cat` 之外的读写；分析时用副本不要动原件：

```bash
cp -p /var/log/secure /tmp/evidence/secure.orig   # OK
cat /var/log/secure > /tmp/copy                    # 改变了 atime
```

---

## 相关文档

- `10-system-basics.md` ~ `50-memory-traffic.md` — 各排查面的具体命令
- `events/*.md` — 按事件类型组织的工具用法
- `.ir-tools/README.md` — 工具安装细节与环境坑位
- `.ir-tools/MANIFEST.md` — 完整文件清单 + MD5 校验表
