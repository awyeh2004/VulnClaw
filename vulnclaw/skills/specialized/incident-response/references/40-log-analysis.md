# 日志分析

应急响应里**时间线还原的主力**。核心用法：**先锚一个时间点（文件创建/修改时间），再去日志里找该时间窗的可疑行为，然后顺着 IP / 时间往前后扩**。

---

## 一、Windows

### 日志文件位置

**旧版本**（Windows 2000 Pro / XP / Server 2003，后缀 `.evt`）：

```cmd
C:\WINDOWS\System32\config\SysEvent.evt     :: 系统日志
C:\WINDOWS\System32\config\SecEvent.evt     :: 安全性日志
C:\WINNT\System32\config\AppEvent.evt       :: 应用程序日志
```

**新版本**（Vista / 7 / 8 / 10 / Server 2008+，后缀 `.evtx`）：

```cmd
%SystemRoot%\System32\Winevt\Logs\System.evtx
%SystemRoot%\System32\Winevt\Logs\Security.evtx
%SystemRoot%\System32\Winevt\Logs\Application.evtx
```

同目录下还有大量其它日志：**远程桌面会话日志**（RDP 登录源地址、登录用户）、Dhcp、Bits-Client 等——**Webshell 事件里 RDP 日志同样要查**。

打开方式：

```cmd
eventvwr            :: 事件查看器
```

### ⭐ 事件 ID 总表（应急响应最常用）

> 合并《指南》表 2.5.1 与第 6 章表 6.4.9。旧版本 ID 仅 Win2000/XP/2003 使用。

| ID | 描述 | 归属日志 | 用途 |
|---|---|---|---|
| **1102** | **清理审计日志** | 安全 | ⭐ 攻击者擦痕迹——出现即高度可疑 |
| 4624 | 用户登录成功 | 安全 | 定位入侵时间 |
| 4625 | 用户登录失败 | 安全 | 爆破排查（**解锁屏幕不产生此日志**） |
| 4672 | 特权用户登录成功 | 安全 | ⭐ Administrator 登录时与 4624 **成对出现** |
| 4776 | 账户认证成功/失败 | 安全 | NTLM 认证 |
| 4720 | **创建用户** | 安全 | ⭐ 后门账户 |
| 4722 | 启用用户 | 安全 | |
| 4724 | 试图重置账号密码 | 安全 | ⭐ 管理员密码被改 |
| 4726 | 删除用户 | 安全 | |
| 4728 | 加入**全局**安全组 | 安全 | 域场景 |
| 4729 | 从全局安全组移除 | 安全 | |
| 4732 | 加入**本地**安全组 | 安全 | ⭐ 通常是加进 Administrators = 提权 |
| 2949 → **7045** | **服务创建** | 系统 | ⭐ 持久化后门 |
| 2944 → 7040 | IPSEC 服务启动类型改为自动 | 系统 | 隐蔽持久化 |
| 2934 → 7030 | 服务创建错误 | 系统 | 失败痕迹 |

**RDP 会话日志**（`%SystemRoot%\System32\Winevt\Logs\` 下的 Microsoft-Windows-TerminalServices-* ）：

| ID | 描述 |
|---|---|
| 21 | 远程桌面会话登录成功 |
| 24 | 远程桌面会话断开连接 |
| 25 | 远程桌面会话重新连接成功 |

### ⭐ 登录类型数字对照表（表 2.5.2）

成功/失败登录事件里会用**数字**表示登录类型。直接考"数字 N 是什么登录"。

| 数字 | 类型 | 描述 |
|---|---|---|
| 2 | Interactive | 用户登录到本机 |
| 3 | Network | 网络共享 / `net use` / `net view` |
| 4 | Batch | 批处理登录，无须用户干预 |
| 5 | Service | 服务控制管理器登录 |
| 7 | Unlock | 用户解锁主机 |
| 8 | NetworkCleartext | 从网络登录，**密码以非哈希形式传递** |
| 9 | NewCredentials | 进程/线程克隆令牌，但为出站连接指定新凭据 |
| **10** | **RemoteInteractive** | ⭐ 终端服务 / 远程桌面登录 |
| 11 | CachedInteractive | 本地缓存凭据登录（域控不可达时） |
| 12 | CachedRemoteInteractive | 同 10，内部用于审计 |
| 13 | CachedUnlock | 登录尝试解锁 |

> **答题技巧**：问"这个登录是什么方式"→ 看登录类型数字。**10 / 3 / 5 / 4 是最高频**。

### 分析手段

```cmd
eventvwr                                    :: 图形界面筛选
wevtutil qe Security /f:text /c:50          :: 命令行导出最近 50 条
wevtutil epl Security C:\sec.evtx           :: 导出
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720}   :: PowerShell 精确查
```

工具：**FullEventLogView**（免费便携，代替需注册的 Event Log Explorer）、**Log Parser**（SQL 式查询，可 CLI 脚本化）、LogParser Lizard、Event Log Explorer。

### ⚠️ 前提：审核策略

**不开启审核策略就没有安全日志**。若 `Security.evtx` 空或记录极少，先查审核策略——这本身就是一条答题线索（"为什么无法溯源"）。

---

## 二、Linux

### 日志位置总表（`/var/log/`）

| 文件 | 说明 |
|---|---|
| `messages` | ⭐ 系统重要信息，出问题**第一个看** |
| **`secure`** | ⭐ **认证授权**：SSH 登录、su、sudo、**添加/修改用户密码** |
| `cron` | 定时任务相关 |
| `dmesg` | 开机内核自检（也可 `dmesg` 命令） |
| `maillog` / `mailog` | 邮件 |
| `cups` | 打印 |
| **`btmp`** | ⭐ 错误登录（**二进制**，用 **`lastb`** 看） |
| **`lastlog`** | ⭐ 所有用户最后登录时间（**二进制**，用 **`lastlog`** 看） |
| **`wtmp`** | ⭐ 登录/注销/启动/关机（**二进制**，用 **`last`** 看） |
| `utmp` | 当前已登录用户（**二进制**，用 `w` / `who` / `users` 看） |
| `boot.log` | 引导过程事件 |

查看日志配置：`more /etc/rsyslog.conf`

> ⚠️ `btmp` / `lastlog` / `wtmp` / `utmp` **不能 `vi` 直接看**，必须用对应命令。这是常见踩坑点。

### ⭐ 高频排查命令

```bash
# ── 爆破排查 ──────────────────────────────────────────
# 有多少 IP 在爆破 root
grep "Failed password for root" /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more

# 有哪些 IP 在爆破（正则提取 IPv4）
grep "Failed password" /var/log/secure | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | uniq -c

# 爆破用的用户名字典是什么
grep "Failed password" /var/log/secure | perl -e 'while($_=<>){ /for(.*?) from/; print "$1\n";}' | uniq -c | sort -nr

# ── 登录成功 ──────────────────────────────────────────
# 登录成功的 IP 排行
grep "Accepted " /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more

# 登录成功的 日期+时间+用户名+IP（⭐ 最常用的一条）
grep "Accepted " /var/log/secure | awk '{print $1,$2,$3,$9,$11}'

# Ubuntu（用 auth.log 而非 secure）
grep "Accepted " /var/log/auth.log | awk '{print $1,$2,$3,$9,$11}'

# ── 账号变动 ──────────────────────────────────────────
grep "useradd" /var/log/secure
grep "userdel" /var/log/secure

# ── 登录记录（二进制日志） ──────────────────────────────
last            # wtmp：登录/注销/重启历史
lastb           # btmp：失败登录
lastlog         # 每个用户最后登录时间
who -a          # 当前会话
```

### journald（CentOS 7+ / systemd 系统）

```bash
journalctl -u sshd --since "2024-01-01" --until "2024-01-02"
journalctl -S "2 hours ago" -p err
journalctl --disk-usage
```

---

## 三、Web / 中间件日志位置总表（表 2.5.3）

**比赛常见第一问："日志在哪？"**

| 组件 | 位置 |
|---|---|
| **IIS** | `%SystemDrive%\inetpub\logs\LogFiles`<br>`%SystemRoot%\System32\LogFiles\W3SVC1`<br>`%SystemDrive%\inetpub\logs\LogFiles\W3SVC1`<br>`%SystemDrive%\Windows\System32\LogFiles\HTTPERR` |
| **Apache** | `/var/log/httpd/access.log`<br>`/var/log/apache/access.log`<br>`/var/log/apache2/access.log`<br>`/var/log/httpd-access.log` |
| **Nginx** | 默认 `/usr/local/nginx/logs`（`access.log` 访问、`error.log` 错误）<br>非默认路径 → 查 `nginx.conf` 里的 `access_log` |
| **Tomcat** | `TOMCAT_HOME/logs/`：`catalina.out`、`catalina.YYYY-MM-DD.log`、`localhost.YYYY-MM-DD.log`、**`localhost_access_log.YYYY-MM-DD.txt`**、`host-manager.*.log`、`manager.*.log` |
| **WebLogic** | access log：`$MW_HOME\user_projects\domains\<domain>\servers\<server>\logs\access.log`<br>server log：同目录 `<server>.log`<br>domain log：`...\servers\<adminserver>\logs\<domain>.log` |
| **Vsftp** | ⚠️ **默认不单独记日志**，统一在 `/var/log/messages`。改 `/etc/vsftp/vsftp.conf` 可启用 `vsftpd.log` 和 `xferlog` |

### ⚠️ 坑位一：Tomcat 日志可能被注释掉

真实案例：`server.xml` 里的**日志配置项被注释**，即未启用日志 → **完全无 Web 日志记录 → 溯源困难**。排查不到日志时先确认配置。

### ⚠️ 坑位二：IIS 日志时区与系统时间不一致

真实案例：**IIS 日志时间与系统时间相差 8 小时**。系统时间 15:08 对应的日志要查 07:08 的。
**不校正时区，时间线永远对不上。** 先确认偏移量再关联。

### ⚠️ 坑位三：应用服务器默认不记录 POST 请求体

真实案例原文："一般应用服务器**默认日志不记录 POST 请求内容**"。
所以"文件创建时间点附近没有可疑上传记录，但有可疑接口访问"是**正常现象**——**要顺着接口去代码里找漏洞，而不是继续等上传记录**。

---

## 四、数据库日志

| 数据库 | 查看方法 |
|---|---|
| **MySQL** | `show variables like 'log_%'` 看是否启用<br>`show variables like 'general'` 看 general_log 位置<br>默认路径 `/var/log/mysql/`<br>配置：Windows `C:\Windows\my.ini` / `C:\Windows\mysql\my.ini`；Linux `/etc/mysql/my.cnf` |
| **Oracle** | `select * from v$logfile` 查日志路径<br>默认 `$ORACLE/rdbms/log`<br>`select * from v$sql` 查执行过的 SQL |
| **SQL Server** | ⚠️ **无法直接看文件**，需登录 SSMS → 「管理」→「SQL Server 日志」 |

### ⭐ MySQL 关键判读技巧

**查 Webshell 的当前用户**：

- 是 `MySQL` → 很可能**通过 MySQL 漏洞打进来的**
- 是 `httpd` → 很可能**通过 Web 攻击打进来的**

这条能直接回答"攻击者是怎么进来的"。

### 数据库落库型后门

参见 `events/webshell.md`。要点：数据库表里存着"生成 Webshell 的 SQL/URL"，
**删了文件还会被重新生成**——清除时必须同时清数据库记录。

---

## 五、⭐ Web 日志分析

### 两种分析思路（《指南》第 2 章第 3 篇）

1. **以时间为线索**：确定入侵时间范围 → 查该范围内可疑日志 → 定位攻击者、还原过程
2. **以后门为线索**：先找到后门文件 → 以它为线索倒推访问来源

### 常用统计命令（Apache / Nginx access log）

```bash
# 当天访问次数最多的 IP
cut -d- -f 1 access.log | uniq -c | sort -rn | head -20

# 有多少个不同 IP 访问
awk '{print $1}' access.log | sort | uniq | wc -l

# 某页面被访问次数
grep "/index.php" access.log | wc -l

# 每个 IP 访问了多少个页面
awk '{++S[$1]} END {for (a in S) print a,S[a]}' access.log

# 某 IP 访问了哪些页面
grep ^111.111.111.111 access.log | awk '{print $1,$7}'

# 某小时的访问 IP 数
awk '{print $4,$1}' access.log | grep 21/Jun/2018:14 | awk '{print $2}' | sort | uniq | wc -l

# HTTP 状态码分布
cat access.log | awk '{print $9}' | sort | uniq -c | sort -rn | more

# URL 访问排行
cat access.log | awk '{print $7}' | sort | uniq -c | sort -rn | more

# 带参数的 URL（找注入点/上传点）
cat access.log | awk '{print $7}' | egrep '\?|&' | sort | uniq -c | sort -rn | more

# 文件流量统计
grep ' 200 ' access.log | awk '{sum[$7]+=$10} END{for(i in sum){print sum[i],i}}' | sort -rn | more
```

### ⭐ 反代场景：用浏览器指纹代替 IP 定位攻击者

真实案例：Nginx 代理转发到内网，**日志只记录了代理服务器 IP，没有访问者真实 IP**。

**解法**：用 **User-Agent（浏览器指纹）** 关联。

```
指纹: Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.1;+WOW64;+Trident/7.0;+SLCC2;+.NET+CLR+2.0.50727;...)
```

筛选同指纹的全部日志 → 还原攻击路径：

```
A 访问首页和登录页
B 访问 MsgSjlb.aspx / MsgSebd.aspx
C 访问 Xzuser.aspx
D 多次 POST（怀疑上传模块缺陷）
E 访问图片木马
```

→ 确认 `Xzuser.aspx` 存在文件上传漏洞 + 越权访问（特定 URL 免登录进后台）。

> **这是"日志没 IP 就查不动"困局的破法**，比赛里遇到代理场景直接用。

### 攻击特征速查

| 特征 | 含义 |
|---|---|
| 同一 IP 短时间大量 404 | 目录爆破 |
| 大量 `POST` 到同一 .php/.jsp | 上传或注入 |
| URL 含 `../` / `%2e%2e` | 路径穿越 |
| URL 含 `union` / `select` / `sleep` / `benchmark` | SQL 注入 |
| 访问 `.php` 却返回 200 且参数可疑 | 可能的 Webshell 连接 |
| **某脚本文件只有 1~2 次访问记录且间隔很久** | ⭐ 长期潜藏的 Webshell（真实案例：`image.jsp` 一年只被访问两次） |

---

## 六、时间线还原方法

```bash
# 1. 锚定时间点：恶意文件的创建/修改时间
stat <file>                     # Linux：Access / Modify / Change 三个时间
dir /tc <file>                  # Windows：创建时间

# 2. 圈定该时间窗的文件变动
find / -ctime 0 -name "*.sh"                    # 一天内新增的 sh
find /opt -iname "*" -atime 1 -type f           # 一天前访问过的文件
forfiles /m *.exe /d +2020/2/12 /s /p c:\ /c "cmd /c echo @path @fdate @ftime" 2>nul

# 3. 去日志里找该时间窗
grep "<时间窗>" access.log
grep "<时间窗>" /var/log/secure

# 4. 顺着找到的 IP 往前后扩（关联分析）
grep "<该IP>" access.log
grep "<该IP>" /var/log/secure
```

**日志保留期不足时**：只能给出时间的**下界**（"该后门在 XXXX-XX-XX 之前就已存在"），必须明确说明——真实案例里攻击者潜藏半年以上，日志只保留一年，无法确定原始入侵点。

---

## 相关文档

- `10-system-basics.md` — 启动项、计划任务排查
- `20-accounts.md` — 账号相关事件 ID 的具体用法
- `30-file-artifacts.md` — 文件时间戳判读、完整性校验
- `events/webshell.md` — Web 日志定位上传点的完整流程
- `casebook.md` — 含 3 个完整日志溯源案例（含跨主机）
