# 第2章 日志分析

> 来源：《网络安全应急响应技术实战指南》奇安信安服团队, 电子工业出版社 2020
> 本文件由 pdfminer 自动提取, 页码 印刷53-69

第 2 章
网络安全应急响应工程师基础技能
图 2.4.23    排查情况 2
（5）排查 SUID 程序，即对于一些设置了 SUID 权限的程序进行排查，可以
使用【find / -type f -perm -04000 -ls -uid 0 2>/dev/null】命令，如图 2.4.24 所示。
图 2.4.24    排查 SUID 程序
2.5    日志分析
1．Windows 系统
1）日志概述
在 Windows 系统中，日志文件包括：系统日志、安全性日志及应用程序日志，
53
网络安全应急响应技术实战指南
对于应急响应工程师来说这三类日志需要熟练掌握，其位置如下。
在 Windows 2000  专业版/Windows XP/Windows Server 2003（注意日志文件的
后缀名是 evt）系统中：
系统日志的位置为 C:\WINDOWS\System32\config\SysEvent.evt；
安全性日志的位置为 C:\WINDOWS\System32\config\SecEvent.evt；
应用程序日志的位置为 C:\WINNT\System32\config\AppEvent.evt。
在 Windows Vista/Windows 7/Windows 8 /Windows 10/Windows Server 2008 及
以上版本系统中：
系统日志的位置为%SystemRoot%\System32\Winevt\Logs\System.evtx；
安全性日志的位置为%SystemRoot%\System32\Winevt\Logs\Security.evtx；
应 用 程 序 日 志 的 位 置 为 %SystemRoot%\System32\Winevt\Logs\Application.
evtx。
（1）系统日志。
系统日志主要是指 Windows 系统中的各个组件在运行中产生的各种事件。这
些事件一般可以分为：系统中各种驱动程序在运行中出现的重大问题、操作系统
的多种组件在运行中出现的重大问题及应用软件在运行中出现的重大问题等。这
些重大问题主要包括重要数据的丢失、错误，以及系统产生的崩溃行为等。事件
ID 为 8033 的系统日志详情如图 2.5.1 所示。
图 2.5.1    事件 ID 为 8033 的系统日志详情
54
第 2 章
网络安全应急响应工程师基础技能
（2）安全性日志。
安全性日志与系统日志不同，安全性日志主要记录了各种与安全相关的事件。
构成该日志的内容主要包括：各种登录与退出系统的成功或不成功的信息；对系
统中各种重要资源进行的各种操作，如对系统文件进行的创建、删除、更改等操
作。事件 ID 为 513 的安全性日志详情如图 2.5.2 所示。（注意：由于系统版本不同，
部分“安全性”日志也可写为“安全”日志。）
图 2.5.2    事件 ID 为 513 的安全性日志详情
（3）应用程序日志。
应用程序日志主要记录各种应用程序所产生的各类事件。例如，系统中 SQL
Server 数据库程序在受到暴力破解攻击时，日志中会有相关记录，该记录中包含与
对应事件相关的详细信息。事件 ID 为 18456 的应用程序日志详情如图 2.5.3 所示。
除了上述日志，Windows 系统还有其他的日志，在进行应急响应和溯源时也
可能用到。
在 Windows 2000 专业版/Windows XP/Windows Server 2003 系统中，只有应用
程序、安全性及系统三类日志，如图 2.5.4 所示。
在 Windows  7/Windows  8  /Windows  10/Windows  Server  2008/Windows  Server
2012 等系统中进行应急响应时，除了会用到应用程序、安全性及系统三类日志，
还会用到其他日志，如 Dhcp、Bits-Client 等，这些日志存储在“%SystemRoot%\
55
网络安全应急响应技术实战指南
System32\Winevt\Logs”目录下，如图 2.5.5 所示。
图 2.5.3    事件 ID 为 18456 的应用程序日志详情
图 2.5.4    应用程序、安全性及系统三类日志                          图 2.5.5    其他日志
还可以在【运行】对话框中输入【eventvwr】命令，打开【事件查看器】窗
口，查看相关的日志，如图 2.5.6 所示。
56
第 2 章
网络安全应急响应工程师基础技能
图 2.5.6  【事件查看器】窗口
在应急响应中还经常使用 PowerShell 日志，图 2.5.7 是典型的 PowerShell 日
志详细情况。
图 2.5.7    典型的 PowerShell 日志详细情况
2）日志常用事件 ID
Windows 系统中的每个事件都有其相应的事件 ID，表 2.5.1 是应急响应中常
57
网络安全应急响应技术实战指南
用的事件 ID，其中旧版本指 Windows  2000  专业版/Windows  XP/Windows  Server
2003，新版本指 Windows Vista/Windows 7/Windows 8 /Windows 10/Windows Server
2008 等。
表 2.5.1    应急响应中常用的事件 ID
事件 ID（旧版本）  事件 ID（新版本）
描        述
事件日志
528
529
680
624
636
632
2934
2944
2949
4624
4625
4776
4720
4732
4728
7030
7040
7045
成功登录
失败登录
成功/失败的账户认证
创建用户
添加用户到启用安全性的本地组中
添加用户到启用安全性的全局组中
服务创建错误
IPSEC 服务的启动类型已从禁用更改为自动启动
服务创建
安全
安全
安全
安全
安全
安全
系统
系统
系统
成功/失败登录事件提供的有用信息之一是用户/进程尝试登录（登录类型），
Windows 系统将此信息显示为数字，表 2.5.2 是数字及其对应说明。
表 2.5.2    数字及其对应说明
数        字
登  录  类  型
描        述
Interactive
用户登录到本机
Network
Batch
Service
Unlock
如果网络共享，或使用 net use 访问网络共享、使用 net view 查看网
络共享，那么用户或其他计算机从网络登录到本机
批处理登录类型，无须用户干预
服务控制管理器登录
用户解锁主机
NetworkCleartext
用户从网络登录到此计算机，用户密码用非哈希的形式传递
NewCredentials
进程或线程克隆了其当前令牌，但为出站连接指定了新凭据
Remotelnteractive
使用终端服务或远程桌面连接登录
Cachedlnteractive
法验证凭据），如果主机不能连接域控，以前使用域账户登录过这台
用户使用本地存储在计算机上的凭据登录计算机（域控制器可能无
CachedRemotelnteractive
与  Remotelnteractive  相同，内部用于审计
主机，那么再登录就会产生这样的日志
CachedUnlock
登录尝试解锁
2
3
4
5
7
8
9
10
11
12
13
58
第 2 章
网络安全应急响应工程师基础技能
表 2.5.3 是登录相关日志事件 ID 对应的描述。
表 2.5.3    登录相关日志事件 ID 对应的描述
事件 ID
名        称
描        述
4624
4625
用户登录成功
大部分登录事件成功时会产生的日志
用户登录失败
大部分登录事件失败时会产生的日志（解锁屏幕并不会产生这个日
志）
4672
特殊权限用户登录
特殊权限用户登录成功时会产生的日志，例如，登录 Administrator，
一般会看到 4624 和 4672 日志一起出现
4648
显式凭证登录
一些其他的登录情况，如使用 runas /user 以其他用户身份运行程序时
会产生的日志（不过在使用 runas 时，也会产生一条 4624 日志）
表 2.5.4 是常用启动事件相关日志事件 ID 对应的描述。
表 2.5.4    常用启动事件相关日志事件 ID 对应的描述
事        件
事件 ID
事  件  级  别  事  件  日  志
事  件  来  源
关机初始化失败
1074
Windows 关闭
Windows 启动
13
12
警告
信息
信息
User32
系统
系统
User32
Microsoft-Windows-Kernel-General
Microsoft-Windows-Kernel-General
表 2.5.5 是日志被清除相关日志事件 ID 对应的描述。
表 2.5.5    日志被清除相关日志事件 ID 对应的描述
事        件
事件 ID
事  件  级  别  事  件  日  志
事  件  来  源
事件日志服务关闭
1100
事件日志被清除
事件日志被清除
104
1102
信息
信息
信息
安全
系统
安全
Microsoft-Windows-EventLog
Microsoft-Windows- EventLog
Microsoft-Windows- EventLog
3）日志分析
日志分析就是在众多的日志中找出自己需要的日志，一般 Windows 系统中日
志的分析主要有以下几种方法。
（1）通过内置的日志筛选器进行分析。
使用日志筛选器可以对记录时间、事件级别、任务类别、关键字等信息进行
筛选，如图 2.5.8 所示。
59
网络安全应急响应技术实战指南
图 2.5.8    日志筛选器
（2）通过 PowerShell 对日志进行分析。
在使用 PowerShell 进行日志分析时，需要有管理员权限才可以对日志进行
操作。
通 过 PowerShell 进 行 查 询 最 常 用 的 两 个 命 令 是 【 Get-EventLog 】 和
【Get-WinEvent】，两者的区别是【Get-EventLog】只获取传统的事件日志，而
【Get-WinEvent】是从传统的事件日志（如系统日志和应用程序日志）和新 Windows
事件日志技术生成的事件日志中获取事件，其还会获取 Windows 事件跟踪（ETW）
生成的日志文件中的事件。注意，【Get-WinEvent】需要 Windows Vista、Windows
Server  2008 或更高版本的 Windows 系统，还需要 Microsoft  .NET  Framework  3.5
及以上的版本。总体来说，【Get-WinEvent】功能更强大，但是对系统和.NET 的
版本有更多要求。
以下列举部分实例，读者可以根据语法及相关帮助文档编写更多功能。
使用【Get-EventLog Security -InstanceId 4625】命令，可获取安全性日志下事
件 ID 为 4625（失败登录）的所有日志信息，如图 2.5.9 所示。
注意，使用【Get-WinEvent】和【Get-EventLog】命令的查询语句是不同的。
使用【Get-WinEvent -FilterHashtable @{LogName='Security';ID='4625'}】命令，也
可获取安全性日志下事件 ID 为 4625 的所有日志信息，如图 2.5.10 所示。
60
第 2 章
网络安全应急响应工程师基础技能
图 2.5.9    日志筛选
图 2.5.10    日志筛选
通过设置起始时间和终止时间变量，可查询指定时间内的事件。先设置起始
时间变量 StartTime 和终止时间变量 EndTime，再使用【Get-WinEvent】命令，可
61
网络安全应急响应技术实战指南
查询这段时间内的系统日志情况，执行结果如图 2.5.11 所示。
图 2.5.11    执行结果
通过逻辑连接符可对多种指定日志 ID 进行联合查询。例如，使用【Get-
WinEvent -LogName system | Where-Object {$_.ID -eq "12" -or $_.ID -eq "13"}】命
令，可对 Windows 启动和关闭日志进行查询，如图 2.5.12 所示。
图 2.5.12    联合查询
62
第 2 章
网络安全应急响应工程师基础技能
（3）通过相关的日志工具进行分析查询。以下列举其中几个常用工具。
FullEventLogView：FullEventLogView 是一个轻量级的日志检索工具，其是绿
色版、免安装的，检索速度比 Windows 系统自带的检索工具要快，展示效果更好，
如图 2.5.13 所示。
图 2.5.13    FullEventLogView 工具
Event Log Explorer：Event Log Explorer 是一个检测系统安全的软件，可查看、
监视和分析事件记录，包括安全性、系统、应用程序和其 Windows 系统事件记录，
如图 2.5.14 所示。
图 2.5.14    Event Log Explorer 工具
63
网络安全应急响应技术实战指南
Log Parser：Log Parser 是微软公司推出的日志分析工具，其功能强大，使用
简单，可以分析基于文本的日志文件、XML 文件、CSV（逗号分隔符）文件，以
及操作系统的事件日志、注册表、文件系统、Active  Directory 等。其可以像使用
SQL  语句一样查询分析数据，甚至可以把分析结果以各种图表的形式展现出来。
查 看 登 录 成 功 的 所 有 事 件 ： 使 用 【 LogParser.exe  -i:EVT  -o:DATAGRID
"SELECT * FROM C:\Security.evtx where EventID=4624"】命令，可查看事件 ID 为
4624，即登录成功的所有事件，如图 2.5.15 所示。
图 2.5.15    使用 Log Parser 工具查看登录成功的所有事件
指 定 登 录 时 间 范 围 的 事 件 ： 使 用 【 LogParser.exe  -i:EVT  -o:DATAGRID
"SELECT * FROM C:\Security.evtx where TimeGenerated>'2018-01-01 23:59:59' and
TimeGenerated<'2019-06-01 23:59:59' and EventID=4625"】命令，可查看从 2018 年
1 月 1 日 23 时 59 分 59 秒到 2019 年 6 月 1 日 23 时 59 分 59 秒，事件 ID 为 4625，
即登录失败的所有事件，如图 2.5.16 所示。
图 2.5.16    使用 Log Parser 工具查看指定登录时间范围的事件
提取登录成功用户的用户名和 IP 地址：使用【LogParser.exe -i:EVT -o:DATAGRID
"SELECT  EXTRACT_TOKEN(Message,13,  '  ')  as  EventType,  TimeGenerated  as
LoginTime,  EXTRACT_TOKEN(Strings,5,  '|')  as  Username,  EXTRACT_TOKEN
64
第 2 章
网络安全应急响应工程师基础技能
(Message,38,' ') as Loginip FROM c:\Security.evtx where EventID=4624"】命令，可
查看事件 ID 为 4624（即登录成功的用户）的用户名和 IP 信息，如图 2.5.17 所示。
图 2.5.17    使用 Log Parser 工具提取登录成功用户的用户名和 IP 地址
查 看 系 统 历 史 开 关 机 记 录 ： 使 用 【 LogParser.exe  -i:EVT  -o:DATAGRID
"SELECT  TimeGenerated,EventID,Message  FROM  C:\System.evtx  where  EventID=12
or EventID=13"】命令，可查看系统历史开关机记录，如图 2.5.18 所示。
图 2.5.18    使用 Log Parser 工具查看系统历史开关机记录
2．Linux 系统
1）日志概述
Linux 系统中的日志一般存放在目录“/var/log/”下，具体的日志功能如下。
/var/log/wtmp：记录登录进入、退出、数据交换、关机和重启，即 last。
/var/log/cron：记录与定时任务相关的日志信息。
/var/log/messages：记录系统启动后的信息和错误日志。
/var/log/apache2/access.log：记录 Apache 的访问日志。
/var/log/auth.log：记录系统授权信息，包括用户登录和使用的权限机制等。
65
网络安全应急响应技术实战指南
/var/log/userlog：记录所有等级用户信息的日志。
/var/log/xferlog(vsftpd.log)：记录 Linux FTP 日志。
/var/log/lastlog：记录登录的用户，可以使用命令 lastlog 查看。
/var/log/secure：记录大多数应用输入的账号与密码，以及登录成功与否。
/var/log/faillog：记录登录系统不成功的账号信息。
通过查看相关的日志文件可以获取相关的日志信息。以下列举常用的日志使
用方法。
使用【cat /var/log/cron】命令，可查看任务计划相关的操作日志，如图 2.5.19
所示。
图 2.5.19    查看任务计划相关的操作日志
使用【cat  /var/log/messages】命令，可查看整体系统信息，其中也记录了某
个用户切换到 root 权限的日志，如图 2.5.20 所示。
使用【cat  /var/log/secure】命令，可查看验证和授权方面的信息，如 sshd 会
将所有信息（包括失败登录）记录在这里，如图 2.5.21 所示。
66
第 2 章
网络安全应急响应工程师基础技能
图 2.5.20  查看整体系统信息
图 2.5.21  查看验证和授权方面的信息
使用【ls -alt /var/spool/mail】命令，可查看邮件相关日志记录文件，如图 2.5.22
所示。
图 2.5.22    查看邮件相关日志记录文件
使用【cat /var/spool/mail/root】命令，可发现针对 80 端口的攻击行为（当 Web
访问异常时，及时向当前系统配置的邮箱地址发送报警邮件），如图 2.5.23 所示。
67
网络安全应急响应技术实战指南
图 2.5.23  报警邮件日志查看
2）日志分析
对于 Linux 系统日志的分析主要使用【grep】、【sed】、【sort】和【awk】等命
令。常用查询日志命令及功能如下。
【tail -n 10 test.log】命令：查询最后 10 行的日志。
【tail -n +10 test.log】命令：查询 10 行之后的所有日志。
【head -n 10 test.log】命令：查询头 10 行的日志。
【head -n -10 test.log  】命令：查询除了最后 10 行的其他所有日志。
在*.log 日志文件中统计独立 IP 地址个数的命令如下。
【awk '{print $1}' test.log | sort | uniq | wc -l】
【awk '{print $1}' /access.log | sort | uniq -c | sort -nr | head -10】
查找指定时间段日志的命令如下。
【sed -n '/2014-12-17 16:17:20/,/2014-12-17 16:17:36/p' test.log】
【grep '2014-12-17 16:17:20' test.log  】
定位有多少 IP 地址在暴力破解主机 root 账号的命令如下。
【 cat  /var/log/secure  |awk  '/Accepted/{print  $(NF-3)}'|sort|uniq  -c|awk  '{print
$2"="$1;}'(CentOS)  】
68
第 2 章
网络安全应急响应工程师基础技能
查看登录成功的 IP 地址的命令如下。
【 cat  /var/log/auth.log  |awk  '/Failed/{print  $(NF-3)}'|sort|uniq  -c|awk  '{print
$2"="$1;}' ) (ubuntu)  】
查看登录成功日期、用户名、IP 地址的命令如下。
【grep "Accepted " /var/log/secure | awk '{print $1,$2,$3,$9,$11}'】
3．其他日志
除了可对 Windows 和 Linux 系统日志进行分析，还可对 Web 日志、中间件日
志、数据库日志、FTP 日志等进行分析。日志分析的方法一般是结合系统命令及
正则表达式，或者利用相关成熟的工具进行分析，分析的目的是提取相关特征规
则，对攻击者的行为进行分析。
需要重点排查的其他日志常见位置如下。
1）IIS 日志的位置
%SystemDrive%\inetpub\logs\LogFiles；
%SystemRoot%\System32\LogFiles\W3SVC1；
%SystemDrive%\inetpub\logs\LogFiles\W3SVC1；
%SystemDrive%\Windows\System32\LogFiles\HTTPERR。
2）Apache 日志的位置
/var/log/httpd/access.log；
/var/log/apache/access.log；
/var/log/apache2/access.log；
/var/log/httpd-access.log。
3）Nginx 日志的位置
默认在/usr/local/nginx/logs 目录下，access.log 代表访问日志，error.log 代表错
误日志。若没有在默认路径下，则可以到 nginx.conf 配置文件中查找。
4）Tomcat 日志的位置
默认在 TOMCAT_HOME/logs/目录下，有 catalina.out、catalina.YYYY-MM-
DD.log、localhost.YYYY-MM-DD.log、localhost_access_log.YYYY-MM-DD.txt、
host-manager.YYYY-MM-DD.log、manager.YYYY-MM-DD.log 等几类日志。
69
