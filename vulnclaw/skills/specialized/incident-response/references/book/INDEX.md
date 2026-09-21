# 应急响应比赛题目模式索引

> 基于出题方教材《网络安全应急响应技术实战指南》14 个典型案例的结构化提炼。
> 每个模式对应"标准比赛问法 → 排查路径 → 答案依据"三段式，供解题时快速定位。

## 使用方法

比赛题给出"被入侵服务器 + 基础提示"后：
1. 先按现象分型（下方表格），定位到对应案例模式
2. 按模式的排查路径逐步执行，每步结论挂证据
3. 按标准问法组织答案提交

## 分型速查表

| 现象关键词 | 场景 | 参考文件 | 案例数 |
|---|---|---|---|
| 加密文件/勒索信/后缀变异 | 勒索病毒 | ch4-ransomware-guide.md + ch4-ransomware-cases.md | 2 |
| CPU占用高/矿池/stratum/xmr | 挖矿木马 | ch5-cryptomining-guide.md + ch5-cryptomining-cases.md | 2 |
| 可疑PHP/JSP文件/一句话木马 | Webshell | ch6-webshell-guide.md + ch6-webshell-cases.md | 3 |
| 首页被改/黑页/暗链 | 网页篡改 | ch7-defacement-guide.md | 2 |
| 流量异常/带宽占满/SYN flood | DDoS | ch8-ddos-guide.md | 1 |
| 数据外传/敏感信息泄露 | 数据泄露 | ch9-datalleak-guide.md | 2 |
| DNS解析异常/页面跳转/劫持 | 流量劫持 | ch10-traffic-hijack.md | 3 |

## 标准问法 → 排查路径映射

### Q1: 攻击者 IP 是什么？
- Linux: `grep -E "Accepted|Failed" /var/log/auth.log` / nginx access.log 中异常 POST/扫描 UA
- Windows: 事件查看器 4624/4625（登录成功/失败）来源 IP / IIS 日志
- **来源**: ch2-log-analysis.md 登录类型表 + 各案例"日志排查"节

### Q2: 恶意文件路径是什么？
- 时间点圈定: `find / -newerct "2020-05-13" -not -newerct "2020-05-14"` (以已知入侵日为轴)
- Web 目录: `find /var/www -name "*.php" -mtime -30` / `grep -rE "eval|assert|system" --include="*.php"`
- 临时目录: /tmp /dev/shm /var/tmp 下可执行文件
- Windows: Prefetch / 最近修改的 exe / %APPDATA% / %TEMP%
- **来源**: ch2-file-artifacts.md + ch6-webshell-guide.md Webshell排查节

### Q3: 首次入侵时间是什么？
- 日志首条异常登录: auth.log "Accepted password for [invalid user]" / 4624 事件
- Web 日志首次扫描/上传行为: access.log 中首次出现 sqlmap/扫描器 UA
- 文件创建时间: 恶意文件的 stat / ls -la 时间戳（注意 touch -r 反取证）
- **来源**: ch2-log-analysis.md + 各案例"入侵时间确定"节

### Q4: 利用的是什么漏洞？
- Web 日志分析攻击 payload（URL 中的 union select / eval / 上传路径）
- 对比漏洞特征: 永恒之蓝(MS17-010,445端口) / SQL注入 / 文件上传 / 反序列化
- 结合恶意文件落地的 Web 路径推断入口点
- **来源**: 各案例"漏洞分析"节 + ch6-webshell-guide.md 漏洞复现

### Q5: 持久化机制是什么？
- Linux: crontab -l / /etc/cron.* / ~/.ssh/authorized_keys / systemd timer / LD_PRELOAD(/etc/ld.so.preload)
- Windows: 注册表 Run 键(HKLM\...\Run) / 计划任务 schtasks / 服务 / 启动文件夹 / WMI事件订阅
- 隐藏账号: Linux UID=0 的非 root 用户 / Windows 尾缀 $ 的账号(如 1q$)
- **来源**: ch2-system-basics.md 启动项+任务计划 + ch2-accounts.md + 25-process-service.md

### Q6: 清除方案是什么？
- 杀进程 → 删恶意文件 → 清持久化(cron/Run键/隐藏账号) → 修漏洞 → 加固
- 勒索特殊: 先隔离(断网) → 确定家族 → 查解密工具 → 恢复备份（禁止直接支付）
- **来源**: 各章"常规处置方法"+"清除加固"节

## 14 案例的考点要素卡

### 勒索-GlobeImposter (ch4 cases)
- 隐藏用户 `1q$` / 加密后缀 `.RESERVE` / svchost.exe 假进程 / RDP 3389 入口
- 考点: 隐藏账号发现 + 勒索家族识别 + 错误处置(直接重装=丢分)

### 勒索-Crysis (ch4 cases)
- 加密后缀 `.id-xxx.[email].Crysis` / 计划任务持久化 / RDP 弱口令
- 考点: 勒索信邮箱提取 + 计划任务排查 + RDP 日志分析

### 挖矿-Windows (ch5 cases)
- 永恒之蓝 445 传播 / TrustedHostex.exe / 高 CPU 占用
- 考点: 进程定位(ProcessExplorer) + 网络连接(矿池) + MS17-010 补丁

### 挖矿-Linux (ch5 cases)
- crontab 定时任务 / base64 编码命令 / /tmp 下二进制自删除
- 考点: cron 排查 + base64 解码 + 无文件挖矿识别

### Webshell-篡改 (ch6 cases)
- 弱密码 asd123 / 后台登录页面被改 / 2018-11-29 04:47 入侵
- 考点: 弱口令发现 + 入侵时间(日志) + 篡改定位

### Webshell-Linux (ch6 cases)
- PHP 一句话 / /var/www/html 路径 / rootkit 检测
- 考点: webshell 扫描 + 日志溯源攻击 IP + rootkit 检测(chkrootkit/rkhunter)

### Webshell-Windows (ch6 cases)
- ASPX 大马 / IIS 日志分析 /隐藏目录
- 考点: IIS 日志格式 + ASPX 特征码 + 事件日志关联

### 篡改-主页 (ch7 guide)
- 首页 index.html 被替换 / 数据库注入篡改 / CDN/反向代理层
- 考点: 篡改层级定位(文件/数据库/CDN) + 恢复优先级

### 篡改-暗链 (ch7 guide)
- 首页底部暗链 SEO / 外链赌博/色情 / js 动态插入
- 考点: 暗链发现(grep 外链域名) + 清除 + 来源分析

### DDoS (ch8 guide)
- SYN flood / CC 攻击 / DNS 放大
- 考点: 攻击类型判断(流量特征) + 缓解措施 + 溯源

### 数据泄露-Web服务器 (ch9 guide)
- Hawkeye 工具 / Sysmon 日志 / 数据外传通道
- 考点: Sysmon 日志分析 + 异常网络连接 + 数据量统计

### 数据泄露-Web应用 (ch9 guide)
- SQL 注入拖库 / union select / 后台弱口令
- 考点: Web 日志 payload 分析 + 数据库审计日志

### 劫持-DNS (ch10 guide)
- nslookup/dig 检测 / hosts 文件篡改 / DNS 服务器污染
- 考点: DNS 解析链排查 + hosts 文件 + 防火墙规则

### 劫持-搜索引擎 (ch10 guide)
- 搜索引擎快照劫持 / UA 判断跳转 / 302 重定向
- 考点: UA 区分的跳转代码 + Nginx 配置审查

---

> 每个要素卡只列考点关键词，完整操作步骤见对应章节文件。
> 比赛时: 分型 → 读对应要素卡 → 按标准问法组织答案。
