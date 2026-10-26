---
name: security-hardening
description: 安全加固/基线加固/防守题 — 按题目检查器修系统、中间件、Web 漏洞和权限，保证服务可用，完成验证拿 flag；不是重新找漏洞打进去。
requires_target: true
routing:
  task_types: [ctf, audit]
  target_types: [host, web, ctf]
  protocols: [http, ssh]
  aliases:
    - 安全加固
    - 安全基线
    - 系统加固
    - 中间件加固
    - 主机加固
    - 基线加固
    - 权限配置
    - harden
    - hardening
    - security baseline
    - baseline hardening
---

# 安全加固 Skill

比赛里的加固题是**防守题**：题目给你一台/一套“带病”的靶机、中间件或 Web 应用，按题目要求把漏洞和错误配置修掉，同时保证服务仍然可用；平台用检查脚本/验证按钮判分，通过才给 Flag。

它和渗透题的目标相反：**不要 getshell，要让检查器满意且服务不死。** 你不需要再挖一个新洞，只需要找到并修掉题目指定的不合规项。

## 识别信号

- 题目出现“安全加固 / 基线加固 / 系统加固 / 中间件加固 / 权限配置 / 漏洞修复 / hardening / baseline”
- 题目说“完成验证得分 / 跑检查器 / 点击验证 / 加固后提交 Flag”
- 给你的是 SSH、RDP、Web 终端或一台已经能跑的服务，而不是一个待渗透的站点

> 如果题目只写“加固”而没有“安全加固”，建议显式 `/security-hardening` 或在 goal 里写
> `Use VulnClaw skill security-hardening. ...`，避免被其他 skill 抢路由；solver 的
> `_looks_like_hardening` 仍会按“加固”注入加固指令和工具面。

## 工作流（30–40 分钟）

1. **先找检查器，再动手。** 常见位置：`/root/check/*`、`/root/flags`、`/tmp/secret`；定时任务：`crontab -l`、`/etc/cron.*`、`systemctl list-timers --all`；进程：`ps aux | grep -Ei 'check|verify'`；平台上的“验证”按钮。把每条要求抄成 checklist。只读题目环境内允许读的文件；**不要修改/绕过检查器，不要攻击平台**。
2. **快照。** 改之前把要动的配置 `cp -a` 到备份目录，`tar` Web 根，必要时 `mysqldump`；保持第二个 SSH/终端会话。不要只开一个窗口改 SSH/防火墙。
3. **基线巡检。** 账户与空口令、UID=0、SSH 生效配置（`sshd -T`）、sudoers、SUID/世界可写、监听端口/服务、中间件配置、Web 根备份文件、cron。先看清现状，不要上来就改。
4. **按优先级修。** 权限/账户 → 暴露面（端口/服务） → 中间件配置 → Web 代码。**一次只改一项**，先语法检查/平滑重载，再重跑检查器；失败就回滚这一项，不要连续盲改。
5. **保活验证。** `sshd -t`、`nginx -t`、`apachectl configtest`、`systemctl reload`（能 reload 不 restart）、`curl` 正常页面、`mysqladmin ping`。不要关掉检查器要用的 SSH 密码登录，不要停检查器要测的服务，不要 `chmod 777` Flag/Web 根，不要盲删 SUID。
6. **远程目标用对工具。** SSH 目标用 `remote_exec`/`remote_collect`（先配 `remote.hosts` 别名）；`shell_command`/`python_execute` 跑在**本机**，不是靶机。每次声称“已修复”前，确认命令确实在目标上执行。
7. **记账。** 先用 `blackboard_create_angle` 开一条加固路径；每验证一项，调用 `blackboard_add_fact` 记录“改了什么 + 哪条命令/输出证明”，并 `blackboard_hit_angle` 记录该路径；检查器通过时 `blackboard_set_lock` 记下验证结果。加固 run 如果只改文件、不记账，可能被 stall guard 判成没有进展。
8. **拿 Flag / 报告。** 检查器输出 Flag 时，把原始输出记入证据，并在 `FINAL:` 里原样写出。只返回通过/不通过时，报告已验证项和检查器输出，不要编造 Flag。如果题目是“提交 Flag”型，goal 里要写明“跑检查器拿 flag”；如果平台是点击验证型（不返 flag），goal 里不要写“拿 flag”，否则完成门会一直要 Flag。
9. **时间盒。** 30–40 分钟不成就保存现场、报告已验证项和剩余项，先去做其他分项。**不要套用 CTF 的 8-turn fail-fast**；加固题的价值在逐项验证，不在快速换题。

## 铁律

- 不过度加固：检查器可能同时测正常功能；改到“刚好满足要求”即可。
- 不把“改配置文件”当成“已生效”：先 reload，再用生效配置/行为验证。
- 不猜检查器：能读题目给的检查命令就读；读不到就用平台验证按钮的失败提示逐项排。
- 不在 Web 根留 `.bak/.swp/.git/.env`；不把备份文件放在可访问目录。
- 不把 Flag 改成 world-readable；需要让某个用户读时用组/ACL，并确认父目录可进入。
- 不攻击/篡改判分平台；规则明确禁止，违规取消成绩。

## 参考文件

按需用 `load_skill_reference` 读取：

- `00-quick-checklist.md` — 30 分钟检查清单、检查器发现、常见翻车点
- `01-linux-baseline.md` — 账户、SSH、权限、SUID、服务、防火墙、sysctl、cron
- `02-middleware-and-db.md` — Nginx/Apache/Tomcat/MySQL/Redis/VSFTPD
- `03-web-remediation.md` — SQLi/XSS/上传/包含/RCE/穿越/SSRF/反序列化
- `04-permissions-and-verification.md` — chmod/chown/setfacl/sudoers、Flag 权限、验证
- `05-windows-baseline.md` — Windows/IIS/SMB/RDP/账户策略
