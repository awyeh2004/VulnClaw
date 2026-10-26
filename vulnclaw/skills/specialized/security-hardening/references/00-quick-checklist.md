# 00 — 加固速查清单（先读这份）

## 0. 找检查器

```bash
ls -la /root/check /root/flags /tmp/secret 2>/dev/null
cat /root/check/* 2>/dev/null

crontab -l 2>/dev/null
ls -la /etc/cron.* /var/spool/cron 2>/dev/null
systemctl list-timers --all 2>/dev/null
ps aux | grep -Ei 'check|verify' | grep -v grep

# 题目说明/任务清单
find / -maxdepth 3 \( -iname '*readme*' -o -iname '*task*' -o -iname '*check*' \) 2>/dev/null | head -30
```

- 检查器可读：按它的断言逐条做，不要猜。
- 检查器不可读：先点平台“验证”，用失败提示排；仍然没有提示就按题目文字列 checklist。
- 只读题目环境内的文件；不要改检查器、不要攻击平台。

## 0.1 SSH 靶机：先配 `remote.hosts`

加固目标如果是 SSH 可达的 Linux 主机，先在 VulnClaw 配置里加别名，再用
`remote_exec`/`remote_collect`；`shell_command`/`python_execute` 跑在本机，不会改靶机。

```yaml
remote:
  hosts:
    victim1:
      hostname: 10.0.0.5
      port: 22
      username: root
      password: "题目给的密码"     # 或 key_file: C:/Users/me/.ssh/id_ed25519
      host_key_policy: accept_new  # 首次 TOFU；之后指纹变化会拒绝
```

```text
remote_exec(host="victim1", command="sshd -T | grep -Ei 'permitrootlogin|maxauthtries'")
```

> `remote_exec` 的写操作（改配置、chmod、重启服务）走审批门，只读命令不会。
> 加固前确认审批模式或有人在旁边批准；否则 run 会停在等待输入，不是卡死。

## 1. 30 分钟流程

| 时间 | 动作 |
|---|---|
| 0–3 min | 读题、找检查器、抄 checklist |
| 3–5 min | 快照：`cp -a` 配置、`tar` Web 根、`mysqldump`；开第二个会话 |
| 5–10 min | 基线巡检：账户/SSH/权限/端口/中间件/Web 根/cron |
| 10–25 min | 按“权限/账户 → 暴露面 → 中间件 → 代码”逐项修，每项验证 |
| 25–35 min | 跑检查器、保活验证、处理失败项 |
| 35–40 min | 提交 Flag；没通过就报告已验证项，撤 |

## 2. 最小巡检命令

```bash
# 账户
awk -F: '($2==""){print "EMPTY:",$1}' /etc/shadow 2>/dev/null
awk -F: '($3==0){print "UID0:",$1}' /etc/passwd
getent passwd | awk -F: '($7!~/(nologin|false)$/){print $1,$7}'

# SSH 生效配置
sshd -T 2>/dev/null | grep -Ei 'permitrootlogin|passwordauthentication|permitemptypasswords|maxauthtries'

# 权限
stat -c '%a %U:%G %n' /etc/shadow /etc/passwd /etc/group 2>/dev/null
find / -xdev -type f -perm -4000 2>/dev/null
find / -xdev -type f -perm -0002 2>/dev/null
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null

# 服务/端口
ss -tulnp
systemctl --failed --no-pager
systemctl list-unit-files --state=enabled --no-pager | head -50

# 中间件
nginx -T 2>/dev/null | grep -Ei 'server_tokens|autoindex|listen|root'
apachectl -S 2>/dev/null
mysql -uroot -e "SELECT user,host FROM mysql.user;" 2>/dev/null
ss -lntp 2>/dev/null | grep 6379

# Web 根
find /var/www -maxdepth 4 \( -name '.git' -o -name '.env' -o -name '*.bak' -o -name '*.swp' -o -name '*.old' -o -name '*.zip' -o -name '*.sql' \) 2>/dev/null

# cron
crontab -l 2>/dev/null
grep -rInE 'curl|wget|base64|bash -i|nc |/dev/tcp' /etc/cron* /var/spool/cron 2>/dev/null
```

## 3. 常见翻车点

1. **过度加固**：关了 SSH 密码登录/停了服务，检查器本身用密码登录或要测功能 → 直接失败。
2. **改文件不等于生效**：改完 `sshd_config`/`nginx.conf` 没 `sshd -t`/`nginx -t` 就重启，或者没 reload。
3. **把自己关在门外**：改 SSH/防火墙只有一个会话；先留第二个会话。
4. **Flag 权限改错方向**：`chmod 777` 满足不了“只给指定用户读”；只改文件没改父目录执行位，检查器进不去。
5. **Web 根留备份**：`.bak/.swp/.git/.env` 被检查器扫到，直接扣分。
6. **盲删 SUID/盲停服务**：题目没要求就不要动；先看检查器断言。
7. **只在本地改**：`shell_command`/`python_execute` 跑在本机；SSH 靶机必须用 `remote_exec`。
8. **不记账**：连续改配置不记 fact/angle，stall guard 可能判成没进展；每验证一项就记。

## 4. 完成前自检

```bash
# 服务还在
systemctl is-active ssh nginx apache2 mysql redis-server 2>/dev/null
ss -tulnp

# 正常功能还在
curl -s -o /dev/null -w 'home:%{http_code}\n' http://127.0.0.1/
mysqladmin -uroot ping 2>/dev/null
redis-cli ping 2>/dev/null

# 跑题目检查器
/root/check/* 2>/dev/null || true
```

检查器通过后立刻提交；不要为了“再优化一下”错过窗口。
