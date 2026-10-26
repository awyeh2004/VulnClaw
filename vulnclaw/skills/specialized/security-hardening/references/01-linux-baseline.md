# 01 — Linux 系统基线加固

> 先备份：`mkdir -p /root/hardening-backup && cp -a /etc/ssh/sshd_config /etc/passwd /etc/shadow /etc/group /etc/sudoers /root/hardening-backup/`
> 改 SSH/防火墙前保持第二个会话。

## 1. 账户与密码

```bash
# 空口令账号
awk -F: '($2==""){print $1}' /etc/shadow
# 锁定（题目要求删除时再 userdel）
passwd -l USER
usermod -L USER

# 非 root 的 UID 0
awk -F: '($3==0){print $1}' /etc/passwd
# 改成普通 UID（先确认不是 root）
usermod -u 1001 USER

# 服务账号不应有登录 shell
usermod -s /usr/sbin/nologin USER

# 密码策略
grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)' /etc/login.defs
# 常见基线：PASS_MAX_DAYS 90、PASS_MIN_LEN 8、PASS_WARN_AGE 7
chage -l USER
```

`/etc/login.defs` 示例：

```text
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_MIN_LEN    8
PASS_WARN_AGE   7
```

需要复杂度时用 `pam_pwquality`：

```bash
grep -rE 'pam_pwquality|pam_cracklib' /etc/pam.d/ 2>/dev/null
# /etc/security/pwquality.conf:
# minlen = 8
# dcredit = -1
# ucredit = -1
# lcredit = -1
# ocredit = -1
```

## 2. SSH

`/etc/ssh/sshd_config` 最小改动：

```text
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
```

可选（先确认检查器不用密码登录，且你已有 key）：

```text
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers youruser
```

应用：

```bash
sshd -t && systemctl reload sshd
sshd -T | grep -Ei 'permitrootlogin|permitemptypasswords|maxauthtries|passwordauthentication'
```

> 不要因为“更安全”就关掉检查器要用的登录方式；题目要求优先。

## 3. sudo 与权限

```bash
visudo -c
sudo -l
grep -rE 'NOPASSWD|ALL=\(ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
# 删除不必要的 NOPASSWD；限制到具体命令：
# deploy ALL=(root) NOPASSWD: /bin/systemctl restart nginx
```

关键文件权限：

```bash
chown root:shadow /etc/shadow; chmod 640 /etc/shadow
chown root:root /etc/passwd;  chmod 644 /etc/passwd
chown root:root /etc/group;   chmod 644 /etc/group
chown root:root /etc/gshadow; chmod 640 /etc/gshadow
chmod 600 /etc/ssh/sshd_config
stat -c '%a %U:%G %n' /etc/shadow /etc/passwd /etc/group /etc/gshadow /etc/ssh/sshd_config
```

> 以题目/检查器要求为准；有的系统 shadow 是 `000` 或 `640`，不要死记一个值。

## 4. SUID / 世界可写

```bash
# 先看，不要盲删
find / -xdev -type f -perm -4000 2>/dev/null
find / -xdev -type f -perm -2000 2>/dev/null

# 只去掉题目要求/明显异常的
chmod u-s /path/to/file
chmod g-s /path/to/file

# 世界可写文件（排除 /tmp 等）
find / -xdev -type f -perm -0002 \
  -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' \
  -not -path '/run/*' -not -path '/tmp/*' -not -path '/var/tmp/*' 2>/dev/null
chmod o-w /path/to/file

# 世界可写且无 sticky 的目录
find / -xdev -type d -perm -0002 ! -perm -1000 \
  -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' \
  -not -path '/run/*' -not -path '/tmp/*' -not -path '/var/tmp/*' 2>/dev/null
chmod +t /path/to/dir
chmod o-w /path/to/dir
```

> 常见的合法 SUID：`su`、`sudo`、`passwd`、`mount`、`umount`、`ping`、`chsh`、`gpasswd`、`newgrp`、`pkexec`。不要为了“干净”全删。

## 5. 服务与端口

```bash
ss -tulnp
systemctl --failed --no-pager
systemctl list-unit-files --state=enabled --no-pager
```

按题目要求关闭不必要服务：

```bash
systemctl disable --now telnet.socket 2>/dev/null
systemctl disable --now rsh.socket rlogin.socket 2>/dev/null
systemctl disable --now vsftpd 2>/dev/null
systemctl disable --now rpcbind avahi-daemon cups 2>/dev/null
```

> 不要停检查器要测试的 Web/数据库/SSH 服务；不确定就先不动。

## 6. 防火墙

**先放行 SSH，再开默认拒绝**，并保持第二个会话：

```bash
# ufw
ufw allow 22/tcp
ufw allow 80,443/tcp
ufw default deny incoming
ufw default allow outgoing
ufw enable
ufw status verbose

# firewalld
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
firewall-cmd --list-all

# iptables（谨慎，先确认规则不会锁死自己）
iptables -P INPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
```

如果题目只要求“禁止某端口外部访问”，只加一条拒绝，不要改默认策略：

```bash
# 例：Redis 只允许本机（配合 bind 127.0.0.1）
iptables -A INPUT -p tcp --dport 6379 ! -s 127.0.0.1 -j DROP
```

## 7. 内核参数

```bash
cat >/etc/sysctl.d/99-hardening.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.ip_forward = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF
sysctl -p /etc/sysctl.d/99-hardening.conf
```

> `ip_forward=0` 只在主机不是路由器时用；如果题目要求转发/内网网关，保留 1。

## 8. umask / cron / 后门

```bash
# umask
grep -R '^[[:space:]]*umask' /etc/profile /etc/bashrc /etc/profile.d 2>/dev/null
# 常见基线：027 或 022，以题目为准

# cron
crontab -l
ls -la /etc/cron.* /var/spool/cron 2>/dev/null
grep -rInE 'curl|wget|base64|bash -i|nc |/dev/tcp|python -c' /etc/cron* /var/spool/cron 2>/dev/null

# 可疑 webshell/后门
find /var/www -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.war' \) -mtime -7 2>/dev/null
grep -rIlE 'eval[[:space:]]*\(|base64_decode|shell_exec|passthru|popen|assert[[:space:]]*\(' /var/www 2>/dev/null
```

## 9. 完成后自检

```bash
sshd -t
sshd -T | grep -Ei 'permitrootlogin|permitemptypasswords|maxauthtries'
stat -c '%a %U:%G %n' /etc/shadow /etc/passwd /etc/group
ss -tulnp
systemctl is-active ssh 2>/dev/null
```
