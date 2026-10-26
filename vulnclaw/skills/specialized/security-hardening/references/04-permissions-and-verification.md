# 04 — 权限配置与验证

> 权限题最容易“改错方向”：不是越开放越好，也不是一律 777。先读题目/检查器要求的目标用户和权限。

## 1. Web 根与上传目录

```bash
# 属主
chown -R www-data:www-data /var/www/html

# 目录 755、文件 644
find /var/www/html -type d -exec chmod 755 {} +
find /var/www/html -type f -exec chmod 644 {} +

# 上传目录：可写但不可执行
chown -R www-data:www-data /var/www/html/uploads
chmod 750 /var/www/html/uploads
find /var/www/html/uploads -type f -exec chmod 640 {} +
```

Web 服务器层再禁执行（Nginx/Apache 见 `02-middleware-and-db.md`）。只靠 `chmod -x` 不够：PHP-FPM/Apache 可能仍按扩展名解析。

## 2. Flag 文件：只给指定用户

题目常见要求：让检查器（以 `www-data`/`ctf` 运行）能读，但其他人不能读。

**方案 A：组权限**

```bash
groupadd -f ctfread
chown root:ctfread /flag
chmod 640 /flag
usermod -aG ctfread www-data
# 让 www-data 重新登录/重启服务后组才生效
```

**方案 B：ACL（更精确，不动属主）**

```bash
setfacl -m u:www-data:r /flag
getfacl /flag
```

**关键：父目录也要可进入**

```bash
namei -l /flag
# 如果 /secret 是 700，即使 /flag 是 644，www-data 也进不去
setfacl -m u:www-data:x /secret
# 或 chmod o+x /secret（只在题目允许时）
```

**验证（用目标用户，不要用 root）**

```bash
sudo -u www-data cat /flag && echo OK
sudo -u nobody cat /flag 2>&1 | head -1   # 应 Permission denied
```

**不要做的事**

- `chmod 777 /flag`：检查器可能明确检查“不能 world-readable”。
- 只改文件不改父目录：检查器以普通用户运行，路径遍历不进去。
- 改错属主：检查器可能要求 `root:root`；用组/ACL，不要改属主。
- ACL 与 chmod 冲突：`chmod` 会重算 mask；先 `setfacl`，再 `getfacl` 确认 effective 权限。

## 3. SSH 密钥与 home

```bash
chmod 700 /home/USER/.ssh
chmod 600 /home/USER/.ssh/authorized_keys
chmod 600 /home/USER/.ssh/id_*
chmod 644 /home/USER/.ssh/*.pub
chown -R USER:USER /home/USER/.ssh
```

## 4. 服务账号

```bash
# 系统账号、无 home、不可登录
useradd -r -s /usr/sbin/nologin -M svc
usermod -s /usr/sbin/nologin svc
passwd -l svc
```

## 5. sudoers

```bash
visudo -c
sudo -l
grep -rE 'NOPASSWD|ALL=\(ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```

最小权限示例：

```text
deploy ALL=(root) NOPASSWD: /bin/systemctl restart nginx
```

> 不要为了“安全”把检查器要用的 sudo 命令也删掉；先看题目要求。

## 6. 临时目录与 umask

```bash
chmod 1777 /tmp
chmod 1777 /var/tmp
ls -ld /tmp /var/tmp

# umask：/etc/profile、/etc/bashrc 或 /etc/profile.d/*.sh
umask 027
```

## 7. 验证权限的通用方法

```bash
# 看数字权限/属主
stat -c '%a %U:%G %n' /path

# 看 ACL
getfacl /path

# 看父目录链
namei -l /path

# 用目标用户实测
sudo -u TARGET test -r /path && echo readable
sudo -u TARGET cat /path >/dev/null && echo OK
```

## 8. 权限题常见检查器断言

- `stat -c %a /flag` 不是 777/755，且 owner/group 符合要求
- 以低权限用户能读/不能读
- 上传目录对 Web 用户可写，但脚本不可执行
- `/etc/shadow` 不是 world-readable
- 没有 world-writable 的普通文件/目录（`/tmp` 除外）
- 服务账号 shell 是 `nologin`
- sudoers 没有多余的 `NOPASSWD`

## 9. 验证检查器本身

```bash
# 如果题目给了检查器，直接跑；把输出完整记录到证据
/root/check/* 2>&1 | tee /tmp/hardening-check.txt

# 看退出码
echo $?
```

通过后立刻提交 Flag；如果只返回通过/不通过，把 `hardening-check.txt` 的内容和已修项写入 FINAL，不要编造 Flag。
