# 02 — 中间件与数据库加固

> 每改完一项先做语法检查/平滑重载，再跑检查器。不要一次改多个服务。

## Nginx

`/etc/nginx/nginx.conf` 或站点配置：

```nginx
server_tokens off;

# 禁止目录列表（默认就是 off；显式写死防止站点配置打开）
autoindex off;

# 敏感文件/备份文件
location ~ /\.(git|svn|env|htaccess) { deny all; }
location ~* \.(bak|swp|old|zip|tar|gz|sql|conf)$ { deny all; }

# 只允许常用方法（按业务调整；有 PUT/DELETE 需求就不要照抄）
if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }

# 上传目录禁执行
location ^~ /uploads/ {
    location ~ \.(php|php5|phtml|jsp|jspx|asp|aspx)$ { deny all; }
}

# 隐藏后端版本头
proxy_hide_header X-Powered-By;

# 安全头（按业务调整 CSP，避免把页面打坏）
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header Referrer-Policy no-referrer-when-downgrade always;
```

TLS：

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5:!3DES;
ssl_prefer_server_ciphers on;
```

验证：

```bash
nginx -t && systemctl reload nginx
nginx -T | grep -E 'server_tokens|autoindex'
curl -sI http://127.0.0.1/ | grep -Ei 'server|x-powered-by'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1/.git/config
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1/uploads/
```

## Apache

`/etc/apache2/conf-enabled/security.conf` 或主配置：

```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off

<Directory /var/www/html>
    Options -Indexes -Includes -ExecCGI
    AllowOverride None
    Require all granted
</Directory>
```

安全头（mod_headers）：

```apache
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Referrer-Policy "no-referrer-when-downgrade"
```

TLS：

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
SSLHonorCipherOrder on
```

验证：

```bash
apachectl configtest && systemctl reload apache2
curl -sI http://127.0.0.1/ | grep -Ei 'server|x-powered-by'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1/icons/
```

## Tomcat

```bash
# 1) 删除默认应用
rm -rf "$CATALINA_HOME"/webapps/{manager,host-manager,examples,docs}

# 2) 关闭 shutdown 端口：conf/server.xml 的 Server 行
#    <Server port="-1" shutdown="SHUTDOWN">  或设置强口令

# 3) 隐藏版本：Connector 加 server=" "
#    <Connector port="8080" protocol="HTTP/1.1" server=" " ... />

# 4) 不用 AJP 就注释/删除 8009 Connector；要用则设置 secret

# 5) 关闭 PUT：确认 conf/web.xml 的 DefaultServlet readonly=true
grep -n 'readonly' "$CATALINA_HOME"/conf/web.xml

# 6) 管理账号：conf/tomcat-users.xml 删掉 manager-gui/manager-script；
#    或加 RemoteAddrValve 只允许 127.0.0.1
```

验证：

```bash
curl -sI http://127.0.0.1:8080/ | grep -Ei 'server'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/manager/html
curl -X PUT -d test http://127.0.0.1:8080/test.txt -o /dev/null -w '%{http_code}\n'
```

## MySQL

```sql
-- 匿名用户
DROP USER IF EXISTS ''@'localhost';
DROP USER IF EXISTS ''@'%';

-- root 只允许本地
SELECT user,host FROM mysql.user WHERE user='root';
-- 如有 root@'%'：
-- RENAME USER 'root'@'%' TO 'root'@'localhost';
-- 或 DROP USER 'root'@'%';

-- 删 test 库
DROP DATABASE IF EXISTS test;

-- 应用账号最小权限
GRANT SELECT,INSERT,UPDATE,DELETE ON appdb.* TO 'app'@'localhost';
REVOKE FILE,PROCESS,SUPER ON *.* FROM 'app'@'localhost';
FLUSH PRIVILEGES;
```

`/etc/mysql/mysql.conf.d/mysqld.cnf`：

```ini
bind-address = 127.0.0.1
local_infile = 0
secure_file_priv = /var/lib/mysql-files/
```

验证：

```bash
mysql -uroot -e "SELECT user,host FROM mysql.user;"
mysql -uroot -e "SHOW DATABASES LIKE 'test';"
mysql -uroot -e "SHOW VARIABLES LIKE 'local_infile';"
mysql -h TARGET_IP -uroot -p -e 'SELECT 1;'   # 应失败
mysqladmin -uroot ping
```

> 改 `bind-address` 后要重启 mysqld；如果应用在远程连库，先确认题目是否要求保留远程访问。

## Redis

`/etc/redis/redis.conf`：

```conf
bind 127.0.0.1 ::1
protected-mode yes
requirepass 强口令

rename-command CONFIG ""
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command EVAL ""
```

验证：

```bash
redis-cli ping                         # 未认证应失败
redis-cli -a 强口令 ping               # PONG
ss -lntp | grep 6379                   # 只监听 127.0.0.1
```

> 重命名 `CONFIG` 后，部分管理脚本会失效；题目如果要求用 `CONFIG` 验证，不要重命名。

## VSFTPD

`/etc/vsftpd.conf`：

```conf
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
pasv_min_port=50000
pasv_max_port=60000
```

验证：

```bash
ftp -inv 127.0.0.1 <<'EOF'
user anonymous test
bye
EOF
# 匿名登录应失败；普通用户只能在自己的 home 下
```

## 通用验证顺序

1. `nginx -t` / `apachectl configtest` / Tomcat 启动日志
2. `systemctl reload`（或 restart）
3. `ss -tulnp` 确认端口/监听地址
4. `curl`/`mysql`/`redis-cli` 做正常功能测试
5. 跑题目检查器
