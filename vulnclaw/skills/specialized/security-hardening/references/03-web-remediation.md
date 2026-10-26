# 03 — Web 漏洞修复

> 加固题里的“漏洞修复”通常是改源码/配置，不是加 WAF 规则。检查器可能用多种 payload 复测；优先修根因，别只拦一个字符串。

## SQL 注入

PHP PDO：

```php
// VULNERABLE: $sql = "SELECT * FROM users WHERE name='$name'";
$stmt = $pdo->prepare('SELECT * FROM users WHERE name = ?');
$stmt->execute([$name]);
$row = $stmt->fetch();
```

Python：

```python
# VULNERABLE: cur.execute(f"SELECT * FROM users WHERE name='{name}'")
cur.execute("SELECT * FROM users WHERE name = ?", (name,))
```

Java：

```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
```

验证：

```bash
# 用一个不会破坏数据的布尔 payload；登录成功/返回异常说明 SQLi 还在
curl -s "http://127.0.0.1/login.php?user=admin'%20OR%20'1'='1&pass=x" | head
```

## XSS

```php
echo htmlspecialchars($input, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
```

Python/Jinja2 默认自动转义；不要对用户输入用 `|safe`。JavaScript 用 `textContent`，不要 `innerHTML`。

验证：

```bash
curl -s "http://127.0.0.1/search?q=%3Cscript%3Ealert(1)%3C/script%3E" | grep -F '<script>alert(1)</script>'
# 有原样输出 = 未转义；应看到 &lt;script&gt;
```

## 文件上传

```php
$allowed = ['jpg' => 'image/jpeg', 'png' => 'image/png', 'gif' => 'image/gif'];
$ext  = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
$mime = (new finfo(FILEINFO_MIME_TYPE))->file($_FILES['f']['tmp_name']);
if (!isset($allowed[$ext]) || $allowed[$ext] !== $mime) {
    http_response_code(400); exit;
}
$name = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['f']['tmp_name'], '/var/www/uploads/' . $name);
chmod('/var/www/uploads/' . $name, 0640);
```

再加 Web 服务器层：上传目录禁执行（见 `02-middleware-and-db.md`）。

验证：

```bash
# 用无害标记文件测试，不要上传真实 webshell
printf '<?php echo "marker"; ?>' > /tmp/test.php
curl -s -o /dev/null -w '%{http_code}\n' -F 'f=@/tmp/test.php;type=image/jpeg' http://127.0.0.1/upload.php
# 应 400/403；再传一张正常 png 应成功
```

## 文件包含 / 路径穿越

```php
$page = $_GET['page'] ?? 'home';
$allowed = ['home', 'about', 'contact'];
if (!in_array($page, $allowed, true)) { http_response_code(404); exit; }
include __DIR__ . "/pages/$page.php";
```

路径穿越：

```php
$base = realpath('/var/www/files');
$path = realpath($base . '/' . $_GET['f']);
if ($path === false || strpos($path, $base . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(403); exit;
}
```

验证：

```bash
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1/download.php?f=../../../../etc/passwd'
# 应 403/404，不应返回 root:
```

## 命令执行 / RCE

- 删掉 `eval`、`system`、`shell_exec`、`passthru`、`popen`、`proc_open` 等不必要的调用。
- 必须调用外部命令时用参数数组/`escapeshellarg`，不要拼接用户输入。
- PHP 可在 `php.ini` 禁用危险函数（注意别把业务打坏）：

```ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
```

验证：

```bash
curl -s 'http://127.0.0.1/ping.php?ip=127.0.0.1;id' | grep -E 'uid=|gid='
# 无回显才对
```

## SSRF

- 协议白名单：只允许 `http`/`https`。
- 主机白名单，或解析后拒绝私网/回环/链路本地地址（`127.0.0.0/8`、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、`::1`、`fc00::/7`）。
- 禁止 `file://`、`gopher://`、`dict://`。

验证：

```bash
curl -s 'http://127.0.0.1/fetch.php?url=http://127.0.0.1:6379/'
curl -s 'http://127.0.0.1/fetch.php?url=file:///etc/passwd'
# 应被拒绝
```

## 反序列化

- PHP：不要对用户输入 `unserialize`；改用 JSON；必须用时签名/白名单类。
- Python：不要 `pickle.loads` 用户数据；`yaml.safe_load` 代替 `yaml.load`。
- Java：不要对不可信数据 `ObjectInputStream`；用白名单/JSON。

## 错误处理与安全头

```ini
; php.ini
expose_php = Off
display_errors = Off
log_errors = On
allow_url_fopen = Off
allow_url_include = Off
session.cookie_httponly = 1
session.use_strict_mode = 1
```

响应头：

```text
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer-when-downgrade
Content-Security-Policy: default-src 'self'; ...
```

验证：

```bash
curl -sI http://127.0.0.1/ | grep -Ei 'server|x-powered-by|x-content-type|x-frame|content-security'
curl -s http://127.0.0.1/nonexistent | grep -Ei 'stack|trace|/var/www|Warning|Fatal'
```

## Web 根清理

```bash
find /var/www/html -maxdepth 4 \( -name '.git' -o -name '.env' -o -name '*.bak' -o -name '*.swp' -o -name '*.old' -o -name '*.zip' -o -name '*.sql' \) 2>/dev/null
# 确认无用后删除或移出 Web 根
```

## 修复顺序建议

1. 先修“检查器一定会打”的入口（登录、搜索、上传、下载、ping/fetch）。
2. 再修“配置类”问题（目录列表、备份文件、错误页、版本头）。
3. 最后做安全头/CSP 等可能影响页面渲染的项；每改一项先测正常页面。
