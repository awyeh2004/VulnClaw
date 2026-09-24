---
name: PHP XXE (vulhub php_xxe)
fingerprint: X-Powered-By: PHP/7.0.30; index.php = phpinfo(); /dom.php returns DOMDocument dump with "Empty string supplied as input"
status: validated
updated_at: 2026-09-23T12:00:45.441666+00:00
---

1) Start the challenge env (platform_start_env -> platform_read_env until running); target is plain HTTP on the given host:port.
2) Fingerprint: GET {HOST}/ returns a phpinfo() page (X-Powered-By: PHP/7.0.x). Enumerate and find {HOST}/dom.php, which returns "DOMDocument::loadXML(): Empty string supplied as input" (source is /var/www/html/dom.php).
3) LOCK: dom.php does `$data=file_get_contents('php://input'); $dom=new DOMDocument(); $dom->loadXML($data); print_r($dom);` -- unauthenticated XML parsing = classic XXE.
4) CONFIRMED XXE: POST XML to {HOST}/dom.php with Content-Type: application/xml and body `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><name>&xxe;</name></root>`; the file content appears in the [textContent] field of the DOMDocument dump.
5) Read arbitrary files with file:// ENTITY. To read PHP source use `php://filter/convert.base64-encode/resource=/var/www/html/dom.php` (base64 decoded = the dom.php source).
6) The flag lives in the environment: GET {HOST}/index.php (phpinfo) and grep for the env var `FLAG` -- it appears as `$_ENV['FLAG']` and in the Environment section, e.g. CTF2{…}.
7) Submit the flag; release the env with platform_stop_env.
