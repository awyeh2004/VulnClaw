---
name: AutoNotes direct-ctf2.dasctf.com:27087
fingerprint: http://direct-ctf2.dasctf.com:27087 Target: http://direct-ctf2.dasctf.com:27087
This is a CTF challenge web service ([PHP]XXE). Exploit it to obtain the flag.
The flag is stored inside the target container: usually an environment variable named FLAG, or a file such as /flag. Report the exact flag value.
Do not attack the CTF platform itself; only this target is in scope.
status: validated
updated_at: 2026-09-23T12:13:30.764863+00:00
---

LOCK: DASCTF direct-ctf2 PHP XXE: /dom.php parses attacker XML via DOMDocument::loadXML() and echoes resolved entity content in [textContent]; flag lives in container env var FLAG, exfiltrated via php://filter base64 on /proc/self/environ.
CONFIRMED: php://filter/convert.base64-encode/resource=/proc/self/environ via XXE returns base64 that decodes to contain FLAG=CTF2{f86f…2478}
ANGLES: [hit] XXE on /dom.php to read container FLAG env var via /proc/self/environ
TARGET: http://direct-ctf2.dasctf.com:27087
GOAL: Target: http://direct-ctf2.dasctf.com:27087
This is a CTF challenge web service ([PHP]XXE). Exploit it to obtain the flag.
The flag is stored inside the target container: usually an environment variable named FLAG, or a file such as /flag. Report the exact flag value.
Do not attack the CTF platform itself; only this target is in scope.
OUTCOME: CTF2{f86f…2478} (evidence: e008, e009; blackboard LOCK n1, confirmed fact n3, ANGLE n4 HIT)
