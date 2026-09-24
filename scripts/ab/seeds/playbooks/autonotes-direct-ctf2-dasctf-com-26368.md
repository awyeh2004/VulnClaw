---
name: AutoNotes direct-ctf2.dasctf.com:26368
fingerprint: http://direct-ctf2.dasctf.com:26368 Target: http://direct-ctf2.dasctf.com:26368
This is a CTF challenge web service ([Weblogic]CVE-2017-10271). Exploit it to obtain the flag.
The flag is stored inside the target container: usually an environment variable named FLAG, or a file such as /flag. Report the exact flag value.
Do not attack the CTF platform itself; only this target is in scope.
status: validated
updated_at: 2026-09-23T12:09:21.123847+00:00
---

LOCK: WebLogic 10.3.6 wls-wsat CVE-2017-10271 XMLDecoder RCE (as root); flag is env var FLAG; exfiltrated via a file written into the unauthenticated bea_wls_internal static docRoot.
CONFIRMED: CVE-2017-10271 RCE confirmed: blind ProcessBuilder command wrote output to the Weblogic bea_wls_internal docRoot; GET /bea_wls_internal/flag.txt returned the dumped recon. Environment contains FLAG=CTF2{5c08…fd46} and id shows uid=0(root).
TARGET: http://direct-ctf2.dasctf.com:26368
GOAL: Target: http://direct-ctf2.dasctf.com:26368
This is a CTF challenge web service ([Weblogic]CVE-2017-10271). Exploit it to obtain the flag.
The flag is stored inside the target container: usually an environment variable named FLAG, or a file such as /flag. Report the exact flag value.
Do not attack the CTF platform itself; only this target is in scope.
OUTCOME: CVE-2017-10271 (WebLogic wls-wsat XMLDecoder RCE) exploited on `http://direct-ctf2.dasctf.com:26368`. The unauthenticated `/wls-wsat/CoordinatorPortType` endpoint executed a `/bin/bash -c` ProcessBuilder command as `uid=0(root)`; because exfil had to stay on the target, output was written into the served static docRoot of the unauthenticated `bea_wls_internal` app and retrieved via `GET /bea_wls_internal/flag.txt`.

Confirmed flag value (from env var `FLAG`, evidence e022):

`CTF2{5c08…fd46}`

Evidence: e022 (raw recon dump showing `FLAG=CTF2{5c08…fd46}` and `uid=0(root)`), with the writable/served-channel confirmation in e020–e021.
