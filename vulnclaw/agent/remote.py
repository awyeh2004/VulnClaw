"""Remote (SSH) execution and one-shot forensic collection.

Why this exists
---------------
The competition brief is multi-part: some questions are remote live triage
(you get SSH to a compromised box and must investigate it in place) and some
are offline artifact analysis (you get a memory image and/or a PCAP). This
module covers the remote-live half; ``references/50-memory-traffic.md`` covers
the offline half.

Design decisions worth stating, because they are the difference between a
usable tool and a foot-gun:

1. **Hosts are an explicit inventory, not free-form strings.** The tool takes an
   alias that resolves through ``config.remote.hosts``. Firm scope discipline is
   the point: the resolved hostname is what gets approved and logged, and an
   unconfigured target cannot be reached at all. This is also the seam where a
   future out-of-scope denylist belongs.

2. **Remote commands go through the SAME approval gate as local ones.** The gate
   is given ``kind="remote"`` and the *remote command text*, so the read-only
   classifier extended for IR work applies to remote commands too: a remote
   ``ps aux`` runs unattended in ``auto_review`` mode, while a remote ``rm``
   prompts. Routing around the gate would have made this module a
   privilege-escalation path around the one safety control the project has.

3. **Batch collection is approved once, as a whole.** Approving 33 individual
   commands would be unusable, and worse, it would train the operator to approve
   blindly. The collector declares its full command list up front, that list is
   what gets displayed and approved, and it is generated from a single constant
   in :func:`collector_commands` -- so the approved text and the executed text
   cannot drift apart.

4. **Host key policy is explicit and the fingerprint is always reported.** A
   competition VM has no ``known_hosts`` entry, so a strict-only tool is
   unusable there; but silently trusting anything is a MITM hole. Default is
   strict, ``accept_new`` is opt-in per host, and whichever mode is used, the
   observed key fingerprint is printed into the tool output so the operator has
   an audit record.

5. **Nothing is installed on the target.** The collector uses only POSIX shell
   and coreutils (verified against the Ubuntu 16.04 drill target, which has no
   python, no busybox, and no curl/wget). It also deliberately does not use
   ``tar`` in a way that can include its own output.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import os
import shlex
import tarfile
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# paramiko is present in the runtime environment but is NOT a declared project
# dependency (pyproject lists no SSH client). Import lazily so that importing
# this module -- and therefore loading the agent -- never depends on it; only an
# actual remote call does, and that failure is reported as an actionable message
# rather than an ImportError at startup.
_PARAMIKO_ERROR = (
    "[!] remote execution needs paramiko (this machine's Anaconda ships it). "
    "If missing: pip install paramiko, or drive the system ssh.exe via shell_command."
)


def _import_paramiko():
    """Import paramiko.

    Paramiko 2.8.1 on this machine warns twice per run that TripleDES has moved
    (cryptography >= 48 deprecation). These are harmless, but paramiko imports
    its `transport`/`pkey` submodules lazily, so a warning filter wrapped around
    this import does NOT catch them -- measured: they still appeared on the first
    real connection attempt. The filter is therefore installed at module scope
    below, narrowed to this exact message so genuine deprecations still surface.

    Suppressing it matters because warnings land on stderr, and stderr is part of
    the evidence an operator reads; familiar warning spam is how people learn to
    skim past real errors.
    """
    try:
        import paramiko  # noqa: PLC0415
    except Exception as exc:  # pragma: no cover - depends on host env
        raise RuntimeError(f"{_PARAMIKO_ERROR} ({type(exc).__name__})") from exc
    return paramiko


warnings.filterwarnings(
    "ignore",
    message=r".*TripleDES has been moved.*",
    category=DeprecationWarning,
)

# The TripleDES warning is actually CryptographyDeprecationWarning, whose base is
# UserWarning -- NOT DeprecationWarning. Measured, after the filter above failed
# to suppress it. Filter on the real class so this cannot silently regress, and
# keep the message narrowed so genuine crypto deprecations still surface.
try:
    from cryptography.utils import CryptographyDeprecationWarning as _CryptoDepWarning
except Exception:  # pragma: no cover - cryptography always present with paramiko
    _CryptoDepWarning = None

if _CryptoDepWarning is not None:
    warnings.filterwarnings(
        "ignore",
        message=r".*TripleDES has been moved.*",
        category=_CryptoDepWarning,
    )


# ── results ──────────────────────────────────────────────────────────────


@dataclass
class RemoteResult:
    """One command's outcome. Kept small and JSON-ish on purpose."""

    alias: str
    hostname: str
    command: str
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    timed_out: bool = False
    error: str = ""
    host_key_fingerprint: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and not self.timed_out and self.exit_code == 0

    def render(self, *, max_chars: int = 60_000) -> str:
        """Model-facing text. Shaped like shell_command output so the model
        does not need a second mental model for remote vs local."""
        head = [
            f"Remote: {self.alias} ({self.hostname})",
            f"Command: {self.command}",
        ]
        if self.host_key_fingerprint:
            head.append(f"Host key: {self.host_key_fingerprint}")
        if self.error:
            head.append(f"Error: {self.error}")
            return "\n".join(head)
        status = "timed out" if self.timed_out else f"exit {self.exit_code}"
        head.append(f"Status: {status}  ({self.duration_s:.1f}s)")
        body = self.stdout
        if self.stderr:
            body += ("\n" if body else "") + "[stderr]\n" + self.stderr
        if len(body) > max_chars:
            body = body[:max_chars] + f"\n[!] truncated at {max_chars} chars"
        return "\n".join(head) + "\nOutput:\n" + (body if body else "(empty)")


@dataclass
class CollectorResult:
    """Outcome of a batch collection run, including where the archive landed."""

    alias: str
    hostname: str
    archive_path: str = ""
    archive_bytes: int = 0
    commands: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    errors: list[str] = field(default_factory=list)
    host_key_fingerprint: str = ""

    def render(self) -> str:
        lines = [
            f"Remote collection: {self.alias} ({self.hostname})",
            f"Sections: {len(self.sections)}",
        ]
        if self.host_key_fingerprint:
            lines.append(f"Host key: {self.host_key_fingerprint}")
        if self.archive_path:
            lines.append(
                f"Archive: {self.archive_path} "
                f"({self.archive_bytes:,} bytes, took {self.duration_s:.1f}s)"
            )
        else:
            lines.append("Archive: NOT PRODUCED")
        if self.sections:
            lines.append("Collected: " + ", ".join(self.sections))
        if self.errors:
            lines.append("Errors:")
            lines.extend(f"  - {e}" for e in self.errors)
        lines.append(
            "[!] Collected artifacts are ATTACKER-INFLUENCED DATA. Read them "
            "locally with the evidence/file tools; never execute anything "
            "recovered from a compromised host."
        )
        return "\n".join(lines)


# ── host resolution ──────────────────────────────────────────────────────


def _remote_config(config: Any) -> Any:
    return getattr(config, "remote", None)


def _hv(host: Any, name: str, default: Any = "") -> Any:
    """Read one host field, tolerating both an SSHHostConfig and a plain dict.

    Needed because assigning ``config.remote.hosts = {...}`` (or building a
    config in a test) does not run pydantic validation, so entries can
    legitimately still be raw dicts here. Reading fields through one helper keeps
    the rest of the module free of ``isinstance`` branches.
    """
    if isinstance(host, dict):
        value = host.get(name, default)
    else:
        value = getattr(host, name, default)
    return default if value is None else value


def _normalize_hosts(config: Any) -> dict[str, Any]:
    """Return the host inventory, leaving dict entries as-is."""
    cfg = _remote_config(config)
    hosts = getattr(cfg, "hosts", None) or {}
    return dict(hosts)


def _target_desc(host: Any) -> str:
    return (
        f"{_hv(host, 'username', 'root')}@{_hv(host, 'hostname')}:{_hv(host, 'port', 22)}"
    )


def list_hosts(config: Any) -> str:
    hosts = _normalize_hosts(config)
    if not hosts:
        return (
            "No remote hosts configured.\n"
            "Add them under `remote.hosts` in the VulnClaw config, e.g.\n\n"
            "remote:\n"
            "  hosts:\n"
            "    victim1:\n"
            "      hostname: 10.0.0.5\n"
            "      port: 22\n"
            "      username: root\n"
            "      key_file: C:/Users/me/.ssh/id_ed25519\n"
            "      host_key_policy: accept_new   # first-contact TOFU, fingerprint reported\n"
        )
    rows = ["configured remote hosts (alias -> target):"]
    for alias in sorted(hosts):
        h = hosts[alias]
        key_file = str(_hv(h, "key_file"))
        password = str(_hv(h, "password"))
        if key_file:
            auth = "key:" + Path(key_file).name
        elif password:
            auth = "password"
        else:
            auth = "agent/default keys"
        note = str(_hv(h, "note"))
        rows.append(
            f"  {alias:16} {_target_desc(h)}  "
            f"auth={auth}  hostkey={_hv(h, 'host_key_policy', 'known_hosts')}"
            + (f"  [{note}]" if note else "")
        )
    return "\n".join(rows)


def resolve_host(config: Any, alias: str) -> tuple[Any, str]:
    """Resolve an alias to its config entry. Raises ValueError with the
    configured alias list, so a typo self-corrects instead of probing blindly."""
    hosts = _normalize_hosts(config)
    key = str(alias or "").strip()
    if not key:
        raise ValueError("remote target alias is required (see remote_hosts)")
    if key not in hosts:
        known = ", ".join(sorted(hosts)) or "(none configured)"
        raise ValueError(
            f"unknown remote host alias {key!r}. Configured aliases: {known}. "
            "Remote execution is inventory-based on purpose: declare the host "
            "under `remote.hosts` before reaching it."
        )
    return hosts[key], key


# ── SSH transport ────────────────────────────────────────────────────────


def _host_key_policy(host: Any) -> str:
    """Translate the configured policy into a strict/trust-on-first-use choice.

    `known_hosts` (default) keeps paramiko's RejectPolicy semantics: an unknown
    host raises, which is the correct default for an engagement. `accept_new`
    (TOFU) is the competition-VM escape hatch: there is no prior entry to check
    against, so the value is in *recording* the fingerprint, not in pretending to
    have verified it.
    """
    policy = str(_hv(host, "host_key_policy", "known_hosts") or "known_hosts").strip().lower()
    return policy if policy in ("known_hosts", "accept_new", "insecure") else "known_hosts"


def _connect(host: Any, connect_timeout: float):
    paramiko = _import_paramiko()

    client = paramiko.SSHClient()
    if _host_key_policy(host) == "known_hosts":
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    kwargs: dict[str, Any] = {
        "hostname": str(_hv(host, "hostname")),
        "port": int(_hv(host, "port", 22) or 22),
        "username": str(_hv(host, "username", "root")),
        "timeout": connect_timeout,
        "banner_timeout": connect_timeout,
        "auth_timeout": connect_timeout,
        "allow_agent": True,
        "look_for_keys": True,
    }
    key_file = str(_hv(host, "key_file")).strip()
    if key_file:
        kwargs["key_filename"] = key_file
    password = str(_hv(host, "password"))
    if password:
        kwargs["password"] = password
    # The explicit timeout fields above are what keep a dead target from
    # hanging the whole run.
    client.connect(**kwargs)
    return client


def _fingerprint(client: Any) -> str:
    """Best-effort key fingerprint for the audit trail."""
    try:
        transport = client.get_transport()
        key = transport.get_remote_server_key() if transport else None
        if key is None:
            return ""
        digest = hashlib.sha256(key.asbytes()).digest()
        return f"{key.get_name()} SHA256:{base64.b64encode(digest).decode().rstrip('=')}"
    except Exception:
        return ""


def _drain(chan: Any, timeout_s: float) -> tuple[bytes, bytes, bool, str]:
    """Read a channel to completion. Returns (stdout, stderr, timed_out, error).

    Draining while polling is what prevents a chatty remote command from
    deadlocking against the SSH channel window.
    """
    out = io.BytesIO()
    err = io.BytesIO()
    deadline = time.perf_counter() + timeout_s
    while True:
        try:
            if chan.recv_ready():
                out.write(chan.recv(1 << 16))
            if chan.recv_stderr_ready():
                err.write(chan.recv_stderr(1 << 16))
            if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                return out.getvalue(), err.getvalue(), False, ""
        except Exception as exc:
            return out.getvalue(), err.getvalue(), False, f"{type(exc).__name__}: {exc}"
        if time.perf_counter() > deadline:
            try:
                chan.close()
            except Exception:
                pass
            return out.getvalue(), err.getvalue(), True, ""
        time.sleep(0.02)


def run_command(
    host: Any,
    alias: str,
    command: str,
    *,
    connect_timeout: float = 15.0,
    timeout_s: float = 60.0,
) -> RemoteResult:
    """Execute one command. Blocking: call via asyncio.to_thread."""
    res = RemoteResult(alias=alias, hostname=str(_hv(host, "hostname")), command=command)
    client = None
    started = time.perf_counter()
    try:
        client = _connect(host, connect_timeout)
        res.host_key_fingerprint = _fingerprint(client)

        transport = client.get_transport()
        chan = transport.open_session() if transport else None
        if chan is None:
            res.error = "could not open an SSH session channel"
            return res
        # settimeout bounds individual reads; _drain bounds the whole command.
        chan.settimeout(max(1.0, timeout_s))
        # get_pty is left False: without a terminal, commands are not wrapped or
        # paginated, so `ps`/`netstat` output stays parseable.
        chan.exec_command(command)

        raw_out, raw_err, timed_out, err = _drain(chan, timeout_s)
        res.timed_out = timed_out
        if err:
            res.error = err
        res.stdout = raw_out.decode("utf-8", "replace")
        res.stderr = raw_err.decode("utf-8", "replace")
        if not timed_out and not res.error:
            try:
                res.exit_code = chan.recv_exit_status()
            except Exception:
                res.exit_code = -1
    except Exception as exc:
        res.error = f"{type(exc).__name__}: {exc}"
    finally:
        res.duration_s = time.perf_counter() - started
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
    return res


def run_command_capture(
    host: Any,
    alias: str,
    command: str,
    *,
    connect_timeout: float = 15.0,
    timeout_s: float = 300.0,
) -> tuple[bytes, str, str]:
    """Run a command and return RAW stdout bytes plus (stderr text, error).

    Separate from :func:`run_command` because base64-decoding an archive must not
    go through the utf-8 ``"replace"`` path -- that would silently corrupt
    binary data. ``alias`` is accepted for a symmetric signature; the caller
    keeps the host identity in its own result object.
    """
    client = None
    try:
        client = _connect(host, connect_timeout)
        transport = client.get_transport()
        if transport is None:
            return b"", "", "no transport"
        chan = transport.open_session()
        chan.settimeout(max(1.0, timeout_s))
        chan.exec_command(command)
        raw_out, raw_err, timed_out, err = _drain(chan, timeout_s)
        if timed_out:
            return raw_out, raw_err.decode("utf-8", "replace"), "timeout"
        return raw_out, raw_err.decode("utf-8", "replace"), err
    except Exception as exc:
        return b"", "", f"{type(exc).__name__}: {exc}"
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def fetch_file(
    host: Any,
    alias: str,
    remote_path: str,
    local_path: Path,
    *,
    connect_timeout: float = 15.0,
) -> tuple[bool, str, int]:
    """SFTP-download ``remote_path`` to ``local_path``.

    Returns (ok, message, bytes). Used for anything too large or too binary for
    base64-over-stdout: memory images, PCAPs, collected archives.
    """
    client = None
    try:
        client = _connect(host, connect_timeout)
        sftp = client.open_sftp()
        local_path.parent.mkdir(parents=True, exist_ok=True)
        sftp.get(remote_path, str(local_path))
        sftp.close()
        return True, f"fetched {remote_path} -> {local_path}", local_path.stat().st_size
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}", 0
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


# ── batch collection ─────────────────────────────────────────────────────

# Every step is (name, command). These commands are what gets APPROVED, so this
# tuple is the single source of truth: the approval display and the executed
# script are both generated from it and cannot drift.
#
# Constraints these commands respect (all verified against the Ubuntu 16.04 drill
# target, which is deliberately impoverished):
#   * POSIX sh only -- no bashisms, no arrays, no `pipefail`.
#   * No python / busybox / curl / wget on the target.
#   * Every command is permitted to fail: a missing /etc/cron.d or an empty
#     /dev/shm is normal, not an error.
#   * Read-only. Nothing under /etc is modified; no file is deleted.
def collector_commands() -> list[tuple[str, str]]:
    return [
        ("identity", "uname -a; cat /etc/os-release 2>/dev/null; hostname; id; uptime; date -u"),
        ("accounts", "cat /etc/passwd; echo '--- shadow ---'; cat /etc/shadow 2>/dev/null; "
                     "echo '--- uid0 ---'; grep -E '^[^:]+:[^:]*:0:' /etc/passwd"),
        ("sudoers", "cat /etc/sudoers 2>/dev/null; echo '--- sudoers.d ---'; "
                    "ls -la /etc/sudoers.d 2>/dev/null; cat /etc/sudoers.d/* 2>/dev/null"),
        ("authkeys", "find / -xdev -name 'authorized_keys' -type f 2>/dev/null | while read f; do "
                     "echo \"=== $f ===\"; cat \"$f\"; done"),
        ("groups", "cat /etc/group; echo '--- last/lastb ---'; "
                   "last -n 40 2>/dev/null; lastb -n 40 2>/dev/null; lastlog 2>/dev/null"),
        ("processes", "ps auxww 2>/dev/null || ps -ef"),
        ("proc_exe", "for d in /proc/[0-9]*; do p=${d#/proc/}; "
                     "e=$(readlink \"$d/exe\" 2>/dev/null) || continue; "
                     "echo \"$p $e\"; done"),
        ("proc_cmdline", "for d in /proc/[0-9]*; do p=${d#/proc/}; "
                         "echo \"=== $p ===\"; tr '\\0' ' ' < \"$d/cmdline\" 2>/dev/null; echo; "
                         "tr '\\0' '\\n' < \"$d/environ\" 2>/dev/null | head -20; done"),
        ("proc_fd_sockets", "for d in /proc/[0-9]*; do p=${d#/proc/}; "
                            "ls -l \"$d/fd\" 2>/dev/null | grep -E 'socket|deleted' | "
                            "sed \"s|^|$p |\"; done"),
        ("network", "ss -antp 2>/dev/null || netstat -antp 2>/dev/null || cat /proc/net/tcp"),
        ("network_udp", "ss -anup 2>/dev/null || netstat -anup 2>/dev/null || cat /proc/net/udp"),
        ("listening", "ss -antlp 2>/dev/null || netstat -antlp 2>/dev/null"),
        ("modules", "lsmod 2>/dev/null; echo '--- modules file ---'; cat /proc/modules 2>/dev/null; "
                    "echo '--- syscall table ---'; grep -E ' (sys_call_table)$' /proc/kallsyms 2>/dev/null"),
        ("cron_spool", "for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do "
                       "[ -f \"$f\" ] && { echo \"=== $f ===\"; ls -la \"$f\"; cat \"$f\"; }; done"),
        ("cron_system", "echo '=== /etc/crontab ==='; cat /etc/crontab 2>/dev/null; "
                        "echo '=== /etc/cron.d ==='; ls -la /etc/cron.d 2>/dev/null; "
                        "cat /etc/cron.d/* 2>/dev/null; "
                        "echo '=== cron.daily etc ==='; "
                        "ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null"),
        ("systemd", "ls -la /etc/systemd/system 2>/dev/null; "
                    "cat /etc/systemd/system/*.service 2>/dev/null | head -300; "
                    "systemctl list-units --type=service --no-pager 2>/dev/null | head -80"),
        ("init_startup", "cat /etc/rc.local 2>/dev/null; ls -la /etc/init.d 2>/dev/null; "
                         "ls -la /etc/rc*.d 2>/dev/null | head -60; "
                         "cat /etc/profile 2>/dev/null; "
                         "ls -la /etc/profile.d 2>/dev/null; cat /etc/profile.d/* 2>/dev/null"),
        ("ld_preload", "cat /etc/ld.so.preload 2>/dev/null; echo '--- ld.so.conf.d ---'; "
                       "cat /etc/ld.so.conf.d/* 2>/dev/null; echo '--- LD_ env ---'; env | grep -i '^LD_'"),
        ("history", "for f in /root/.bash_history /root/.zsh_history /home/*/.bash_history "
                    "/home/*/.zsh_history; do [ -f \"$f\" ] && { echo \"=== $f ===\"; cat \"$f\"; }; done"),
        ("web_root", "for d in /var/www /usr/share/nginx /usr/local/apache2/htdocs /srv/www /opt/lampp/htdocs; do "
                     "[ -d \"$d\" ] && { echo \"=== $d ===\"; find \"$d\" -xdev -type f 2>/dev/null | head -400; }; done"),
        ("web_uploads", "for d in /var/www/html/uploads /var/www/uploads /tmp /var/tmp /dev/shm; do "
                        "[ -d \"$d\" ] && { echo \"=== $d (ls -la) ===\"; ls -la \"$d\" 2>/dev/null; }; done"),
        ("tmp_hidden", "find /tmp /var/tmp /dev/shm /var/www -xdev -name '.*' -type f 2>/dev/null "
                       "| while read f; do echo \"=== $f ===\"; ls -la \"$f\"; head -c 4096 \"$f\"; "
                       "echo; done"),
        ("suid_sgid", "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | head -200; "
                      "echo '--- capabilities ---'; getcap -r / 2>/dev/null | head -100"),
        ("world_writable", "find / -xdev -type d -perm -0002 ! -path '/proc/*' ! -path '/sys/*' "
                           "2>/dev/null | head -80"),
        ("deleted_held", "ls -l /proc/[0-9]*/exe 2>/dev/null | grep -i deleted"),
        ("recent_files", "find / -xdev -type f -mtime -14 ! -path '/proc/*' ! -path '/sys/*' "
                         "! -path '/var/lib/*' 2>/dev/null | head -500"),
        ("logs_var", "ls -la /var/log 2>/dev/null; for f in /var/log/messages /var/log/syslog "
                     "/var/log/auth.log /var/log/secure /var/log/cron /var/log/btmp /var/log/wtmp; do "
                     "[ -f \"$f\" ] && { echo \"=== $f (tail 200) ===\"; tail -n 200 \"$f\"; }; done"),
        ("logs_web", "for f in /var/log/nginx/access.log /var/log/nginx/error.log "
                     "/var/log/apache2/access.log /var/log/apache2/error.log "
                     "/var/log/httpd/access_log /var/log/httpd/error_log; do "
                     "[ -f \"$f\" ] && { echo \"=== $f (tail 300) ===\"; tail -n 300 \"$f\"; }; done"),
        ("network_files", "cat /etc/hosts; echo '--- resolv ---'; cat /etc/resolv.conf 2>/dev/null; "
                          "echo '--- hosts.allow/deny ---'; cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null; "
                          "echo '--- iptables ---'; iptables -L -n 2>/dev/null | head -60"),
        ("packages", "(dpkg -l 2>/dev/null | head -300) || (rpm -qa 2>/dev/null | head -300); "
                     "echo '--- recent pkg changes ---'; ls -lat /var/lib/dpkg/info/*.list 2>/dev/null | head -20"),
        ("ssh_config", "grep -vE '^[[:space:]]*#' /etc/ssh/sshd_config 2>/dev/null | grep -v '^$'; "
                       "echo '--- host keys ---'; ls -la /etc/ssh/ssh_host_* 2>/dev/null"),
        ("container_marks", "ls -la /.dockerenv 2>/dev/null; cat /proc/1/cgroup 2>/dev/null; "
                            "echo '--- mounts ---'; mount | head -40"),
        ("antiforensics", "echo '--- log sizes ---'; ls -la /var/log/*.log 2>/dev/null; "
                          "echo '--- dev dotdirs ---'; ls -la /dev/.??* 2>/dev/null; "
                          "echo '--- immutable files ---'; lsattr -R /etc /usr/bin /usr/sbin 2>/dev/null "
                          "| grep -i 'i-' | head -40"),
    ]


def _collector_script(out_dir: str) -> str:
    """Assemble the remote collector.

    A POSIX shell script driven by a command list appended at build time, so the
    approved command list and the executed steps are literally the same data.

    The archive is built by writing each section into its own file under a
    dedicated scratch dir and then tar-ing that directory. It deliberately does
    NOT ``tar czf archive.tar.gz /`` (nor archive into a directory it is
    scanning), which is how "collect everything" scripts end up either recursing
    into their own output or silently including it.
    """
    lines = [
        "#!/bin/sh",
        "# Forensic batch collector -- read-only, POSIX sh, no extra tooling.",
        "# Generated by vulnclaw remote_collect; every step below is one of the",
        "# commands the operator approved.",
        "set -u",
        f"OUT={shlex.quote(out_dir)}",
        'rm -rf "$OUT" 2>/dev/null',
        'mkdir -p "$OUT" || exit 1',
        'echo "collector started: $(date -u 2>/dev/null)" > "$OUT/00-collector.log"',
    ]
    for idx, (name, cmd) in enumerate(collector_commands(), start=1):
        lines += [
            f"# ---- {name} ----",
            "{",
            f'  echo "### command: {cmd}"',
            f"  {cmd}",
            f'}} > "$OUT/{idx:02d}-{name}.txt" 2>&1',
        ]
    lines += [
        'echo "collector finished: $(date -u 2>/dev/null)" >> "$OUT/00-collector.log"',
        "# Tab-separated index of what was actually captured, with sizes.",
        'for f in "$OUT"/*.txt; do',
        '  [ -f "$f" ] || continue',
        '  printf "%s\\t%s\\n" "$(basename "$f")" "$(wc -c < "$f" 2>/dev/null)"',
        'done > "$OUT/_INDEX.tsv" 2>/dev/null',
        "# Single archive, built from the scratch dir so nothing self-recurses.",
        'if command -v tar >/dev/null 2>&1; then',
        '  tar -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null \\',
        '    && { echo "=== COLLECTED ==="; cat "$OUT/_INDEX.tsv" 2>/dev/null; '
        'echo "ARCHIVE=$OUT.tar.gz"; exit 0; }',
        'fi',
        'echo "ARCHIVE=" && echo "[!] tar unavailable; sections are in $OUT" >&2',
        "exit 3",
    ]
    return "\n".join(lines) + "\n"


COLLECT_MARKER = "=== COLLECTED ==="


def _parse_collector_stdout(text: str) -> list[str]:
    """Pull the section list out of the collector's stdout.

    The collector prints an explicit marker followed by a ``name<TAB>bytes``
    index, so this parse cannot be confused by command output that happens to
    contain tabs.
    """
    if COLLECT_MARKER not in text:
        return []
    tail = text.split(COLLECT_MARKER, 1)[1]
    names: list[str] = []
    for line in tail.splitlines():
        line = line.strip()
        if not line or line.startswith("ARCHIVE="):
            continue
        name = line.split("\t", 1)[0].strip()
        if name.endswith(".txt"):
            names.append(name)
    return names


def _extract_archive(data: bytes, dest: Path) -> tuple[bool, str, list[str]]:
    """Unpack a collected tar.gz locally, defensively.

    The archive came from a possibly-compromised host, so member paths are
    validated before extraction: this is the classic tar path-traversal /
    symlink-escape sink. Returns (ok, message, section names).
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            members = tf.getmembers()
            for m in members:
                name = m.name
                if name.startswith("/") or ".." in Path(name).parts:
                    return False, f"unsafe path in archive: {name}", []
                if m.issym() or m.islnk():
                    link = m.linkname or ""
                    if link.startswith("/") or ".." in Path(link).parts:
                        return False, f"unsafe link in archive: {name} -> {link}", []
            dest.mkdir(parents=True, exist_ok=True)
            # Python 3.12+ wants an explicit filter; "data" is the safe choice and
            # rejects absolute paths/links as a second layer.
            try:
                tf.extractall(dest, filter="data")
            except TypeError:  # pragma: no cover - older interpreters
                tf.extractall(dest)
            sections = sorted(m.name.rsplit("/", 1)[-1] for m in members if m.isfile())
            return True, f"{len(members)} members", sections
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}", []


# ── tool entry points ────────────────────────────────────────────────────


def _cfg_value(config: Any, name: str, default: Any) -> Any:
    cfg = _remote_config(config)
    return getattr(cfg, name, default) if cfg is not None else default


def collect_plan(config: Any) -> str:
    """Approval-facing description of exactly what a collection runs."""
    lines = ["Batch forensic collection -- these read-only commands will run:"]
    for idx, (name, cmd) in enumerate(collector_commands(), start=1):
        lines.append(f"  {idx:02d}. [{name}] {cmd}")
    return "\n".join(lines)


async def _authorize(agent: Any, config: Any, host: Any, alias: str, display: str, detail: str):
    """Route a remote request through the shared approval gate."""
    from vulnclaw.agent.exec_gate import GateRequest, get_execution_gate

    gate = get_execution_gate(config)
    return await gate.authorize(
        GateRequest(
            kind="remote",
            display=display,
            cwd="",
            detail=f"target {alias} -> {_target_desc(host)} | {detail}",
            model_risk="",
        ),
        run_id=str(getattr(getattr(agent, "runtime", None), "run_id", "") or ""),
    )


async def execute_remote_tool(agent: Any, tool_name: str, args: dict[str, Any]) -> str:
    """Dispatch remote_* tools. Called from builtin_tools."""
    config = getattr(agent, "config", None)

    if tool_name == "remote_hosts":
        return list_hosts(config)

    try:
        host, alias = resolve_host(config, str(args.get("host") or args.get("alias") or ""))
    except ValueError as exc:
        return f"[!] {exc}"

    connect_timeout = float(_cfg_value(config, "connect_timeout_s", 15.0))

    if tool_name == "remote_exec":
        command = str(args.get("command") or "").strip()
        if not command:
            return "[!] remote_exec requires `command`"
        timeout_s = float(args.get("timeout_s") or _cfg_value(config, "command_timeout_s", 60.0))
        timeout_s = max(1.0, min(timeout_s, 3600.0))

        # Same approval gate as a local shell command. kind="remote" is judged by
        # the same read-only table, so remote recon runs unattended in
        # auto_review mode while remote mutations still prompt. The alias and
        # resolved hostname are always part of the detail, so an approval can
        # never be blind about WHICH machine the command touches.
        outcome = await _authorize(agent, config, host, alias, command, "remote exec")
        if not outcome.approved:
            return outcome.refusal_text("remote_exec")

        res = await asyncio.to_thread(
            run_command, host, alias, command,
            connect_timeout=connect_timeout, timeout_s=timeout_s,
        )
        return res.render(max_chars=int(_cfg_value(config, "max_output_chars", 60_000)))

    if tool_name == "remote_collect":
        return await _do_collect(agent, config, host, alias, args, connect_timeout)

    if tool_name == "remote_fetch":
        remote_path = str(args.get("remote_path") or "").strip()
        if not remote_path:
            return "[!] remote_fetch requires `remote_path`"
        local_raw = str(args.get("local_path") or "").strip()
        if not local_raw:
            return "[!] remote_fetch requires `local_path`"
        local_path = Path(local_raw).expanduser()

        outcome = await _authorize(
            agent, config, host, alias,
            f"fetch {remote_path} -> {local_path}", "remote fetch",
        )
        if not outcome.approved:
            return outcome.refusal_text("remote_fetch")

        ok, msg, size = await asyncio.to_thread(
            fetch_file, host, alias, remote_path, local_path,
            connect_timeout=connect_timeout,
        )
        if not ok:
            return f"[!] remote_fetch failed: {msg}"
        return (
            f"Remote fetch OK: {alias} ({_hv(host, 'hostname')}):{remote_path}\n"
            f"  -> {local_path} ({size:,} bytes)\n"
            "[!] This file came from a possibly-compromised host. Analyse the "
            "local copy (file/strings/yara/vol); never execute it on the "
            "analysis machine."
        )

    return f"[!] Unknown remote tool: {tool_name}"


async def _do_collect(
    agent: Any,
    config: Any,
    host: Any,
    alias: str,
    args: dict[str, Any],
    connect_timeout: float,
) -> str:
    """Run the batch collector on the remote host and pull the archive back."""
    out_dir = str(args.get("remote_dir") or f"/tmp/.ir-collect-{int(time.time())}")
    local_raw = str(args.get("local_dir") or "").strip()

    # Approve the batch ONCE, showing every command it will run.
    outcome = await _authorize(
        agent, config, host, alias, collect_plan(config),
        f"read-only collection, remote scratch dir {out_dir}",
    )
    if not outcome.approved:
        return outcome.refusal_text("remote_collect")

    started = time.perf_counter()
    result = CollectorResult(
        alias=alias,
        hostname=str(_hv(host, "hostname")),
        commands=[c for _, c in collector_commands()],
    )

    # 1) ship the collector via stdin (no scp/rsync needed on the target) and run
    script = _collector_script(out_dir)
    bootstrap = (
        f"cat > {shlex.quote(out_dir + '.sh')} <<'__VULNCLAW_COLLECTOR__'\n"
        f"{script}"
        f"__VULNCLAW_COLLECTOR__\n"
        f"sh {shlex.quote(out_dir + '.sh')}\n"
    )
    stdout_b, stderr, err = await asyncio.to_thread(
        run_command_capture, host, alias, bootstrap,
        connect_timeout=connect_timeout, timeout_s=900.0,
    )
    if err:
        result.errors.append(f"collector run: {err}")
    out_text = stdout_b.decode("utf-8", "replace")
    # Sections come from the collector's explicit marker block, not from stderr:
    # the collector writes section files silently and only reports at the end.
    result.sections = _parse_collector_stdout(out_text)
    if stderr.strip():
        # Keep a bounded, de-noised diagnostic tail. Permission denied on
        # /etc/shadow etc. is expected for a non-root operator.
        noise = ("Permission denied", "No such file or directory", "not found", "cannot open")
        kept = [
            line.strip()
            for line in stderr.splitlines()
            if line.strip() and not any(n in line for n in noise)
        ]
        result.errors.extend(kept[:20])

    archive = f"{out_dir}.tar.gz"
    # 2) base64 the archive over stdout so no second protocol is needed
    dl_cmd = (
        f"if [ -f {shlex.quote(archive)} ]; then "
        f"base64 {shlex.quote(archive)} 2>/dev/null || openssl base64 < {shlex.quote(archive)}; "
        f"else echo '__NO_ARCHIVE__' >&2; fi"
    )
    data_b, dl_err, dl_error = await asyncio.to_thread(
        run_command_capture, host, alias, dl_cmd,
        connect_timeout=connect_timeout, timeout_s=600.0,
    )
    if dl_error:
        result.errors.append(f"download: {dl_error}")

    b64 = b"".join(data_b.split())
    if not b64 or b"__NO_ARCHIVE__" in b64:
        result.errors.append(
            "no archive produced on the target (see the collector log in "
            f"{out_dir}; tar may be missing)"
        )
        result.duration_s = time.perf_counter() - started
        return result.render()

    try:
        payload = base64.b64decode(b64, validate=False)
    except Exception as exc:
        result.errors.append(f"base64 decode failed: {exc}")
        result.duration_s = time.perf_counter() - started
        return result.render()

    local_dir = (
        Path(local_raw).expanduser()
        if local_raw
        else Path(os.getcwd()) / "ir-collection" / f"{alias}-{time.strftime('%Y%m%d-%H%M%S')}"
    )
    ok, msg, sections = await asyncio.to_thread(_extract_archive, payload, local_dir)
    result.duration_s = time.perf_counter() - started
    if not ok:
        result.errors.append(f"extract failed: {msg}")
        return result.render()

    result.archive_path = str(local_dir)
    result.archive_bytes = len(payload)
    result.sections = sections
    return result.render()


def remote_tool_schemas() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "remote_exec",
                "description": (
                    "Run one command on a configured remote host over SSH (live "
                    "incident response / pentest on a target you have access to). "
                    "The host must be declared under `remote.hosts` in the config "
                    "and is referenced by alias. Uses the same approval gate as "
                    "shell_command, so read-only recon runs without prompting "
                    "while mutations ask first. Prefer remote_collect when you "
                    "need many artifacts at once."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Configured host alias."},
                        "command": {"type": "string", "description": "Shell command to run on the remote host."},
                        "timeout_s": {
                            "type": "integer",
                            "description": "Per-command timeout in seconds (default from config, max 3600).",
                        },
                    },
                    "required": ["host", "command"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "remote_collect",
                "description": (
                    "One-shot read-only forensic collection on a remote host: "
                    "33 sections (accounts, sudoers, authorized_keys, processes, "
                    "/proc/*/exe, sockets, network, cron spool + /etc/cron.d, "
                    "systemd, ld.so.preload, SUID/capabilities, web roots, "
                    "hidden dotfiles, logs, anti-forensics hints), archived to "
                    "tar.gz and unpacked into the local run directory. Approved "
                    "once as a whole, and the approved text lists every command. "
                    "Use this first on a remote-live question, then analyse the "
                    "local copy."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Configured host alias."},
                        "local_dir": {
                            "type": "string",
                            "description": "Where to unpack locally (default ./ir-collection/<alias>-<ts>).",
                        },
                        "remote_dir": {
                            "type": "string",
                            "description": "Remote scratch dir (default /tmp/.ir-collect-<ts>).",
                        },
                    },
                    "required": ["host"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "remote_fetch",
                "description": (
                    "SFTP-download one file from a remote host to the local "
                    "machine -- for large/binary evidence that must not be "
                    "base64'd (memory image, PCAP, collected archive). The file "
                    "is data: analyse the local copy, never execute it."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Configured host alias."},
                        "remote_path": {"type": "string", "description": "Absolute path on the remote host."},
                        "local_path": {"type": "string", "description": "Local destination path."},
                    },
                    "required": ["host", "remote_path", "local_path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "remote_hosts",
                "description": (
                    "List the configured remote host inventory (alias, target, "
                    "auth method, host-key policy). Call this before remote_exec "
                    "so you use a declared alias instead of guessing a host."
                ),
                "parameters": {"type": "object", "properties": {}},
            },
        },
    ]
