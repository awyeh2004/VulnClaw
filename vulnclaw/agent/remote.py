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
   blindly. The collector declares its full effect up front — the data commands
   *and* the setup/finish steps (scratch-dir delete, archive write, teardown) and
   the local unpack destination — and both the approved text and the executed
   script are generated from the same lists in :func:`collector_commands`,
   :func:`_collector_preamble` and :func:`_collector_tail`, so they cannot drift
   apart. The `rm -rf "$OUT"` step is bounded twice over: :func:`_validate_remote_dir`
   only accepts a scratch dir directly under /tmp|/var/tmp|/dev/shm named
   `.ir-collect*`, and the script re-checks that pattern itself.

4. **Host key policy is explicit and the fingerprint is always reported.** A
   competition VM has no ``known_hosts`` entry, so a strict-only tool is
   unusable there; but silently trusting anything is a MITM hole. Default is
   strict; ``accept_new`` records the first-contact key into VulnClaw's own
   known_hosts and verifies against it from then on (TOFU with memory, not
   trust-always); ``insecure`` skips both. Whichever mode is used, the observed
   key fingerprint is printed into the tool output as an audit record.

5. **Nothing is left installed on the target.** The collector uses only POSIX
   shell and coreutils (verified against the Ubuntu 16.04 drill target, which has
   no python, no busybox, and no curl/wget), and it deliberately does not use
   ``tar`` in a way that can include its own output. It does create a scratch dir
   and an archive on the target while it runs; both — plus the uploaded script —
   are removed again once the archive is safely local, unless
   ``keep_remote=true`` was requested. That is a temporary write, not a
   read-only batch, and the approval text says so explicitly.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import os
import re
import shlex
import tarfile
import tempfile
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
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
    remote_cleaned: bool = False

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
        if self.remote_cleaned:
            lines.append(
                "Target left clean: the uploaded script, the archive and the "
                "scratch dir were removed from the remote host."
            )
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
    host raises, which is the correct default for an engagement.

    `accept_new` is TOFU with memory: the first contact is recorded into our own
    known_hosts file (see :func:`_known_hosts_path`) and every later session
    verifies against it, so a key that changes afterwards raises
    BadHostKeyException instead of being silently accepted. Recording is what
    makes the two policies genuinely different — without it, `accept_new` and
    `insecure` were behaviourally identical and every session was a fresh MITM
    window.

    `insecure` is the explicit "do not check, do not record" escape hatch.
    """
    policy = str(_hv(host, "host_key_policy", "known_hosts") or "known_hosts").strip().lower()
    return policy if policy in ("known_hosts", "accept_new", "insecure") else "known_hosts"


def _known_hosts_path() -> Path:
    """VulnClaw's own known_hosts, so TOFU decisions survive across sessions."""
    try:
        from vulnclaw.config.settings import CONFIG_DIR

        return Path(CONFIG_DIR) / "known_hosts"
    except Exception:  # pragma: no cover - config module always importable
        return Path.home() / ".vulnclaw" / "known_hosts"


def _load_our_host_keys(client: Any) -> None:
    path = _known_hosts_path()
    if path.is_file():
        try:
            client.load_host_keys(str(path))
        except Exception:
            pass  # unreadable/corrupt: fall back to system keys only


def _connect(host: Any, connect_timeout: float):
    paramiko = _import_paramiko()

    policy = _host_key_policy(host)
    client = paramiko.SSHClient()
    if policy == "known_hosts":
        client.load_system_host_keys()
        _load_our_host_keys(client)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        # Load what we already recorded: with AutoAddPolicy paramiko only
        # consults the policy for a MISSING key, so a host we have seen before
        # is still verified and a changed key raises.
        _load_our_host_keys(client)
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

    if policy == "accept_new":
        # Persist the key we just accepted so the NEXT session checks against it.
        try:
            path = _known_hosts_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            client.save_host_keys(str(path))
        except Exception:
            pass  # recording is best-effort; the fingerprint is still reported
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
    timeout_s: float = 600.0,
    overwrite: bool = False,
) -> tuple[bool, str, int]:
    """SFTP-download ``remote_path`` to ``local_path``.

    Returns (ok, message, bytes). Used for anything too large or too binary for
    base64-over-stdout: memory images, PCAPs, collected archives.

    Bounded in three ways, because an SFTP transfer over a black-holed link used
    to hang the worker thread forever (``asyncio.to_thread`` cannot be
    cancelled, so nothing upstream could rescue it):
      * the SFTP channel gets a socket timeout;
      * a per-chunk callback enforces a wall-clock deadline;
      * the download lands in a sibling temp file that is renamed into place
        only on success — a truncated transfer never replaces the destination
        or leaves a file that looks complete.

    ``local_path`` is never overwritten unless the caller opted in explicitly.
    """
    client = None
    tmp_path: Path | None = None
    try:
        if local_path.exists() and not overwrite:
            return (
                False,
                f"{local_path} already exists — refusing to overwrite it. "
                "Choose another local_path, or pass overwrite=true (the approval "
                "prompt names the file that will be replaced).",
                0,
            )
        client = _connect(host, connect_timeout)
        sftp = client.open_sftp()
        effective = max(1.0, min(float(timeout_s), 3600.0))
        try:
            chan = sftp.get_channel()
            if chan is not None:
                chan.settimeout(effective)
        except Exception:
            pass  # channel tuning is best-effort; the callback still bounds us
        local_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + effective

        def _watch(_transferred: int, _total: int) -> None:
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"transfer exceeded {effective:.0f}s (peer stalled?)"
                )

        fd, tmp_name = tempfile.mkstemp(
            dir=str(local_path.parent), prefix=".vulnclaw-fetch-"
        )
        os.close(fd)
        tmp_path = Path(tmp_name)
        sftp.get(remote_path, str(tmp_path), callback=_watch)
        sftp.close()
        size = tmp_path.stat().st_size
        os.replace(str(tmp_path), str(local_path))
        tmp_path = None
        return True, f"fetched {remote_path} -> {local_path}", size
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}", 0
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except OSError:
                pass
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


# ── collector scratch-dir policy ─────────────────────────────────────────
#
# The collector runs `rm -rf "$OUT"` where OUT is a model-supplied argument, so
# OUT has to be provably one of our own scratch dirs. Two independent gates:
# this Python check (a clear error before anything runs) and a `case` guard
# inside the script itself (defence in depth if the script is ever reused).
_SCRATCH_ROOTS = ("/tmp", "/var/tmp", "/dev/shm")
_SCRATCH_PREFIX = ".ir-collect"
# The basename is interpolated into shell and matched by an in-script `case`
# glob, so keep it to a charset those two agree on.
_SCRATCH_NAME_RE = re.compile(r"^\.ir-collect[A-Za-z0-9._-]*$")


def _validate_remote_dir(raw: str) -> tuple[str | None, str | None]:
    """Return (path, None) when safe to `rm -rf`, else (None, error)."""
    value = (raw or "").strip()
    if not value:
        return None, "remote_dir is empty"
    path = PurePosixPath(value)
    if not value.startswith("/"):
        return None, "remote_dir must be an absolute path on the target"
    if ".." in path.parts:
        return None, "remote_dir must not contain '..'"
    parent = str(path.parent)
    if parent not in _SCRATCH_ROOTS:
        return None, (
            f"remote_dir must sit directly under one of {_SCRATCH_ROOTS} "
            f"(got parent {parent!r}) — the collector deletes it recursively"
        )
    if not _SCRATCH_NAME_RE.match(path.name):
        return None, (
            f"remote_dir basename must match {_SCRATCH_PREFIX}[A-Za-z0-9._-]* "
            "(the collector deletes it recursively and the name is used in shell, "
            "so only its own scratch dir with a plain name may be targeted)"
        )
    return value, None


def _local_dir_entries(local_dir: Path) -> list[str]:
    """Existing entries in ``local_dir`` (empty when absent or unreadable)."""
    try:
        if not local_dir.exists():
            return []
        return sorted(p.name for p in local_dir.iterdir())
    except OSError:
        return []


def _collector_preamble(out_dir: str) -> list[tuple[str, str]]:
    """Fixed setup steps as (human description, shell line).

    Both the approval text and the executed script are generated from this list,
    which is what keeps them from drifting apart.
    """
    return [
        (
            f"refuse to run unless the scratch dir is one of ours "
            f"({out_dir} must match /tmp|/var/tmp|/dev/shm/{_SCRATCH_PREFIX}-*)",
            'case "$OUT" in '
            "/tmp/.ir-collect-*|/var/tmp/.ir-collect-*|/dev/shm/.ir-collect-*) ;; "
            '*) echo "refusing unexpected OUT=$OUT" >&2; exit 9 ;; esac',
        ),
        (
            "delete that scratch dir if it already exists (rm -rf, bounded by the "
            "guard above)",
            'rm -rf "$OUT" 2>/dev/null',
        ),
        ("recreate the scratch dir", 'mkdir -p "$OUT" || exit 1'),
        (
            "start the collector log",
            'echo "collector started: $(date -u 2>/dev/null)" > "$OUT/00-collector.log"',
        ),
    ]


def _collector_tail(out_dir: str, *, keep_remote: bool) -> list[tuple[str, str]]:
    """Fixed finishing steps as (human description, shell line)."""
    script_path = f"{out_dir}.sh"
    archive = f"{out_dir}.tar.gz"
    steps: list[tuple[str, str]] = [
        (
            "stamp the finish time",
            'echo "collector finished: $(date -u 2>/dev/null)" >> "$OUT/00-collector.log"',
        ),
        (
            "index the collected sections with their sizes",
            'for f in "$OUT"/*.txt; do\n'
            '  [ -f "$f" ] || continue\n'
            '  printf "%s\\t%s\\n" "$(basename "$f")" "$(wc -c < "$f" 2>/dev/null)"\n'
            'done > "$OUT/_INDEX.tsv" 2>/dev/null',
        ),
        (
            f"pack the sections into {archive} on the target (built from the "
            "scratch dir's parent, so it never archives itself)",
            'if command -v tar >/dev/null 2>&1; then\n'
            '  tar -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")" '
            "2>/dev/null \\\n"
            '    && { echo "=== COLLECTED ==="; cat "$OUT/_INDEX.tsv" 2>/dev/null; '
            'echo "ARCHIVE=$OUT.tar.gz"; exit 0; }\n'
            'fi\n'
            'echo "ARCHIVE=" && echo "[!] tar unavailable; sections are in $OUT" >&2\n'
            "exit 3",
        ),
    ]
    if keep_remote:
        steps.append((
            f"keep {archive} and {script_path} on the target (keep_remote=true)",
            ": # keep_remote=true -- nothing is removed from the target",
        ))
    else:
        steps.append((
            f"remove the uploaded script {script_path} from the target; "
            f"{archive} and the scratch dir are removed afterwards, once the "
            "archive is safely on this machine",
            f"rm -f {shlex.quote(script_path)} 2>/dev/null",
        ))
    return steps


def _collector_script(out_dir: str, *, keep_remote: bool = False) -> str:
    """Assemble the remote collector.

    A POSIX shell script driven by a command list appended at build time, so the
    approved command list and the executed steps are literally the same data.
    The fixed setup/finish steps come from :func:`_collector_preamble` and
    :func:`_collector_tail`, which the approval text also renders — the plan and
    the script therefore cannot disagree about what runs.

    The archive is built by writing each section into its own file under a
    dedicated scratch dir and then tar-ing that directory. It deliberately does
    NOT ``tar czf archive.tar.gz /`` (nor archive into a directory it is
    scanning), which is how "collect everything" scripts end up either recursing
    into their own output or silently including it.
    """
    lines = [
        "#!/bin/sh",
        "# Forensic batch collector -- POSIX sh, no extra tooling.",
        "# Generated by vulnclaw remote_collect; every step below is one of the",
        "# commands the operator approved.",
        "set -u",
        f"OUT={shlex.quote(out_dir)}",
    ]
    lines += [shell for _desc, shell in _collector_preamble(out_dir)]
    for idx, (name, cmd) in enumerate(collector_commands(), start=1):
        lines += [
            f"# ---- {name} ----",
            "{",
            f'  echo "### command: {cmd}"',
            f"  {cmd}",
            f'}} > "$OUT/{idx:02d}-{name}.txt" 2>&1',
        ]
    lines += [shell for _desc, shell in _collector_tail(out_dir, keep_remote=keep_remote)]
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


def _unsafe_member_reason(name: str) -> str | None:
    """Reject a member name that could escape the destination directory.

    Covers the POSIX shapes and the Windows ones that previously relied on
    ``filter="data"`` alone: ``C:/evil`` and ``\\\\server\\share`` are absolute
    on Windows even though POSIX code reads them as relative names, and the
    pre-3.12 fallback path had no filter at all.
    """
    value = name or ""
    if not value.strip():
        return "empty name"
    if "\x00" in value:
        return "NUL byte in name"
    normalized = value.replace("\\", "/")
    if normalized.startswith("/"):
        return "absolute path"
    if PureWindowsPath(value).drive:
        return "drive or UNC path"
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return "parent-directory traversal"
    return None


def _extract_archive(
    data: bytes, dest: Path, *, overwrite: bool = False
) -> tuple[bool, str, list[str]]:
    """Unpack a collected tar.gz locally, defensively.

    The archive came from a possibly-compromised host, so member paths are
    validated here — this is the classic tar path-traversal / symlink-escape
    sink. Extraction is then done member by member: the validation above is the
    gate, not the interpreter's ``filter=`` default, so an older Python without
    ``filter`` support cannot silently fall back to an unfiltered unpack. Local
    files are never replaced unless the caller opted in.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            members = tf.getmembers()
            for m in members:
                reason = _unsafe_member_reason(m.name)
                if reason:
                    return False, f"unsafe path in archive: {m.name} ({reason})", []
                if m.issym() or m.islnk():
                    link = m.linkname or ""
                    reason = _unsafe_member_reason(link)
                    if reason:
                        return (
                            False,
                            f"unsafe link in archive: {m.name} -> {link} ({reason})",
                            [],
                        )
                if m.ischr() or m.isblk() or m.isfifo() or m.isdev():
                    return False, f"unsafe member type in archive: {m.name}", []
            dest.mkdir(parents=True, exist_ok=True)
            if not overwrite:
                clashes = [str(dest / m.name) for m in members if (dest / m.name).exists()]
                if clashes:
                    return (
                        False,
                        f"refusing to overwrite {len(clashes)} existing path(s), "
                        f"e.g. {clashes[0]} (pass overwrite=true to replace them)",
                        [],
                    )
            for m in members:
                # Never restore setuid/setgid/sticky from evidence.
                m.mode &= 0o777
                try:
                    tf.extract(m, dest, filter="data")
                except TypeError:  # pragma: no cover - Python < 3.12
                    tf.extract(m, dest)
            sections = sorted(m.name.rsplit("/", 1)[-1] for m in members if m.isfile())
            return True, f"{len(members)} members", sections
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}", []


# ── tool entry points ────────────────────────────────────────────────────


def _as_bool(value: Any) -> bool:
    """Coerce a tool argument to bool without falling for ``bool("false")``.

    Tool schemas are advisory: a model can send the string ``"false"``, which is
    truthy in Python and would silently switch an opt-in guard ON.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    if value is None:
        return False
    return bool(value)


def _cfg_value(config: Any, name: str, default: Any) -> Any:
    cfg = _remote_config(config)
    return getattr(cfg, name, default) if cfg is not None else default


def collect_plan(
    config: Any,
    *,
    out_dir: str = "",
    local_dir: Any = None,
    keep_remote: bool = False,
    overwrite: bool = False,
) -> str:
    """Approval-facing description of exactly what a collection does.

    Rendered from the same lists that build the script (``collector_commands``,
    :func:`_collector_preamble`, :func:`_collector_tail`) plus the local
    destination. The previous version advertised "these read-only commands"
    while the script also ran ``rm -rf "$OUT"`` on a model-chosen path, unpacked
    into a model-chosen local directory, and left files on the target — an
    approval prompt that misdescribes the action is worse than no prompt, because
    the operator's consent is based on the description.
    """
    out = out_dir or "/tmp/.ir-collect-<timestamp>"
    lines = ["Batch forensic collection. Exactly what this will do:", ""]
    lines.append("ON THE TARGET — setup, before the commands below:")
    for step, (desc, _shell) in enumerate(_collector_preamble(out), start=1):
        lines.append(f"  {step:02d}. [setup] {desc}")
    lines.append("")
    lines.append("ON THE TARGET — data collection (read-only commands):")
    for step, (name, cmd) in enumerate(collector_commands(), start=1):
        lines.append(f"  {step:02d}. [{name}] {cmd}")
    lines.append("")
    lines.append("ON THE TARGET — finish:")
    tail = _collector_tail(out, keep_remote=keep_remote)
    for offset, (desc, _shell) in enumerate(tail, start=1):
        lines.append(f"  {len(collector_commands()) + offset:02d}. [finish] {desc}")
    lines.append("")
    lines.append("ON THIS MACHINE:")
    lines.append(
        f"  - unpack the downloaded archive into: {local_dir or '<default local_dir>'}"
    )
    if overwrite:
        lines.append(
            "    [overwrite=true] existing files at those paths WILL be replaced"
        )
    else:
        lines.append(
            "    [refused if occupied] existing files there are never replaced; "
            "the unpack is refused instead"
        )
    lines.append(
        "  - retrieved files are attacker-influenced data: read them with the "
        "evidence/file tools, never execute them"
    )
    lines.append("")
    lines.append(
        "NOTE: despite the read-only command list, this batch is not itself "
        "read-only — it deletes+recreates the scratch dir named above, writes an "
        "archive to the target, and (unless keep_remote=true) removes those again "
        "once the archive is safely local."
    )
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
        if not local_path.is_absolute():
            local_path = Path(os.getcwd()) / local_path
        overwrite = _as_bool(args.get("overwrite"))
        replacing = local_path.exists()
        if replacing and not overwrite:
            return (
                f"[!] remote_fetch: {local_path} already exists. Refusing to "
                "replace it — pick another local_path, or pass overwrite=true "
                "(the approval prompt then names the file being replaced)."
            )

        outcome = await _authorize(
            agent, config, host, alias,
            f"fetch {remote_path} -> {local_path}"
            + (
                "\n[!] the local file above EXISTS and will be REPLACED"
                if replacing
                else ""
            ),
            "remote fetch" + (" | overwrites an existing local file" if replacing else ""),
        )
        if not outcome.approved:
            return outcome.refusal_text("remote_fetch")

        ok, msg, size = await asyncio.to_thread(
            fetch_file, host, alias, remote_path, local_path,
            connect_timeout=connect_timeout,
            timeout_s=float(_cfg_value(config, "fetch_timeout_s", 600.0)),
            overwrite=overwrite,
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
    out_raw = str(args.get("remote_dir") or "").strip() or (
        f"/tmp/.ir-collect-{int(time.time())}"
    )
    out_dir, dir_error = _validate_remote_dir(out_raw)
    if dir_error:
        return f"[!] remote_collect: {dir_error}"
    assert out_dir is not None  # narrowed by dir_error being None

    keep_remote = _as_bool(args.get("keep_remote"))
    overwrite = _as_bool(args.get("overwrite"))

    local_raw = str(args.get("local_dir") or "").strip()
    local_dir = (
        Path(local_raw).expanduser()
        if local_raw
        else Path(os.getcwd()) / "ir-collection" / f"{alias}-{time.strftime('%Y%m%d-%H%M%S')}"
    )
    if not local_dir.is_absolute():
        local_dir = Path(os.getcwd()) / local_dir

    # Refuse to unpack over existing files: the destination is part of what the
    # operator must be able to see and consent to, and extract used to overwrite
    # same-named local files silently.
    occupied = _local_dir_entries(local_dir)
    if occupied and not overwrite:
        return (
            f"[!] remote_collect: local_dir {local_dir} already exists and is not "
            f"empty ({len(occupied)} entries, e.g. {occupied[0]}). Unpacking would "
            "replace same-named files. Pass overwrite=true to replace them, or "
            "pick a new/empty directory."
        )

    # Approve the batch ONCE, showing every remote step AND the local destination.
    outcome = await _authorize(
        agent, config, host, alias,
        collect_plan(
            config,
            out_dir=out_dir,
            local_dir=local_dir,
            keep_remote=keep_remote,
            overwrite=overwrite,
        ),
        f"batch collection | remote scratch dir {out_dir} | local unpack dir "
        f"{local_dir} | keep_remote={keep_remote}",
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
    script = _collector_script(out_dir, keep_remote=keep_remote)
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

    ok, msg, sections = await asyncio.to_thread(
        _extract_archive, payload, local_dir, overwrite=overwrite
    )
    result.duration_s = time.perf_counter() - started
    if not ok:
        result.errors.append(f"extract failed: {msg}")
        return result.render()

    result.archive_path = str(local_dir)
    result.archive_bytes = len(payload)
    result.sections = sections

    # 3) Leave nothing behind on the target unless asked to. The archive is only
    #    removed now, i.e. after it is safely unpacked locally — the previous
    #    behaviour left the uploaded script, the archive and the scratch dir on
    #    the target while the tool advertised that nothing was installed.
    if not keep_remote:
        cleanup = (
            f"rm -f {shlex.quote(archive)} {shlex.quote(out_dir + '.sh')} 2>/dev/null; "
            f"rm -rf {shlex.quote(out_dir)} 2>/dev/null; echo CLEANED"
        )
        _c_out, cleanup_err, cleanup_txt = await asyncio.to_thread(
            run_command_capture, host, alias, cleanup,
            connect_timeout=connect_timeout, timeout_s=60.0,
        )
        if cleanup_err or "CLEANED" not in cleanup_txt:
            result.errors.append(
                "remote cleanup did not confirm: "
                f"{cleanup_err or cleanup_txt.strip()[:200]} — "
                f"{archive}, {out_dir}.sh and {out_dir} may still exist on the target"
            )
        else:
            result.remote_cleaned = True

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
                    "One-shot forensic collection on a remote host: 33 read-only "
                    "triage sections (accounts, sudoers, authorized_keys, "
                    "processes, /proc/*/exe, sockets, network, cron spool + "
                    "/etc/cron.d, systemd, ld.so.preload, SUID/capabilities, web "
                    "roots, hidden dotfiles, logs, anti-forensics hints), archived "
                    "to tar.gz and unpacked into the local run directory. The batch "
                    "is approved once, and the approved text lists every remote "
                    "step — including the scratch-dir delete and the teardown — "
                    "plus the local unpack directory. Use this first on a "
                    "remote-live question, then analyse the local copy."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Configured host alias."},
                        "local_dir": {
                            "type": "string",
                            "description": (
                                "Where to unpack locally (default "
                                "./ir-collection/<alias>-<ts>). Must be empty/new "
                                "unless overwrite=true."
                            ),
                        },
                        "remote_dir": {
                            "type": "string",
                            "description": (
                                "Remote scratch dir (default "
                                "/tmp/.ir-collect-<ts>). Must sit directly under "
                                "/tmp, /var/tmp or /dev/shm with a basename "
                                "starting with '.ir-collect' — the collector "
                                "deletes it recursively."
                            ),
                        },
                        "keep_remote": {
                            "type": "boolean",
                            "description": (
                                "Leave the archive/script/scratch dir on the target "
                                "(default false: they are removed once the archive "
                                "is safely local)."
                            ),
                        },
                        "overwrite": {
                            "type": "boolean",
                            "description": (
                                "Allow replacing existing files in local_dir "
                                "(default false: a non-empty local_dir is refused)."
                            ),
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
                    "is data: analyse the local copy, never execute it. An "
                    "existing local file is never replaced unless overwrite=true."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Configured host alias."},
                        "remote_path": {"type": "string", "description": "Absolute path on the remote host."},
                        "local_path": {"type": "string", "description": "Local destination path."},
                        "overwrite": {
                            "type": "boolean",
                            "description": (
                                "Replace local_path if it already exists (default "
                                "false: the fetch is refused instead)."
                            ),
                        },
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
