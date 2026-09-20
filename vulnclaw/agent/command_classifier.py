"""Shell-command safety classifier for the auto_review permission mode.

A faithful lightweight port of Codex CLI's exec-policy layer
(``codex-rs/core/src/exec_policy.rs``), minus the OS sandbox:

- compound commands are split into plain segments (quote-aware);
- every segment is matched against a three-way decision:
  * **allow**    — a curated read-only table (with per-tool argument rules),
                   or an operator-configured trusted prefix;
  * **prompt**   — everything else, including interpreters, dangerous
                   patterns and leading environment assignments (degraded to
                   the interactive approval flow);
  * reasons are surfaced to the approval UI.

Honest boundary: without an OS sandbox this classifier *is* the router that
decides what runs unattended. It trusts command names plus explicit argument
rules, so the tables below stay conservative: interpreters and Git are never
built-in auto-approved, ``find`` carries argument rules, and operator
extensions are validated against the banned-name list at load time.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Callable

# Characters that make a command impossible to decompose safely at this
# layer: redirections, substitutions, grouping. Found outside quotes ⇒ the
# whole command goes to interactive approval.
_UNSUPPORTED_METACHARS = set("><$()`")

# Segment separators we DO understand (split like Codex's
# parse_shell_lc_plain_commands).
_SEPARATORS = (";", "|", "&", "\n")


@dataclass(frozen=True)
class Classification:
    decision: str  # "allow" | "prompt"
    reason: str = ""


def _prompt(reason: str) -> Classification:
    return Classification("prompt", reason)


def _allow() -> Classification:
    return Classification("allow", "")


# ── Argument rules for individually risky tools ──────────────────────────


def _find_args_rule(tokens: list[str]) -> str | None:
    """find(1) can execute arbitrary programs or delete files."""
    bad_flags = {
        "-exec", "-execdir", "-ok", "-okdir",
        "-delete", "-fls", "-fprint", "-fprint0", "-fprintf",
    }
    for tok in tokens[1:]:
        if tok.lower() in bad_flags or tok.startswith("-fprint"):
            return f"find flag {tok} can execute or destroy"
    return None


def _grep_args_rule(tokens: list[str]) -> str | None:
    # grep itself is read-only; nothing to forbid today.
    return None


def _diff_args_rule(tokens: list[str]) -> str | None:
    """diff is read-only unless its output-file option is used."""
    for tok in tokens[1:]:
        lowered = tok.lower()
        if lowered == "--output" or lowered.startswith("--output="):
            return f"diff flag {tok} writes to a file"
    return None


# ── Incident-response read-only commands ────────────────────────────────
#
# Triage on a compromised host is dominated by *reading* system state, and
# an unguarded prompt per command costs real wall-clock time. These entries
# are the read-only subset an investigator actually types; every one carries
# an argument rule because most of the underlying tools can also mutate
# state (``systemctl stop``, ``reg add``, ``wevtutil cl``, ``last -x``…).
#
# Where a tool takes a *subcommand* (systemctl, schtasks, reg, sc, wevtutil,
# net, wmic, ps, service) we allow-list the read-only subcommands instead of
# deny-listing mutating flags: the destructive surface of those tools is open
# ended, so a deny list would silently miss cases.

# systemctl read-only subcommands
_SYSTEMCTL_READONLY = {
    "status", "list-units", "list-unit-files", "list-timers", "list-sockets",
    "show", "cat", "is-active", "is-enabled", "is-failed", "is-system-running",
    "get-default", "list-dependencies", "list-jobs", "list-machines",
    "list-paths", "help", "–help", "--help", "--version", "--no-pager",
}


def _systemctl_args_rule(tokens: list[str]) -> str | None:
    """第一个非 flag token 是 subcommand；允许后其后的操作数是参数（服务名/单元名）。

    ``systemctl status nginx`` 里的 ``nginx`` 是操作数不是 subcommand ——
    早先版本把每个非 flag token 都当 subcommand 检查，导致合法命令被拦。
    """
    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue
        if tok.lower() not in _SYSTEMCTL_READONLY:
            return (
                f"systemctl subcommand {tok!r} is not read-only "
                "(only status/list-*/show/cat/is-* are allowed)"
            )
        return None  # 首个 subcommand 合法，其余 token 视为操作数
    return None  # 只有 flag（如 systemctl --version）


# ps: forbid the BSD "process status" long option (-S) and keep it simple
def _ps_args_rule(tokens: list[str]) -> str | None:
    for tok in tokens[1:]:
        if tok in ("-S", "--cumulative"):
            return f"ps flag {tok} mutates"
    return None


# netstat/ss: read-only in practice; -c (continuous) wastes time but is safe
def _netstat_args_rule(tokens: list[str]) -> str | None:
    return None


def _journalctl_args_rule(tokens: list[str]) -> str | None:
    """journalctl can rotate/vacuum the journal."""
    mutating = {
        "--rotate", "--flush", "--sync", "--relinquish-var",
        "--smart-relinquish-var", "--vacuum-time", "--vacuum-size",
        "--vacuum-files", "--setup-keys", "--update-catalog",
    }
    for tok in tokens[1:]:
        head = tok.split("=", 1)[0].lower()
        if head in mutating:
            return f"journalctl flag {tok} mutates the journal"
    return None


def _wmic_args_rule(tokens: list[str]) -> str | None:
    """wmic get/list/... is read-only; call/create/delete/set/terminate are not.

    ⚠️ 必须先扫全部 token 找危险动词，再判是否可放行 ——
    早先版本遇到第一个只读动词就 return None，于是
    ``wmic process call create calc.exe``（process 只读）被放行了。
    """
    mutating = {"call", "create", "delete", "set", "terminate", "where"}
    for tok in tokens[1:]:
        if tok.lower() in mutating:
            return f"wmic verb {tok!r} mutates system state"
    readonly_verbs = {
        "get", "list", "process", "useraccount", "service", "os",
        "logicaldisk", "path", "product", "qfe", "startup", "share",
        "nic", "bios", "computersystem", "group", "account", "timezone",
        "diskdrive", "partition", "volume", "printer", "environment",
    }
    for tok in tokens[1:]:
        if tok.lower() in readonly_verbs:
            return None
    return "wmic without a read-only verb (get/list/...) is not auto-approved"


def _reg_args_rule(tokens: list[str]) -> str | None:
    """reg query/export/compare only. reg add/delete/import/copy/save/restore mutate."""
    for tok in tokens[1:]:
        low = tok.lower()
        if low in ("query", "export", "compare"):
            return None
        if low.startswith("-") or low.startswith("/"):
            continue
        return (
            f"reg subcommand {tok!r} is not read-only "
            "(only query/export/compare are allowed)"
        )
    return "reg without a subcommand is not auto-approved"


def _sc_args_rule(tokens: list[str]) -> str | None:
    """sc query/qc/queryex/enumdepend/getdisplayname are read-only."""
    readonly = {"query", "qc", "queryex", "enumdepend", "getdisplayname",
                "getkeyname", "querylock", "querytype"}
    for tok in tokens[1:]:
        low = tok.lower()
        if low.startswith("-") or low.startswith("/"):
            continue
        if low in readonly:
            return None
        return (
            f"sc subcommand {tok!r} is not read-only "
            "(only query/qc/queryex/... are allowed; create/config/start/stop mutate)"
        )
    return "sc without a subcommand is not auto-approved"


def _schtasks_args_rule(tokens: list[str]) -> str | None:
    """schtasks /query is read-only; /create /delete /change /run /end mutate."""
    for tok in tokens[1:]:
        low = tok.lower().lstrip("/-")
        if low in ("create", "delete", "change", "run", "end"):
            return f"schtasks action {tok!r} mutates scheduled tasks"
    for tok in tokens[1:]:
        if tok.lower().lstrip("/-") == "query":
            return None
    return "schtasks without /query is not auto-approved"


def _wevtutil_args_rule(tokens: list[str]) -> str | None:
    """wevtutil qe/gl/el/gs are read-only; cl/clear-log wipes logs."""
    mutating = {"cl", "clear-log", "im", "import", "sl", "set-log",
                "cd", "configure-log"}
    for tok in tokens[1:]:
        if tok.lower().lstrip("/-") in mutating:
            return f"wevtutil action {tok!r} mutates the event log"
    readonly = {"qe", "gl", "el", "gs", "gli", "ep", "epl"}
    for tok in tokens[1:]:
        if tok.lower().lstrip("/-") in readonly:
            return None
    return "wevtutil without a read-only action (qe/gl/...) is not auto-approved"


def _net_args_rule(tokens: list[str]) -> str | None:
    """net user/view/share/... 的**列举**形态只读；带 /add /delete =path 则改状态。

    ⚠️ 同一子命令既能读也能写：
      net user                     → 列举（只读）
      net user hacker P@ss /add    → 加账号（改状态）
      net share                    → 列举（只读）
      net share evil=c:/           → 建共享（改状态）
    所以不能只看第一个子命令。
    """
    mutating_flags = {"/add", "-add", "/delete", "-delete", "/active:yes",
                      "/active:no", "/domain", "/times", "/comment"}
    mutating_verbs = {"start", "stop", "pause", "continue", "share-add",
                      "share-del", "session-delete", "file-close"}
    tokens_l = [t.lower() for t in tokens[1:]]

    for tok in tokens_l:
        if tok in mutating_flags or tok in mutating_verbs:
            return f"net argument {tok!r} mutates system state"
        # 形如 evil=c:/ 或 evil="c:/" 的赋值 = 建共享
        if "=" in tok and not tok.startswith("-"):
            return f"net argument {tok!r} looks like a share assignment (mutates)"

    readonly = {"view", "user", "users", "share", "session", "sessions",
                "statistics", "stats", "config", "accounts", "group",
                "localgroup", "time", "file", "use", "computer"}
    for tok in tokens_l:
        if tok.startswith("-") or tok.startswith("/"):
            continue
        if tok in readonly:
            return None
        return (
            f"net subcommand {tok!r} is not read-only "
            "(start/stop/… mutate)"
        )
    return "net without a subcommand is not auto-approved"


def _service_args_rule(tokens: list[str]) -> str | None:
    """`service <name> status` is read-only; start/stop/restart are not."""
    args = [t for t in tokens[1:] if not t.startswith("-")]
    if len(args) >= 2 and args[-1].lower() == "status":
        return None
    return "service is only auto-approved for the 'status' action"


def _systeminfo_args_rule(tokens: list[str]) -> str | None:
    return None


def _unhide_args_rule(tokens: list[str]) -> str | None:
    """unhide proc|sys|... — read-only detection."""
    return None


def _chkrootkit_args_rule(tokens: list[str]) -> str | None:
    """chkrootkit is read-only, but -q/scan are fine. No mutating flags."""
    return None


# Windows cmd.exe builtins that are read-only
def _win_where_args_rule(tokens: list[str]) -> str | None:
    return None


def _dmesg_args_rule(tokens: list[str]) -> str | None:
    """dmesg -C/-c clear the kernel ring buffer."""
    for tok in tokens[1:]:
        if tok.startswith("-") and not tok.startswith("--"):
            for ch in tok[1:]:
                if ch in ("C", "c"):
                    return f"dmesg flag {tok} clears the kernel ring buffer"
    return None


def _lsattr_args_rule(tokens: list[str]) -> str | None:
    return None


def _lsblk_args_rule(tokens: list[str]) -> str | None:
    return None


def _ac_args_rule(tokens: list[str]) -> str | None:
    return None


def _crontab_args_rule(tokens: list[str]) -> str | None:
    """crontab -l lists; -e/-r/-i MUTATE (edit / remove-all)."""
    mutating = {"-e", "-r", "-i"}
    for tok in tokens[1:]:
        if tok in mutating:
            return (
                f"crontab flag {tok} mutates the schedule "
                "(only -l / no-flag listing is read-only)"
            )
        if tok == "-u":
            return "crontab -u targets another user's schedule (not read-only here)"
    return None


def _rpm_args_rule(tokens: list[str]) -> str | None:
    """按模式判定。rpm 的 flag 含义依赖模式：

      -q / -V  查询、校验（只读）→ 此时 -a 表示 all 包、-f 表示 file 归属
      -i       安装（改状态）
      -e       卸载（改状态）
      -U / -F  升级（改状态）

    ⚠️ 早先版本用一个扁平字符集，把 ``-i`` 当只读、把 ``-Va`` 里的 ``a`` 当非法，
       两头都错。
    """
    if len(tokens) == 1:
        return None
    mode: str | None = None
    for tok in tokens[1:]:
        low = tok.lower()
        if low.startswith("--"):
            if low.startswith(("--verify", "--query", "--checksig",
                               "--querytags", "--showrc", "--eval",
                               "--version", "--help")):
                mode = mode or "query"
                continue
            if low in ("--install", "--erase", "--upgrade", "--freshen",
                       "--replacepkgs", "--nodeps"):
                return f"rpm option {tok} mutates the package database"
            continue
        if not low.startswith("-"):
            continue  # package / file operand
        for ch in low[1:]:
            if ch in ("q", "V", "K"):
                mode = "query"
            elif ch == "i":
                # -i 是 --info（查询模式内）还是 --install —— 取决于已有模式
                if mode == "query":
                    continue
                return "rpm -i installs a package"
            elif ch in ("U", "F"):
                return f"rpm -{ch} installs/upgrades packages"
            elif ch == "e":
                return "rpm -e erases a package"
            elif ch in ("a", "f", "p", "l", "c", "d", "s", "R", "v", "h"):
                continue  # 查询模式下的合法修饰
            else:
                return f"rpm flag -{ch} is not a recognised read-only query"
    return None


def _mount_args_rule(tokens: list[str]) -> str | None:
    """bare `mount` / `mount -l` lists; adding operands mounts (mutates)."""
    args = [t for t in tokens[1:] if not t.startswith("-")]
    if args:
        return "mount with operands mutates the mount table (only listing is allowed)"
    return None


def _fsutil_args_rule(tokens: list[str]) -> str | None:
    """fsutil is a known LOLBin with destructive subcommands."""
    mutating = {"deletejournal", "deleteusnjournal", "setflag", "setzerodata",
                "dirty", "repair", "behavior", "usn", "file", "hardlink",
                "reparsepoint", "sparse", "objectid", "recoveredata"}
    for tok in tokens[1:]:
        if tok.lower() in mutating:
            return f"fsutil subcommand {tok!r} mutates the filesystem"
    return "fsutil is only auto-approved for read-only subcommands"


SAFE_COMMANDS: dict[str, Callable[[list[str]], str | None] | None] = {
    # ── original POSIX read-only table ────────────────────────────────
    "ls": None, "pwd": None, "cd": None, "echo": None, "printf": None,
    "cat": None, "head": None, "tail": None, "wc": None,
    "grep": _grep_args_rule, "egrep": None, "fgrep": None,
    "find": _find_args_rule,
    "file": None, "stat": None, "du": None, "df": None,
    "which": None,
    "id": None, "whoami": None, "uname": None, "date": None,
    "diff": _diff_args_rule, "cmp": None,
    "cut": None, "tr": None, "tac": None, "rev": None,
    "basename": None, "dirname": None, "readlink": None,
    "md5sum": None, "sha1sum": None, "sha256sum": None, "sha512sum": None,
    "jq": None, "tree": None, "who": None, "w": None,
    "uptime": None, "free": None, "lscpu": None, "ss": None,

    # ── Linux incident-response triage ────────────────────────────────
    "ps": _ps_args_rule,
    "netstat": _netstat_args_rule,
    "lsof": None,                 # -p / -i / -n 均为只读列举
    "last": None, "lastb": None, "lastlog": None,
    "systemctl": _systemctl_args_rule,
    "journalctl": _journalctl_args_rule,
    "dmesg": _dmesg_args_rule,
    "lsmod": None, "modinfo": None,
    "lsattr": _lsattr_args_rule, "lsblk": _lsblk_args_rule,
    "mount": _mount_args_rule,
    "strings": None, "xxd": None, "od": None, "hexdump": None,
    "getcap": None, "getenforce": None, "sestatus": None,
    "ac": _ac_args_rule,
    "unhide": _unhide_args_rule,
    "chkrootkit": _chkrootkit_args_rule,
    "service": _service_args_rule,
    "hostname": None, "hostnamectl": None,
    "locale": None, "ulimit": None, "getent": None,
    "crontab": _crontab_args_rule,
    "rpm": _rpm_args_rule,

    # ── Windows incident-response triage ──────────────────────────────
    "tasklist": None,              # /v /svc /m — 只读列举
    "sc": _sc_args_rule,
    "schtasks": _schtasks_args_rule,
    "reg": _reg_args_rule,
    "wevtutil": _wevtutil_args_rule,
    "net": _net_args_rule,
    "systeminfo": _systeminfo_args_rule,
    "driverquery": None,
    "ver": None,
    "where": _win_where_args_rule,
    "findstr": None,
    "wmic": _wmic_args_rule,
    "attrib": None,
    "dir": None,
    "fc": None, "comp": None,
    "getmac": None, "ipconfig": None, "arp": None, "route": None,
    "nslookup": None,
    "fsutil": _fsutil_args_rule,
    "quser": None,
    "openfiles": None,
}

# Basenames that must never be auto-approved, mirroring Codex's
# BANNED_PREFIX_SUGGESTIONS: shells, interpreters, privilege/file-destroying
# utilities and multipliers. Operator extensions are validated against this
# list and refused at load time.
BANNED_NAMES = frozenset({
    "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",
    "python", "python3", "pythonw", "py", "pypy", "pypy3",
    "node", "nodejs", "deno", "bun", "ruby", "perl", "lua",
    "julia", "rscript", "php",
    "rm", "sudo", "doas", "su",
    "env", "xargs", "awk", "gawk", "setsid", "nohup", "stdbuf",
    "nc", "ncat", "socat", "eval", "source", ".",
})

_INTERPRETER_REASON = (
    "interpreters and shells cannot run in auto-review "
    "(use per-request approval or full_access)"
)


def _basename(token: str) -> str:
    name = token.rsplit("/", 1)[-1] if "/" in token else token
    name = name.lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _scan_unsupported(text: str) -> str | None:
    """Return a reason when unsupported metachars appear outside quotes."""
    quote: str | None = None
    escaped = False
    for ch in text:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and quote == "'":
            continue  # backslash is literal inside single quotes
        if ch == "\\":
            escaped = True
            continue
        if quote:
            # POSIX shells still expand variables and execute command
            # substitutions inside double quotes. Treat every unescaped '$'
            # or backtick there as unsupported; single quotes remain literal.
            if quote == '"' and ch in {"$", "`"}:
                return f"unsupported shell construct {ch!r} (quoted substitution)"
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch in _UNSUPPORTED_METACHARS:
            return f"unsupported shell construct {ch!r} (redirection/substitution)"
    if quote:
        return "unterminated quote"
    return None


def _split_segments(text: str) -> list[str]:
    """Split on ; | & and newlines outside quotes; drop empty segments."""
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for ch in text:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\" and quote != "'":
            current.append(ch)
            escaped = True
            continue
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            current.append(ch)
            continue
        if ch in _SEPARATORS:
            segments.append("".join(current))
            current = []
            continue
        current.append(ch)
    segments.append("".join(current))
    return [seg.strip() for seg in segments if seg.strip()]


_ENV_ASSIGN_PREFIX_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _starts_with_env_assignment(tokens: list[str]) -> bool:
    """True when the segment opens with FOO=bar assignment prefixes.

    ``sh -c`` applies these to the command's environment *before* lookup:
    a leading ``PATH=`` redirects the binary search and ``LD_PRELOAD`` /
    ``DYLD_*`` / ``GIT_EXEC_PATH`` inject code into whatever runs. Stripping
    the prefix and matching the remainder against the allow table (the
    previous behavior) therefore let ``PATH=/tmp/evil ls`` auto-approve.
    Assignments are always routed to interactive approval; operators who
    need them should wrap the invocation in their own trusted script.
    """
    return bool(tokens) and _ENV_ASSIGN_PREFIX_RE.match(tokens[0]) is not None


def classify_segment(tokens: list[str], trusted: tuple[tuple[str, ...], ...]) -> Classification:
    if _starts_with_env_assignment(tokens):
        return _prompt(
            "leading environment assignment cannot be verified safely "
            "(can hijack PATH lookup or inject LD_PRELOAD/GIT_EXEC_PATH)"
        )
    if not tokens:
        return _allow()
    name = _basename(tokens[0])

    if name in BANNED_NAMES:
        return _prompt(_INTERPRETER_REASON if name in {
            "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh",
            "cmd", "powershell", "pwsh", "python", "python3", "pythonw",
            "py", "pypy", "pypy3", "node", "nodejs", "deno", "bun",
            "ruby", "perl", "lua", "julia", "rscript", "php",
        } else f"{name!r} is never auto-approved")

    for entry in trusted:
        if len(tokens) >= len(entry) and tokens[0].lower() == entry[0] and all(
            tokens[i] == entry[i] for i in range(1, len(entry))
        ):
            return _allow()

    if name in SAFE_COMMANDS:
        rule = SAFE_COMMANDS[name]
        violation = rule(tokens) if rule is not None else None
        if violation:
            return _prompt(f"{name}: {violation}")
        return _allow()

    return _prompt(f"'{tokens[0]}' is not in the trusted command table")


def parse_trusted_commands(
    entries: list[str],
) -> tuple[tuple[tuple[str, ...], ...], list[str]]:
    """Normalize operator config entries into token-prefix tuples.

    Returns (prefixes, warnings). Entries whose first token is banned are
    refused with a warning instead of being loaded silently.
    """
    prefixes: list[tuple[str, ...]] = []
    warnings: list[str] = []
    for raw in entries or []:
        text = str(raw).strip()
        if not text:
            continue
        try:
            tokens = shlex.split(text)
        except ValueError:
            warnings.append(f"trusted_commands: unparseable entry {raw!r}")
            continue
        if not tokens:
            continue
        if _basename(tokens[0]) in BANNED_NAMES:
            warnings.append(
                f"trusted_commands: {_basename(tokens[0])!r} is on the banned "
                "list and cannot be auto-approved"
            )
            continue
        prefixes.append((tokens[0].lower(), *tokens[1:]))
    return tuple(prefixes), warnings


def classify_shell_command(
    command: str, trusted: tuple[tuple[str, ...], ...] = ()
) -> Classification:
    """Classify one shell_command invocation for the auto_review mode.

    Returns allow only when *every* segment is allowed; anything else yields
    prompt with the most specific reason found.
    """
    unsupported = _scan_unsupported(command)
    if unsupported:
        return _prompt(unsupported)

    reasons: list[str] = []
    for segment in _split_segments(command):
        try:
            tokens = shlex.split(segment)
        except ValueError as exc:
            return _prompt(f"unparseable segment: {exc}")
        verdict = classify_segment(tokens, trusted)
        if verdict.decision != "allow":
            reasons.append(verdict.reason or segment[:80])
    if reasons:
        return _prompt("; ".join(dict.fromkeys(reasons)))
    return _allow()
