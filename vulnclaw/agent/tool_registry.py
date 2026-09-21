"""Deterministic external tool registry — the capability card.

Solves the "installed but invisible" gap: sqlmap/hashcat/ffuf/gobuster/binwalk/
exiftool/john/ROPgadget are installed on this machine but the solve agent has
no reliable way to know they exist or how to invoke them. This module builds a
compact text block ("capability card") injected into the system prompt at solve
start, listing only tools that are actually present and relevant to the goal.

**Where the tool bundles are looked up.** Round-5 review N7: the entries were
built from one hardcoded ``E:\\vulnclaw\\tools`` plus a ``C:\\Users\\<name>\\...``
WinSCP path — a personal username committed to the repository, and on any other
machine every probe failed silently, so the card just came back missing entries.
Roots are now resolved at build time, in order:

1. ``$VULNCLAW_TOOLS_DIR`` (explicit override; see .env.example)
2. ``<CONFIG_DIR>/tools`` (where the setup wizard puts bundles)
3. ``~/vulnclaw/tools``, then ``~/tools``
4. the legacy ``E:\\vulnclaw\\tools`` — kept only so an existing install keeps
   working; set ``VULNCLAW_TOOLS_DIR`` and this can be deleted.

Detection also falls back to ``PATH`` (``shutil.which``) and to importable Python
modules, so a tool installed the normal way is found without any root at all.
"""

from __future__ import annotations

import glob
import os
import shutil
from pathlib import Path

#: Legacy bundle location, probed last. See the module docstring.
_LEGACY_TOOLS_DIR = Path(r"E:\vulnclaw\tools")


def _candidate_roots() -> list[Path]:
    """Every directory a tool bundle may live under, highest priority first."""
    roots: list[Path] = []
    env = os.environ.get("VULNCLAW_TOOLS_DIR", "").strip()
    if env:
        roots.append(Path(env).expanduser())
    try:
        from vulnclaw.config.settings import CONFIG_DIR

        roots.append(Path(CONFIG_DIR) / "tools")
    except Exception:
        pass
    roots.append(Path.home() / "vulnclaw" / "tools")
    roots.append(Path.home() / "tools")
    roots.append(_LEGACY_TOOLS_DIR)

    seen: set[str] = set()
    unique: list[Path] = []
    for root in roots:
        key = str(root).lower()
        if key not in seen:
            seen.add(key)
            unique.append(root)
    return unique


def tools_dir() -> Path:
    """The first tools root that exists (the legacy path when nothing else does)."""
    for root in _candidate_roots():
        if root.is_dir():
            return root
    return _candidate_roots()[-1]


def _local_app_data() -> Path:
    """``%LOCALAPPDATA%`` when set — an env value, never a hardcoded user name."""
    raw = (os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME") or "").strip()
    return Path(raw) if raw else Path.home() / "AppData" / "Local"


# Each entry: name, detection, invocation, when-to-use keywords, one-line usage.
# Detection runs at build time; absent tools are omitted.
#
# Detection keys, tried in this order by :func:`_detect`:
#   "abs_candidates"  callables returning absolute paths (env-derived)
#   "module"          importable Python module
#   "rel"             path parts under each tools root
#   "rel_glob"        glob under each tools root
#   "which"           command name on PATH
# "cmd" is a template in which "{path}" is replaced by whatever detection found.
_REGISTRY: list[dict] = [
    {
        "name": "sqlmap",
        "rel": ("sqlmap", "sqlmap.py"),
        "which": "sqlmap",
        "cmd": 'python "{path}"',
        "keywords": ["sqli", "sql注入", "注入", "inject", "union", "sql map"],
        "usage": '-u <url> --batch --dbs (注入检测); --forms --crawl=2 (自动表单)',
        "when": "SQL 注入检测与利用",
    },
    {
        "name": "hashcat (GPU)",
        "rel_glob": ("hashcat-beta", "*", "hashcat.exe"),
        "which": "hashcat",
        "cmd": '"{path}"',
        "keywords": ["hash", "哈希", "破解", "crack", "md5", "sha", "ntlm", "bcrypt", "密码"],
        "usage": "-m <mode> -a 0 <hash_file> <wordlist> (GPU 加速)",
        "when": "GPU 加速哈希爆破（比 john 快）",
    },
    {
        "name": "john",
        "rel": ("john", "john-1.9.0-jumbo-1-win64", "run", "john.exe"),
        "which": "john",
        "cmd": '"{path}"',
        "keywords": ["zip", "rar", "压缩包", "密码", "crack", "ssh key", "id_rsa"],
        "usage": "--wordlist=<dict> <hash_file>; zip2john <file.zip> > hash (提取 zip 密码哈希)",
        "when": "ZIP/RAR/SSH 密钥密码爆破 (CPU)",
    },
    {
        "name": "ffuf",
        "rel": ("ffuf", "ffuf.exe"),
        "which": "ffuf",
        "cmd": '"{path}"',
        "keywords": ["目录", "dir", "fuzz", "枚举", "enum", "path", "endpoint", "api"],
        "usage": '-u http://target/FUZZ -w <wordlist> -fc 404 (目录/路径 fuzz)',
        "when": "Web 目录与 API 端点发现",
    },
    {
        "name": "gobuster",
        "rel": ("gobuster", "gobuster.exe"),
        "which": "gobuster",
        "cmd": '"{path}"',
        "keywords": ["目录", "dir", "子域名", "subdomain", "vhost"],
        "usage": 'dir -u http://target -w <wordlist> (目录); dns -d domain -w subs.txt (子域)',
        "when": "Web 目录与子域名枚举",
    },
    {
        "name": "binwalk",
        "module": "binwalk",
        "cmd": "python -m binwalk",
        "keywords": ["固件", "firmware", "嵌入", "embedded", "提取", "extract", " carve", "签名", "magic"],
        "usage": '<file> (签名扫描); -e <file> (自动提取嵌入文件)',
        "when": "固件/文件系统/嵌入文件提取",
    },
    {
        "name": "exiftool",
        "rel": ("exiftool", "exiftool(-k).exe"),
        "which": "exiftool",
        "cmd": '"{path}"',
        "keywords": ["exif", "元数据", "metadata", "图片", "image", "jpg", "png", "pdf", "时间戳", "gps"],
        "usage": '<file> (读元数据); -a -u -g1 <file> (全量含重复组)',
        "when": "文件元数据提取（EXIF/GPS/PDF 作者等）",
    },
    {
        "name": "ROPgadget",
        "which": "ROPgadget",
        "cmd": "ROPgadget",
        "keywords": ["rop", "gadget", "栈溢出", "stack", "ret2", "payload", "pwn"],
        "usage": '--binary <elf> (列 gadgets); --only "pop|ret" (过滤)',
        "when": "ROP 链构建（pwn 题 gadget 搜索）",
    },
    {
        "name": "nmap",
        "which": "nmap",
        "cmd": "nmap",
        "keywords": ["端口", "port", "扫描", "scan", "服务", "service", "网络", "network"],
        "usage": '-sV -sC <target> (服务版本); -p- <target> (全端口)',
        "when": "网络端口与服务发现",
    },
]

# IR-specific tools (separate section). No user-specific paths: WinSCP is probed
# under %LOCALAPPDATA% and on PATH, so the same entry works on any Windows box.
_IR_REGISTRY: list[dict] = [
    {
        "name": "WinSCP (CLI)",
        "rel": ("WinSCP", "WinSCP.com"),
        "which": "WinSCP.com",
        "abs_candidates": (
            lambda: _local_app_data() / "Programs" / "WinSCP" / "WinSCP.com",
        ),
        "cmd": '"{path}"',
        "keywords": ["sftp", "scp", "文件传输", "upload", "download", "取证", "collect"],
        "usage": '/command "open sftp://user:pass@host/" "get /remote/path C:\\local\\" (SFTP 传输)',
        "when": "SFTP/SCP 文件传输（取证采集、webshell 上传）",
    },
]


def _render_cmd(entry: dict, path: str | None) -> str:
    """Substitute the resolved path into the entry's command template."""
    template = entry.get("cmd") or entry["name"]
    if "{path}" in template:
        return template.replace("{path}", path or entry["name"])
    return template


def _detect(entry: dict) -> str | None:
    """Return the invocation command if the tool is present, else None."""
    # 1) explicit absolute candidates (env-derived, never a user name)
    for factory in entry.get("abs_candidates") or ():
        try:
            candidate = factory()
        except Exception:
            continue
        if Path(candidate).is_file():
            return _render_cmd(entry, str(candidate))

    # 2) an importable module
    module = entry.get("module")
    if module:
        try:
            __import__(module)
        except ImportError:
            pass
        else:
            return _render_cmd(entry, None)

    # 3) the tools roots (relative paths, so any root works)
    rel = entry.get("rel")
    if rel:
        for root in _candidate_roots():
            candidate = root.joinpath(*rel)
            if candidate.is_file():
                return _render_cmd(entry, str(candidate))
    rel_glob = entry.get("rel_glob")
    if rel_glob:
        for root in _candidate_roots():
            hits = glob.glob(str(root.joinpath(*rel_glob)))
            if hits:
                return _render_cmd(entry, hits[0])

    # 4) PATH — how tools are normally installed
    which = entry.get("which")
    if which:
        found = shutil.which(which)
        if found:
            return _render_cmd(entry, found)
    return None


def _match(goal_lower: str, keywords: list[str]) -> bool:
    return any(k in goal_lower for k in keywords)


def build_tool_card(goal: str) -> str:
    """Build the capability card for this goal. Returns empty string if no tools match."""
    goal_lower = (goal or "").lower()
    lines: list[str] = []

    for entry in _REGISTRY:
        cmd = _detect(entry)
        if not cmd:
            continue
        if not _match(goal_lower, entry.get("keywords", [])):
            continue
        lines.append(f"- **{entry['name']}**: `{cmd}` — {entry['usage']} ({entry['when']})")

    if not lines:
        return ""

    card = "\n\n# External tools available on this host\n"
    card += "These are installed and verified. Use shell_command to invoke them.\n"
    card += "\n".join(lines)

    # bg_launch hint when cracking tools are relevant
    if any(k in goal_lower for k in ["hash", "crack", "破解", "密码", "爆破"]):
        card += (
            "\n- ⭐ Long-running cracking: use `bg_launch` to run hashcat/john "
            "in the background while you continue exploring."
        )
    return card
