"""Deterministic external tool registry — the capability card.

Solves the "installed but invisible" gap: sqlmap/hashcat/ffuf/gobuster/binwalk/
exiftool/john/ROPgadget are installed on this machine but the solve agent has
no reliable way to know they exist or how to invoke them. This module builds a
compact text block ("capability card") injected into the system prompt at solve
start, listing only tools that are actually present and relevant to the goal.
"""

from __future__ import annotations

import shutil
from pathlib import Path

TOOLS_DIR = Path(r"E:\vulnclaw\tools")

# Each entry: name, detection (path or which), invocation, when-to-use keywords,
# one-line usage. Detection runs at build time; absent tools are omitted.
_REGISTRY: list[dict] = [
    {
        "name": "sqlmap",
        "detect": TOOLS_DIR / "sqlmap" / "sqlmap.py",
        "cmd": f'python "{TOOLS_DIR / "sqlmap" / "sqlmap.py"}"',
        "keywords": ["sqli", "sql注入", "注入", "inject", "union", "sql map"],
        "usage": '-u <url> --batch --dbs (注入检测); --forms --crawl=2 (自动表单)',
        "when": "SQL 注入检测与利用",
    },
    {
        "name": "hashcat (GPU)",
        "detect": None,  # glob for beta dir
        "detect_glob": str(TOOLS_DIR / "hashcat-beta" / "*" / "hashcat.exe"),
        "cmd": None,  # resolved at runtime from glob
        "keywords": ["hash", "哈希", "破解", "crack", "md5", "sha", "ntlm", "bcrypt", "密码"],
        "usage": "-m <mode> -a 0 <hash_file> <wordlist> (RTX 4060 MD5 ~28 GH/s)",
        "when": "GPU 加速哈希爆破（比 john 快 100 倍）",
    },
    {
        "name": "john",
        "detect": str(TOOLS_DIR / "john" / "john-1.9.0-jumbo-1-win64" / "run" / "john.exe"),
        "cmd": f'"{TOOLS_DIR / "john" / "john-1.9.0-jumbo-1-win64" / "run" / "john.exe"}"',
        "keywords": ["zip", "rar", "压缩包", "密码", "crack", "ssh key", "id_rsa"],
        "usage": "--wordlist=<dict> <hash_file>; zip2john <file.zip> > hash (提取 zip 密码哈希)",
        "when": "ZIP/RAR/SSH 密钥密码爆破 (CPU)",
    },
    {
        "name": "ffuf",
        "detect": TOOLS_DIR / "ffuf" / "ffuf.exe",
        "cmd": f'"{TOOLS_DIR / "ffuf" / "ffuf.exe"}"',
        "keywords": ["目录", "dir", "fuzz", "枚举", "enum", "path", "endpoint", "api"],
        "usage": '-u http://target/FUZZ -w <wordlist> -fc 404 (目录/路径 fuzz)',
        "when": "Web 目录与 API 端点发现",
    },
    {
        "name": "gobuster",
        "detect": TOOLS_DIR / "gobuster" / "gobuster.exe",
        "cmd": f'"{TOOLS_DIR / "gobuster" / "gobuster.exe"}"',
        "keywords": ["目录", "dir", "子域名", "subdomain", "vhost"],
        "usage": 'dir -u http://target -w <wordlist> (目录); dns -d domain -w subs.txt (子域)',
        "when": "Web 目录与子域名枚举",
    },
    {
        "name": "binwalk",
        "detect": None,  # python module
        "detect_module": "binwalk",
        "cmd": "python -m binwalk",
        "keywords": ["固件", "firmware", "嵌入", "embedded", "提取", "extract", " carve", "签名", "magic"],
        "usage": '<file> (签名扫描); -e <file> (自动提取嵌入文件)',
        "when": "固件/文件系统/嵌入文件提取",
    },
    {
        "name": "exiftool",
        "detect": TOOLS_DIR / "exiftool" / "exiftool(-k).exe",
        "cmd": f'"{TOOLS_DIR / "exiftool" / "exiftool(-k).exe"}"',
        "keywords": ["exif", "元数据", "metadata", "图片", "image", "jpg", "png", "pdf", "时间戳", "gps"],
        "usage": '<file> (读元数据); -a -u -g1 <file> (全量含重复组)',
        "when": "文件元数据提取（EXIF/GPS/PDF 作者等）",
    },
    {
        "name": "ROPgadget",
        "detect": None,
        "detect_which": "ROPgadget",
        "cmd": "ROPgadget",
        "keywords": ["rop", "gadget", "栈溢出", "stack", "ret2", "payload", "pwn"],
        "usage": '--binary <elf> (列 gadgets); --only "pop|ret" (过滤)',
        "when": "ROP 链构建（pwn 题 gadget 搜索）",
    },
    {
        "name": "nmap",
        "detect": None,
        "detect_which": "nmap",
        "cmd": "nmap",
        "keywords": ["端口", "port", "扫描", "scan", "服务", "service", "网络", "network"],
        "usage": '-sV -sC <target> (服务版本); -p- <target> (全端口)',
        "when": "网络端口与服务发现",
    },
]

# IR-specific tools (separate section)
_IR_REGISTRY: list[dict] = [
    {
        "name": "WinSCP (CLI)",
        "detect": Path(r"C:\Users\伟\AppData\Local\Programs\WinSCP\WinSCP.com"),
        "cmd": r'"C:\Users\伟\AppData\Local\Programs\WinSCP\WinSCP.com"',
        "keywords": ["sftp", "scp", "文件传输", "upload", "download", "取证", "collect"],
        "usage": '/command "open sftp://user:pass@host/" "get /remote/path C:\\local\\" (SFTP 传输)',
        "when": "SFTP/SCP 文件传输（取证采集、webshell 上传）",
    },
]


def _detect(entry: dict) -> str | None:
    """Return the invocation command if the tool is present, else None."""
    if entry.get("detect_glob"):
        import glob
        hits = glob.glob(entry["detect_glob"])
        if hits:
            return f'"{hits[0]}"'
        return None
    if entry.get("detect_module"):
        try:
            __import__(entry["detect_module"])
            return entry.get("cmd", entry["name"])
        except ImportError:
            return None
    if entry.get("detect_which"):
        if shutil.which(entry["detect_which"]):
            return entry["cmd"] or entry["name"]
        return None
    path = entry.get("detect")
    if path is None:
        return entry.get("cmd") or entry["name"]
    if Path(path).exists():
        return entry.get("cmd") or entry.get("name")
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
