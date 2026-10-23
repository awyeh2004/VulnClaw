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
import re
import shutil
from pathlib import Path

#: Legacy bundle location, probed last. See the module docstring.
_LEGACY_TOOLS_DIR = Path(r"E:\vulnclaw\tools")


def _repo_ir_tools_dir() -> Path:
    """``<repo>/.ir-tools`` when running from a checkout, else a harmless miss.

    Resolved relatively (``tool_registry.py`` -> parents[2]) so the same code
    works on any machine; never an absolute personal path.
    """
    return Path(__file__).resolve().parents[2] / ".ir-tools"


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
    # Workspace-local IR toolkit (gitignored; mirrored to the portable drive as
    # G:\tool\ir-toolkit). Probed LAST so an explicit override or a wizard-installed
    # bundle always wins -- but probed at all, because otherwise the ~30 incident-
    # response tools under .ir-tools/bin were undetectable and never reached the
    # capability card, leaving the IR half of a competition with no tool awareness.
    roots.append(_repo_ir_tools_dir())

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
        "name": "7-Zip full (RAR + encrypted archives)",
        "rel": ("7z-full", "7z.exe"),
        "cmd": '"{path}"',
        # `always` under ctf for the same reason as bsdtar: the handout's FORMAT is
        # not in the goal text. Measured 2026-10-18 (after bsdtar was added and
        # working): challenges kept shipping ENCRYPTED RARs, which bsdtar/libarchive
        # cannot open, so the agent went back to installing extractors mid-run --
        # downloading 7zip installers and probing pip for `unrar` bindings. The full
        # 7-Zip build bundles unrar-capable code in 7z.dll; verified that
        # `7z x -pctf enc.rar` extracts an encrypted RAR ("Everything is Ok").
        "always": True,
        "keywords": ["rar", "7z", "加密", "password", "密码", "压缩包", "archive", "extract", "解压"],
        "usage": '-x -y -p<pw> <file> -o<dir> (解压，支持加密 RAR); l <file> (列表)',
        "when": "**加密 RAR 只有它能解**（bsdtar/libarchive 不支持 RAR 加密，会静默失败）。"
                "zip/tar/7z 也可以用它",
    },
    {
        "name": "bsdtar (libarchive)",
        "which": "bsdtar",
        "cmd": "bsdtar",
        # `always` means "offered on every CTF run regardless of goal wording",
        # because a challenge attachment's FORMAT never appears in the goal text
        # (CTF goals carry only the name/category/difficulty). Measured 2026-10-18:
        # a RAR challenge produced a card WITHOUT bsdtar -- in fact an empty card --
        # and the agent went back to hunting for unrar.
        #
        # Deliberately NOT global: `build_tool_card` honours this flag for
        # ``mode == "ctf"`` only. A bug-hunting engagement does not arrive as a
        # handout, so `pentest` stays keyword-driven (an archive-related goal still
        # matches here); `auto`/`ir` are unaffected. See ``build_tool_card``.
        "always": True,
        "keywords": ["zip", "rar", "7z", "压缩包", "archive", "extract", "解压", "解包", "attachment"],
        # Why the "when" text names the failures: a generic "extract archives"
        # line did not stop the hunt. Measured across one afternoon of runs, the
        # agent tried rarfile (needs an unrar binary that is not installed),
        # py7zr (no RAR support), the bundled 7zr.exe (lists a RAR header then
        # fails with "Cannot open the file as archive"), and a full-disk scan for
        # unrar*.exe -- while bsdtar was on PATH the whole time. `reverse1` only
        # got past the same gap because the model happened to guess `tar`.
        "usage": '-tf <file> (列表); -xf <file> -C <dir> (解压). Windows 自带同名同款: C:\\Windows\\System32\\tar.exe',
        "when": "解压 zip/7z/tar。**能列 RAR 但不能解加密 RAR**（解压会失败）——"
                "RAR 一律优先用上面的 7-Zip full，别在这里浪费时间",
    },
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
        "name": "F5 隐写 (F5.jar)",
        "rel": ("stego", "Extract.class"),
        "cmd": (
            'java --add-exports java.base/sun.security.provider=ALL-UNNAMED '
            '-cp "{dir}" Extract'
        ),
        # Why this entry exists (2026-10-18): JPEG F5 steganography is a BUUCTF
        # staple and the only extractor is F5.jar. Measured across two days of
        # logs, F5 was named in 52 of them -- the run would search the whole disk
        # for F5.jar, fail, and either give up or waste a stall window. The class
        # files are vendored under the configured tools root so the tool is
        # always present. `cmd` is a compound because the classes are loaded by
        # class name from their directory (java needs the classpath), which is
        # why the template carries `{dir}` rather than `{path}` -- it used to
        # hardcode one machine's tools root and broke on any other root.
        #
        # ``--add-exports`` is REQUIRED on JDK >= 9 (measured 2026-10-19, JDK 24).
        # Without it the tool does not start at all:
        #   IllegalAccessError: class crypt.F5Random cannot access class
        #   sun.security.provider.SecureRandom (in module java.base)
        # The module system stopped exporting that package, so the registered
        # command was silently unusable -- "tool exists" was not "tool works".
        "keywords": ["jpg", "jpeg", "隐写", "stego", "f5", "图片", "image", "藏"],
        "usage": '-p <password> <image.jpg> (提取; 默认密码 abc123); '
                 'Embed <cover.jpg> -e <file> -p <pw> <out.jpg> (嵌入)',
        "when": "JPEG 的 F5 隐写提取/嵌入。**别的工具都解不了 F5**：steghide/outguess 是不同算法。"
                "先试默认密码 abc123，不行再用 run 里的口令线索",
    },
    {
        "name": "二维码/条码识别 (pyzbar + cv2)",
        "module": "pyzbar",
        "cmd": "python -c \"from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open(r'<img>')))\"",
        "keywords": ["qr", "二维码", "barcode", "条码", "扫码", "识别"],
        "usage": 'pyzbar.pyzbar.decode(Image.open(path)) — 返回 data 字节; '
                 'cv2.QRCodeDetector().detectAndDecode(img) 作为备选',
        "when": "二维码/条码解码（pyzbar 已装；损坏的码可先 cv2 放大二值化）",
    },
    {
        "name": "OCR (easyocr)",
        "module": "easyocr",
        "cmd": "python -c \"import easyocr; print(easyocr.Reader(['ch_sim','en'], gpu=False).readtext(r'<img>', detail=0))\"",
        "keywords": ["ocr", "识别文字", "图片文字", "截图", "screenshot", "读字", "图", "image", "文字"],
        "usage": "easyocr.Reader(['ch_sim','en'], gpu=False).readtext(path, detail=0)",
        "when": "图片/截图里的文字识别。**本机没有 tesseract**，用 easyocr（已装，纯 Python，首次加载模型约 20s）",
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
        "keywords": ["端口", "port", "扫描", "scan", "服务发现", "服务版本", "service", "网络", "network"],
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
    # ── Windows host forensics (the .ir-tools/bin bundle; Sysinternals + NirSoft) ──
    {
        "name": "Autoruns",
        "rel": ("bin", "Autoruns", "Autoruns64.exe"),
        "which": "Autoruns64.exe",
        "cmd": '"{path}" -accepteula -a * -c -h -s -m -v > autoruns.csv',
        "keywords": ["持久化", "自启动", "开机启动", "persistence", "autorun", "注册表启动", "计划任务"],
        "usage": '-accepteula -a * -c -h -s -m -v > out.csv (全量含哈希, 免交互)',
        "when": "自启动/持久化项全量导出（应急响应第一优先）",
    },
    {
        "name": "Process Explorer",
        "rel": ("bin", "ProcessExplorer", "procexp64.exe"),
        "which": "procexp64.exe",
        "cmd": '"{path}" /accepteula',
        "keywords": ["进程", "句柄", "dll", "父进程", "可疑进程", "异常进程"],
        "usage": '/accepteula (GUI；查进程树、句柄、加载的 DLL 与数字签名)',
        "when": "可疑进程与 DLL 分析（比任务管理器深）",
    },
    {
        "name": "Procmon",
        "rel": ("bin", "Procmon", "Procmon64.exe"),
        "which": "Procmon64.exe",
        "cmd": '"{path}" /accepteula /Quiet /Minimized /BackingFile trace.pml',
        "keywords": ["行为监控", "文件监控", "注册表监控", "动态分析", "恶意行为"],
        "usage": '/accepteula /Quiet /BackingFile t.pml (后台录制文件/注册表/进程行为)',
        "when": "动态行为监控（复现恶意样本动作）",
    },
    {
        "name": "TCPView",
        "rel": ("bin", "TCPView", "Tcpview64.exe"),
        "which": "Tcpview64.exe",
        "cmd": '"{path}" /accepteula',
        "keywords": ["网络连接", "tcp", "udp", "外联", "回连", "端口占用", "c2", "外联地址"],
        "usage": '/accepteula (GUI；看哪个进程持有哪个连接，含已关闭连接)',
        "when": "进程↔连接归属（定位外联/C2）",
    },
    {
        "name": "FullEventLogView",
        "rel": ("bin", "FullEventLogView", "FullEventLogView.exe"),
        "which": "FullEventLogView.exe",
        "cmd": '"{path}" /scomma events.csv',
        "keywords": ["事件日志", "eventlog", "日志分析", "4624", "4625", "登录", "审计", "windows日志"],
        "usage": '/scomma out.csv (全部事件导出 CSV；含安全/系统/应用日志)',
        "when": "Windows 事件日志批量导出与检索",
    },
    {
        "name": "LastActivityView",
        "rel": ("bin", "LastActivityView", "LastActivityView.exe"),
        "which": "LastActivityView.exe",
        "cmd": '"{path}" /scomma activity.csv',
        "keywords": ["活动记录", "操作痕迹", "入侵时间", "时间线", "timeline", "最近操作", "首次入侵"],
        "usage": '/scomma out.csv (合并出主机活动时间线)',
        "when": "主机活动时间线（推断入侵时间点）",
    },
    {
        "name": "BrowsingHistoryView",
        "rel": ("bin", "BrowsingHistoryView", "BrowsingHistoryView.exe"),
        "which": "BrowsingHistoryView.exe",
        "cmd": '"{path}" /scomma history.csv',
        "keywords": ["浏览器", "browser", "历史记录", "history", "下载记录", "上网痕迹"],
        "usage": '/scomma out.csv (聚合 IE/Edge/Chrome/Firefox 历史)',
        "when": "浏览器历史取证（攻击者访问痕迹）",
    },
    {
        "name": "ShellBagsView",
        "rel": ("bin", "ShellBagsView", "ShellBagsView.exe"),
        "which": "ShellBagsView.exe",
        "cmd": '"{path}" /scomma shellbags.csv',
        "keywords": ["shellbags", "文件夹访问", "资源管理器", "目录访问痕迹", "挂载"],
        "usage": '/scomma out.csv (攻击者浏览过的目录)',
        "when": "目录访问痕迹（已删除/外接盘的访问证据）",
    },
    {
        "name": "UserAssistView",
        "rel": ("bin", "UserAssistView", "UserAssistView.exe"),
        "which": "UserAssistView.exe",
        "cmd": '"{path}" /scomma userassist.csv',
        "keywords": ["userassist", "程序执行痕迹", "执行记录", "gui程序"],
        "usage": '/scomma out.csv (通过 Explorer 启动过的程序)',
        "when": "程序执行痕迹（攻击者运行过什么）",
    },
    {
        "name": "WinPrefetchView",
        "rel": ("bin", "WinPrefetchView", "WinPrefetchView.exe"),
        "which": "WinPrefetchView.exe",
        "cmd": '"{path}" /scomma prefetch.csv',
        "keywords": ["prefetch", "预读取", "程序执行", "执行次数", "取证"],
        "usage": '/scomma out.csv (含执行次数与最后执行时间)',
        "when": "程序执行取证（Prefetch 解析）",
    },
    {
        "name": "DNSDataView",
        "rel": ("bin", "DNSDataView", "DNSDataView.exe"),
        "which": "DNSDataView.exe",
        "cmd": '"{path}" /scomma dns.csv',
        "keywords": ["dns", "域名解析", "解析缓存", "c2域名", "解析记录", "dns缓存"],
        "usage": '/scomma out.csv (DNS 客户端缓存解析记录)',
        "when": "DNS 缓存取证（C2 域名解析痕迹）",
    },
    {
        "name": "WifiHistoryView",
        "rel": ("bin", "WifiHistoryView", "WifiHistoryView.exe"),
        "which": "WifiHistoryView.exe",
        "cmd": '"{path}" /scomma wifi.csv',
        "keywords": ["wifi", "无线", "接入点", "地理位置", "移动痕迹"],
        "usage": '/scomma out.csv (连接过的 AP 与时间)',
        "when": "无线接入历史（设备移动轨迹）",
    },
    {
        "name": "Sysmon",
        "rel": ("bin", "Sysmon", "Sysmon64.exe"),
        "which": "Sysmon64.exe",
        "cmd": '"{path}" -accepteula -i <config.xml>',
        "keywords": ["sysmon", "进程创建", "审计", "监控", "遥测", "日志采集"],
        "usage": '-accepteula -i config.xml (安装；进程/网络/文件/注册表遥测进事件日志)',
        "when": "主机遥测采集（需要更细粒度的执行证据时）",
    },
    {
        "name": "volatility3",
        "rel": ("bin", "vol.cmd"),
        "which": "vol",
        "cmd": '"{path}" -f <memory.dmp> <plugin>',
        "keywords": ["内存镜像", "内存取证", "memory", "dump", "进程列表", "malfind", "pslist", "内核"],
        "usage": '-f <dmp> windows.pslist|windows.malfind|windows.netscan (内存镜像分析)',
        "when": "内存镜像取证（进程/注入/网络连接）",
    },
    {
        "name": "D盾_Web查杀",
        "rel": ("bin", "D盾_Web查杀", "D_Safe_Manage.exe"),
        "which": "D_Safe_Manage.exe",
        "cmd": '"{path}"',
        "keywords": ["webshell", "查杀", "木马", "后门", "网页后门", "web目录", "一句话"],
        "usage": 'GUI：指定 web 根目录做 webshell 特征查杀与可疑文件定位',
        "when": "Web 目录 webshell 查杀（国内环境特征库强）",
    },
]


def _render_cmd(entry: dict, path: str | None) -> str:
    """Substitute the resolved path into the entry's command template.

    ``{path}`` is the resolved file, ``{dir}`` its parent directory -- for tools
    that load classes by directory (F5's ``-cp "<dir>" Extract``). The entry used
    to hardcode one machine's tools root, so a relocated bundle produced a card
    that "found" F5 but could not run it (2026-10-19).
    """
    template = entry.get("cmd") or entry["name"]
    resolved = path or entry["name"]
    if "{path}" in template:
        template = template.replace("{path}", resolved)
    if "{dir}" in template:
        template = template.replace("{dir}", str(Path(resolved).parent))
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


def _unavailable_on_host(entry: dict[str, Any]) -> bool:
    """Whether every named alternative is absent from the process PATH.

    The old block hardcoded one developer machine's Docker/package-manager
    state and rendered it on every CTF run. Only the absence of the actual
    alternatives is portable and verifiable here; host-specific installation
    policy is deliberately not asserted.
    """
    for command in entry.get("commands", ()):
        if shutil.which(command):
            return False
    return True


def _match(goal_lower: str, keywords: list[str]) -> bool:
    """Keyword match with word boundaries for pure-ASCII tokens.

    Round-5 N2: bare substring matching made tokens like "ioc" fire inside
    "association" and "triage" inside "pilgrimage" — over-injection only, but
    noisy. Pure-ASCII keywords require non-alphanumeric edges; CJK and mixed
    keywords keep plain substring semantics (no word concept to anchor on).
    """
    for k in keywords:
        if k.isascii() and k.isalnum():
            if re.search(rf"(?:^|[^a-z0-9]){re.escape(k)}(?:$|[^a-z0-9])", goal_lower):
                return True
        elif k in goal_lower:
            return True
    return False


# The IR section is gated as a WHOLE, not only per tool.
#
# Round-6 review F3: per-tool keywords alone let a web challenge description
# containing 「登录」 inject FullEventLogView and friends into the system prompt,
# and the same shape had already been admitted for nmap's 「服务」 matching
# 「服务器」. A keyword is a weak signal; the *intent* of the goal is a strong one.
# So the section renders only when the goal reads like incident response at all,
# and the per-tool keywords then refine WHICH tools show.
#
# The vocabulary deliberately mirrors the incident-response skill's routing
# keywords (vulnclaw/skills/dispatcher.py) so "what an IR goal looks like" has one
# answer in the codebase instead of two drifting ones.
IR_INTENT_KEYWORDS: tuple[str, ...] = (
    # Qualified phrases mirroring the incident-response skill's routing keywords
    # (vulnclaw/skills/dispatcher.py) — one vocabulary, not two that drift.
    "应急响应", "应急排查", "应急取证", "入侵排查", "被入侵", "失陷主机", "失陷",
    "被植入", "恶意程序", "恶意行为", "恶意样本", "webshell", "webshell查杀",
    "查马", "查杀木马", "后门排查", "隐藏后门", "持久化排查", "权限维持",
    "挖矿木马", "挖矿", "勒索病毒", "勒索信", "勒索", "网页篡改", "挂黑链",
    "暗链", "黑链", "网页被改", "克隆账号", "隐藏账号", "隐藏用户", "异常账号",
    "账号被篡改", "日志分析", "日志排查", "攻击溯源", "溯源分析", "主机取证",
    "内存取证", "内存马", "痕迹分析", "事件日志", "事件id", "登录类型",
    "incident response", "dfir", "forensic", "compromise assessment",
    "threat triage", "triage", "ioc", "evtx", "prefetch", "amcache",
    # Bare host-malware / evidence-handling terms: specific enough on their own.
    # (Deliberately NOT here: 排查 / 响应 / 审计 alone — a pentest goal like
    # "排查一下这个接口的越权" would open the gate for no reason.)
    "木马", "后门", "查杀", "痕迹", "取证",
)


def _is_ir_goal(goal_lower: str) -> bool:
    """Whether the goal is an incident-response / forensics task at all."""
    return _match(goal_lower, list(IR_INTENT_KEYWORDS))


#: Tools the goal will make the model reach for that this host CANNOT run, plus what
#: to do instead. Rendered as an explicit "not available" block.
#:
#: Why this exists (measured 2026-10-20, 九连环): the model wanted steghide for a JPEG
#: stego challenge. It was not installed, so the model went looking for a package
#: manager, then launched Docker Desktop and waited for the daemon — which cannot
#: start on this host. It burned 8+ steps and several minutes on the installation
#: attempt before the run had to be stopped by hand. Nothing in the card said "this
#: tool does not exist here"; silence reads as "not detected yet, go find it".
#:
#: Keep this list SHORT and factual: it states what the host lacks, not whether the
#: technique is worth trying.
_UNAVAILABLE: tuple[dict[str, Any], ...] = (
    {
        "name": "steghide / outguess / zsteg",
        "keywords": [
            "jpg", "jpeg", "隐写", "stego", "steghide", "outguess", "zsteg",
            "图片", "image", "藏", "wav", "音频", "音频隐写",
        ],
        "why": "not detected on this host's PATH or configured tool roots. "
               "Do not try to install it or spend solve steps setting up a package manager "
               "or container runtime: carve appended/embedded data by hand instead "
               "(trailing bytes after FFD9 / RIFF end, PK\\x03\\x04 header, LSB planes); "
               "for F5 use the F5 entry above.",
        "commands": ("steghide", "outguess", "zsteg"),
    },
)


def build_tool_card(goal: str, mode: str = "auto") -> str:
    """Build the capability card for this goal. Returns empty string if no tools match.

    ``mode`` follows the explicit task-mode switch (agent/task_mode.py):
    ``ir`` renders ONLY the incident-response section — an IR answer round has
    no use for attack tools and their presence dilutes the card;
    ``pentest``/``ctf`` render only the attack-tool section; ``auto`` keeps the
    legacy per-section keyword guessing (IR intent gate + goal keywords).
    """
    goal_lower = (goal or "").lower()
    lines: list[str] = []

    if mode != "ir":
        # `always` entries are offered on every CTF run regardless of goal wording,
        # because a challenge attachment's FORMAT never appears in the goal text.
        # Measured 2026-10-18: a RAR challenge produced a card WITHOUT bsdtar and the
        # agent resumed hunting for unrar.
        #
        # Scoped to `ctf` ONLY. A pentest engagement does not arrive as an archive
        # the way a CTF handout does, and a real bug-hunting run should not spend
        # context on a "how to unzip" line it will never use — `pentest` therefore
        # stays purely keyword-driven (an archive-related goal still gets bsdtar via
        # its keywords). `auto` is unchanged, so unrelated goals still produce an
        # empty card (`test_unrelated_goal_returns_empty`).
        always_ok = mode == "ctf"
        for entry in _REGISTRY:
            cmd = _detect(entry)
            if not cmd:
                continue
            if not (always_ok and entry.get("always")) and not _match(
                goal_lower, entry.get("keywords", [])
            ):
                continue
            lines.append(f"- **{entry['name']}**: `{cmd}` — {entry['usage']} ({entry['when']})")

    ir_lines: list[str] = []
    ir_wanted = mode == "ir" or (mode == "auto" and _is_ir_goal(goal_lower))
    if ir_wanted:
        for entry in _IR_REGISTRY:
            cmd = _detect(entry)
            if not cmd:
                continue
            if not _match(goal_lower, entry.get("keywords", [])):
                continue
            ir_lines.append(
                f"- **{entry['name']}**: `{cmd}` — {entry['usage']} ({entry['when']})"
            )

    missing = [
        entry
        for entry in _UNAVAILABLE
        if _unavailable_on_host(entry)
        and (mode == "ctf" or _match(goal_lower, entry.get("keywords", [])))
    ]

    if not lines and not ir_lines and not missing:
        return ""

    card = ""
    if lines or ir_lines:
        card = "\n\n# External tools available on this host\n"
        card += "These are installed and verified. Use shell_command to invoke them.\n"
        if lines:
            card += "\n".join(lines)
        if ir_lines:
            card += "\n\n## Incident-response / evidence-handling tools\n"
            card += "These are installed and verified. Use shell_command to invoke them.\n"
            card += "\n".join(ir_lines)

    # ``bg_launch`` hint when cracking tools are relevant (attack-side only)
    if mode != "ir" and any(k in goal_lower for k in ["hash", "crack", "破解", "密码", "爆破"]):
        card += (
            "\n- ⭐ Long-running cracking: use `bg_launch` to run hashcat/john "
            "in the background while you continue exploring."
        )

    # What this host does NOT have, stated up front. Without it, "not in the card"
    # reads as "not found yet" and the model starts installing things. The text
    # is intentionally detection-backed and portable: it does not claim anything
    # about Docker, package managers, or another machine's desktop state.
    if missing:
        card += "\n\n## NOT available on this host — do not try to install\n"
        for entry in missing:
            card += f"- **{entry['name']}**: {entry['why']}\n"
    return card
