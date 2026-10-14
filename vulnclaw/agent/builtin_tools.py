"""Agent built-in tools and OpenAI tool schema helpers."""

from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import json
import logging
import os
import posixpath
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext

from urllib.parse import quote, urljoin, urlparse

logger = logging.getLogger(__name__)

import httpx

from vulnclaw.agent.agent_state import clip_text, one_line
from vulnclaw.agent.constraint_policy import validate_tool_action
from vulnclaw.agent.network_scan import (
    attach_network_scan_to_session,
    build_nmap_command,
    build_nmap_plan,
    deescalate_nmap_argv,
    nmap_failure_needs_deescalation,
    nmap_has_raw_socket_access,
    parse_nmap_xml_structured,
    summarize_network_scan,
    target_is_private_literal,
    without_privileged_nmap_args,
)
from vulnclaw.agent.roles import role_tool_violation, tool_allowed_for_role
from vulnclaw.agent.solver import _looks_like_quiz
from vulnclaw.agent.tool_result_overrides import set_raw_tool_output_override
from vulnclaw.agent.tool_schemas import append_builtin_tool_schemas
from vulnclaw.utils.http_client import (
    async_http_client as make_async_http_client,
    bypass_proxy_for,
    http_client as make_http_client,
    is_local_target,
    resolve_egress_proxy,
)
from vulnclaw.utils.subprocess_text import combine_output, run_text
from vulnclaw.config.source_render import (
    render_highlighted_source_block,
    strip_highlighted_source,
)

# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V1 违规 — infer_port_from_url 已移至 config/url_utils.py，
#          此处重新导出以保持向后兼容。
from vulnclaw.config.url_utils import host_in_scope, infer_port_from_url  # noqa: F401 — re-export
from vulnclaw.intel.tools import (
    INTEL_TOOL_NAMES,
    dispatch_intel_tool,
    intel_tool_schemas,
)
from vulnclaw.traffic.tools import (
    TRAFFIC_BIND_TOOL_NAMES,
    TRAFFIC_TOOL_NAMES,
    dispatch_traffic_tool,
    traffic_bind_evidence_text,
    traffic_tool_schemas,
)
from vulnclaw.ctf_platform import (
    CTF_TOOL_NAMES,
    ctf2_tool_schemas,
    ctf2_tools_enabled,
    dispatch_ctf2_tool,
)
from vulnclaw.platforms.tools import (
    CORE_TOOL_NAMES as _PLATFORM_CORE_TOOL_NAMES,
    PLATFORM_TOOL_NAMES as _PLATFORM_TOOL_NAMES,
    _flag_submission_enabled,
    _submission_disabled_message,
    dispatch_platform_tool,
    platform_tool_schemas,
)
from vulnclaw.gcs_platform import (
    GCS_TOOL_NAMES,
    dispatch_gcs_tool,
    gcs_tool_schemas,
    gcs_tools_enabled,
)

# 本地化工具名（新增）
_OCR_TOOL_NAMES = {"ocr"}


def role_allows_tool(role: str | None, tool_name: str) -> bool:
    """Return whether the active team role may see or call a tool."""
    return tool_allowed_for_role(tool_name, role)


# Tools whose invocation executes arbitrary code on the host. These are the
# C-1/C-2 surface: they stay registered (the agent's core capability) but are
# subject to ExecutionGate approval and are never available to leaf agents.
DANGEROUS_TOOLS = frozenset({"shell_command", "python_execute"})


def is_subagent(agent: AgentContext | None) -> bool:
    """Whether *agent* is a spawned child agent rather than the main agent.

    ``SubagentContext.depth == 0`` marks the main agent; every child built
    through ``_child_factory`` runs with ``depth > 0``.
    """
    if agent is None:
        return False
    ctx = getattr(agent, "_subagent_ctx", None)
    if ctx is None:
        return False
    return getattr(ctx, "depth", 0) > 0


def dangerous_tool_refusal(tool_name: str, agent: AgentContext | None = None) -> str | None:
    """Fail-closed check for dangerous tools.

    Leaf agents can never reach host execution regardless of role globs or
    hand-crafted tool calls; the main agent passes through to the caller's
    approval flow.
    """
    if tool_name not in DANGEROUS_TOOLS:
        return None
    if is_subagent(agent):
        return (
            f"[!] {tool_name} is not available to subagents. Arbitrary "
            "execution requests must be issued by the main agent and "
            "approved by the local operator."
        )
    return None

BLOCKED_PATTERNS: list[str] = [
    r"os\.\s*system\s*\(",
    r"subprocess\.\s*Popen\s*\(",
    r"shutil\.\s*rmtree\s*\(",
    r"__import__\s*\(\s*['\"]os['\"]",
    r"open\s*\(\s*['\"].*vulnclaw.*config",
    r"open\s*\(\s*['\"].*\.vulnclaw",
]

# ── host-wide "hunt the answer on disk" detection ───────────────────
# Measured (2026-09-23): a stalled solve abandoned its inert web target and walked
# the operator's drives looking for flag-shaped strings -- it grepped E:\vulnclaw and
# C:\vulnclaw and hit *other* tasks' artifacts (earlier solve reports, other runs'
# logs, test fixtures), each containing SOME challenge's real flag. The agent's own
# stated reason was "the harness must run it locally", so it saw this as legitimate.
#
# That is not a credentials problem (which the prompt already forbids) but an
# answer-provenance problem: reporting a flag found in another task's report is a
# fabricated result that still looks evidenced. The prompt now states the rule; this
# is the mechanical backstop.
#
# Scope is deliberately narrow to avoid blocking real work: it needs BOTH a broad
# filesystem TRAVERSAL and a flag-SHAPED search token. Grepping one downloaded file
# (`strings easyre.exe | grep flag`) has no traversal and is untouched -- RE work
# depends on exactly that.
_BROAD_ROOTS = (
    # An optional string prefix matters: the measured call was os.walk(r'C:\vulnclaw'),
    # and a pattern anchored on the quote right after "(" misses every raw string.
    r"os\.walk\s*\(\s*[rbfuRBFU]{0,2}['\"](?:[A-Za-z]:[\\/]|/|~)",
    r"glob\s*\.\s*(?:iglob|glob)\s*\(\s*[rbfuRBFU]{0,2}['\"](?:[A-Za-z]:[\\/]|/|~)",
    r"\.rglob\s*\(\s*[rbfuRBFU]{0,2}['\"]",
    r"Path\s*\(\s*[rbfuRBFU]{0,2}['\"](?:[A-Za-z]:[\\/]|/|~)",
)
_FLAG_SHAPED = (
    r"flag\s*\{",
    r"FLAG\s*\{",
    r"CTF\s*\{",
    r"[\"']flag[\"']",
    r"flag_pattern",
    r"flag_regex",
)
_HOST_FLAG_HUNT_REASON = (
    "refusing a host-wide search for flag-shaped strings. The answer must come from "
    "the target, not from this machine: earlier solve reports, other runs' logs, "
    "state files and test fixtures on disk may contain OTHER challenges' real flags, "
    "so reporting one would be fabricating a result that still looks evidenced. "
    "Local files are for analysis only -- to grep a downloaded attachment, pass its "
    "exact path instead of traversing a directory tree."
)


def _host_flag_hunt_reason(code: str) -> str | None:
    """Return the refusal reason when `code` hunts the host filesystem for a flag.

    Requires a broad traversal AND a flag-shaped token: neither alone is a problem,
    and requiring both keeps genuine analysis of a single downloaded artifact working.

    ⚠️ This is a HEURISTIC and it is trivially bypassable -- see
    ``_SHELL_FLAG_HUNT_REASON`` and the tests that pin the known bypasses. It exists to
    stop the naive form, not a determined author: the primary control is the prompt rule
    ("the answer must come from the target"), and this is the mechanical backstop.
    """
    text = code or ""
    if not any(re.search(pattern, text) for pattern in _BROAD_ROOTS):
        return None
    if not any(re.search(pattern, text) for pattern in _FLAG_SHAPED):
        return None
    return _HOST_FLAG_HUNT_REASON


# ── the same intent, on the shell path ──────────────────────────────
# Audit finding A3: `_host_flag_hunt_reason` had exactly ONE call site, inside
# python_execute, so the identical intent was completely unguarded when expressed as a
# shell command (`grep -r`, `findstr /s`, `Select-String -Recurse`, ...). The prompt
# rule was the only thing standing there. This closes the "zero mechanical
# interception on that path" half.
#
# Same narrow trigger as the Python side: a RECURSIVE search over a BROAD root AND a
# flag-shaped token. A single-file grep (`strings chal.exe | grep flag{`) has no
# recursion and stays allowed.
_SHELL_RECURSIVE = (
    r"\bgrep\b[^|;&]*\s-(?:[A-Za-z]*[rR])",          # grep -r / -R / -rn / -iR
    r"\bgrep\b[^|;&]*--recursive",
    r"\brg\b",                                        # ripgrep is recursive by default
    r"\bag\b[^|;&]*\s-",
    r"\bfindstr\b[^|;&]*\s/s\b",
    r"\bSelect-String\b[^|;&]*-Recurse",
    r"\bGet-ChildItem\b[^|;&]*-Recurse",
    r"\bdir\b[^|;&]*\s/s\b",
    r"\bfind\b[^|;&]*-exec\s+grep",
)
_SHELL_BROAD_ROOT = (
    # Any drive-ABSOLUTE path, not only the bare drive root. Round-8 finding R8-2: the
    # branch used to require whitespace/end/`*`/quote immediately after `E:\`, so the
    # one shape this guard exists for -- the shape actually measured on 2026-09-23,
    # `grep -r flag{ E:\vulnclaw` -- was the one shape it let through, while the Python
    # side (`[A-Za-z]:[\\/]`, no trailing boundary) refused the same intent. A drive
    # subdirectory is no less "host-wide" than the root: the guard's own remedy is to
    # pass the exact file, which works identically in both cases.
    r"[A-Za-z]:[\\/]",
    r"(?:^|\s)/(?:\s|$)",                             # POSIX root
    r"(?:^|\s)~",
    r"\$HOME",
    r"[A-Za-z]:[\\/](?:Users|home)\b",
    r"(?:^|\s)/(?:home|Users|root)\b",
)
# Includes the SPLIT form the audit used for the Python side (`/c:fla` + `g{`), because
# a shell command makes that spelling natural rather than exotic.
_SHELL_FLAG_SHAPED = (
    r"flag\s*\{",
    r"FLAG\s*\{",
    r"CTF\s*\{",
    r"[\"']flag[\"']",
    r"/c:fla\b",
    r"\bfla\b[\"']?\s*[\"']?g\{",
)
_SHELL_FLAG_HUNT_REASON = (
    "refusing a host-wide search for flag-shaped strings. The answer must come from the "
    "target, not from this machine: earlier solve reports, other runs' logs and test "
    "fixtures on disk may contain OTHER challenges' real flags, so reporting one would "
    "be fabricating a result that still looks evidenced. Local files are for analysis "
    "only -- to search a downloaded attachment, pass its exact path instead of "
    "recursing over a directory tree."
)


def _shell_flag_hunt_reason(command: str) -> str | None:
    """Shell-command counterpart of :func:`_host_flag_hunt_reason`.

    ⚠️ Same caveat, and it must not be lost: this is a HEURISTIC over command text and is
    bypassable by any reformulation (a variable holding the root, a needle built at
    runtime, an unknown traversal verb). It stops the naive form; the prompt rule is the
    primary control. `tests/agent/test_answer_provenance_limits.py` pins the known
    bypasses as tests so this limitation stays visible.

    Round-8 finding R8-2 narrowed the gap that mattered, though: the broad-root half used
    to recognise only a BARE drive root, so the measured command itself
    (`grep -r flag{ E:\\vulnclaw`) was allowed while the Python side refused the same
    intent. Any drive-absolute path now counts -- see ``_SHELL_BROAD_ROOT``.
    """
    text = command or ""
    if not any(re.search(pattern, text, re.IGNORECASE) for pattern in _SHELL_RECURSIVE):
        return None
    if not any(re.search(pattern, text) for pattern in _SHELL_BROAD_ROOT):
        return None
    if not any(re.search(pattern, text, re.IGNORECASE) for pattern in _SHELL_FLAG_SHAPED):
        return None
    return _SHELL_FLAG_HUNT_REASON


# ── AST-based sandbox bypass detection ──────────────────────────────
# Regex alone cannot catch dynamic import/loading patterns.
# This AST checker identifies:
#   1. importlib.import_module() / importlib.__import__()
#   2. exec() / eval() / compile() that could hide code
#   3. getattr() on builtins or modules to access blocked names
#   4. __builtins__ direct access
#   5. Dynamic attribute access on dangerous modules (os, subprocess, etc.)

_DANGEROUS_MODULES = frozenset({
    "os", "subprocess", "shutil", "sys", "socket",
    "http", "urllib", "requests", "ftplib", "smtplib",
    "pathlib", "importlib",
})

_DANGEROUS_BUILTIN_NAMES = frozenset({
    "open", "exec", "eval", "compile", "__import__",
    "getattr", "setattr", "delattr", "globals", "locals",
    "vars", "dir", "type",
})


def _ast_check_sandbox_bypass(code: str) -> str | None:
    """AST-based check for sandbox bypass patterns.

    Returns a description string if a bypass is detected, None if safe.
    Catches patterns that regex-based SAFE_MODE_PATTERNS miss:
    - importlib.import_module('os')
    - exec("import os; os.system('id')")
    - getattr(__builtins__, "open")
    - getattr(alias, "attr") where alias is a dangerous module
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None  # Syntax errors are caught elsewhere

    # Pass 1: collect import aliases (import socket as s → s = socket)
    _alias_to_module: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname if alias.asname else alias.name
                _alias_to_module[local_name] = alias.name.split(".")[0]

    def _resolve_name(name: str) -> str | None:
        """Resolve a name to its real module, checking alias map."""
        if name in _DANGEROUS_MODULES:
            return name
        if name in _alias_to_module:
            real = _alias_to_module[name]
            if real in _DANGEROUS_MODULES:
                return real
        return None

    for node in ast.walk(tree):
        # 1. exec() / eval() / compile() — can hide arbitrary code
        if isinstance(node, ast.Call):
            func = node.func
            func_name = ""
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                func_name = func.attr

            if func_name in ("exec", "eval", "compile"):
                return "exec/eval/compile detected (bypasses static analysis)"

            # 2. importlib.import_module() / importlib.__import__()
            if func_name == "import_module" and isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name) and func.value.id == "importlib":
                    return "importlib.import_module() detected"
            if func_name == "__import__":
                return "__import__() detected"

            # 3. getattr() on builtins or modules
            if func_name == "getattr" and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Name):
                    if first_arg.id in ("__builtins__", "builtins"):
                        return "getattr on __builtins__ detected"
                    resolved = _resolve_name(first_arg.id)
                    if resolved:
                        return f"getattr on module '{resolved}' detected"
                if isinstance(first_arg, ast.Attribute):
                    root = first_arg
                    while isinstance(root, ast.Attribute):
                        root = root.value
                    if isinstance(root, ast.Name):
                        if root.id in ("__builtins__", "builtins"):
                            return "getattr on __builtins__ detected"
                        resolved = _resolve_name(root.id)
                        if resolved:
                            return f"getattr on module '{resolved}' detected"

        # 4. __builtins__ direct access
        if isinstance(node, ast.Attribute) and node.attr == "__builtins__":
            return "__builtins__ access detected"
        if isinstance(node, ast.Name) and node.id == "__builtins__":
            return "__builtins__ access detected"

    return None

RESERVED_IP_RANGES: list[tuple[str, str, str]] = [
    ("198.18.0.0", "198.19.255.255", "RFC 2544 基准测试地址"),
    ("10.0.0.0", "10.255.255.255", "RFC 1918 私有地址"),
    ("172.16.0.0", "172.31.255.255", "RFC 1918 私有地址"),
    ("192.168.0.0", "192.168.255.255", "RFC 1918 私有地址"),
    ("127.0.0.0", "127.255.255.255", "RFC 1122 环回地址"),
    ("169.254.0.0", "169.254.255.255", "RFC 3927 链路本地"),
    ("0.0.0.0", "0.255.255.255", "RFC 1122 当前网络"),
    ("224.0.0.0", "239.255.255.255", "RFC 5771 多播地址"),
    ("240.0.0.0", "255.255.255.255", "RFC 1112 保留地址"),
]

SAFE_MODE_PATTERNS: list[str] = [
    r"open\s*\(",
    r"with\s+open\s*\(",
    r"socket\.",
    r"urllib",
    r"http\.client",
    r"ftplib",
    r"smtplib",
    r"requests\.",
    r"import\s+os",
    r"from\s+os\s+import",
    r"import\s+subprocess",
    r"from\s+subprocess\s+import",
    r"import\s+shutil",
    r"from\s+shutil\s+import",
    r"import\s+pathlib",
    r"from\s+pathlib\s+import",
    r"__import__",
]

LAB_MODE_PATTERNS: list[str] = [
    r"import\s+subprocess",
    r"from\s+subprocess\s+import",
    r"os\.\s*system\s*\(",
    r"subprocess\.\s*Popen\s*\(",
    r"shutil\.\s*rmtree\s*\(",
]


def _evidence_base(agent: AgentContext) -> Any:
    """The directory that owns this agent's evidence tree.

    Ordered: the live run anchor (``agent.run_dir``, injected by the
    orchestrator -- see ``orchestrator.run_agent_task``) wins, then the legacy
    session-level carrier, then ``None`` so the resolver uses the config-scoped
    root. The run anchor must win: a resumed or concurrent agent can still be
    carrying a session that was built before the run-dir work landed.
    """
    run_dir = getattr(agent, "run_dir", None)
    if run_dir:
        return run_dir
    session = getattr(agent, "session_state", None)
    return getattr(session, "evidence_dir", None) or getattr(session, "run_dir", None)


def resolve_traffic_store(agent: AgentContext) -> Any:
    """Resolve the per-run traffic evidence store for this agent.

    Prefers the agent's own run directory (injected per run); otherwise falls
    back to the config-scoped evidence directory so headless/CI runs still get a
    durable store.
    """
    from vulnclaw.traffic.paths import resolve_traffic_store as _resolve

    return _resolve(_evidence_base(agent))


def resolve_evidence_store(agent: AgentContext) -> Any:
    """Resolve the pinned-evidence store this agent writes to.

    Same base-directory seam as :func:`resolve_traffic_store`, so pins land
    beside the capture log in the run's own ``evidence/`` tree rather than in a
    stale global directory.
    """
    from vulnclaw.traffic.paths import resolve_evidence_store as _resolve

    return _resolve(_evidence_base(agent))


def _session_findings(agent: AgentContext) -> list[Any]:
    """Every finding this agent has recorded, in insertion order."""
    session = getattr(agent, "session_state", None)
    findings = getattr(session, "findings", None)
    if findings is None:
        ctx_state = getattr(getattr(agent, "context", None), "state", None)
        findings = getattr(ctx_state, "findings", None)
    return list(findings or [])


def resolve_finding_for_binding(agent: AgentContext, handle: str) -> tuple[Any | None, str]:
    """Find the finding a binding call names.

    Returns ``(finding, message)`` where a ``None`` finding always comes with the
    reason. ``finding_id`` matches exactly and wins outright; anything else is a
    case-insensitive title substring, which is how a model that just reported a
    finding tends to refer back to it. Ambiguity is reported rather than guessed:
    binding proof to the WRONG finding is worse than asking again.
    """
    needle = str(handle or "").strip()
    if not needle:
        return None, "缺少 finding 参数（请传 finding_id 或标题片段）"

    findings = _session_findings(agent)
    if not findings:
        return None, "当前会话还没有任何漏洞发现，请先上报漏洞再绑定证据"

    for finding in findings:
        if str(getattr(finding, "finding_id", "") or "") == needle:
            return finding, ""

    lowered = needle.lower()
    matches = [f for f in findings if lowered in str(getattr(f, "title", "") or "").lower()]
    if not matches:
        titles = "; ".join(str(getattr(f, "title", "")) for f in findings[:5])
        return None, f"没有匹配「{handle}」的漏洞发现。已有: {titles}"
    if len(matches) > 1:
        titles = "; ".join(str(getattr(f, "title", "")) for f in matches)
        return None, f"「{handle}」匹配到多个漏洞发现，请用更精确的标题或 finding_id: {titles}"
    return matches[0], ""


def execute_traffic_bind_tool(agent: AgentContext, args: dict[str, Any]) -> str:
    """Bind captured requests to a finding as durable reproduction evidence."""
    finding, message = resolve_finding_for_binding(agent, str(args.get("finding", "")))
    if finding is None:
        return f"[traffic] {message}"
    return traffic_bind_evidence_text(
        finding,
        traffic_store=resolve_traffic_store(agent),
        evidence_store=resolve_evidence_store(agent),
        specs=args.get("evidence"),
    )


#: The model-facing finding-write verb. Measured 2026-10-09: the model had NO
#: way to create a finding — ``findings_report``/``findings_diff`` are read-only,
#: every other finding came from ``finding_parser`` regexing model prose, and
#: ``blackboard_record_answer`` writes an ``ir-answer`` card that reports filter
#: out. So ``traffic_bind_evidence`` ("report the finding first") had no upstream
#: verb: four live runs produced 4/4 answer cards and zero bindable findings, and
#: the whole evidence chain was unreachable from the model's seat.
REPORT_FINDING_TOOL_NAME = "report_finding"

_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
#: Most severe first, so the rank has to count DOWN the tuple: rank 5 = Critical.
#: (Enumerating from 1 the other way round makes "only move up" move down.)
_SEVERITY_RANK = {name: len(_SEVERITIES) - index for index, name in enumerate(_SEVERITIES)}

#: Fields a re-report may fill on an existing finding. Only ever fills what is
#: EMPTY there: re-reporting is the model saying more about a bug it already
#: filed, not a licence to overwrite a conclusion that is already written down.
_REPORT_MERGE_FIELDS = (
    "vuln_type",
    "description",
    "impact",
    "evidence",
    "remediation",
    "endpoint",
    "method",
    "code_location",
)


def _finding_title_key(title: str) -> str:
    """Case/whitespace-insensitive title identity, ignoring the quarantine prefix.

    Two reports of one bug rarely repeat the title byte-for-byte, and a bare
    finding carries a ``[未验证]`` prefix that the promoted one does not — so the
    key has to normalise both away or the same bug is filed twice.
    """
    from vulnclaw.config.domain_models import UNVERIFIED_TITLE_PREFIX

    cleaned = re.sub(rf"^{re.escape(UNVERIFIED_TITLE_PREFIX)}\s*", "", str(title or ""))
    return " ".join(cleaned.split()).casefold()


def _finding_for_report(session: Any, finding: Any, raw_title: str) -> Any | None:
    """The already-recorded finding this report refers to, else ``None``.

    Identity, in order: the generated ``finding_id`` (which is vuln_type + the
    location found in the text), then the normalised title. The title key matters
    because adding evidence to a report changes its generated id — the model
    walks report_finding → exploit → report_finding, and the second call carries
    a URL the first one did not.

    IR answer cards are never a match: they live in the same finding store but
    they are question answers, not vulnerabilities, so merging a report into one
    would rewrite the answer sheet.
    """
    from vulnclaw.config.domain_models import is_answer_card

    identity = str(getattr(finding, "finding_id", "") or "")
    key = _finding_title_key(raw_title)
    for existing in getattr(session, "findings", None) or []:
        if is_answer_card(existing):
            continue
        if identity and str(getattr(existing, "finding_id", "") or "") == identity:
            return existing
        if key and _finding_title_key(getattr(existing, "title", "")) == key:
            return existing
    return None


def _merge_report_into(existing: Any, finding: Any) -> list[str]:
    """Fill ``existing``'s empty fields from a newer report; returns what changed."""
    filled: list[str] = []
    for field in _REPORT_MERGE_FIELDS:
        new_value = getattr(finding, field, None)
        if new_value and not getattr(existing, field, None):
            setattr(existing, field, new_value)
            filled.append(field)

    # Severity only moves up: re-reporting without naming a severity must not
    # quietly downgrade a Critical that was already recorded.
    if _SEVERITY_RANK.get(finding.severity, 0) > _SEVERITY_RANK.get(existing.severity, 0):
        existing.severity = finding.severity
        filled.append("severity")

    from vulnclaw.config.domain_models import is_unsubstantiated

    if filled and not is_unsubstantiated(existing):
        # It is no longer the bare thing the intake quarantine was written for.
        existing.clear_intake_quarantine()
    return filled


def execute_report_finding_tool(agent: AgentContext, args: dict[str, Any]) -> str:
    """Record a vulnerability finding the model has actually established.

    Deliberately narrow: it writes ONE finding and returns its id. Verification
    is the caller's claim (``verified``), never implied -- an unverified report
    is stored as a candidate, which is the honest shape for "I think this is
    exploitable but have not proven it". Binding captured proof is a SEPARATE
    step (``traffic_bind_evidence``) so a model cannot claim proof it never saw.

    Reporting a bug that is ALREADY recorded updates that record instead of
    filing a second one. Without this the natural live order -- report when you
    find it, report again once you have exploited it -- hit ``add_finding``'s
    exact-id dedup, which returns False *without* applying its
    keep-the-stronger-evidence rule: the verification claim was dropped, the tool
    still answered "已记为已验证漏洞", and the finding stayed out of the report
    (2026-10-09 audit finding #2/#3).
    """
    from vulnclaw.config.domain_models import VulnerabilityFinding, is_unsubstantiated

    title = str(args.get("title") or "").strip()
    if not title:
        return "[report_finding] 拒绝：缺少 title（漏洞标题不能为空）"

    severity = str(args.get("severity") or "Medium").strip().title()
    if severity not in _SEVERITIES:
        severity = "Medium"

    session = getattr(agent, "session_state", None)
    if session is None or not hasattr(session, "add_finding"):
        return "[report_finding] 拒绝：当前会话不支持记录漏洞发现"

    finding = VulnerabilityFinding(
        title=title,
        severity=severity,
        vuln_type=str(args.get("vuln_type") or "").strip(),
        description=str(args.get("description") or "").strip(),
        impact=str(args.get("impact") or "").strip(),
        evidence=str(args.get("evidence") or "").strip(),
        remediation=str(args.get("remediation") or "").strip(),
        endpoint=str(args.get("endpoint") or "").strip() or None,
        method=str(args.get("method") or "").strip().upper() or None,
        code_location=str(args.get("code_location") or "").strip() or None,
    )

    # "verified" gates the report/SARIF output, so it has to rest on something a
    # reader can check. Ask for the same substantiating signal the intake
    # quarantine asks for; otherwise record the honest shape (a candidate) and
    # say why, so the model can re-report with the missing field in one turn.
    wants_verified = bool(args.get("verified", False))
    refused_verification = wants_verified and is_unsubstantiated(finding)
    if refused_verification:
        wants_verified = False
    if wants_verified:
        finding.mark_verified(note=str(args.get("verification_note") or "").strip())

    next_step = (
        "  下一步：用 traffic_list 拿到请求 request_id，再用 traffic_bind_evidence "
        "把这个漏洞的复现证据绑定进报告。"
    )

    def _tail(recorded_as_verified: bool) -> str:
        """The refusal note belongs in the answer only when it actually took effect."""
        if not refused_verification or recorded_as_verified:
            return ""
        return (
            "  ⚠️ verified=true 未被采纳：报告里没有任何可核查的依据（evidence / vuln_type / "
            "remediation 至少给一项），已按候选记录。补上依据后再报一次即可升级。"
        )

    existing = _finding_for_report(session, finding, title)
    if existing is not None:
        filled = _merge_report_into(existing, finding)
        if wants_verified and not existing.verified:
            existing.mark_verified(note=str(args.get("verification_note") or "").strip())
        handle = str(getattr(existing, "finding_id", "") or "")
        state = "已标记为已验证" if existing.verified else "仍为候选（未验证）"
        changed = f"，补全字段：{', '.join(filled)}" if filled else ""
        return (
            f"[report_finding] 「{title}」已更新本次运行中已有的发现（finding_id={handle}），"
            f"未新增重复记录；当前{state}{changed}。\n"
            f"{next_step}{_tail(existing.verified)}"
        )

    try:
        stored = session.add_finding(finding)
    except Exception as exc:  # noqa: BLE001 - a tool must return, not raise
        return f"[report_finding] 记录失败：{type(exc).__name__}: {exc}"

    handle = str(getattr(finding, "finding_id", "") or "")
    if not stored:
        # add_finding refused it. Two very different reasons, and the message must
        # not confuse them: the new report superseded a weaker record (it IS in
        # state now), or it was dropped as a semantic duplicate.
        superseded = any(item is finding for item in (getattr(session, "findings", None) or []))
        if superseded:
            state = "已记为已验证漏洞" if finding.verified else "已记为候选漏洞（未验证）"
            return (
                f"[report_finding] 「{title}」{state}，并替换了本次运行中证据较弱的那条同名记录"
                f"（finding_id={handle}）。\n{next_step}{_tail(finding.verified)}"
            )
        return (
            f"[report_finding] 「{title}」未新增：与本次运行中已有的发现语义重复，"
            "且已有那条的证据不弱于本次上报，按既有规则保留原记录。"
            "如需为它补充证据或提升验证状态，请用它的标题或 finding_id 重新上报"
            "（report_finding），绑定报文仍用 traffic_bind_evidence。"
        )

    state = "已记为已验证漏洞" if finding.verified else "已记为候选漏洞（未验证）"
    return (
        f"[report_finding] 「{title}」{state}（severity={severity}，finding_id={handle}）。\n"
        f"{next_step}{_tail(finding.verified)}"
    )



def enforce_traffic_repeat_constraints(
    agent: AgentContext, store: Any, args: dict[str, Any]
) -> str | None:
    """Gate a ``traffic_repeat`` against task host/path/port constraints.

    The effective target is the ``url`` override if supplied, else the stored
    request's URL. Returns a violation message when the target is out of scope,
    or ``None`` when the replay is allowed.
    """
    target_url = str(args.get("url") or "").strip()
    if not target_url:
        entry = store.find(str(args.get("request_id", "")))
        target_url = str((entry or {}).get("url", "")).strip()
    if not target_url:
        return None

    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    violation = enforce_host_path_constraints(agent, host=host, path=path, target=host)
    if violation is not None:
        return violation

    port = infer_port_from_url(target_url)
    if port is not None:
        violation = enforce_port_constraints(agent, [port], target=host or target_url)
        if violation is not None:
            return violation
    return None


def _agent_state_for_tool(agent: AgentContext) -> Any:
    state = getattr(getattr(agent, "context", None), "state", None)
    return getattr(state, "agent_state", None)


def execute_evidence_tool(agent: AgentContext, tool_name: str, args: dict[str, Any]) -> str:
    agent_state = _agent_state_for_tool(agent)
    if agent_state is None:
        return "[!] AgentState is not available"
    if tool_name == "evidence_list":
        return agent_state.format_evidence_list(limit=int(args.get("limit", 20) or 20))
    if tool_name == "evidence_view":
        return agent_state.format_evidence_view(
            str(args.get("evidence_id", "") or ""),
            offset=int(args.get("offset", 0) or 0),
            limit=int(args.get("limit", 12000) or 12000),
        )
    if tool_name == "evidence_search":
        return agent_state.format_evidence_search(
            str(args.get("query", "") or ""),
            evidence_id=str(args.get("evidence_id", "") or ""),
            regex=bool(args.get("regex", False)),
            context_chars=int(args.get("context_chars", 180) or 180),
            limit=int(args.get("limit", 12) or 12),
        )
    return f"[!] Unknown evidence tool: {tool_name}"


def _strip_highlighted_source(raw: str) -> str:
    return strip_highlighted_source(raw)


def _source_signal_lines(source: str, *, context: int = 1) -> list[str]:
    markers = (
        "highlight_file", "show_source", "unserialize", "serialize", "__destruct",
        "__wakeup", "__tostring", "eval", "assert", "system", "exec(",
        "shell_exec", "passthru", "call_user_func", "preg_match", "$_cookie",
        "$_get", "$_post", "$_request", "class ", "function ", "->", "::",
    )
    lines = source.splitlines()
    selected: dict[int, str] = {}
    for index, line in enumerate(lines):
        lower = line.lower()
        if any(marker in lower for marker in markers):
            for neighbor in range(max(0, index - context), min(len(lines), index + context + 1)):
                selected[neighbor + 1] = lines[neighbor]
    return [f"L{line_no}: {line}" for line_no, line in sorted(selected.items())]


def _extract_html_surfaces(raw: str) -> list[str]:
    surfaces: list[str] = []
    for pattern, label in (
        (r"(?is)<form\b[^>]*>", "form"),
        (r"(?is)<input\b[^>]*>", "input"),
        (r"(?is)<textarea\b[^>]*>", "textarea"),
        (r"(?is)<select\b[^>]*>", "select"),
    ):
        for match in re.finditer(pattern, raw or ""):
            surfaces.append(f"{label}: {one_line(match.group(0), 260)}")
    return surfaces[:80]


def _extract_endpoints(raw: str) -> list[str]:
    endpoints: list[str] = []
    patterns = [
        r"""(?i)\b(?:href|src|action)\s*=\s*["']([^"']{1,300})["']""",
        r"""(?i)\b(?:fetch|open)\s*\(\s*["']([^"']{1,300})["']""",
        r"""(?i)\burl\s*:\s*["']([^"']{1,300})["']""",
    ]
    for pattern in patterns:
        for endpoint in re.findall(pattern, raw or ""):
            if endpoint and endpoint not in endpoints:
                endpoints.append(endpoint)
    return endpoints[:120]


async def execute_source_extract(agent: AgentContext, args: dict[str, Any]) -> str:
    """Normalize highlighted HTML/source evidence and extract vulnerability signals."""

    raw = str(args.get("text") or "")
    source_label = "inline text"
    evidence_id = str(args.get("evidence_id") or "").strip()
    if evidence_id:
        agent_state = _agent_state_for_tool(agent)
        if agent_state is None:
            return "[!] AgentState is not available"
        for evidence in agent_state.evidence:
            if evidence.id == evidence_id:
                raw = evidence.content
                source_label = f"evidence {evidence_id}"
                break
        else:
            return f"[!] evidence not found: {evidence_id}"
    if not raw.strip():
        return "[!] source_extract requires evidence_id or text"

    normalized = _strip_highlighted_source(raw)
    signal_lines = _source_signal_lines(normalized)
    surfaces = _extract_html_surfaces(raw)
    endpoints = _extract_endpoints(raw)
    parts = [f"# source_extract — {source_label}"]
    if signal_lines:
        parts.append("\n## High-signal source lines")
        parts.extend(signal_lines)
    if surfaces:
        parts.append("\n## HTML form/input surfaces")
        parts.extend(f"- {item}" for item in surfaces)
    if endpoints:
        parts.append("\n## Endpoints")
        parts.extend(f"- {endpoint}" for endpoint in endpoints)
    parts.append("\n## Normalized source/text")
    parts.append(normalized)
    return "\n".join(parts)


_GATED_SUBMIT_TOOL_NAMES = frozenset({"ctf2_submit_flag", "gcs_submit_flag"})
"""Submit verbs yield to a shadowing MCP face, but only past the operator gate.

Operator decision (2026-10-07): the CTF2 platform's own MCP face is the
authoritative executor for ``ctf2_submit_flag`` — the schema the model sees is
the schema that runs, and the platform's own confirmation sentinel plus its
server-side attempt limits are the enforcement. What is NOT delegated is the
master switch: with ``competition.allow_flag_submission`` OFF the call returns
the disabled message without reaching MCP (fail closed, same text the shared
policy returns). The client attempt guard / dedup stay on the builtin path only
(no MCP owner, or the face exposed): the platform accounts attempts
server-side, so re-keeping them from an MCP result would mean parsing rendered
JSON to duplicate enforcement the platform already applies.
"""


from vulnclaw.agent.tools._shared import _runtime_config  # noqa: F401 — re-export


def _mcp_registry_owns(agent: Any, tool_name: str) -> bool:
    """Whether a connected MCP server currently provides this tool name.

    Defensive on purpose: a bare agent without a manager/registry (tests,
    programmatic callers) simply means "no MCP owner", which restores the
    builtin route — the property CTF_TOOL_NAMES_BY_SCHEMA's docstring pins.
    """
    registry = getattr(getattr(agent, "mcp_manager", None), "registry", None)
    lookup = getattr(registry, "get_server_for_tool", None)
    if lookup is None:
        return False
    try:
        return bool(lookup(tool_name))
    except Exception:
        return False


def _builtin_face_claims(agent: Any, tool_name: str, face_exposed: bool) -> bool:
    """Whether the builtin legacy face should handle this call (else yield to MCP).

    Yield happens when the face is hidden from the model AND an MCP server owns
    the same name — the face the caller could only have been talking to. The
    caller (``execute_mcp_tool``) still gates submit verbs before yielding (see
    ``_GATED_SUBMIT_TOOL_NAMES``).
    """
    return face_exposed or not _mcp_registry_owns(agent, tool_name)


async def execute_mcp_tool(agent: AgentContext, tool_name: str, args: dict[str, Any]) -> str:
    """Execute a tool call via MCP manager or built-in tools."""
    violation = role_tool_violation(
        getattr(agent, "active_role", None),
        tool_name,
        args,
    )
    if violation is not None:
        return violation

    # Fail-closed at dispatch too: even a hand-crafted tool call for a
    # dangerous tool cannot reach execution from a leaf agent.
    dangerous_refusal = dangerous_tool_refusal(tool_name, agent)
    if dangerous_refusal is not None:
        # Round-22 (2026-10-06): the refusal stands as the failure mode, but a
        # sub-agent's request now has one escalation path -- it is re-issued
        # through the main agent, where the normal operator approval flow
        # applies. Returns None (i.e. keeps the refusal) when there is no trust
        # channel, no delegation runtime, or the per-leaf cap is spent.
        from vulnclaw.agent.subagent.exec_escalation import escalate_dangerous_call

        escalated = await escalate_dangerous_call(agent, tool_name, args)
        return escalated if escalated is not None else dangerous_refusal

    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is not None:
        tool_violation = validate_tool_action(tool_name, args, constraints)
        if tool_violation is not None:
            if session is not None and hasattr(session, "add_constraint_violation_event"):
                from vulnclaw.agent.constraint_policy import infer_tool_action

                session.add_constraint_violation_event(
                    source="tool",
                    action=infer_tool_action(tool_name, args),
                    tool_name=tool_name,
                    code="tool_action_blocked",
                    severity="high",
                    summary=tool_violation,
                    detail=json.dumps(args, ensure_ascii=False)[:500],
                )
            return f"[constraint_violation] {tool_violation}"

    if tool_name in {"agent_run", "agent_job"}:
        from vulnclaw.agent.subagent.integration import (
            execute_agent_job,
            execute_agent_run,
        )

        if tool_name == "agent_run":
            return await execute_agent_run(agent, args)
        return await execute_agent_job(agent, args)

    if tool_name in INTEL_TOOL_NAMES:
        return await dispatch_intel_tool(agent, tool_name, args)

    # Platform-neutral tools. The platform rides in the `ref` argument, so there
    # is no tool name that could express the wrong platform (the old
    # ctf2_submit_flag / gcs_submit_flag pair is what let an agent pick wrongly).
    if tool_name in _PLATFORM_TOOL_NAMES:
        return await dispatch_platform_tool(tool_name, args, agent=agent)

    # ── Legacy per-platform faces: dispatch must follow the face the caller read ──
    #
    # A legacy name can belong to TWO faces at once. Measured on 2026-10-07: the
    # CTF2 platform's own MCP endpoint ships `ctf2_submit_flag` whose schema takes
    # `practice_ground_id`, while the builtin legacy face takes `practice_id`.
    # With the legacy face hidden (`expose_legacy_tool_names: false`) the model's
    # schema contains ONLY the MCP version — so an MCP-vocabulary call arrives
    # here, the name matched the builtin table, and the handler died on a bare
    # KeyError('practice_id') after the flag was already solved. The run then
    # churned instead of submitting: no completion, no playbook capture.
    #
    # The rule below mirrors the schema build: when the builtin face is hidden
    # AND the MCP registry owns the name, the call yields to the MCP manager —
    # the face the model could only have been talking to, and (operator decision,
    # 2026-10-07) for the submit verb the EXECUTOR too. Programmatic callers
    # (CLI, saved playbooks, tests) keep the builtin route: with no such MCP
    # tool registered, nothing changes for them. When the face IS exposed, both
    # schemas are in the model's view and the builtin face keeps precedence —
    # the pre-existing, operator-opted-in ambiguity.
    if tool_name in CTF_TOOL_NAMES:
        if _builtin_face_claims(
            agent, tool_name, ctf2_tools_enabled(_runtime_config(agent))
        ):
            return await dispatch_ctf2_tool(tool_name, args)
        if tool_name in _GATED_SUBMIT_TOOL_NAMES:
            if not _flag_submission_enabled():
                return _submission_disabled_message()
            # 提交证据门（``vulnclaw/agent/submit_gate.py``）：这条"让给平台 MCP"的
            # 路此前是唯一没有任何证据检查的提交路径 —— 2026-10-14 巡航实测 9 次白花
            # 尝试全部经由此路，被拒候选签名一致（附件只有 `flag{`，body 与闭括号由
            # 模型自己补出，补完形态合法，连 FINAL 的 shape 检查也看不出）。本地拒绝
            # **不消耗平台尝试数**；有界拒绝（见 submit_gate.MAX_REFUSALS），真 flag
            # 不会被永久关在门外。
            from vulnclaw.agent.submit_gate import submission_refusal

            refusal = submission_refusal(agent, args)
            if refusal is not None:
                return refusal
        # else: yield to the MCP manager at the bottom of this function.

    if tool_name in GCS_TOOL_NAMES:
        if _builtin_face_claims(
            agent, tool_name, gcs_tools_enabled(_runtime_config(agent))
        ):
            return await dispatch_gcs_tool(tool_name, args)
        if tool_name in _GATED_SUBMIT_TOOL_NAMES:
            if not _flag_submission_enabled():
                return _submission_disabled_message()
            from vulnclaw.agent.submit_gate import submission_refusal

            refusal = submission_refusal(agent, args)
            if refusal is not None:
                return refusal

    if tool_name in TRAFFIC_TOOL_NAMES:
        store = resolve_traffic_store(agent)
        if tool_name == "traffic_repeat":
            # A url override could aim the replay at a blocked/out-of-scope host,
            # so gate it with the same host/path/port guards other network tools
            # use — the generic action check above does not see the target URL.
            violation = enforce_traffic_repeat_constraints(agent, store, args)
            if violation is not None:
                return violation
        # traffic_repeat issues a real network request; keep the loop responsive.
        return await asyncio.to_thread(
            dispatch_traffic_tool,
            store,
            tool_name,
            args,
            proxy=resolve_egress_proxy(_runtime_config(agent)),
        )

    if tool_name in TRAFFIC_BIND_TOOL_NAMES:
        # Binding needs the target finding and the pinned-evidence store, not just
        # the capture log, so it routes through its own agent-aware handler.
        return await asyncio.to_thread(execute_traffic_bind_tool, agent, args)

    if tool_name == REPORT_FINDING_TOOL_NAME:
        # Pure in-process state write (session findings), no I/O: the model's
        # only way to create the finding that traffic_bind_evidence binds proof to.
        return execute_report_finding_tool(agent, args)

    if tool_name in {"evidence_list", "evidence_view", "evidence_search"}:
        return execute_evidence_tool(agent, tool_name, args)

# ── Blackboard reasoning graph ──
    if tool_name in ("blackboard_summary", "blackboard_add_fact", "blackboard_record_answer", "blackboard_verify_fact", "blackboard_challenge_fact", "blackboard_add_intent", "blackboard_reject_intent", "blackboard_start_intent", "blackboard_review", "blackboard_set_lock", "blackboard_create_angle", "blackboard_hit_angle", "blackboard_miss_angle", "blackboard_create_tension"):
        try:
            from vulnclaw.agent.blackboard import dispatch_blackboard_tool
            return await dispatch_blackboard_tool(agent, tool_name, args)
        except Exception as e:
            return f"[!] blackboard 工具执行错误: {e}"

    # ── Solve playbooks (reusable attack recipes) ──
    if tool_name in ("lookup_playbook", "save_playbook"):
        try:
            from vulnclaw.agent.playbook import execute_playbook_tool
            return await execute_playbook_tool(tool_name, args)
        except Exception as e:
            return f"[!] playbook 工具执行错误: {e}"

    # ── Pwn local replay (Docker) ──
    if tool_name in ("pwn_local_replay", "pwn_local_stop", "libc_lookup"):
        try:
            from vulnclaw.agent.pwn_local import execute_pwn_local_tool
            return await execute_pwn_local_tool(agent, tool_name, args)
        except Exception as e:
            return f"[!] pwn_local 工具执行错误: {e}"

    # ── Remote (SSH) — live IR / pentest against a declared host inventory ──
    # Note: these route through ExecutionGate with kind="remote", so the same
    # read-only command classifier that governs local shell_command also governs
    # remote commands. Do not add a bypass here.
    if tool_name in _REMOTE_TOOL_NAMES:
        try:
            from vulnclaw.agent.remote import execute_remote_tool
            return await execute_remote_tool(agent, tool_name, args)
        except Exception as e:
            return f"[!] remote 工具执行错误: {type(e).__name__}: {e}"

    # ── 后台任务（爆破等耗时操作不阻塞）───────────────────────────────────────
    if tool_name in _BG_TOOL_NAMES:
        if tool_name == "bg_launch":
            return await execute_bg_launch(agent, args)
        return execute_bg_result(agent, args)

    # ── OCR（本地 GPU 加载 + 可能的 PowerShell/HTTP 降级链，整体重同步活）
    # to_thread：easyocr Reader 首次加载可达数十秒，同步直调会冻结整个 agent 循环
    if tool_name in _OCR_TOOL_NAMES:
        return await asyncio.to_thread(execute_ocr, agent, args)

    # ── pyc 字节码分析（CTF REVERSE）──────────────────────────────────────────
    if tool_name in _PYC_TOOL_NAMES:
        return execute_pyc_analyze(agent, args)

    # ── PDF 取证分析（CTF forensics）──────────────────────────────────────────
    if tool_name in _PDF_TOOL_NAMES:
        return execute_pdf_analyze(agent, args)

    # ── WebMap site-structure recorder ──
    if tool_name in ("web_map_add", "web_map_link", "web_map_render", "web_map_summary", "web_map_reset"):
        try:
            from vulnclaw.agent.web_map import dispatch_web_map_tool
            return dispatch_web_map_tool(agent, tool_name, args)
        except Exception as e:
            return f"[!] web_map 工具执行错误: {e}"

    if tool_name == "memory_search":
        query = str(args.get("query") or "").strip()
        if not query:
            return "[!] memory_search requires a non-empty query"
        context = getattr(agent, "context", None)
        search = getattr(context, "search_cold_memory", None)
        if not callable(search):
            return "[-] No cold memory is configured"
        matches = search(query, limit=args.get("limit", 5))
        if not matches:
            return "[-] No matching archived conversation"
        rendered = json.dumps(matches, ensure_ascii=False, indent=2)
        max_chars = max(256, int(getattr(context, "search_max_chars", 6000)))
        if len(rendered) > max_chars:
            suffix = "\n...[cold-memory search output truncated]"
            rendered = rendered[: max_chars - len(suffix)] + suffix
        return rendered

    if tool_name in {"vault_archive", "vault_restore", "vault_search", "vault_status"}:
        return execute_vault_tool(agent, tool_name, args)

    if tool_name == "source_extract":
        return await execute_source_extract(agent, args)

    if tool_name == "runtime_diff_probe":
        return await execute_runtime_diff_probe(agent, args)

    if tool_name == "shell_command":
        return await execute_shell_command(agent, args)

    if tool_name == "http_probe_batch":
        return await execute_http_probe_batch(agent, args)

    if tool_name == "python_execute":
        return await execute_python(agent, args)

    if tool_name == "load_skill_reference":
        try:
            from vulnclaw.skills.loader import load_skill_reference

            skill_name = args.get("skill_name", "")
            ref_name = args.get("reference_name", "")
            content = load_skill_reference(skill_name, ref_name)
            if content:
                state = getattr(agent, "session_state", None) or getattr(
                    getattr(agent, "context", None), "state", None
                )
                if state is not None and hasattr(state, "record_loaded_reference"):
                    state.record_loaded_reference(skill_name, ref_name)
                return content
            return f"[!] 参考文档未找到: {skill_name}/{ref_name}"
        except Exception as e:
            return f"[!] 加载参考文档错误: {e}"

    if tool_name == "nmap_scan":
        return await execute_nmap(agent, args)

    if tool_name == "crypto_decode":
        try:
            from vulnclaw.skills.crypto_tools import execute as crypto_execute

            operation = args.get("operation", "")
            input_str = args.get("input", "")
            kwargs: dict[str, Any] = {}
            for key in ("key", "iv", "shift", "secret", "header", "algorithm"):
                if key in args and args[key]:
                    kwargs[key] = args[key]
                    if key == "shift":
                        kwargs[key] = int(args[key])
            result = crypto_execute(operation=operation, input_str=input_str, **kwargs)
            if result.get("success"):
                return f"[✓] {operation} 结果:\n{result['result']}"
            return f"[!] {operation} 失败: {result.get('error', '未知错误')}"
        except Exception as e:
            return f"[!] 加密工具执行错误: {e}"

    if tool_name == "brute_force_login":
        return await execute_brute_force(agent, args)

    if tool_name in {"space_search", "subdomain_enum", "js_recon", "dir_enum", "unauth_test"}:
        from vulnclaw.agent import recon_tools

        dispatch = {
            "space_search": recon_tools.execute_space_search,
            "subdomain_enum": recon_tools.execute_subdomain_enum,
            "js_recon": recon_tools.execute_js_recon,
            "dir_enum": recon_tools.execute_dir_enum,
            "unauth_test": recon_tools.execute_unauth_test,
        }
        try:
            return await dispatch[tool_name](agent, args)
        except Exception as e:
            return f"[!] 工具执行错误 ({tool_name}): {e}"

    if not agent.mcp_manager:
        return f"[!] MCP 管理器未初始化，无法执行工具: {tool_name}"

    try:
        result = await agent.mcp_manager.call_tool(tool_name, args)
        if isinstance(result, dict):
            if result.get("ok", False):
                content = result.get("content")
                structured = result.get("structured_content")
                summary_parts: list[str] = []
                if content is not None:
                    summary_parts.append(str(content))
                if isinstance(structured, dict) and structured:
                    summary_parts.append(
                        f"[structured] {json.dumps(structured, ensure_ascii=False)}"
                    )
                if summary_parts:
                    return "\n".join(summary_parts)
                return f"[tool:{tool_name}] completed"

            message = str(result.get("message") or "")
            suggestion = str(result.get("suggestion") or "")
            error_type = str(result.get("error_type") or "error")
            if suggestion:
                return f"[{error_type}] {message}\n[suggestion] {suggestion}".strip()
            return f"[{error_type}] {message}".strip()

        text = str(result)
        if text.strip() in ("undefined", "null", "None"):
            return f"[!] 工具 {tool_name} 返回空结果 (undefined)，调用可能失败"
        return text
    except Exception as e:
        return f"[!] 工具执行错误 ({tool_name}): {e}"


def enforce_port_constraints(agent: AgentContext, ports: list[int], *, target: str = "") -> str | None:
    """Return a user-facing violation message when requested ports are out of scope."""
    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is None or constraints.is_empty():
        return None

    if constraints.allowed_ports:
        disallowed = [port for port in ports if port not in constraints.allowed_ports]
        if disallowed:
            allowed = ", ".join(str(p) for p in constraints.allowed_ports)
            denied = ", ".join(str(p) for p in disallowed)
            suffix = f" for target {target}" if target else ""
            return f"[constraint_violation] Port(s) {denied} are outside allowed scope [{allowed}]{suffix}."

    blocked = [port for port in ports if port in constraints.blocked_ports]
    if blocked:
        denied = ", ".join(str(p) for p in blocked)
        suffix = f" for target {target}" if target else ""
        return f"[constraint_violation] Port(s) {denied} are blocked by task constraints{suffix}."

    return None


def _normalize_url_path(path: str) -> str:
    """Resolve dot segments and every percent-encoding layer before scope
    matching (round13 F3, round14 F-A).

    ``urlparse().path`` does NOT normalize ``..``/``.`` segments, and servers
    resolve them (and percent-encoded dots) before routing — so a raw-path
    prefix check let ``/storage/../admin`` pass an allowed ``/storage`` prefix
    while the request landed on ``/admin``. Decoding runs until stable
    (bounded), so ``/storage/%252e%252e/admin`` — which a double-decoding
    server would route to ``/admin`` — resolves out too (round14 F-A).
    Returns a dot-segment-free path with collapsed duplicate leading slashes
    (``posixpath.normpath`` keeps ``//x`` intact); relative inputs pass
    through unchanged.
    """
    from urllib.parse import unquote

    text = str(path or "")
    for _ in range(3):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    if not text:
        return ""
    text = re.sub(r"^/+", "/", text)
    if not text.startswith("/"):
        return text
    return posixpath.normpath(text)


def _raw_path_in_scope(raw_path: str, entry: str) -> bool:
    """Whether the RAW urlparse path stays inside an allowed entry under its
    literal reading (round14 F-B). The normalized leg resolves encodings, so
    alone it is fail-open for servers that keep ``%2F`` literal: decoding
    turned ``/storage%2Fdocs`` into an in-scope prefix while such a server
    routes it to a resource outside ``/storage/*``. Requiring BOTH readings
    closes that flip; innocent encodings (``%20``, UTF-8 percent octets) pass
    both legs unchanged. Dot segments need no raw leg — a raw prefix can
    legitimately contain ``..`` — the normalized leg owns those.
    """
    base = entry.rstrip("/")
    return (
        raw_path == entry
        or (bool(base) and raw_path == base)
        or (bool(base) and raw_path.startswith(base + "/"))
        or (not base and raw_path.startswith("/"))
    )


def enforce_host_path_constraints(
    agent: AgentContext, *, host: str = "", path: str = "", target: str = ""
) -> str | None:
    """Return a user-facing violation when host/path are out of scope."""
    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is None or constraints.is_empty():
        return None

    if constraints.allowed_hosts and host and not host_in_scope(host, constraints.allowed_hosts):
        allowed = ", ".join(constraints.allowed_hosts)
        return f"[constraint_violation] Host {host} is outside allowed scope [{allowed}] for target {target or host}."

    if host and host_in_scope(host, constraints.blocked_hosts):
        return f"[constraint_violation] Host {host} is blocked by task constraints for target {target or host}."

    # Both checks below match on the DOT-SEGMENT-RESOLVED path (round13 F3) so
    # a request cannot walk out of (or into) a scope edge behind ``..`` — the
    # raw path from urlparse is only kept as an additional exact-match input.
    # round14 F-A: the normalizer now decodes EVERY percent-encoding layer, so
    # double-encoded dot segments resolve out as well. round14 F-B: the
    # allowed check requires BOTH the normalized and the raw reading to be in
    # scope — the normalized leg alone was fail-open for servers that keep
    # ``%2F`` literal (decoding made ``/storage%2Fdocs`` look in-scope).
    normalized_path = _normalize_url_path(path)
    normalized_blocked = {_normalize_url_path(b) for b in constraints.blocked_paths}

    if constraints.allowed_paths and path:
        # Prefix semantics: an allowed entry "/storage" covers "/storage" and
        # every subpath ("/storage/{addr}/{slot}"). Exact-match here made a
        # task description that mentioned the API path lock the whole run to
        # a single unusable literal path (round-12 UX postmortem).
        in_scope = any(
            (
                normalized_path == _normalize_url_path(a)
                or normalized_path.startswith(_normalize_url_path(a).rstrip("/") + "/")
            )
            and _raw_path_in_scope(str(path), a)
            for a in constraints.allowed_paths
        )
        if not in_scope:
            allowed = ", ".join(constraints.allowed_paths)
            return f"[constraint_violation] Path {path} is outside allowed scope [{allowed}] for target {target or host}."

    if path and (path in constraints.blocked_paths or normalized_path in normalized_blocked):
        return f"[constraint_violation] Path {path} is blocked by task constraints for target {target or host}."

    return None


def infer_ports_from_nmap_args(args: dict[str, Any]) -> list[int]:
    """Infer concrete target ports from nmap arguments for constraint checks."""
    custom_ports = str(args.get("ports", "") or "").strip()
    scan_type = str(args.get("scan_type", "top_ports") or "top_ports")

    if custom_ports:
        ports: list[int] = []
        for chunk in custom_ports.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start_text, end_text = chunk.split("-", 1)
                try:
                    start = int(start_text)
                    end = int(end_text)
                except ValueError:
                    continue
                if 0 < start <= end <= 65535:
                    ports.extend(range(start, end + 1))
                continue
            try:
                port = int(chunk)
            except ValueError:
                continue
            if 0 < port <= 65535:
                ports.append(port)
        return sorted(set(ports))

    if scan_type == "top_ports":
        return []
    return []


# Remote (SSH) tools. Kept next to the other name sets so the dispatch branch at
# the top of this module and the registrations below stay in sync.
_REMOTE_TOOL_NAMES = frozenset(
    {"remote_exec", "remote_collect", "remote_fetch", "remote_hosts"}
)

# Core tools always available regardless of the inferred task type: they are
# cheap, general-purpose and often needed for grounding/verification.
_ALWAYS_KEEP_TOOLS = frozenset({
    "load_skill_reference",
    "evidence_list",
    "evidence_view",
    "evidence_search",
    "python_execute",
    "crypto_decode",
    "shell_command",
    "blackboard_summary",
    "blackboard_add_fact",
    "blackboard_record_answer",
    "blackboard_verify_fact",
    "blackboard_challenge_fact",
    "blackboard_add_intent",
    "blackboard_start_intent",
    "blackboard_reject_intent",
    "blackboard_review",
    "blackboard_set_lock",
    "blackboard_create_angle",
    "blackboard_hit_angle",
    "blackboard_miss_angle",
    "blackboard_create_tension",
    "pwn_local_replay",
    "pwn_local_stop",
    "libc_lookup",
    "remote_exec",
    "remote_collect",
    "remote_fetch",
    "remote_hosts",
    "lookup_playbook",
    "save_playbook",
    "web_map_add",
    "web_map_link",
    "web_map_render",
    "web_map_summary",
    "web_map_reset",
    # NOTE: the GCS tools used to be pinned here by hand. That list had drifted
    # from reality -- it named 6 of the 9 gcs_* tools, so three were prunable
    # while six were force-kept. The GCS tool face is now controlled by one
    # setting (`gcs.tools_enabled`, default off) and gcs_tool_schemas() returns
    # an empty list when it is disabled, which removes the tools from the schema
    # entirely. Nothing to pin, and no list to keep in sync.
    #
    # ⚠️ The platform-neutral tools DO have to be pinned, and this was measured
    # rather than assumed: `_infer_allowed_tools` prunes the schema from the goal
    # text, and a goal containing any task keyword ("password", "http://", "登录",
    # "源码"...) dropped the entire ctf2_*/gcs_* face -- measured as
    # `n=41, ctf2 in: []`. A model that cannot see a platform tool cannot address
    # the platform at all, and the failure is silent. So the 6 core verbs are
    # kept unconditionally; only the optional, capability-gated ones can be pruned.
    *_PLATFORM_CORE_TOOL_NAMES,
})

# Task-specific tool bundles keyed by inferred task type. Names not listed here
# (recon/web/network/traffic/reporting heavy tools) are pruned unless required.
_TASK_TOOL_BUNDLES: dict[str, set[str]] = {
    "crypto": {"crypto_decode", "python_execute", "load_skill_reference"},
    "misc": {"crypto_decode", "python_execute", "load_skill_reference"},
    "reverse": {"python_execute", "shell_command", "load_skill_reference", "source_extract"},
    "code": {"python_execute", "shell_command", "load_skill_reference", "source_extract", "evidence_view", "evidence_search"},
    "web": {
        "fetch",
        "http_probe_batch",
        "dir_enum",
        "brute_force_login",
        "source_extract",
        "runtime_diff_probe",
        "nmap_scan",
    },
    "network": {
        "nmap_scan",
        "shell_command",
        "python_execute",
        "http_probe_batch",
        "subdomain_enum",
        "space_search",
        "unauth_test",
        "js_recon",
    },
    "osint": {
        "space_search",
        "subdomain_enum",
        "js_recon",
        "cve_lookup",
        "osint_recon",
        "fetch",
    },
}

# Strong keyword signals per task type. The first matching bundle wins.
_TASK_KEYWORDS: dict[str, list[str]] = {
    "crypto": [
        "rot13", "rot", "base64", "md5", "sha1", "sha256", "aes", "des", "rsa",
        "加密", "解密", "密文", "cipher", "decode", "encode", "哈希", "hash",
        "caesar", "凯撒", "维吉尼亚", "vigenere", "xor", "异或", "rc4", "凯撒密码",
        "base", "ascii", "摩斯", "morse", "进制",
        "flag{", "synt{", "flag{", "ctf{",
    ],
    "misc": ["zip", "压缩包", "隐写", "steg", "流量包", "pcap", "取证", "forensic", "misc"],
    "reverse": ["逆向", "reverse", "elf", "pe", "ida", "ghidra", "apk", "so文件", "脱壳"],
    "code": ["源码", "代码审计", "代码", "php", "审计", "分析源码", "source"],
    "web": [
        "web", "sql注入", "xss", "csrf", "ssrf", "上传", "rce", "命令执行",
        "后台", "登录", "login", "password", "用户名", "http://", "https://",
        "目录", "dir", "爆破", "brute", "绕过", "waf", "文件包含",
    ],
    "network": ["nmap", "端口", "内网", "主机", "子域名", "subdomain", "c段", "网段", "资产", "扫描"],
    "osint": ["osint", "情报", "信息收集", "资产发现", "社工", "whois", "shodan", "fofa", "hunter"],
}


def _infer_allowed_tools(user_input: str) -> set[str] | None:
    """Infer a task-specific tool subset from the user's request.

    Returns None when the request looks like a general pentest (keep all tools).
    """
    if not user_input:
        return None
    text = user_input.lower()

    # Knowledge-quiz goals (see solver._looks_like_quiz) read and submit a quiz
    # page. Technical stems (RSA/AES/端口…) must not prune `fetch` via the
    # crypto/network bundles below — the quiz directive and the completion gate
    # both direct the model to fetch, so the tool must exist in the schema.
    # Module-level import is safe: solver's dependency tree never imports this
    # module, so a regression surfaces loudly at import time, not silently here.
    if _looks_like_quiz(user_input):
        bundle = set(_ALWAYS_KEEP_TOOLS)
        bundle |= _TASK_TOOL_BUNDLES["web"]
        bundle |= {"crypto_decode"}
        return bundle

    # An explicit bare flag/encoded string is a crypto/misc task even without
    # an obvious keyword.
    if re.search(r"\{\w{8,}\}", text) or re.search(r"(flag|synt|ctf)\{", text):
        bundle = set(_ALWAYS_KEEP_TOOLS)
        bundle |= _TASK_TOOL_BUNDLES["crypto"]
        return bundle

    # General/ambiguous pentest goals keep the full toolset.
    if any(k in text for k in ("渗透", "pentest", "测试目标", "全面", "综合", "exploit", "exp", "漏洞挖掘")):
        if not any(k in text for k in ("http", "web", "登录", "密码", "decode", "rot", "端口")):
            return None

    for task_type, keywords in _TASK_KEYWORDS.items():
        if any(k in text for k in keywords):
            bundle = set(_ALWAYS_KEEP_TOOLS)
            bundle |= _TASK_TOOL_BUNDLES[task_type]
            return bundle

    return None


def build_openai_tools(
    mcp_manager: Any,
    *,
    active_role: str | None = None,
    allowed_tools: set[str] | None = None,
    include_subagent_tool: bool = True,
    config: Any = None,
) -> list[dict[str, Any]]:
    """Build OpenAI function calling schema from MCP tools + built-in tools.

    ``allowed_tools`` optionally restricts the returned schema to a subset of
    tool names (e.g. inferred from the user's task). Restricting the schema cuts
    tokens per call and reduces the chance the model reaches for irrelevant
    heavy tools; it does not change runtime dispatch, so a pruned name can still
    be executed if the model somehow calls it.

    ``config`` is the runtime config the agent was built with, forwarded to the ablation
    switches (round8 L4): this function runs every turn, and the switches used to re-read
    the config file here. Optional so the tool-face tests can keep calling it bare.
    """
    tools: list[dict[str, Any]] = []
    # Operator-configured tools the active role withheld; logged once at the end of the
    # MCP pass. Measured 2026-10-14: with any registry role, `role_allows_tool` denies
    # every `ctf2_*` name, so the operator bypass above silently does nothing.
    withheld_operator_tools: list[str] = []

    def append_tool(tool: dict[str, Any]) -> None:
        name = str(tool.get("function", {}).get("name", ""))
        if role_allows_tool(active_role, name) and (
            allowed_tools is None or name in allowed_tools
        ):
            tools.append(tool)

    def append_operator_tool(tool: dict[str, Any]) -> None:
        """Append a tool the operator configured, bypassing goal-text pruning.

        `allowed_tools` is a keyword heuristic over the goal text, and it prunes
        anything it does not recognise -- including whole MCP servers the
        operator explicitly enabled in config. Measured 2026-10-13: a goal about
        solving CTF2 practice challenges pruned every ``ctf2_*`` agent tool
        (``ctf2_agent_next_challenges`` and ``ctf2_submit_flag`` were absent
        from the built schema), so the model could not see the platform's own
        provisioned channel and re-implemented the platform client by hand
        instead. That is the same silent failure the platform-core pin above
        documents; a keyword guess must not undo an explicit configuration
        decision. Role gating still applies, and the server list is bounded by
        config, so the token cost stays finite.
        """
        name = str(tool.get("function", {}).get("name", ""))
        if role_allows_tool(active_role, name):
            tools.append(tool)
        else:
            withheld_operator_tools.append(name)

    append_builtin_tool_schemas(append_tool)

    # ── Pwn local replay (Docker) ────────────────────────────────────
    from vulnclaw.agent.pwn_local import pwn_local_tool_schemas

    for schema in pwn_local_tool_schemas():
        append_tool(schema)

    from vulnclaw.agent.remote import remote_tool_schemas
    for schema in remote_tool_schemas():
        append_tool(schema)

    if include_subagent_tool:
        from vulnclaw.agent.subagent.integration import tool_schemas
        for schema in tool_schemas():
            append_tool(schema)

    # ── Blackboard reasoning graph tools ────────────────────────────
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_summary",
                "description": "Read the full blackboard reasoning graph: confirmed facts, active intents, dead ends, and hints. Use this at the start of each round to avoid repeating dead ends.",
                "parameters": {"type": "object", "properties": {}},
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_add_fact",
                "description": "Record a finding on the blackboard. With an evidence_ref whose tool output contains the description, the fact is CONFIRMED; otherwise it is stored as an unverified candidate until you verify it. Facts persist and are visible to all agents.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": "Description of the finding (state it exactly as it appears in the tool output so it can be verified)",
                        },
                        "parent_id": {
                            "type": "string",
                            "description": "Optional ID of the intent this fact supports",
                        },
                        "evidence_ref": {
                            "type": "string",
                            "description": "Evidence ID the finding was witnessed in (e.g. e001). Strongly recommended: facts without a matching evidence_ref stay unverified candidates.",
                        },
                    },
                    "required": ["description"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_record_answer",
                "description": "Record ONE graded answer (IR answer rounds): writes the answer as a blackboard fact AND as a session finding — findings are the only surface the grader sees, so every answer must go through this. Use question='Q1: 攻击者 IP 是什么？' style, answer as the one-line final answer, evidence as the verbatim command output that proves it.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "question": {
                            "type": "string",
                            "description": "The question with its number, e.g. 'Q1: 攻击者 IP 是什么？'",
                        },
                        "answer": {
                            "type": "string",
                            "description": "The final answer, stated exactly (IP / path / time / account name / step list). Never a paraphrase.",
                        },
                        "evidence": {
                            "type": "string",
                            "description": "Verbatim command output or log line that proves the answer",
                        },
                        "evidence_ref": {
                            "type": "string",
                            "description": "Optional evidence ID (e.g. e007) to link the board fact to stored evidence",
                        },
                    },
                    "required": ["question", "answer"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_verify_fact",
                "description": "Confirm a candidate fact by checking its description against its referenced evidence output. Only succeeds when the description was actually witnessed in real tool output.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "node_id": {
                            "type": "string",
                            "description": "The candidate fact node ID to verify (e.g. n5)",
                        },
                    },
                    "required": ["node_id"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_challenge_fact",
                "description": "Mark a previously recorded fact as disputed when new evidence contradicts it. Challenged facts are excluded from the trusted context until re-verified.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "node_id": {
                            "type": "string",
                            "description": "The fact node ID to challenge (e.g. n2)",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Why this fact is now in doubt",
                        },
                    },
                    "required": ["node_id", "reason"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_add_intent",
                "description": "Declare a direction you plan to investigate (e.g. 'Test SQL injection on /login'). This tells other agents and your future self what you are working on.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": "Description of the investigation direction",
                        },
                        "parent_id": {
                            "type": "string",
                            "description": "Optional parent intent this refines",
                        },
                    },
                    "required": ["description"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_reject_intent",
                "description": "Mark an intent as a dead end so you won't repeat it. Provide the node_id and a brief reason why this path didn't work.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "node_id": {
                            "type": "string",
                            "description": "The intent node ID to reject (e.g. n3)",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Why this path was a dead end",
                        },
                    },
                    "required": ["node_id", "reason"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_start_intent",
                "description": "Mark an intent as currently in progress so other agents know you are working on it.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "node_id": {
                            "type": "string",
                            "description": "The intent node ID to mark as in progress (e.g. n3)",
                        },
                    },
                    "required": ["node_id"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_set_lock",
                "description": "Set or replace your current understanding of what this challenge tests and where the flag likely lives. Replaces the previous LOCK. The LOCK wins over speculation.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": "One-sentence LOCK statement (e.g. 'WordPress 5.x site, flag likely in wp-config.php behind auth bypass on /wp-admin')",
                        },
                    },
                    "required": ["description"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_create_angle",
                "description": "Register an untried attack surface/direction for systematic coverage. Each angle should be a specific testable hypothesis.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": "Attack surface description (e.g. 'sqli on login param', 'IDOR on /api/user/1')",
                        },
                        "parent_id": {
                            "type": "string",
                            "description": "Optional parent angle this refines",
                        },
                    },
                    "required": ["description"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_hit_angle",
                "description": "Mark an angle as tried and it produced a positive result (vulnerability confirmed, data leaked, etc).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "node_id": {
                            "type": "string",
                            "description": "The angle node ID to mark as hit",
                        },
                    },
                    "required": ["node_id"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_miss_angle",
                "description": "Mark an angle as tried and it did not work (no vulnerability, false positive, etc).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "node_id": {
                            "type": "string",
                            "description": "The angle node ID to mark as miss",
                        },
                    },
                    "required": ["node_id"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_create_tension",
                "description": "Record two mutually exclusive judgments that coexist and cannot both be true. Forces explicit resolution instead of silent contradiction.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": "Description of the contradiction (e.g. 'evidence A suggests XSS is possible, but CSP header blocks inline scripts')",
                        },
                    },
                    "required": ["description"],
                },
            },
        }
    )

    for tool in intel_tool_schemas():
        append_tool(tool)

    # ── WebMap site-structure recorder tools ─────────────────────────
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "web_map_add",
                "description": "Record a discovered web page or endpoint into the site map (URL, HTTP method, query/form params, content-type, notes). Use this whenever you discover a new path or endpoint so later rounds and teammates do not re-scrape it.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Full URL of the page or endpoint, e.g. http://host/index.php"},
                        "method": {"type": "string", "description": "HTTP method observed (GET/POST/etc.)"},
                        "params": {"type": "string", "description": "Query string or form parameters observed"},
                        "content_type": {"type": "string", "description": "Response content type (e.g. text/html, application/json)"},
                        "notes": {"type": "string", "description": "What this page does or notable details"},
                    },
                    "required": ["url"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "web_map_link",
                "description": "Record how one mapped page reaches another (kind: link, form, redirect, iframe, ajax, script). Unknown endpoints are auto-created as placeholder pages so the graph stays connected.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "from_url": {"type": "string", "description": "Source page URL"},
                        "to_url": {"type": "string", "description": "Target page or endpoint URL"},
                        "kind": {"type": "string", "description": "Relationship kind: link, form, redirect, iframe, ajax, script"},
                        "notes": {"type": "string", "description": "Optional detail (e.g. form field names)"},
                    },
                    "required": ["from_url", "to_url"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "web_map_render",
                "description": "Render the recorded site map as a Mermaid flowchart plus a text summary. Paste the mermaid block into https://mermaid.live to visualize the site structure.",
                "parameters": {"type": "object", "properties": {}},
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "web_map_summary",
                "description": "Read the recorded site map as text: every page/endpoint and the links between them. Useful before planning further exploration.",
                "parameters": {"type": "object", "properties": {}},
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "web_map_reset",
                "description": "Clear the site map (e.g. when starting a fresh target).",
                "parameters": {"type": "object", "properties": {}},
            },
        }
    )

    for tool in traffic_tool_schemas():
        append_tool(tool)

    # The finding-write verb sits next to the traffic tools on purpose: the two
    # form the evidence chain the model actually walks (report_finding ->
    # traffic_list -> traffic_bind_evidence), and the binding schema's own
    # description tells the model to report first. Without this verb that
    # instruction pointed at nothing (no tool could create a finding).
    append_tool(
        {
            "type": "function",
            "function": {
                "name": REPORT_FINDING_TOOL_NAME,
                "description": (
                    "上报一个你已确认的漏洞发现，写入本次运行的报告。"
                    "当你在授权范围内确认了可复现的漏洞（注入/越权/上传/凭证泄露等）时调用它——"
                    "报告只统计经此上报的发现，blackboard_record_answer 记的是答题卡，不进漏洞报告。"
                    "上报后请用 traffic_list 拿到 request_id，再用 traffic_bind_evidence "
                    "把复现报文绑定为该漏洞的证据。"
                    "同一个漏洞可以多次上报：会更新已有记录而不是新增第二条，"
                    "所以先报发现、实弹打通后再报一次（带 verified=true 与证据）即可把它升级为"
                    "「已验证」——报告只收录已验证的发现，没升级的不会出现在报告里。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "漏洞标题，如 'SQL Injection in /user'（必填，唯一标识）",
                        },
                        "severity": {
                            "type": "string",
                            "enum": list(_SEVERITIES),
                            "description": "严重级别，默认 Medium",
                        },
                        "vuln_type": {
                            "type": "string",
                            "description": "漏洞类型，如 SQLi / XSS / RCE / IDOR",
                        },
                        "description": {
                            "type": "string",
                            "description": "漏洞描述：问题与位置（what/where）",
                        },
                        "impact": {"type": "string", "description": "影响与业务风险"},
                        "evidence": {
                            "type": "string",
                            "description": "证明漏洞存在的关键观察（文字摘要；报文证据用 traffic_bind_evidence 绑定）",
                        },
                        "remediation": {"type": "string", "description": "修复建议"},
                        "endpoint": {"type": "string", "description": "受影响的 URL/端点"},
                        "method": {"type": "string", "description": "HTTP 方法，如 POST"},
                        "code_location": {
                            "type": "string",
                            "description": "源码位置 file:line（代码审计类发现）",
                        },
                        "verified": {
                            "type": "boolean",
                            "description": (
                                "你是否已实弹验证该漏洞（默认 false=仅候选项）。"
                                "只有报告里给出可核查依据（evidence/vuln_type/remediation 至少一项）"
                                "才会被采纳，否则按候选记录并在返回值里说明。"
                            ),
                            "default": False,
                        },
                        "verification_note": {
                            "type": "string",
                            "description": "验证方式说明（verified=true 时建议填写）",
                        },
                    },
                    "required": ["title"],
                },
            },
        }
    )

    for tool in ctf2_tool_schemas(config):
        append_tool(tool)

    for tool in platform_tool_schemas(config):
        append_tool(tool)

    for tool in gcs_tool_schemas(config):
        append_tool(tool)

    if mcp_manager:
        for schema in mcp_manager.get_tool_schemas():
            append_operator_tool(
                {
                    "type": "function",
                    "function": {
                        "name": schema.get("name", ""),
                        "description": schema.get("description", ""),
                        "parameters": schema.get(
                            "inputSchema", {"type": "object", "properties": {}}
                        ),
            },
        }
    )
        if withheld_operator_tools:
            # Silence is how this class of failure went unnoticed (see the docstring
            # above): a whole operator-enabled MCP server can be dropped by role
            # gating, which is correct but must be visible somewhere.
            logger.debug(
                "MCP tools withheld by role %r: %s",
                active_role,
                ", ".join(sorted(withheld_operator_tools)),
            )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "blackboard_review",
                "description": "Review the blackboard for factual disputes and dead ends. Challenges facts not witnessed in evidence, merges superseded facts, and flags dead-end intents. Run periodically to clean up stale information.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "lookup_playbook",
                "description": (
                    "Look up a reusable attack recipe (playbook) for a challenge you may have solved before. "
                    "Give a page signature/fingerprint from your first-round probe (page title + distinguishing "
                    "paths + form fields), and get back prior playbooks ranked by match score, with validated "
                    "recipes first. If an old playbook matches the current target, REPLAY its steps against the "
                    "new host instead of re-deriving the attack from scratch."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "fingerprint": {
                            "type": "string",
                            "description": "Page signature from your first probe, e.g. title 'Encrypted Flask @n1book' plus paths '/world/N /login /register'.",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max playbooks to return (default 3).",
                        },
                    },
                    "required": ["fingerprint"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "save_playbook",
                "description": (
                    "Persist a reusable attack recipe once you have a confirmed attack path (even before flag "
                    "extraction). status='validated' when you actually got the flag; 'draft' when the path is "
                    "figured out but not yet proven. Reproduction steps should use a {HOST} placeholder so the "
                    "recipe replays on any new instance of the same challenge. "
                    "QUALITY GATE: steps must be >=80 chars AND contain at least one LOCK/CONFIRMED/ANGLES "
                    "heading (e.g. 'LOCK: <what the challenge is>'); short or unstructured saves are rejected."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Challenge family name, e.g. 'Encrypted Flask'.",
                        },
                        "fingerprint": {
                            "type": "string",
                            "description": "Page signature (title + paths + form fields) used to re-identify this challenge later.",
                        },
                        "steps": {
                            "type": "string",
                            "description": "Numbered reproduction steps using {HOST} placeholder, e.g. '1) register donor with username A*15+0x05+admin... 2) extract T16 token ...'.",
                        },
                        "status": {
                            "type": "string",
                            "description": "validated (flag obtained) or draft (path known, unproven). Default draft.",
                        },
                    },
                    "required": ["name", "fingerprint", "steps"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "bg_launch",
                "description": "在后台启动一个爆破/纯计算命令(hashcat/john/python计算)，不阻塞当前探索。仅允许白名单命令前缀，禁止 shell 管道/下载/编码执行。启动后可用 bg_result 查询结果。适用于 hash 爆破、字典穷举等耗时任务，让 agent 边跑边干别的。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "要后台执行的命令。仅允许: hashcat/john/hydra/medusa/fcrackzip/zip2john/python 开头的纯计算命令。禁止 | > < & curl wget powershell -enc base64 等危险模式。",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "超时秒数(默认180, 最大3600)",
                        },
                    },
                    "required": ["command"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "bg_result",
                "description": "查询后台任务(bg_launch 启动)的状态和输出。注意: 后台爆破出的密码/结果必须用真实请求验证后才能采信, 不能直接当成已确认事实。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "task_id": {
                            "type": "string",
                            "description": "后台任务ID (如 bg1)",
                        },
                    },
                    "required": ["task_id"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "ocr",
                "description": "提取图片中的文字：优先本地 easyocr(GPU)/pytesseract/Windows OCR，全部失败时自动降级到 vision LLM(deepseek-v4-flash-vision-exp)理解图片。适用于验证码、截图、PDF渲染图、图片藏flag等场景。",                "parameters": {
                    "type": "object",
                    "properties": {
                        "image_path": {
                            "type": "string",
                            "description": "图片路径（必需）",
                        },
                        "method": {
                            "type": "string",
                            "description": "OCR 方法：auto（自动选择）/easyocr（GPU 加速，推荐）/pytesseract（需 tesseract）/windows（Windows 10/11 原生）/llm（仅用 vision LLM）",
                            "enum": ["auto", "easyocr", "pytesseract", "windows", "llm"],
                        },
                        "use_llm": {
                            "type": "boolean",
                            "description": "本地 OCR 全部失败时是否降级到 vision LLM（默认 true）",
                        },
                        "lang": {
                            "type": "string",
                            "description": "语言代码，默认 en（easyocr 支持 ch_sim 中文）",
                        },
                    },
                    "required": ["image_path"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "pyc_analyze",
                "description": "CTF REVERSE 助手：分析 Python 字节码文件（.pyc）。自动检测/修复被篡改的 magic 头（CTF 常见手法），提供反汇编、反编译、常量/字符串提取。适用于逆向 .pyc 找 flag 或加密逻辑。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pyc_path": {
                            "type": "string",
                            "description": ".pyc 文件路径（必需）",
                        },
                        "mode": {
                            "type": "string",
                            "description": "分析模式：auto（全部，默认）/disasm（反汇编）/decompile（反编译）/consts（提取常量）",
                            "enum": ["auto", "disasm", "decompile", "consts"],
                        },
                    },
                    "required": ["pyc_path"],
                },
            },
        }
    )
    append_tool(
        {
            "type": "function",
            "function": {
                "name": "pdf_analyze",
                "description": "CTF 取证助手：提取 PDF 文本（PyMuPDF），按页输出，可列出图片并提示用 ocr 处理。适用于 PDF 藏 flag、Flate 流压缩文本、图片版题面等场景。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pdf_path": {
                            "type": "string",
                            "description": "PDF 文件路径（必需）",
                        },
                        "extract_images": {
                            "type": "boolean",
                            "description": "是否列出每页图片数量（默认 false）",
                        },
                        "page_limit": {
                            "type": "integer",
                            "description": "最多打印多少页（默认 20，全部文本仍会提取）",
                        },
                    },
                    "required": ["pdf_path"],
                },
            },
        }
    )

    # Model-facing reasoning-graph ablation: the runtime blackboard and every
    # solver-side consumer stay as they are; only the 13 schemas the model would
    # otherwise spend calls on are removed. The names are still dispatchable if a
    # hand-crafted call arrives, which mirrors how allowed_tools pruning behaves.
    from vulnclaw.agent.blackboard import reasoning_graph_enabled

    if not reasoning_graph_enabled(config):
        tools = [t for t in tools if not str(t.get("function", {}).get("name", "")).startswith("blackboard_")]

    return tools


async def execute_vault_tool(agent: AgentContext, tool_name: str, args: dict[str, Any]) -> str:
    """Dispatch the four context-vault tools (archive/restore/search/status)."""
    context = getattr(agent, "context", None)
    if context is None:
        return "[!] vault tools require a session context"
    vault = getattr(context, "vault", None)
    if vault is None:
        vault = context.ensure_vault()

    if tool_name == "vault_status":
        stats = vault.stats(context.get_messages())
        lines = [
            "[V] vault status",
            f"  next ref: ‹v#{int(stats.get('next_ref', 0)) + 1:05d}›",
            f"  active blocks: {stats.get('active_blocks', 0)}",
            f"  restored blocks: {stats.get('restored_blocks', 0)}",
            f"  archived messages: {stats.get('archived_messages', 0)}",
            f"  chars saved: {stats.get('chars_saved', 0)}",
        ]
        return "\n".join(lines)

    if tool_name == "vault_search":
        query = str(args.get("query") or "").strip()
        if not query:
            return "[!] vault_search requires a non-empty query"
        limit = min(20, max(1, int(args.get("limit", 8))))
        max_chars = max(512, int(getattr(context, "search_max_chars", 6000)))
        hits = vault.search(query, limit=limit, max_chars=max_chars)
        if not hits:
            return "[-] No archived block matches the query"
        rendered = json.dumps(hits, ensure_ascii=False, indent=2)
        if len(rendered) > max_chars:
            suffix = "\n...[vault search output truncated]"
            rendered = rendered[: max_chars - len(suffix)] + suffix
        return rendered

    if tool_name == "vault_restore":
        start = str(args.get("start") or "").strip()
        end = str(args.get("end") or "").strip()
        if not start or not end:
            return "[!] vault_restore requires start and end refs (‹v#NNNNN›)"
        ok, message, _ = vault.restore_range(context.get_messages(), start=start, end=end)
        return ("[✓] " if ok else "[!] ") + message

    if tool_name == "vault_archive":
        start = str(args.get("start") or "").strip()
        end = str(args.get("end") or "").strip()
        if not start or not end:
            return "[!] vault_archive requires start and end refs (‹v#NNNNN›)"
        tier = int(args.get("tier", 2))
        ok, message, block = vault.archive_range(
            context.get_messages(),
            start=start,
            end=end,
            tier=tier,
            topic=str(args.get("topic") or ""),
            summary=str(args.get("summary") or ""),
            force=bool(args.get("force", False)),
        )
        if not ok:
            return "[!] " + message
        if block is not None and tier <= 1:
            pointer = vault.render_pointer(block)
            context.add_message(pointer)
            return f"[✓] {message} — pointer injected into context"
        if block is not None and tier == 2:
            distilled = vault.render_distill(block, str(args.get("summary") or ""))
            context.add_message(distilled)
            return f"[✓] {message} — distilled summary injected into context"
        if block is not None:
            return f"[✓] {message} — folded into global digest (tier 3)"
        return "[✓] " + message

    return f"[!] unknown vault tool: {tool_name}"


# ── 后台任务（爆破等耗时操作不阻塞 agent，白名单受限）────────────────────────

_BG_TOOL_NAMES = {"bg_launch", "bg_result"}

import threading as _threading

_bg_tasks: dict[str, dict] = {}
_bg_lock = _threading.Lock()
_bg_seq = 0
_BG_MAX_CONCURRENT = 3
#: How many FINISHED tasks stay queryable via `bg_result`. Running tasks are never evicted,
#: so the table is bounded by `_BG_MAX_CONCURRENT + _BG_MAX_FINISHED`.
#
# Round5 residual item: the table grew without limit. Each row keeps up to 4KB of stdout
# and 2KB of stderr, and nothing ever removed one -- a long run that launches a
# brute-force job per hypothesis accumulated every one for the life of the process. The
# concurrency cap above bounds how many RUN at once, which is a different question.
_BG_MAX_FINISHED = 50

# 允许后台运行的命令前缀（爆破/纯计算类）。拒绝 shell 管道、下载、编码执行。
_BG_ALLOWED_PREFIXES = (
    "hashcat",
    "john",
    "hydra",
    "medusa",
    "fcrackzip",
    "zip2john",
    "python",
    "python3",
    "cmd /c python",
)
# The subset of the allowlist above that is an INTERPRETER: those prefixes make the
# substring blacklist meaningless unless their inline-code flags are refused (A1).
#
# Round-8 finding R8-1: the first version of that check compared raw whitespace-split
# tokens against ("-c", "-m", "--command", "-") and required the command to start with
# one of the strings above FOLLOWED BY A SPACE. Three live bypasses fell straight out
# of that, all measured:
#
#   python "-c" "code"   -- the quotes survive a plain .split(), so the token is "-c"
#                           only to a shell, never equal to the literal "-c";
#   python -c"code"      -- CPython takes an ATTACHED value, so flag and code are one
#                           token (`python -cprint(1)` == `python -c "print(1)"`);
#   python3.13 -c / pythonw -c
#                        -- the allowlist is prefix-based, so both pass it, but neither
#                           command starts with a listed prefix plus a space.
#
# So the interpreter is now identified by BASENAME (an optional `cmd /c` wrapper, then
# python/pythonw/py/pypy with an optional version suffix), and the flags are matched on
# quote-stripped tokens instead of raw text.
_BG_INTERPRETER_RE = re.compile(r"^(?:python|pythonw|py|pypy)(?:\d+(?:\.\d+)*)?$")
_BG_INLINE_FLAGS = ("-c", "-m", "--command", "-")
# `cmd /c python ...`: wrappers to step over before the interpreter token.
_BG_SHELL_WRAPPERS = ("cmd", "/c", "/k", "call")
# 禁止出现的危险模式（配合前缀二次过滤）
_BG_BLOCKED_PATTERNS = (
    "|",
    ">",
    "<",
    "&",
    "curl",
    "wget",
    "powershell",
    "-enc",
    "nc ",
    "bash -c",
    "sh -c",
    "base64",
    ";/",
)


def _bg_new_id() -> tuple[str, int]:
    """Allocate the next task id together with its launch-order seq.

    Both come back from ONE `_bg_lock` hold: the row insert used to re-read
    the global `_bg_seq` after a second lock acquisition, so a concurrent
    launch in between handed two rows the same seq and degraded eviction
    ordering (round9 low-confidence ①, closed round14).
    """
    global _bg_seq
    with _bg_lock:
        _bg_seq += 1
        return f"bg{_bg_seq}", _bg_seq


def _evict_finished_bg_tasks() -> None:
    """Drop the oldest FINISHED tasks once the table exceeds ``_BG_MAX_FINISHED``.

    Caller must hold ``_bg_lock``. Running tasks are never touched: evicting one would
    leave a live thread writing into a row nobody can query. An evicted id answers
    `bg_result` with the existing "unknown task" message, which already tells the model
    what ids look like -- losing the record of a 10-minute-old finished task is the
    smaller loss against unbounded growth.

    Ordered by launch SEQUENCE, not by `started`: tasks launched in a burst share a
    timestamp to within microseconds, and the tie-break then fell through to the task id as
    a STRING -- where "bg10" sorts before "bg7" -- so "oldest first" was arbitrary
    (measured: a test asserting the first ten ids were evicted failed 2 runs in 3).
    """
    finished = [
        (int(task.get("seq") or 0), float(task.get("started") or 0.0), task_id)
        for task_id, task in _bg_tasks.items()
        if task.get("status") != "running"
    ]
    excess = len(finished) - _BG_MAX_FINISHED
    if excess <= 0:
        return
    finished.sort()
    for _, _, task_id in finished[:excess]:
        _bg_tasks.pop(task_id, None)


def _bg_split_tokens(text: str) -> list[str]:
    """Split a command line into tokens, dropping quote characters.

    Deliberately not ``shlex.split(..., posix=True)``: that eats backslashes, and this
    runs on Windows command lines where ``C:\\path`` has to survive. Quotes are removed
    rather than interpreted, so ``python "-c" x`` yields the token ``-c`` -- which is
    the whole point (round-8 finding R8-1).
    """
    tokens: list[str] = []
    current: list[str] = []
    quote = ""
    for ch in text:
        if quote:
            if ch == quote:
                quote = ""
            else:
                current.append(ch)
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch.isspace():
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(ch)
    if current:
        tokens.append("".join(current))
    return tokens


def _bg_looks_like_script(token: str) -> bool:
    """Whether ``token`` is a script path rather than an interpreter option.

    Bounds where an ATTACHED ``-cvalue`` counts as inline code: past the script name the
    options belong to the script, so ``python brute.py -charset abc`` is left alone.
    Exact ``-c``/``-m`` tokens stay refused everywhere, as before.
    """
    if token.startswith("-"):
        return False
    return token.endswith((".py", ".pyw", ".pyc")) or "/" in token or "\\" in token


def _bg_interpreter_inline_code(cmd_raw: str) -> str | None:
    """Return the offending flag when an interpreter prefix carries inline code.

    Audit finding A1, second half. The prefix allowlist accepts ``python``/``python3``,
    which makes the substring blacklist beside it decorative: measured,
    ``python -c "import os;os.system('id')"`` is ACCEPTED here while
    ``python_execute`` blocks ``os.system(`` outright and sits behind
    ``safety.enable_python_execute``. So the background path was a way around that
    policy, not merely an ungated spawn.

    ``-c``/``-m``/bare ``-`` are the inline-code vectors. ``python brute.py words.txt``
    -- the documented "pure computation" use -- still works, and the launch is gated
    anyway. A script that itself wants ``-c`` as its own flag loses; that is the safe
    direction, and the refusal says so.

    Round-8 finding R8-1 rewrote this (see ``_BG_INTERPRETER_RE``): the previous version
    was matched against raw text and missed quoted, concatenated and version-suffixed
    spellings of the same vector. Every one of those is now in
    ``tests/agent/test_bg_launch_gate.py``.
    """
    tokens = _bg_split_tokens(str(cmd_raw or "").lower())
    if not tokens:
        return None
    index = 0
    while index < len(tokens) and tokens[index] in _BG_SHELL_WRAPPERS:
        index += 1
    if index >= len(tokens):
        return None
    interpreter = tokens[index].replace("\\", "/").rsplit("/", 1)[-1]
    if interpreter.endswith(".exe"):
        interpreter = interpreter[: -len(".exe")]
    if not _BG_INTERPRETER_RE.match(interpreter):
        return None
    arguments = tokens[index + 1 :]
    # Exact flag tokens are refused wherever they appear: unchanged behaviour, and
    # `python brute.py -c x` still loses (the documented safe direction above).
    for token in arguments:
        if token in _BG_INLINE_FLAGS:
            return token
    # Attached values (`-cprint(1)`, `-mhttp.server`) only up to the script name, beyond
    # which the option belongs to the script rather than to the interpreter.
    for token in arguments:
        if _bg_looks_like_script(token):
            break
        if token.startswith("--"):
            continue
        if token.startswith(("-c", "-m")):
            return token[:2]
    return None


def _bg_validate_command(cmd_raw: str) -> str | None:
    """Return an error message if the command is not allowed in background, else None."""
    stripped = cmd_raw.strip()
    if not stripped:
        return "command is empty"
    lowered = stripped.lower()
    # 前缀白名单
    if not any(lowered.startswith(p) for p in _BG_ALLOWED_PREFIXES):
        return f"command not allowed in background; allowed prefixes: {', '.join(_BG_ALLOWED_PREFIXES)}"
    # 解释器 + 内联代码 = 绕过 python_execute 的策略（见 A1）
    inline = _bg_interpreter_inline_code(stripped)
    if inline:
        return (
            f"interpreter flag {inline!r} runs inline code, which bypasses the "
            f"python_execute sandbox policy; pass a script file instead "
            f"(e.g. 'python brute.py wordlist.txt')"
        )
    # 危险模式拦截
    for pat in _BG_BLOCKED_PATTERNS:
        if pat in lowered:
            return f"command contains blocked pattern: {pat!r}"
    # 不允许后台起 shell 管道类
    return None


def _bg_run(task_id: str, cmd: list[str], timeout: int) -> None:
    """Background worker: run subprocess, capture output, update task state."""
    import subprocess as _sp

    try:
        proc = _sp.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        with _bg_lock:
            _bg_tasks[task_id]["status"] = "finished"
            _bg_tasks[task_id]["returncode"] = proc.returncode
            _bg_tasks[task_id]["output"] = (proc.stdout or "")[:4000]
            _bg_tasks[task_id]["stderr"] = (proc.stderr or "")[:2000]
            # Also enforce the bound at the terminal transition, not only at insert: a row
            # that finishes between two launches would otherwise push the finished count to
            # cap+1 and stay there until the next launch happened to evict it.
            _evict_finished_bg_tasks()
    except _sp.TimeoutExpired:
        with _bg_lock:
            _bg_tasks[task_id]["status"] = "timeout"
            _bg_tasks[task_id]["output"] = ""
            _evict_finished_bg_tasks()
    except Exception as e:
        with _bg_lock:
            _bg_tasks[task_id]["status"] = "failed"
            _bg_tasks[task_id]["error"] = str(e)[:500]
            _evict_finished_bg_tasks()


async def execute_bg_launch(agent: AgentContext, args: dict[str, Any]) -> str:
    """Launch a command in the background so the agent can keep working.

    Restricted to brute-force / pure-computation commands (hashcat, john, python
    computation). Shell pipelines, downloads, and encoded execution are blocked.
    The agent continues exploring and checks the result later via ``bg_result``.

    Async because it now passes the ExecutionGate, like every other model-reachable
    process spawn. Audit finding A1: this path had NO gate at all -- the three
    ``gate.authorize`` sites then were shell / runtime_diff_probe / python -- so a
    background launch ran an operator-unapproved command, and (via ``python -c``) one
    that ``python_execute`` would have refused outright. The boundary scanner's own
    contract states that model-reachable spawn sites are exactly the ones the gate must
    cover.

    ⚠️ Corrected by round-8 finding R8-8 (D3): this docstring used to say the three
    sites were "shell/python/nmap". ``git show 25b4677^`` shows the third was
    ``runtime_diff_probe`` -- nmap had no gate at all, which is exactly what R8-8
    reported, and it now has one.
    """
    cmd_raw = str(args.get("command") or args.get("cmd") or "").strip()
    if not cmd_raw:
        return "[!] bg_launch requires 'command'"
    blocked = _bg_validate_command(cmd_raw)
    if blocked:
        return f"[!] bg_launch rejected: {blocked}"

    # ── ExecutionGate: per-request operator approval ─────────────────────
    from vulnclaw.agent.exec_gate import GateRequest, get_execution_gate

    model_risk = str(args.get("risk_self_assessment") or "").strip().lower()
    if model_risk not in ("safe", "review"):
        model_risk = ""
    model_reason = str(args.get("assessment_reason") or "").strip()[:300] or (
        "background command (brute-force / pure computation)"
    )
    gate = get_execution_gate(getattr(agent, "config", None))
    outcome = await gate.authorize(
        GateRequest(
            kind="shell",
            display=cmd_raw,
            cwd="",
            model_risk=model_risk,
            model_reason=model_reason,
            detail="background task (bg_launch) -- runs detached, output via bg_result",
        ),
        run_id=str(getattr(getattr(agent, "runtime", None), "run_id", "") or ""),
    )
    if not outcome.approved:
        return outcome.refusal_text("bg_launch")

    # 并发上限
    with _bg_lock:
        running = sum(1 for t in _bg_tasks.values() if t.get("status") == "running")
        if running >= _BG_MAX_CONCURRENT:
            return f"[!] bg_launch rejected: {running} background tasks already running (max {_BG_MAX_CONCURRENT})"
    timeout = max(10, min(3600, int(args.get("timeout", 180))))
    if os.name == "nt":
        cmd = ["cmd", "/c", cmd_raw]
    else:
        import shlex

        cmd = shlex.split(cmd_raw)
    task_id, launch_seq = _bg_new_id()
    with _bg_lock:
        _bg_tasks[task_id] = {
            "status": "running",
            "cmd": cmd_raw,
            "started": time.time(),
            # Launch order, used for eviction ordering (see _evict_finished_bg_tasks).
            "seq": launch_seq,
        }
        _evict_finished_bg_tasks()
    t = _threading.Thread(target=_bg_run, args=(task_id, cmd, timeout), daemon=True)
    t.start()
    return (
        f"[bg_launch] task {task_id} started in background (restricted: brute-force only).\n"
        f"Command: {cmd_raw}\n"
        f"Use bg_result(task_id={task_id!r}) later to check status/output. "
        f"Meanwhile continue exploring other attack paths."
    )


def execute_bg_result(agent: AgentContext, args: dict[str, Any]) -> str:
    """Query a background task's status and output."""
    task_id = str(args.get("task_id") or "").strip()
    if not task_id:
        return "[!] bg_result requires 'task_id'"
    with _bg_lock:
        task = _bg_tasks.get(task_id)
        if task is None:
            return f"[bg_result] unknown task: {task_id} (task ids look like bg1, bg2, ...)"
        snapshot = dict(task)
    status = snapshot.get("status", "unknown")
    lines = [f"[bg_result] task {task_id}: {status}"]
    if snapshot.get("cmd"):
        lines.append(f"  command: {snapshot['cmd']}")
    if status == "running":
        lines.append("  still running; call bg_result again later, or continue other work")
    elif status == "finished":
        lines.append(f"  returncode: {snapshot.get('returncode')}")
        out = snapshot.get("output") or ""
        if out:
            lines.append("  output:")
            lines.append(out[:3000])
        if snapshot.get("stderr"):
            lines.append(f"  stderr: {snapshot['stderr'][:1000]}")
        # 关键安全提示：后台结果必须用真实请求验证后才能采信
        lines.append(
            "\n[!] REMINDER: a background result is NOT confirmed. "
            "Verify any recovered password/secret with a real request "
            "before treating it as a fact."
        )
    elif status == "timeout":
        lines.append(f"  timed out after the configured limit")
    else:
        lines.append(f"  error: {snapshot.get('error', 'unknown')}")
    return "\n".join(lines)


# ── OCR 工具（本地 GPU 加速）────────────────────────────────────────────────────

_OCR_TOOL_NAMES = {"ocr"}
_OCR_READER_CACHE: dict[Any, Any] = {}
# Module-level on purpose: the double-checked lock below used to create a fresh
# ``threading.Lock()`` inside the function on every call, which locks nothing —
# concurrent OCR calls would each load their own GPU Reader.
_OCR_READER_LOCK = _threading.Lock()

# ── 拆出的工具族（tools/ 子包）—— 以下名字原样 re-export，保持旧 import 路径 ──
from vulnclaw.agent.tools.subprocess_util import run_subprocess_capture  # noqa: F401 — re-export
from vulnclaw.agent.tools.pyc import (  # noqa: F401 — re-export
    _PYC_MAGICS,
    _PYC_TOOL_NAMES,
    _detect_pyc_magic,
    _pyc_decompile_via_decompyle3,
    _pyc_disasm_via_xdis,
    _pyc_marshal_ok,
    _pyc_scan_consts,
    execute_pyc_analyze,
)
from vulnclaw.agent.tools.pdf import (  # noqa: F401 — re-export
    _PDF_TOOL_NAMES,
    execute_pdf_analyze,
    extract_pdf_text,
)
from vulnclaw.agent.tools.ocr import (  # noqa: F401 — re-export
    _ocr_via_vision_llm,
    _ocr_with_cached_reader,
    execute_ocr,
)
from vulnclaw.agent.tools.brute_force import (  # noqa: F401 — re-export
    _sync_cookies_to_shared_jar,
    execute_brute_force,
)
from vulnclaw.agent.tools.nmap import (  # noqa: F401 — re-export
    _run_nmap_argv,
    execute_nmap,
    is_reserved_ip,
    parse_nmap_xml,
    validate_scan_target,
)
from vulnclaw.agent.tools.http_probe import (  # noqa: F401 — re-export
    _HTTP_PROBE_ALLOWED_METHODS,
    _HTTP_PROBE_DEFAULT_BODY_CHARS_LIMIT,
    _HTTP_PROBE_DEFAULT_TIMEOUT,
    _HTTP_PROBE_MAX_REQUESTS,
    _HTTP_PROBE_SENSITIVE_HEADER_NAMES,
    _body_with_optional_limit,
    _bounded_float,
    _coerce_nonnegative_int,
    _cookies_need_exact_header,
    _execute_one_http_probe,
    _extract_html_title,
    _format_http_probe_batch,
    _group_http_probe_batch,
    _http_body_signals,
    _jsonish_one_line,
    _masked_probe_headers,
    _object_or_none,
    _prepare_http_probe_request,
    _probe_request_surface_lines,
    _resolve_probe_url,
    _string_dict,
    execute_http_probe_batch,
)
from vulnclaw.agent.tools.python_exec import (  # noqa: F401 — re-export
    _HTTP_CALL_NAMES,
    _call_full_name,
    _extract_request_urls,
    _resolve_python_execute_mode,
    _validate_python_execute_mode,
    _write_python_audit,
    execute_python,
)
from vulnclaw.agent.tools.shell_exec import (  # noqa: F401 — re-export
    _EXEC_ENV_BLOCKED_EXACT,
    _EXEC_ENV_BLOCKED_PREFIXES,
    _close_windows_job,
    _create_windows_kill_job,
    _default_workdir,
    _kill_process_tree,
    _payload_script_dir,
    _resolve_workdir,
    _scratch_dir_if_configured,
    _shell_argv,
    _spawn_captured,
    _terminate_windows_job,
    _validate_command_url_scope,
    _windows_system_dir,
    execute_shell_command,
    sanitized_exec_env,
)
from vulnclaw.agent.tools.runtime_diff import (  # noqa: F401 — re-export
    _PHP_SERIALIZE_LENGTH_TOKEN_RE,
    _PHP_SERIALIZE_STRING_TOKEN_RE,
    _b64_php_string,
    _build_php_runtime_diff_script,
    _detect_target_runtime,
    _execute_php_serialize_diff_probe,
    _execute_regex_diff_probe,
    _parse_python_regex,
    _runtime_diff_candidates,
    _strip_php_open_close_tags,
    execute_runtime_diff_probe,
)
