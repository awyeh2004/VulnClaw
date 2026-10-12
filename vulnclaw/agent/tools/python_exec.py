"""python_execute tool: mode validation, audit, and payload staging."""

from __future__ import annotations

import ast
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from vulnclaw.agent.tool_result_overrides import set_raw_tool_output_override

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


def _resolve_python_execute_mode(agent: AgentContext) -> str:
    safety = getattr(agent.config, "safety", None)
    if safety is None:
        return "trusted-local"

    mode = str(getattr(safety, "python_execute_mode", "") or "").strip().lower()
    if not mode and getattr(safety, "python_execute_restricted", False):
        return "safe"
    if mode in {"safe", "lab", "trusted-local"}:
        return mode
    return "trusted-local"


def _validate_python_execute_mode(mode: str, code: str) -> str | None:
    # SAFE_MODE_PATTERNS/LAB_MODE_PATTERNS and _ast_check_sandbox_bypass stay in
    # the facade (policy), so resolve them there at call time.
    from vulnclaw.agent import builtin_tools as _bt

    patterns = _bt.SAFE_MODE_PATTERNS if mode == "safe" else _bt.LAB_MODE_PATTERNS if mode == "lab" else []
    for pattern in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            return pattern
    # AST-based check for dynamic bypass patterns (importlib, exec, getattr, etc.)
    ast_result = _bt._ast_check_sandbox_bypass(code)
    if ast_result:
        return f"ast:{ast_result}"
    return None


def _write_python_audit(
    agent: AgentContext,
    *,
    purpose: str,
    code: str,
    mode: str,
    outcome: str,
    blocked_reason: str = "",
) -> None:
    safety = getattr(agent.config, "safety", None)
    if safety is None or not getattr(safety, "python_execute_audit_enabled", True):
        return

    try:
        from datetime import datetime

        from vulnclaw.config.settings import PYTHON_EXECUTE_AUDIT_FILE, ensure_dirs

        ensure_dirs()
        record = {
            "timestamp": datetime.now().isoformat(),
            "target": getattr(getattr(agent, "session_state", None), "target", None),
            "mode": mode,
            "purpose": purpose,
            "outcome": outcome,
            "blocked_reason": blocked_reason,
            "code_preview": code[:300],
            "code_lines": code.count("\n") + 1,
        }
        with open(PYTHON_EXECUTE_AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        return


# HTTP-client call names whose string-literal URL argument is a real outbound
# request the script makes. Payload/document strings (SVG xmlns, DTD refs,
# SSRF/redirect urls inside crafted payloads) contain http(s):// text too, but
# the script never requests those hosts itself, so they must not trip the scope
# check. Matching the actual call sites keeps the out-of-scope protection while
# no longer false-positiving on payload content (e.g. "http://www.w3.org/2000/svg").
_HTTP_CALL_NAMES = {
    "requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.delete", "requests.head", "requests.options", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
    "httpx.head", "httpx.request",
    "urllib.request.urlopen", "urlopen", "request.urlopen",
    "session.get", "session.post", "session.put", "session.patch", "session.delete",
}


def _call_full_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_full_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _extract_request_urls(code: str) -> list[tuple[str, str]]:
    """Return (host, path) pairs for http(s) URLs the script will actually request."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return re.findall(r"https?://([a-zA-Z0-9._:-]+)(/[^\s'\"`]*)?", code or "")
    out: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _call_full_name(node.func) not in _HTTP_CALL_NAMES:
            continue
        arg: ast.AST | None = None
        if node.args:
            arg = node.args[0]
        else:
            for kw in node.keywords:
                if kw.arg in {"url", "uri", "path"}:
                    arg = kw.value
                    break
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            m = re.match(r"https?://([a-zA-Z0-9._:-]+)(/[^\s'\"`]*)?", arg.value.strip())
            if m:
                host = m.group(1).split(":", 1)[0].lower()
                out.append((host, m.group(2) or ""))
    return out


async def execute_python(agent: AgentContext, args: dict[str, Any]) -> str:
    # Gating/policy helpers, the audit writer, the spawn runner and the
    # workdir/staging helpers stay in the facade (some are patched there by
    # tests), so resolve every one of them from builtin_tools at call time.
    from vulnclaw.agent import builtin_tools as _bt

    refused = _bt.dangerous_tool_refusal("python_execute", agent)
    if refused:
        return refused

    code = args.get("code", "")
    purpose = args.get("purpose", "")
    workdir_arg = args.get("workdir", "")
    try:
        # 模型可控超时(默认 30s, 上限 300s): 端口扫描/批量 payload/长循环等
        # 场景 30s 不够, 固定超时会导致"到点被杀→重发同样代码"的整轮浪费。
        timeout_seconds = min(max(float(args.get("timeout", 30)), 1.0), 300.0)
    except (TypeError, ValueError):
        timeout_seconds = 30.0
    if not code.strip():
        return "[!] Code is empty; nothing executed"

    for host, path in _extract_request_urls(code):
        host_violation = _bt.enforce_host_path_constraints(
            agent,
            host=host,
            path=(path or "").rstrip("/"),
            target=host,
        )
        if host_violation:
            return host_violation

    safety = getattr(agent.config, "safety", None)
    if safety is None or not safety.enable_python_execute:
        return (
            "[!] python_execute is disabled. Set safety.enable_python_execute = true to enable it"
        )

    mode = _resolve_python_execute_mode(agent)
    max_lines = getattr(safety, "python_execute_max_lines", 50)
    if code.count("\n") + 1 > max_lines:
        _bt._write_python_audit(
            agent,
            purpose=purpose,
            code=code,
            mode=mode,
            outcome="blocked",
            blocked_reason="max_lines",
        )
        return f"[!] Code exceeds the max line limit ({max_lines})"

    show_warning = getattr(safety, "python_execute_show_warning", True)
    warning_prefix = ""
    if show_warning:
        warning_prefix = (
            f"[!] Security warning: python_execute runs local Python code in {mode} mode.\n"
            "Review the code carefully before execution.\n"
            "---\n"
        )

    for pattern in _bt.BLOCKED_PATTERNS:
        if re.search(pattern, code):
            _bt._write_python_audit(
                agent,
                purpose=purpose,
                code=code,
                mode=mode,
                outcome="blocked",
                blocked_reason=pattern,
            )
            return f"[!] Code contains a blocked operation pattern: {pattern}"

    flag_hunt = _bt._host_flag_hunt_reason(code)
    if flag_hunt:
        _bt._write_python_audit(
            agent,
            purpose=purpose,
            code=code,
            mode=mode,
            outcome="blocked",
            blocked_reason="host_flag_hunt",
        )
        return f"[!] {flag_hunt}"

    blocked_pattern = _validate_python_execute_mode(mode, code)
    if blocked_pattern:
        _bt._write_python_audit(
            agent,
            purpose=purpose,
            code=code,
            mode=mode,
            outcome="blocked",
            blocked_reason=blocked_pattern,
        )
        if mode == "safe":
            return f"[!] safe mode blocked operation: {blocked_pattern}"
        return f"[!] lab mode blocked operation: {blocked_pattern}"

    # AST-based check for dynamic bypass patterns (importlib, exec, getattr, etc.)
    ast_bypass = _bt._ast_check_sandbox_bypass(code)
    if ast_bypass:
        _bt._write_python_audit(
            agent,
            purpose=purpose,
            code=code,
            mode=mode,
            outcome="blocked",
            blocked_reason=f"ast:{ast_bypass}",
        )
        return f"[!] Sandbox bypass detected: {ast_bypass}"

    max_output_chars = getattr(safety, "python_execute_max_output_chars", 0)
    model_risk = str(args.get("risk_self_assessment") or "").strip().lower()
    if model_risk not in ("safe", "review"):
        model_risk = ""
    model_reason = str(args.get("assessment_reason") or "").strip()[:300]
    tmp_path = ""
    try:
        # ── ExecutionGate: per-request operator approval ─────────────────
        from vulnclaw.agent.exec_gate import GateRequest, get_execution_gate

        gate = get_execution_gate(getattr(agent, "config", None))
        outcome = await gate.authorize(
            GateRequest(
                kind="python",
                display=code,
                cwd="",
                detail=f"purpose={purpose or '(none)'} mode={mode}",
                model_risk=model_risk,
                model_reason=model_reason,
            ),
            run_id=str(getattr(getattr(agent, "runtime", None), "run_id", "") or ""),
        )
        if not outcome.approved:
            _bt._write_python_audit(
                agent,
                purpose=purpose,
                code=code,
                mode=mode,
                outcome="blocked",
                blocked_reason=f"approval:{outcome.status}",
            )
            return outcome.refusal_text("python_execute")

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8",
            dir=_bt._payload_script_dir(agent), prefix="vulnclaw-payload-",
        ) as f:
            preamble = (
                "import sys, json, re, os, base64, hashlib, itertools, collections, datetime, struct, binascii, textwrap, math, random, string, fractions, decimal, statistics, typing, functools, operator, copy, pprint\n"
                "import urllib.parse, urllib.request, http.client, xml.etree.ElementTree as ET\n"
                "try:\n    import requests\nexcept ImportError:\n    pass\n"
                "# CTF targets almost always use self-signed certs; disable SSL\n"
                "# verification by default so requests calls don't trip on them.\n"
                "try:\n    import urllib3\n    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\nexcept Exception:\n    pass\n"
                "try:\n    import requests.sessions as _rss\n    _rs_orig = _rss.Session.__init__\n"
                "    def _rs_init(self, *a, **k):\n        _rs_orig(self, *a, **k)\n        self.verify = False\n"
                "    _rss.Session.__init__ = _rs_init\nexcept Exception:\n    pass\n"
                "try:\n    from bs4 import BeautifulSoup\nexcept ImportError:\n    pass\n"
                "try:\n    from Crypto.Cipher import AES, DES, Blowfish, ChaCha20\n    from Crypto.Util.number import *\n    from Crypto.PublicKey import RSA\n    from Crypto.Signature import pkcs1_15\n    from Crypto.Hash import SHA256, MD5\nexcept ImportError:\n    pass\n"
                "try:\n    import zlib, gzip, bz2, lzma, zipfile, tarfile, io\nexcept ImportError:\n    pass\n"
                "try:\n    import itertools, functools, collections, math\nexcept ImportError:\n    pass\n\n"
            )
            f.write(preamble)
            f.write(code)
            tmp_path = f.name

        base_env = {"PYTHONIOENCODING": "utf-8"}
        if mode == "trusted-local":
            env = _bt.sanitized_exec_env(
                {k: v for k, v in os.environ.items() if not k.startswith("VULNCLAW_")}
            )
        else:
            env = _bt.sanitized_exec_env(base_env)

        try:
            workdir = _bt._resolve_workdir(workdir_arg or _bt._default_workdir(agent))
        except Exception:
            workdir = Path(os.getcwd()).resolve()
        if not workdir.exists() or not workdir.is_dir():
            workdir = Path(os.getcwd()).resolve()

        loop = asyncio.get_running_loop()
        returncode, proc_stdout, proc_stderr, proc_timed_out = await loop.run_in_executor(
            None,
            lambda: _bt._spawn_captured(
                [sys.executable, tmp_path],
                cwd=str(workdir),
                env=env,
                timeout_s=timeout_seconds,
            ),
        )

        try:
            os.unlink(tmp_path)
        except OSError:
            pass

        output_parts: list[str] = []
        if proc_stdout:
            output_parts.append(proc_stdout)
        if proc_stderr:
            stderr_lines = [
                line
                for line in proc_stderr.splitlines()
                if "ImportError" not in line and "No module named" not in line
            ]
            if stderr_lines:
                output_parts.append("[stderr]\n" + "\n".join(stderr_lines))

        if proc_timed_out:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            agent.runtime.python_timeout_rounds += 1
            _bt._write_python_audit(
                agent, purpose=purpose, code=code, mode=mode, outcome="timeout"
            )
            return f"[!] Python execution timed out after {timeout_seconds} seconds (process tree terminated)"

        if not output_parts:
            _bt._write_python_audit(agent, purpose=purpose, code=code, mode=mode, outcome="success")
            set_raw_tool_output_override(
                agent,
                tool="python_execute",
                arguments=args,
                output="[+] Python executed successfully with no output",
            )
            return f"{warning_prefix}[+] Python executed successfully with no output"

        output = "\n".join(output_parts)
        for sig in ["[DONE]", "[COMPLETE]"]:
            output = output.replace(sig, f"[BLOCKED_{sig[1:-1]}]")
        raw_return = f"[+] Python execution result ({mode}):\n{output}"
        display_output = output
        if max_output_chars > 0 and len(display_output) > max_output_chars:
            clip = max_output_chars // 2
            display_output = display_output[:clip] + "\n...[truncated]...\n" + display_output[-clip:]
        _bt._write_python_audit(agent, purpose=purpose, code=code, mode=mode, outcome="success")
        set_raw_tool_output_override(
            agent,
            tool="python_execute",
            arguments=args,
            output=raw_return,
        )
        return f"{warning_prefix}[+] Python execution result ({mode}):\n{display_output}"
    except subprocess.TimeoutExpired:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        agent.runtime.python_timeout_rounds += 1
        _bt._write_python_audit(agent, purpose=purpose, code=code, mode=mode, outcome="timeout")
        return f"[!] Python execution timed out after {timeout_seconds} seconds"
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        _bt._write_python_audit(
            agent, purpose=purpose, code=code, mode=mode, outcome="error", blocked_reason=str(e)
        )
        return f"[!] Python execution error: {e}"
