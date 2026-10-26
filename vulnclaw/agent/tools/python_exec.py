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


def _task_constraints_active(agent: AgentContext) -> bool:
    """Whether this run carries host/path/port scope that a request must satisfy."""
    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    return constraints is not None and not constraints.is_empty()


def _blocked_host_entries(agent: AgentContext) -> list[str]:
    """Blocked hosts from BOTH sources: task constraints and safety.denied_hosts.

    The hard denylist (``safety.denied_hosts``) is merged into constraints on the
    paths that install a run's scope -- but a run that never installs scope would
    otherwise carry an invisible denylist, so it is read directly here too.
    CIDR-shaped entries are address rules, not text markers; they are skipped.
    """
    entries: list[str] = []
    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is not None:
        entries.extend(str(h) for h in (constraints.blocked_hosts or []))
    safety = getattr(getattr(agent, "config", None), "safety", None)
    if safety is not None:
        entries.extend(str(h) for h in (getattr(safety, "denied_hosts", None) or []))
    return [h.strip().lower() for h in entries if h.strip() and "/" not in h]


def _blocked_host_text_reason(agent: AgentContext, code: str) -> str | None:
    """The cheap first pass (audit item C, 2026-10-24): refuse code that NAMES
    a blocked host anywhere.

    The literal-URL check only sees request URLs; the host string can also reach
    the network through a variable, a file read or a socket call. While a host is
    explicitly off-limits, naming it in the code at all is refused -- a warning
    here would only teach the model to route around the gate.
    """
    blocked = _blocked_host_entries(agent)
    if not blocked:
        return None
    lowered = str(code or "").lower()
    for host in blocked:
        if host in lowered:
            return (
                f"[constraint_violation] Code references blocked host '{host}'. "
                "Any request toward it is out of scope for this run; build the "
                "solution against the allowed target instead."
            )
    return None


def _url_argument(node: ast.Call) -> ast.AST | None:
    """The expression a known HTTP-client call sends its request to."""
    name = _call_full_name(node.func)
    positional = 1 if name.endswith(".request") else 0  # request(method, url, ...)
    if len(node.args) > positional:
        return node.args[positional]
    for kw in node.keywords:
        if kw.arg in {"url", "uri", "path"}:
            return kw.value
    return None


def _static_text(node: ast.AST, bindings: dict[str, str]) -> str | None:
    """The string value of an expression when it is built from constants only."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return bindings.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_text(node.left, bindings)
        right = _static_text(node.right, bindings)
        if left is not None and right is not None:
            return left + right
    return None


def _module_string_bindings(tree: ast.Module) -> dict[str, str]:
    """Module-level ``name = <constant-built string>`` assignments, in order.

    A name bound to a ``*Request("http://...")`` constructor resolves statically
    too, so the common ``req = urllib.request.Request(literal); urlopen(req)``
    shape (used by this repo itself) is not misread as dynamic.
    """
    bindings: dict[str, str] = {}
    for node in tree.body:
        names: list[str] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names = [node.target.id]
            value = node.value
        if value is None or not names:
            continue
        if isinstance(value, ast.Call):
            if not _call_full_name(value.func).endswith("Request"):
                continue
            value = _url_argument(value)
            if value is None:
                continue
        resolved = _static_text(value, bindings)
        if resolved is not None:
            for name in names:
                bindings[name] = resolved
    return bindings


def _dynamic_network_target_reason(code: str) -> str | None:
    """Fail-closed check (audit item C): HTTP calls whose target is not static.

    The scope gate could only check string-literal URLs;
    ``requests.get("http://" + host)``, ``urlopen(os.environ["URL"])`` and URLs
    read from files executed unchecked. When the run carries task scope, an HTTP
    call whose target cannot be resolved statically is refused: a request whose
    host cannot be named cannot be proved in scope. Runs with no scope keep the
    previous behaviour, and static constant-built targets still pass.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None  # the staged run reports the syntax error; nothing executes
    bindings = _module_string_bindings(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _call_full_name(node.func) not in _HTTP_CALL_NAMES:
            continue
        arg = _url_argument(node)
        if arg is None:
            continue
        if _static_text(arg, bindings) is None:
            call = _call_full_name(node.func)
            return (
                f"[constraint_violation] {call}(...) builds its request target "
                "dynamically, so it cannot be checked against the task's host/path "
                "scope. Inline a literal http(s):// URL inside the allowed scope, or "
                "use fetch / http_probe_batch, which scope-check every request."
            )
    return None



def _egress_scope_preamble(agent: AgentContext) -> str:
    """In-process egress guard (audit item C2, python side).

    The staged payload installs a ``sys.addaudithook`` that refuses
    ``socket.getaddrinfo`` / ``socket.connect`` outside the task's host/port
    scope — network-level enforcement for the exact path string/AST scanning
    cannot see (aliases, config files, library internals). Audit hooks cannot
    be uninstalled, so the payload cannot shed the guard mid-run.

    Two deliberate scope limits, both documented residuals:
    * raw-IP connects enforce the BLOCKED lists and ports, but not the
      allowed-name list (a name's IP cannot be verified inside the payload
      without re-resolving); name egress is enforced at getaddrinfo.
    * direct ctypes/winsock calls bypass CPython audit events entirely; that
      residual needs an OS-level boundary (egress proxy/WFP), not more code.
    Empty when the run carries no task constraints (local runs unchanged).
    """
    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is None or constraints.is_empty():
        return ""
    try:
        scope = json.dumps(
            {
                "allowed_hosts": [str(h) for h in (constraints.allowed_hosts or [])],
                "blocked_hosts": [str(h) for h in (constraints.blocked_hosts or [])],
                "allowed_ports": [int(p) for p in (constraints.allowed_ports or [])],
                "blocked_ports": [int(p) for p in (constraints.blocked_ports or [])],
            },
            ensure_ascii=False,
        )
    except (TypeError, ValueError):
        return ""
    return (
        "# ── in-process egress scope guard (framework-injected; see audit C2) ──\n"
        "import sys as _vc_sys, json as _vc_json, ipaddress as _vc_ip\n"
        f"_VC_SCOPE = _vc_json.loads({scope!r})\n"
        "def _vc_match(entry, host):\n"
        "    try:\n"
        "        e = str(entry).strip().lower().rstrip('.')\n"
        "    except Exception:\n"
        "        return False\n"
        "    if not e:\n"
        "        return False\n"
        "    if '/' in e:\n"
        "        try:\n"
        "            return _vc_ip.ip_address(host) in _vc_ip.ip_network(e, strict=False)\n"
        "        except Exception:\n"
        "            return False\n"
        "    return host == e or host.endswith('.' + e)\n"
        "def _vc_blocked(host):\n"
        "    return any(_vc_match(e, host) for e in _VC_SCOPE['blocked_hosts'])\n"
        "def _vc_allowed(host):\n"
        "    allowed = _VC_SCOPE['allowed_hosts']\n"
        "    if not allowed:\n"
        "        return True\n"
        "    return any(_vc_match(e, host) for e in allowed)\n"
        "def _vc_is_ip(host):\n"
        "    try:\n"
        "        _vc_ip.ip_address(host)\n"
        "        return True\n"
        "    except Exception:\n"
        "        return False\n"
        "def _vc_host_ok(host, at_dns):\n"
        "    try:\n"
        "        h = str(host).strip().rstrip('.').lower()\n"
        "    except Exception:\n"
        "        return True\n"
        "    if not h:\n"
        "        return True\n"
        "    if _vc_blocked(h):\n"
        "        return False\n"
        "    if at_dns or not _vc_is_ip(h):\n"
        "        return _vc_allowed(h)\n"
        "    return True\n"
        "def _vc_port_ok(port):\n"
        "    try:\n"
        "        p = int(port)\n"
        "    except Exception:\n"
        "        return True\n"
        "    if p in _VC_SCOPE['blocked_ports']:\n"
        "        return False\n"
        "    allowed = _VC_SCOPE['allowed_ports']\n"
        "    if allowed and p not in allowed:\n"
        "        return False\n"
        "    return True\n"
        "def _vc_audit(event, args):\n"
        "    try:\n"
        "        if event == 'socket.getaddrinfo':\n"
        "            if args and not _vc_host_ok(args[0], at_dns=True):\n"
        "                raise PermissionError(\n"
        "                    '[constraint_violation] DNS resolution of ' + repr(args[0])\n"
        "                    + ' is outside the task host scope')\n"
        "        elif event == 'socket.connect':\n"
        "            addr = args[1] if len(args) > 1 else None\n"
        "            if isinstance(addr, tuple) and addr:\n"
        "                if not _vc_host_ok(addr[0], at_dns=False):\n"
        "                    raise PermissionError(\n"
        "                        '[constraint_violation] connect to ' + repr(addr[0])\n"
        "                        + ' is outside the task host scope')\n"
        "                if len(addr) > 1 and not _vc_port_ok(addr[1]):\n"
        "                    raise PermissionError(\n"
        "                        '[constraint_violation] port ' + repr(addr[1])\n"
        "                        + ' is outside the task port scope')\n"
        "    except PermissionError:\n"
        "        raise\n"
        "    except Exception:\n"
        "        pass\n"
        "_vc_sys.addaudithook(_vc_audit)\n"
    )


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

    # Fail-closed scope guard (audit item C, 2026-10-24). The literal check above
    # predates it and stays first; both of these bite only when the run carries
    # scope or names a hard-denied host, so unconstrained local runs are unchanged.
    blocked_text = _blocked_host_text_reason(agent, code)
    if blocked_text:
        _write_python_audit(
            agent,
            purpose=purpose,
            code=code,
            mode=_resolve_python_execute_mode(agent),
            outcome="blocked",
            blocked_reason="blocked_host_text",
        )
        return blocked_text
    if _task_constraints_active(agent):
        dynamic_reason = _dynamic_network_target_reason(code)
        if dynamic_reason:
            _write_python_audit(
                agent,
                purpose=purpose,
                code=code,
                mode=_resolve_python_execute_mode(agent),
                outcome="blocked",
                blocked_reason="dynamic_network_target",
            )
            return dynamic_reason

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
            f.write(_egress_scope_preamble(agent))
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
