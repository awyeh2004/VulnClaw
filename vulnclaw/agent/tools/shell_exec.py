"""shell_command tool: hardened shell argv/spawn + process-tree kill.

The module imports ``subprocess``/``shutil``/``time`` as the real stdlib module
objects, so tests that patch ``builtin_tools.subprocess.run`` / ``builtin_tools.
time.perf_counter`` (an attribute set on the shared module object) still reach
this code. Names that tests patch on the *facade namespace* (``_spawn_captured``,
``_create_windows_kill_job``) are resolved through builtin_tools at call time.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


def _resolve_workdir(raw_workdir: Any) -> Path:
    workdir = Path(str(raw_workdir or os.getcwd())).expanduser()
    return workdir.resolve()


def _scratch_dir_if_configured(agent: AgentContext) -> Path | None:
    """Per-run scratch dir when ``session.solve_work_root`` is set, else None.

    Single source of truth for the scratch path: the tools' default workdir and
    the staging dir for generated scripts must not drift apart.
    """
    try:
        raw = str(getattr(agent.config.session, "solve_work_root", "") or "").strip()
    except Exception:
        return None
    if not raw:
        return None
    run_id = str(getattr(getattr(agent, "runtime", None), "run_id", "") or "").strip()
    safe = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", run_id)[:120] or "manual"
    try:
        scratch = (Path(raw).expanduser() / safe).resolve()
        scratch.mkdir(parents=True, exist_ok=True)
        return scratch
    except Exception:
        return None


def _default_workdir(agent: AgentContext) -> Path:
    """Process cwd, or the per-run scratch dir when session.solve_work_root is set.

    Solve runs used to drop every payload/probe/response file straight into the
    process cwd — the repo root when launched from the checkout — leaving a
    hundred stray files behind. When solve_work_root is configured, each run
    instead gets its own subdir named by run_id. Any failure falls back to the
    process cwd so a bad path can never take the tools down.
    """
    scratch = _scratch_dir_if_configured(agent)
    return scratch if scratch is not None else Path(os.getcwd()).resolve()


def _payload_script_dir(agent: AgentContext) -> str | None:
    """Where ``python_execute`` stages the script it is about to run.

    It used to go to the system temp dir (``%TEMP%\\tmpXXXX.py``). Generated
    payloads living there have two problems, both measured on 2026-09-23 while
    solving Weblogic CVE-2017-10271: the files are invisible to the rest of a
    run's artifacts, and an endpoint AV quarantines them mid-run — six
    `HEUR:Backdoor/JSP.WebShell.a` hits deleted the staged script between write
    and execute, and the run then spent several turns diagnosing whether
    ``python_execute`` itself was broken.

    Staging inside the run's scratch dir keeps payloads with the run's other
    artifacts (auditable, cleaned up with the run) and lets an operator exclude
    one narrow path in such a product instead of all of ``%TEMP%``.

    Returns None — meaning "use the system temp dir" — when no scratch root is
    configured or it cannot be created: staging must never fail a run.
    """
    scratch = _scratch_dir_if_configured(agent)
    return str(scratch) if scratch is not None else None


def _validate_command_url_scope(agent: AgentContext, command: str) -> str | None:
    # enforce_host_path_constraints is facade/policy and stays in builtin_tools,
    # so resolve it there at call time.
    from vulnclaw.agent import builtin_tools as _bt

    for match in re.finditer(r"https?://[^\s'\"<>]+", command):
        parsed = urlparse(match.group(0))
        host = (parsed.hostname or "").lower()
        path = parsed.path.rstrip("/")
        violation = _bt.enforce_host_path_constraints(
            agent,
            host=host,
            path=path,
            target=host,
        )
        if violation:
            return violation
    return None


def _shell_argv(command: str, shell_name: str) -> list[str]:
    """Build a fully-specified argv for one shell invocation.

    Hardening (C-1): never trust %ComSpec%/PATH lookups for system shells,
    never relax PowerShell execution policy, and disable CMD AutoRun.
    """
    normalized = (shell_name or "").strip().lower()
    if os.name == "nt":
        system_dir = _windows_system_dir()
        if normalized in {"cmd", "cmd.exe"}:
            return [str(system_dir / "cmd.exe"), "/D", "/S", "/C", command]
        if normalized in {"pwsh", "pwsh.exe"}:
            # pwsh is operator-installed: PATH lookup is acceptable here, the
            # binary location is an operator decision, not attacker-controlled.
            return ["pwsh.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command]
        powershell = system_dir / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        exe = str(powershell) if powershell.is_file() else "powershell.exe"
        return [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command]
    return ["/bin/sh", "-c", command]


def _windows_system_dir() -> Path:
    """Trusted system directory (never %ComSpec% or other env values)."""
    root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    return Path(root) / "System32"


# Environment variables that must never reach a child spawned from
# model-influenced input: they hijack interpreters (BASH_ENV/NODE_OPTIONS/
# PYTHONSTARTUP), steal credentials (SSH_AUTH_SOCK/GIT_ASKPASS) or inject
# code into loaders (LD_*/DYLD_*). Matching is case-insensitive; DYLD_ is
# matched as a prefix because macOS exposes several variants.
_EXEC_ENV_BLOCKED_EXACT = frozenset({
    "BASH_ENV", "ENV", "CDPATH", "PYTHONPATH", "PYTHONSTARTUP",
    "PYTHONHOME", "NODE_OPTIONS", "GIT_ASKPASS", "SSH_AUTH_SOCK",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
})
_EXEC_ENV_BLOCKED_PREFIXES = ("DYLD_",)


def sanitized_exec_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Child-process environment: inherited minus interpreter-hijack vectors."""
    source = os.environ if base is None else base
    env: dict[str, str] = {}
    for key, value in source.items():
        upper = key.upper()
        if upper in _EXEC_ENV_BLOCKED_EXACT:
            continue
        if any(upper.startswith(prefix) for prefix in _EXEC_ENV_BLOCKED_PREFIXES):
            continue
        env[key] = value
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _spawn_captured(
    argv: list[str],
    *,
    cwd: str,
    env: dict[str, str] | None = None,
    timeout_s: float,
):
    """Run argv capturing output; on timeout kill the whole process tree.

    POSIX starts the child in its own session so ``killpg`` reaches every
    descendant; Windows falls back to ``taskkill /T /F``. Returns
    ``(returncode, stdout, stderr, timed_out)``.
    """
    # _create_windows_kill_job is patched on the facade by tests, so resolve it
    # there at call time (Windows-only patch path).
    from vulnclaw.agent import builtin_tools as _bt

    popen_kwargs: dict[str, Any] = {
        "cwd": cwd,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.DEVNULL,
    }
    if env is not None:
        popen_kwargs["env"] = env
    new_session = os.name != "nt"
    if new_session:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(argv, **popen_kwargs)
    process_group_id = proc.pid if new_session else None
    windows_job = _bt._create_windows_kill_job(proc)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_tree(
            proc,
            process_group_id=process_group_id,
            windows_job=windows_job,
        )
        cleanup_deadline = time.monotonic() + 1.0
        try:
            out, err = proc.communicate(timeout=1.0)
        except subprocess.TimeoutExpired as exc:
            # A descendant may still hold inherited pipe handles after the
            # process tree has been terminated. Never turn the cleanup drain
            # into another unbounded wait.
            out = exc.output or b""
            err = exc.stderr or b""
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            remaining = max(0.0, cleanup_deadline - time.monotonic())
            if remaining > 0:
                try:
                    proc.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    pass
    except BaseException:
        _kill_process_tree(
            proc,
            process_group_id=process_group_id,
            windows_job=windows_job,
        )
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        _close_windows_job(windows_job)
    return (
        proc.returncode,
        (out or b"").decode("utf-8", errors="replace"),
        (err or b"").decode("utf-8", errors="replace"),
        timed_out,
    )


def _create_windows_kill_job(proc: subprocess.Popen) -> Any | None:
    """Bind *proc* to a kill-on-close Windows Job Object when available."""

    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
        configured = kernel32.SetInformationJobObject(
            job,
            9,  # JobObjectExtendedLimitInformation
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        assigned = configured and kernel32.AssignProcessToJobObject(
            job, wintypes.HANDLE(int(proc._handle))  # type: ignore[attr-defined]
        )
        if not assigned:
            kernel32.CloseHandle(job)
            return None
        return job
    except Exception:
        return None


def _terminate_windows_job(job: Any) -> bool:
    if os.name != "nt" or job is None:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        return bool(kernel32.TerminateJobObject(job, 1))
    except Exception:
        return False


def _close_windows_job(job: Any) -> None:
    if os.name != "nt" or job is None:
        return
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle(job)
    except Exception:
        pass


def _kill_process_tree(
    proc: subprocess.Popen,
    *,
    process_group_id: int | None = None,
    windows_job: Any = None,
) -> None:
    if os.name != "nt":
        import signal

        if process_group_id is not None:
            try:
                # With start_new_session=True the child's pid is also its pgid.
                # The group can remain alive after its leader has already exited.
                os.killpg(process_group_id, signal.SIGKILL)
                return
            except (ProcessLookupError, PermissionError, OSError):
                pass
    else:
        if _terminate_windows_job(windows_job):
            return
        try:
            result = subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                return
        except Exception:
            pass
    if proc.poll() is not None:
        return
    try:
        proc.kill()
    except OSError:
        pass


async def execute_shell_command(agent: AgentContext, args: dict[str, Any]) -> str:
    """Run a local shell command and return command output as model-visible evidence."""
    # Gating/policy helpers and the spawn seam stay in the facade (tests patch
    # _spawn_captured there), so resolve them from builtin_tools at call time.
    from vulnclaw.agent import builtin_tools as _bt

    refused = _bt.dangerous_tool_refusal("shell_command", agent)
    if refused:
        return refused

    command = str(args.get("command") or args.get("cmd") or "").strip()
    if not command:
        return "[!] shell_command requires command"
    scope_violation = _validate_command_url_scope(agent, command)
    if scope_violation:
        return scope_violation
    # Answer-provenance guard, mirroring the python_execute side. Audit finding A3: the
    # identical intent was unguarded here, because the Python-side check is only called
    # from python_execute.
    flag_hunt = _bt._shell_flag_hunt_reason(command)
    if flag_hunt:
        return f"[!] {flag_hunt}"

    try:
        workdir = _resolve_workdir(args.get("workdir") or _default_workdir(agent))
    except OSError as exc:
        return f"[!] shell_command invalid workdir: {exc}"
    if not workdir.exists() or not workdir.is_dir():
        return f"[!] shell_command workdir does not exist or is not a directory: {workdir}"

    timeout_ms = int(args.get("timeout_ms") or 10000)
    timeout_ms = max(1000, min(timeout_ms, 120000))
    max_output_chars = int(args.get("max_output_chars") or 0)
    shell_name = str(args.get("shell") or "")
    argv = _shell_argv(command, shell_name)
    env = sanitized_exec_env()

    # ── ExecutionGate: per-request operator approval ─────────────────────
    from vulnclaw.agent.exec_gate import GateRequest, get_execution_gate

    model_risk = str(args.get("risk_self_assessment") or "").strip().lower()
    if model_risk not in ("safe", "review"):
        model_risk = ""  # omitted/unknown: local classifier stays the authority
    model_reason = str(args.get("assessment_reason") or "").strip()[:300]

    # cmd.exe has no POSIX single-quote quoting, so a read-only verdict from the
    # POSIX-oriented classifier is unsound for such commands. Escalate them to
    # the human path (model_risk="review" is one-way: it can only force review).
    from vulnclaw.agent.command_classifier import windows_shell_quoting_hazard

    quoting_hazard = windows_shell_quoting_hazard(command, shell_name)
    if quoting_hazard:
        model_risk = "review"
        model_reason = (
            quoting_hazard if not model_reason else f"{model_reason} | {quoting_hazard}"
        )[:300]

    gate = get_execution_gate(getattr(agent, "config", None))
    outcome = await gate.authorize(
        GateRequest(
            kind="shell",
            display=command,
            cwd=str(workdir),
            model_risk=model_risk,
            model_reason=model_reason,
        ),
        run_id=str(getattr(getattr(agent, "runtime", None), "run_id", "") or ""),
    )
    if not outcome.approved:
        return outcome.refusal_text("shell_command")

    started = time.perf_counter()
    try:
        loop = asyncio.get_running_loop()
        returncode, stdout, stderr, timed_out = await loop.run_in_executor(
            None,
            lambda: _bt._spawn_captured(
                argv,
                cwd=str(workdir),
                env=env,
                timeout_s=timeout_ms / 1000,
            ),
        )
    except FileNotFoundError as exc:
        return f"[!] shell_command failed: shell executable not found ({exc})"
    except Exception as exc:
        return f"[!] shell_command failed: {exc.__class__.__name__}: {exc}"

    if timed_out:
        return (
            f"[!] shell_command timed out after {timeout_ms}ms\n"
            f"Command: {command}\n"
            f"Workdir: {workdir}\n"
            "Output:\n(process tree terminated)"
        )

    result_returncode = returncode
    result_stdout, result_stderr = stdout, stderr
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    parts = [
        f"Command: {command}",
        f"Workdir: {workdir}",
        f"Exit code: {result_returncode}",
        f"Wall time: {elapsed_ms}ms",
        "Output:",
    ]
    output = ""
    if result_stdout:
        output += result_stdout
    if result_stderr:
        output += ("\n" if output else "") + "[stderr]\n" + result_stderr
    if not output:
        output = "(no output)"
    raw_output = "\n".join(parts + [output])
    if max_output_chars > 0 and len(raw_output) > max_output_chars:
        clip = max_output_chars // 2
        return raw_output[:clip] + "\n...[truncated by max_output_chars]...\n" + raw_output[-clip:]
    return raw_output
