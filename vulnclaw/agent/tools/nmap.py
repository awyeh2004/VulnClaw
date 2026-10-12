"""nmap scan tool + XML parsing + reserved-IP target validation."""

from __future__ import annotations

import asyncio
import shlex
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, Any

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
from vulnclaw.utils.subprocess_text import run_text

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


# ── nmap 扫描族 ──────────────────────────────────────────────────────────────
#
# RESERVED_IP_RANGES is defined in builtin_tools.py (the facade) and stays there:
# it is a facade-level constant (``core.py`` re-exports it as
# ``_RESERVED_IP_RANGES``). is_reserved_ip resolves it from builtin_tools at call
# time, so the facade keeps a single source of truth for the constant.


def _run_nmap_argv(cmd: list[str], **kwargs: Any) -> Any:
    """Synchronous nmap runner for asyncio.to_thread.

    Kept as its own function so the run_text call stays a scannable spawn site:
    passing ``run_text`` itself to to_thread would hide it from
    verify_execution_boundary. Off the event loop because a 120s scan (plus the
    de-escalation retry) used to freeze the whole agent loop.
    """
    return run_text(cmd, **kwargs)


async def execute_nmap(agent: AgentContext, args: dict[str, Any]) -> str:
    # gating helpers and the reserved-range constant live in the facade; resolve
    # them at call time to avoid a module-level circular import.
    from vulnclaw.agent import builtin_tools as _bt

    target = args.get("target", "").strip()
    if not target:
        return "[!] nmap_scan 需要 target 参数（目标 IP 或域名）"

    host_violation = _bt.enforce_host_path_constraints(agent, host=target.lower(), target=target)
    if host_violation:
        return host_violation

    violation = _bt.enforce_port_constraints(
        agent, _bt.infer_ports_from_nmap_args(args), target=target
    )
    if violation:
        return violation

    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        if ips:
            ip = ips[0][4][0]
            is_reserved, reason = is_reserved_ip(ip)
            if is_reserved and not target_is_private_literal(target):
                return (
                    f"[SKIP] 目标 {target} 解析到保留/内网地址 ({reason}, IP: {ip})\n"
                    f"跳过 nmap 扫描。建议直接通过 Web 指纹、目录枚举等方法收集信息，"
                    f"不要在保留地址上浪费轮次。"
                )
    except Exception:
        pass

    scan_type = args.get("scan_type", "top_ports")
    custom_ports = args.get("ports", "")
    timing = int(args.get("timing", 4))
    profile = str(args.get("profile", "") or "").strip().lower()

    nmap_cmd = shutil.which("nmap")
    if not nmap_cmd:
        try:
            # Pinned codec: a `where.exe` path containing bytes invalid for the
            # inherited locale made the reader thread raise, result.stdout came
            # back None, and an installed nmap looked missing.
            result = run_text(["where.exe", "nmap"], timeout=10)
            if result.returncode == 0 and result.stdout:
                nmap_cmd = result.stdout.strip().split("\n")[0]
        except Exception:
            pass
    if not nmap_cmd:
        return "[!] nmap 未安装或不在 PATH 中。请确认 nmap 已安装并加入系统 PATH。"

    if profile:
        plan = build_nmap_plan(
            profile=profile,
            scan_type=str(scan_type or ""),
            ports=str(custom_ports or ""),
            timing=timing,
            prior_recon=getattr(getattr(agent, "session_state", None), "recon_data", {}),
        )
        privileged = nmap_has_raw_socket_access()
        cmd = build_nmap_command(nmap_cmd, target, plan, privileged=privileged)
        deescalated_note = (
            ""
            if privileged or plan.args == without_privileged_nmap_args(plan.args)
            else "[i] 非管理员权限运行：已跳过操作系统指纹识别（-O），SYN 扫描降级为 connect 扫描（-sT）。\n"
        )
    else:
        plan = None
        privileged = nmap_has_raw_socket_access()
        deescalated_note = ""
        cmd = [nmap_cmd, "-v" if scan_type == "full" else "-q", f"-T{max(0, min(5, timing))}"]
        if scan_type == "top_ports":
            cmd.extend(["--top-ports", "100", "-oX", "-"])
        elif scan_type == "syn":
            cmd.extend(["-sS" if privileged else "-sT", "-oX", "-"])
            if not privileged:
                deescalated_note = "[i] 非管理员权限运行：使用 connect 扫描（-sT）代替 SYN 扫描（-sS）。\n"
        elif scan_type == "tcp":
            cmd.extend(["-sT", "-oX", "-"])
        elif scan_type == "service":
            cmd.extend(["-sV", "-oX", "-"])
        elif scan_type == "os":
            if privileged:
                cmd.extend(["-O", "-oX", "-"])
            else:
                cmd.extend(["-sV", "-oX", "-"])
                deescalated_note = (
                    "[i] 非管理员权限运行：操作系统指纹识别（-O）不可用，改用服务探测（-sV）。\n"
                )
        elif scan_type == "vuln":
            cmd.extend(["--script", "vuln", "-oX", "-"])
        elif scan_type == "full":
            if privileged:
                cmd.extend(["-sS", "-O", "-sV", "--script", "default,safe", "-oX", "-"])
            else:
                cmd.extend(["-sT", "-sV", "--script", "default,safe", "-oX", "-"])
                deescalated_note = (
                    "[i] 非管理员权限运行：已跳过操作系统指纹识别（-O），"
                    "SYN 扫描降级为 connect 扫描（-sT）。\n"
                )
        else:
            cmd.extend(["-sV", "-oX", "-"])

        if custom_ports:
            cmd.extend(["-p", custom_ports])
        cmd.append(target)

    # ── ExecutionGate: per-request operator approval ─────────────────────
    # Round-8 finding R8-8: this was the one model-reachable spawn that never
    # asked. `gate.authorize` had exactly four sites -- shell_command,
    # runtime_diff_probe, python_execute and bg_launch -- while `nmap_scan` is
    # explicitly recommended by the prompt, is reachable by the model, and is
    # labelled model-reachable by `scripts/verify_execution_boundary.py`'s own
    # contract ("exactly those the ExecutionGate must gate").
    #
    # A schema-constrained argv is narrower than R8-1's hole, but it is not a
    # substitute for approval: what the operator approves here is not "which
    # flags" but "this host gets scanned". Placed after every in-process
    # refusal (scope, ports, reserved-IP) so a request that is going to be
    # refused anyway never reaches the human, and before the first
    # `_run_nmap_argv` call so nothing is spawned unapproved. In `full_access`
    # the gate approves without asking, exactly as it does for the other four.
    from vulnclaw.agent.exec_gate import GateRequest, get_execution_gate

    gate = get_execution_gate(getattr(agent, "config", None))
    outcome = await gate.authorize(
        GateRequest(
            kind="shell",
            display=shlex.join(cmd),
            cwd="",
            detail=(
                f"nmap {profile or scan_type} scan · target={target}"
                + (f" · ports={custom_ports}" if custom_ports else "")
            ),
        ),
        run_id=str(getattr(getattr(agent, "runtime", None), "run_id", "") or ""),
    )
    if not outcome.approved:
        return outcome.refusal_text("nmap_scan")

    try:
        kwargs: dict[str, Any] = {"timeout": 120}
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            kwargs["startupinfo"] = startupinfo
        result = await asyncio.to_thread(_bt._run_nmap_argv, cmd, **kwargs)
        if (
            result.returncode != 0
            and not result.stdout
            and nmap_failure_needs_deescalation(result.stderr or "")
        ):
            fallback_cmd = deescalate_nmap_argv(cmd)
            if fallback_cmd != cmd:
                fallback = await asyncio.to_thread(_bt._run_nmap_argv, fallback_cmd, **kwargs)
                if fallback.returncode == 0 or fallback.stdout:
                    result = fallback
                    deescalated_note = "[i] 权限错误后已使用非特权 nmap 参数重试。\n"
    except subprocess.TimeoutExpired:
        return "[!] nmap 扫描超时（120秒），请减少扫描范围或使用更快的 timing"
    except PermissionError:
        return "[!] nmap 执行被拒绝（权限不足）。Windows 请以管理员身份运行终端。"
    except Exception as e:
        return f"[!] nmap 执行错误: {e}"

    if result.returncode != 0 and not result.stdout:
        return f"[!] nmap 扫描失败（{result.returncode}）: {result.stderr[:500]}"
    output = result.stdout or result.stderr
    human_summary = parse_nmap_xml(output, target)
    structured = parse_nmap_xml_structured(output, target)
    if getattr(agent, "session_state", None) is not None:
        attach_network_scan_to_session(
            agent.session_state,
            structured,
            profile=profile or str(scan_type or "top_ports"),
            safe_probes=profile != "vuln",
        )
    if profile:
        network_summary = summarize_network_scan(structured)
        return f"{deescalated_note}{human_summary}\n\n{network_summary}"
    return f"{deescalated_note}{human_summary}"


def is_reserved_ip(ip: str) -> tuple[bool, str]:
    from vulnclaw.agent.builtin_tools import RESERVED_IP_RANGES

    try:
        import ipaddress

        addr = ipaddress.ip_address(ip)
        for start, end, desc in RESERVED_IP_RANGES:
            if ipaddress.ip_address(start) <= addr <= ipaddress.ip_address(end):
                return True, desc
        return False, ""
    except Exception:
        return False, ""


def validate_scan_target(target: str) -> str:
    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        if not ips:
            return ""
        ip = ips[0][4][0]
        is_reserved, reason = is_reserved_ip(ip)
        if is_reserved:
            return (
                f"\n\n⚠️ **警告：目标 {target} 解析到保留/内网地址 ({reason})\n"
                f"   IP: {ip}\n"
                f"   扫描此地址得到的结果不代表真实系统的安全状态。\n"
                f"   nmap 扫描结果中的端口信息可能与真实目标无关。**"
            )
    except Exception:
        pass
    return ""


def parse_nmap_xml(xml_output: str, target: str) -> str:
    if not xml_output or "<nmaprun" not in xml_output:
        lines = xml_output.strip().splitlines()[:80]
        return "nmap 原始输出:\n" + "\n".join(lines)

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        lines = xml_output.strip().splitlines()[:80]
        return "nmap 原始输出:\n" + "\n".join(lines)

    lines = [f"nmap 扫描结果 — {target}", "=" * 60]
    for host in root.findall(".//host"):
        hostname = host.find(".//hostname[@type='user']")
        addrs = [a.get("addr", "") for a in host.findall("address")]
        status = host.find("status")
        status_val = status.get("state", "unknown") if status is not None else "unknown"
        host_ip = addrs[0] if addrs else target
        reserved, reason = is_reserved_ip(host_ip)
        if reserved:
            host_str = (
                f"\n[主机] {host_ip} ⚠️ **保留地址 ({reason})，测试网络结果不代表真实目标安全状态**"
            )
        else:
            host_str = f"\n[主机] {host_ip}"
        if hostname is not None:
            host_str += f" ({hostname.get('name', '')})"
        host_str += f" — {status_val}"
        lines.append(host_str)

        for port in host.findall(".//port"):
            port_id = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            port_state = port.find("state")
            svc = port.find("service")
            state_val = port_state.get("state", "unknown") if port_state is not None else "unknown"
            svc_name = svc.get("name", "") if svc is not None else ""
            svc_product = svc.get("product", "") if svc is not None else ""
            svc_version = svc.get("version", "") if svc is not None else ""
            lines.append(
                f"  {proto.upper():5} {port_id}/{'s' if svc is not None and svc.get('tunnel') == 'ssl' else ''} "
                f"{state_val:8}{svc_name:15}{(svc_product + ' ' + svc_version).rstrip()}"
            )
            for script in port.findall("script"):
                lines.append(f"    | {script.get('id', '')}: {script.get('output', '')[:120]}")

    runstats = root.find(".//runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            elapsed = finished.get("elapsed", "")
            summary = finished.get("summary", "")
            lines.append(f"\n完成时间: {elapsed}s | {summary}")
    return "\n".join(lines) or f"nmap 扫描完成（无输出）: {target}"
