"""VulnClaw CLI main entry point with REPL and sub-commands."""

# ruff: noqa: E402

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, Optional


def _configure_windows_console() -> None:
    """Force UTF-8 console I/O on Windows for reliable Unicode output."""
    if sys.platform != "win32":
        return

    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    os.environ.setdefault("PYTHONUTF8", "1")

    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleCP(65001)
        kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass

    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


_configure_windows_console()

import typer
from rich.panel import Panel

from vulnclaw import __version__, headless
from vulnclaw.agent.constraint_policy import validate_action_constraints
from vulnclaw.agent.input_analysis import extract_task_constraints
from vulnclaw.cli import experience_ops

# === Stream Output Renderer ===
# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: S2 修复 — 共享辅助函数已移至 cli/_helpers.py。
from vulnclaw.cli._helpers import (
    TerminalStreamSink,
    _append_action_constraints,
    _append_cli_constraints_compat,
    _generate_report_for_target,
    _inject_local_challenge_hint,
    _make_solve_event_printer,
    _print_agent_output,
    _run_cli_orchestrated_task,
    console,
    err_console,
)
from vulnclaw.cli.manual import available_topics, render_manual
from vulnclaw.config.schema import ENGINE_CHOICES
from vulnclaw.config.settings import (  # noqa: F401 — RUNS_DIR kept as re-export/monkeypatch anchor
    RUNS_DIR,
    apply_provider_preset,
    list_providers,
    load_config,
    save_config,
    set_config_value,
)
from vulnclaw.config.token_provider import has_llm_credentials
from vulnclaw.utils.subprocess_text import run_text

# 以下四个名字被 ctf2/gcs 命令使用，但测试对 cli.main.<name> 打补丁
# （test_platform_command_handoff / test_predownload_attachments），而命令体在
# cli/commands_platform.py 里经 _from_main 于调用时解析——故保留在 main 命名空间。
from vulnclaw.ctf_platform.client import is_configured as ctf2_is_configured  # noqa: F401
from vulnclaw.ctf_platform.client import read_challenge as ctf2_read_challenge  # noqa: F401
from vulnclaw.gcs_platform.client import is_configured as gcs_is_configured  # noqa: F401
from vulnclaw.gcs_platform.client import exercise as gcs_exercise  # noqa: F401
from vulnclaw.i18n import _
from vulnclaw.target_state.store import (  # noqa: F401 — apply_target_state_to_agent kept as re-export/monkeypatch anchor
    apply_target_state_to_agent,
    clear_target_state,
    diff_target_state_snapshots,
    get_target_state_preview,
    list_target_snapshots,
    load_target_state,
    rollback_target_state,
)
from vulnclaw.task_service import (
    TaskCreateRequest,
    TaskOptions,
    prepare_task,
    run_task_action,
)


# ── 拆出的 REPL / 目标识别族（cli/repl.py）—— 以下名字原样 re-export ──────────
from vulnclaw.cli.repl import (  # noqa: F401 — re-export
    _EDIT_FLAGS,
    _CTF2_CHALLENGE_RE,
    _CTF2_PRACTICE_RE,
    _CTF2_UUID,
    _apply_local_path_constraints,
    _auto_save_recon_report,
    _ctf2_task_ref,
    _emit_competition_writeup,
    _emit_solve_report_if_completed,
    _extract_target_from_input,
    _has_actionable_target,
    _is_api_path_prose,
    _is_cited_target,
    _is_local_path_target,
    _localized_phase_label,
    _make_repl_prompt_session,
    _mined_target_for_session,
    _parse_edit_flags,
    _prepare_repl_target,
    _print_help,
    _print_op_result,
    _print_run_completion_summary,
    _print_status,
    _read_repl_line,
    _repl_experience,
    _repl_feedback,
    _repl_has_in_progress_run,
    _repl_last_run_finished,
    _repl_learn,
    _repl_no_auto,
    _repl_switch_language,
    _resolve_team_meta_from_gcs,
    _run_context_kwargs,
    _run_non_interactive,
    _run_repl,
    _run_repl_agent_call,
    _run_repl_command,
    _scope_option_kwargs,
    _should_auto_pentest,
    _should_switch_target,
    _target_after_agent_result,
    _validate_headless_choices,
)

# 鈹€鈹€ Sub-commands 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


app = typer.Typer(
    name="vulnclaw",
    help="VulnClaw - AI-powered penetration testing CLI (run 'vulnclaw tui' for the TUI workbench)",
    no_args_is_help=False,
    add_completion=False,
)

# ── Code sub-command group (local source-code scanning) ──────────────
from vulnclaw.cli.code import code_app  # noqa: E402

app.add_typer(code_app, name="code")

# ── Retest sub-command (A1: 复测已上报的结论 / finding_retests) ──────────────
from vulnclaw.cli.retest_cmd import retest_command  # noqa: E402

app.command("retest", help="复测一条已上报的 finding（A1）")(retest_command)

# ── Evidence maintenance sub-command group（缺口 1/2：GC 调度 + 解绑/重排暴露面）──
from vulnclaw.cli.evidence_cmd import evidence_app  # noqa: E402

app.add_typer(evidence_app, name="evidence")


@app.command()
def run(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    scope: str = typer.Option("full", help="Test scope: full, web, api, mobile"),
    output: Optional[str] = typer.Option(None, help="Output report file path"),
    # [新增] 2026-06-10 Nyaecho - TUI自然语言驱动: 允许通过 --prompt 传入自定义提示词覆盖自动生成的prompt
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom natural language prompt (overrides auto-generated prompt)"
    ),
    engine: Optional[str] = typer.Option(
        None,
        "--engine",
        help="Autonomous engine for this run: solve, team, or rounds",
    ),
    only_port: Optional[int] = typer.Option(
        None, "--only-port", help="Restrict testing to a single port"
    ),
    only_host: Optional[str] = typer.Option(
        None, "--only-host", help="Restrict testing to a single host"
    ),
    only_path: Optional[str] = typer.Option(
        None, "--only-path", help="Restrict testing to a single path"
    ),
    blocked_host: Optional[str] = typer.Option(
        None, "--blocked-host", help="Explicitly blocked host"
    ),
    blocked_path: Optional[str] = typer.Option(
        None, "--blocked-path", help="Explicitly blocked path"
    ),
    allow_actions: Optional[str] = typer.Option(
        None, "--allow-actions", help="Comma-separated allowed actions"
    ),
    block_actions: Optional[str] = typer.Option(
        None, "--block-actions", help="Comma-separated blocked actions"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(
        None, "--snapshot", help="Resume from a specific target snapshot id"
    ),
    # ── Headless / CI knobs ────────────────────────────────────────────
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Headless mode: zero prompts, structured output to the run directory, "
        "and a distinct exit code (see --fail-on). Intended for CI.",
    ),
    scan_mode: str = typer.Option(
        headless.DEFAULT_SCAN_MODE,
        "--scan-mode",
        help="Depth preset over the effort knobs: quick | standard | deep. "
        "Explicit --max-* flags override the preset.",
    ),
    fail_on: str = typer.Option(
        headless.DEFAULT_FAIL_ON,
        "--fail-on",
        help="Which finding class trips a nonzero exit: verified | any | never.",
    ),
    scope_mode: str = typer.Option(
        headless.DEFAULT_SCOPE_MODE,
        "--scope-mode",
        help="Scope selection recorded for the run: full (whole surface, current "
        "behaviour) | auto (diff-scope to changed code — consumed by the Target "
        "diff-scope model, #35; falls back to full until that lands).",
    ),
    max_steps: Optional[int] = typer.Option(
        None, "--max-steps", help="Override the scan-mode explore-step cap"
    ),
    max_directions: Optional[int] = typer.Option(
        None,
        "--max-directions",
        help="Deprecated compatibility option; model-led solve ignores research-direction limits",
    ),
    max_tool_rounds: Optional[int] = typer.Option(
        None, "--max-tool-rounds", help="Override the scan-mode tool-use compatibility budget"
    ),
    max_parallel: Optional[int] = typer.Option(
        None, "--max-parallel", help="Override the scan-mode fan-out cap (1 = single agent)"
    ),
    max_rounds: Optional[int] = typer.Option(
        None, "--max-rounds", help="Override the scan-mode legacy-engine round cap"
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(
        None, "--runs-dir", help="Run-directory root (overrides VULNCLAW_RUNS_DIR)"
    ),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(
        None, "--target-type", help="Override target type: local_repo, repo_url, web_url, domain, ip"
    ),
    mount: bool = typer.Option(
        False, "--mount", help="Use mount ingress mode for local repository targets"
    ),
    repair: bool = typer.Option(
        False, "--repair", help="Repair a corrupt run by rolling back to the last valid snapshot"
    ),
    force_fresh: bool = typer.Option(
        False, "--force-fresh", help="Start a fresh run without overwriting a corrupt one"
    ),
    no_import: bool = typer.Option(
        False, "--no-import", help="Read legacy target state without importing it into a run"
    ),
    stream: bool = typer.Option(
        False,
        "--stream",
        help="Emit newline-delimited JSON events (status/log/finding/complete) for the Rust TUI",
    ),
) -> None:
    """Run a full authorized pentest workflow.

    Interactive by default. Pass ``--non-interactive`` for a headless CI run: no
    prompts, a machine-readable ``summary.json`` in the run directory, and an
    exit code that lets a pipeline tell a clean scan (0) from a broken one (1)
    from one that confirmed a verified finding (2) or only candidates (3).
    Pass ``--stream`` to emit newline-delimited JSON events consumed by the
    Rust ratatui TUI (``vulnclaw tui``).
    """
    config = load_config()

    # A bad target / scan-mode / fail-on / scope-mode is a misconfiguration:
    # exit 1 (never a silent green run).
    if not target or not target.strip():
        err_console.print("[!] A non-empty target is required.")
        raise typer.Exit(headless.EXIT_ERROR)
    bad_choice = _validate_headless_choices(scan_mode, fail_on, scope_mode)
    if bad_choice is not None:
        err_console.print(f"[!] {bad_choice}")
        raise typer.Exit(headless.EXIT_ERROR)
    if not has_llm_credentials(config.llm):
        err_console.print("[!] Configure LLM credentials first (api_key or auth_mode).")
        raise typer.Exit(headless.EXIT_ERROR)
    if engine is not None and engine not in ENGINE_CHOICES:
        err_console.print(f"[!] --engine must be one of: {', '.join(ENGINE_CHOICES)}")
        raise typer.Exit(headless.EXIT_ERROR)

    profile = headless.resolve_scan_profile(
        config,
        scan_mode,
        max_steps=max_steps,
        max_directions=max_directions,
        max_tool_rounds=max_tool_rounds,
        max_parallel=max_parallel,
        max_rounds=max_rounds,
    )

    console.print(
        f"[*] Target: [bold]{target}[/] | Scope: [bold]{scope}[/] | "
        f"Mode: [bold]{profile.scan_mode}[/]"
        + (" | [bold]non-interactive[/]" if non_interactive else "")
    )

    run_context = _run_context_kwargs(
        run_name=run_name,
        resume_run_name=resume_run,
        runs_dir=runs_dir,
        additional_targets=additional_targets,
        target_type=target_type,
        mount=mount,
        repair=repair,
        force_fresh=force_fresh,
        no_import=no_import,
    )
    task_prompt = prompt if prompt else (
        f"Perform an authorized {scope} pentest against {target}. "
        "This target is in scope and explicitly authorized."
    )
    task_prompt = _inject_local_challenge_hint(task_prompt, target)
    task_prompt = _append_cli_constraints_compat(
        task_prompt, only_port, only_host, only_path, blocked_host, blocked_path
    )
    task_request = TaskCreateRequest(
        command="run",
        target=target,
        prompt=task_prompt,
        resume=resume,
        snapshot_id=snapshot,
        **run_context,
        options=TaskOptions(
            engine=engine,
            scope=scope,
            max_steps=profile.max_steps,
            max_directions=profile.max_directions,
            max_tool_rounds=profile.max_tool_rounds,
            max_parallel=profile.max_parallel,
            max_rounds=profile.max_rounds,
            **_scope_option_kwargs(locals()),
        ),
    )
    try:
        task = prepare_task(task_request)
    except ValueError as exc:
        err_console.print(f"[!] {exc}")
        raise typer.Exit(headless.EXIT_ERROR) from exc

    agent_state_holder: dict = {}
    classification_holder: dict = {}
    run_dir_holder: dict = {}
    stream_out = sys.stdout if stream else None

    async def _run():
        async def runner(agent, shared_config):
            # In headless mode suppress streaming thinking so nothing blocks on a TTY.
            if stream:
                from vulnclaw.cli._helpers import JsonlStreamSink

                sink = JsonlStreamSink(stream_out, shared_config.session.show_thinking)

                def on_event(kind: str, payload: dict) -> None:
                    if kind == "agent_step":
                        sink._emit({"type": "log", "message": f"turn {payload.get('step', '?')}"})
                    elif kind == "error":
                        sink._emit({"type": "log", "message": f"error: {payload.get('error', '')}"})
                    elif kind == "ask_user":
                        sink._emit({"type": "log", "message": f"? {payload.get('question', '')}"})
                    elif kind == "completed":
                        sink._emit({"type": "status", "status": "goal reached"})
                    elif kind == "no_path":
                        sink._emit({"type": "log", "message": f"no path: {payload.get('reason', '')}"})
            else:
                sink = (
                    None
                    if non_interactive
                    else TerminalStreamSink(console, shared_config.session.show_thinking)
                )
                on_event = None if non_interactive else _make_solve_event_printer(console)
            result = await run_task_action(
                agent,
                task,
                stream_sink=sink,
                on_event=on_event,
                on_step=lambda r, res: (
                    _print_agent_output(
                        f"[dim]Round {r}[/]: {res.output[:200]}...", shared_config
                    )
                    if res.output and not non_interactive
                    else None
                ),
            )
            agent_state = getattr(
                getattr(getattr(agent, "context", None), "state", None), "agent_state", None
            )
            if agent_state is not None:
                agent_state_holder["agent_state"] = agent_state.get_summary()
            classification_holder["classification"] = headless.classify_findings(
                getattr(agent, "session_state", None)
            )
            # Where the agent actually wrote its evidence (injected by the
            # orchestrator). _run_non_interactive co-locates report + summary
            # here so the reader resolves this run's own evidence tree.
            run_dir_holder["run_dir"] = str(getattr(agent, "run_dir", "") or "")
            return result

        result = await _run_cli_orchestrated_task(
            command="run",
            target=target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **run_context,
        )
        return result

    if non_interactive:
        _run_non_interactive(
            target=target,
            output=output,
            profile=profile,
            scan_mode=scan_mode,
            scope_mode=scope_mode,
            fail_on=fail_on,
            run_coro_factory=_run,
            classification_holder=classification_holder,
            run_dir_holder=run_dir_holder,
        )
        return

    orchestrated = asyncio.run(_run())

    if stream:
        from vulnclaw.cli._helpers import emit_complete_event

        findings: list[dict[str, Any]] = []
        agent_state = agent_state_holder.get("agent_state") or {}
        summary = (
            f"{'✅ goal reached' if agent_state.get('completed') else '⊘ not reached'}"
            f" — steps={agent_state.get('steps', 0)} evidence={agent_state.get('evidence', 0)}"
        )
        # Verified claims map onto the Rust TUI finding list.
        for idx, claim in enumerate(
            (agent_state.get("verified_claims") or [])[:50], start=1
        ):
            if isinstance(claim, dict):
                findings.append(
                    {
                        "id": claim.get("id") or f"v{idx:03d}",
                        "severity": "high",
                        "title": str(claim.get("claim") or "")[:200],
                        "target": target,
                    }
                )
        emit_complete_event(stream_out, summary=summary, findings=findings)
        return

    if agent_state_holder.get("agent_state"):
        agent_state = agent_state_holder["agent_state"]
        status = _("cli.goal_achieved") if agent_state.get("completed") else _("cli.goal_not_achieved")
        console.print(
            f"\n[bold]{status}[/bold] — steps={agent_state.get('steps', 0)} "
            f"evidence={agent_state.get('evidence', 0)} "
            f"tools={agent_state.get('tool_calls', 0)} "
            f"{_('cli.reason')}: {agent_state.get('complete_reason') or _('cli.reason_not_complete')}"
        )
    else:
        total_findings = orchestrated.summary["findings_count"]
        console.print(_("cli.pentest_finished", findings=total_findings))

    report_path = _generate_report_for_target(target, output_path=output)
    console.print(_("cli.report_generated", path=report_path))


def _typer_sentinel_types() -> tuple[type, ...]:
    """typer's ``OptionInfo``/``ArgumentInfo`` classes, when importable."""
    try:
        from typer.models import ArgumentInfo, OptionInfo

        return (OptionInfo, ArgumentInfo)
    except Exception:  # pragma: no cover - exotic typer builds
        return ()


def _is_typer_sentinel(value: Any) -> bool:
    """True for a typer parameter sentinel, without relying on the class NAME.

    Round-5 review (information level): this used to compare
    ``type(value).__name__`` against two strings, so a rename inside typer would
    blind the check and its tests at the same time — the sentinel would then be
    used as a real value and the failure would surface far away. The real classes
    are authoritative; the name comparison stays only as a fallback.
    """
    kinds = _typer_sentinel_types()
    if kinds and isinstance(value, kinds):
        return True
    return type(value).__name__ in {"OptionInfo", "ArgumentInfo"}


def _cli_value(value: Any, default: Any) -> Any:
    """Return a real value where a direct Python call left a typer sentinel.

    When a Typer command function is invoked directly from Python (as ``ctf2`` and
    ``gcs`` do when handing off to ``solve``), its un-passed parameters keep the
    ``OptionInfo``/``ArgumentInfo`` objects instead of the CLI defaults. Those
    sentinels are not merely wrong values -- they are **truthy**, so a
    ``if stream:`` branch takes the streaming path, and they stringify into
    nonsense when used as an override name. ``ctf2`` crashed outright on this
    (``TypeError: Value after * must be an iterable, not OptionInfo`` in
    ``build_targets``) while ``gcs`` had been patched to pass everything
    explicitly.
    """
    if _is_typer_sentinel(value):
        resolved = getattr(value, "default", None)
        return default if resolved is ... else resolved
    return value


def _signature_defaults(command: Any) -> dict[str, Any]:
    """The declared defaults of a Typer command's parameters.

    Unwraps the ``typer.Option``/``typer.Argument`` wrapper to reach the real
    default, and skips required parameters (``...``) — those must come from the
    caller, never from a fabricated value.
    """
    import inspect

    defaults: dict[str, Any] = {}
    try:
        parameters = inspect.signature(command).parameters
    except (TypeError, ValueError):  # pragma: no cover - Typer keeps the signature
        return defaults
    for name, param in parameters.items():
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        declared = getattr(param.default, "default", param.default)
        if declared is inspect.Parameter.empty or declared is ...:
            continue
        defaults[name] = declared
    return defaults


def _solve_defaults(**overrides: Any) -> dict[str, Any]:
    """Keyword arguments for calling :func:`solve` from Python.

    ``solve`` is a Typer command, so calling it directly leaves every un-passed
    parameter as its ``typer.Option`` object — truthy sentinels rather than the
    declared defaults (see :func:`_cli_value`). Every optional flag therefore has
    to be passed.

    Round-5 review (information level): the three hand-off call sites copied those
    values by hand (``max_directions=3``, ``max_tool_rounds=6``, ``model="auto"``…),
    so changing a default inside ``solve`` would have silently left the old value
    at the call site. They come from the command's own signature instead
    (``_SOLVE_DECLARED_DEFAULTS``), and callers override only what they mean to
    change.
    """
    merged = dict(_SOLVE_DECLARED_DEFAULTS)
    merged.update(overrides)
    return merged


@app.command()
def solve(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    goal: Optional[str] = typer.Option(
        None, "--goal", help="Success condition, e.g. 'capture the flag' / 'get a shell'"
    ),
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom task description (overrides auto-generated)"
    ),
    max_steps: int = typer.Option(
        240, "--max-steps", help="Runaway safety budget for autonomous turns (not a planned round count)"
    ),
    max_directions: int = typer.Option(
        3,
        "--max-directions",
        help="Deprecated compatibility option; model-led solve ignores research-direction limits",
    ),
    max_tool_rounds: int = typer.Option(
        6, "--max-tool-rounds", help="Compatibility option; model-led solve decides tool use per step"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(None, "--snapshot", help="Resume from a snapshot id"),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(None, "--target-type", help="Override target type"),
    mount: bool = typer.Option(False, "--mount", help="Use mount ingress mode"),
    repair: bool = typer.Option(False, "--repair", help="Repair a corrupt run"),
    force_fresh: bool = typer.Option(False, "--force-fresh", help="Start a fresh run"),
    no_import: bool = typer.Option(False, "--no-import", help="Do not import legacy state"),
    stream: bool = typer.Option(
        False, "--stream", help="Emit newline-delimited JSON events for the Rust TUI"
    ),
    writeup_dir: Optional[str] = typer.Option(
        None, "--writeup-dir", help="Generate a competition writeup into this directory on success"
    ),
    model: str = typer.Option(
        "auto",
        "--model",
        help=(
            "Model selection: 'auto' (route by challenge category/difficulty), "
            "'glm' (force glm-5.3), or 'ds' (force deepseek-v4-pro)"
        ),
    ),
) -> None:
    """Model-led solve loop; runs until goal, user input, no path, or safety cap."""
    config = load_config()
    if not has_llm_credentials(config.llm):
        err_console.print("[!] Configure LLM credentials first (api_key or auth_mode).")
        raise typer.Exit(1)

    resolved_goal = goal or _("cli.default_goal")
    task_prompt = prompt or _("cli.task_prompt", target=target, goal=resolved_goal)
    console.print(f"[*] Target: [bold]{target}[/] | Goal: [bold]{resolved_goal}[/]")

    holder: dict = {}
    stream_out = sys.stdout if stream else None

    async def _run():
        async def runner(agent, shared_config):
            if stream:
                from vulnclaw.cli._helpers import JsonlStreamSink

                sink = JsonlStreamSink(stream_out, shared_config.session.show_thinking)

                def on_event(kind: str, payload: dict) -> None:
                    if kind == "agent_step":
                        sink._emit({"type": "log", "message": f"turn {payload.get('step', '?')}"})
                    elif kind == "error":
                        sink._emit({"type": "log", "message": f"error: {payload.get('error', '')}"})
                    elif kind == "ask_user":
                        sink._emit({"type": "log", "message": f"? {payload.get('question', '')}"})
                    elif kind == "completed":
                        sink._emit({"type": "status", "status": "goal reached"})
            else:
                sink = TerminalStreamSink(console, shared_config.session.show_thinking)
                on_event = None
            result = await agent.solve(
                task_prompt,
                target=target,
                goal=resolved_goal,
                max_steps=max_steps,
                max_tool_rounds=max_tool_rounds,
                stream_sink=sink,
                on_event=on_event,
            )
            holder["agent_state"] = agent.context.state.agent_state.get_summary()
            holder["agent"] = agent
            return result

        return await _run_cli_orchestrated_task(
            command="solve",
            target=target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            model_override=model,
            **_run_context_kwargs(
                run_name=run_name,
                resume_run_name=resume_run,
                runs_dir=runs_dir,
                additional_targets=additional_targets,
                target_type=target_type,
                mount=mount,
                repair=repair,
                force_fresh=force_fresh,
                no_import=no_import,
            ),
        )

    asyncio.run(_run())
    agent_state = holder.get("agent_state") or {}
    if stream:
        from vulnclaw.cli._helpers import emit_complete_event

        findings: list[dict[str, Any]] = []
        for idx, claim in enumerate((agent_state.get("verified_claims") or [])[:50], start=1):
            if isinstance(claim, dict):
                findings.append(
                    {
                        "id": claim.get("id") or f"v{idx:03d}",
                        "severity": "high",
                        "title": str(claim.get("claim") or "")[:200],
                        "target": target,
                    }
                )
        summary = (
            f"{'✅ goal reached' if agent_state.get('completed') else '⊘ not reached'}"
            f" — steps={agent_state.get('steps', 0)} evidence={agent_state.get('evidence', 0)}"
        )
        emit_complete_event(stream_out, summary=summary, findings=findings)
        return

    status = _("cli.goal_achieved") if agent_state.get("completed") else _("cli.goal_not_achieved")
    console.print(
        f"\n[bold]{status}[/bold] — steps={agent_state.get('steps', 0)} "
        f"evidence={agent_state.get('evidence', 0)} "
        f"tools={agent_state.get('tool_calls', 0)} "
        f"{_('cli.reason')}: {agent_state.get('complete_reason') or _('cli.reason_not_complete')}"
    )
    if agent_state.get("completed"):
        # ``holder`` stores only the summary for status printing, so generate
        # from the live session state captured on the orchestrated agent below.
        live_agent = holder.get("agent")
        if live_agent is not None:
            _emit_solve_report_if_completed(live_agent, config)
            if writeup_dir:
                _emit_competition_writeup(live_agent, config, writeup_dir)


#: Declared defaults of :func:`solve`, captured ONCE from the function Typer
#: registered. Deliberately not re-read at call time: tests (and any wrapper)
#: replace ``main.solve`` with a stub, and inspecting the module global then sees
#: the stub's ``**kwargs`` signature and silently yields no defaults at all.
_SOLVE_DECLARED_DEFAULTS: dict[str, Any] = _signature_defaults(solve)


# ── 平台交接族（cli/commands_platform.py）—— 注册 + 原样 re-export ──────────
from vulnclaw.cli.commands_platform import (  # noqa: F401 — re-export
    _adapter_for_ref,
    _challenge_sort_key,
    _competition_download,
    _competition_latency,
    _competition_plan,
    _competition_solve,
    _platform_challenges,
    _predownload_challenge_attachments,
    competition,
    ctf2,
    gcs,
)

app.command("ctf2")(ctf2)
app.command("gcs")(gcs)
app.command("competition")(competition)


@app.command("go")
def go(
    target: str = typer.Argument(..., help="Target: URL, host, or local challenge id"),
    goal: Optional[str] = typer.Option(
        None, "--goal", "-g", help="Success condition (default: capture the flag)"
    ),
    model: str = typer.Option(
        "auto", "--model", "-m", help="Model: auto/glm/ds (default: config)"
    ),
    type: str = typer.Option(
        None, "--type", "-t",
        help="Challenge type hint (crypto/web/rev/misc) — auto-selects tools",
    ),
) -> None:
    """极简解题入口：只传目标，其余自动推断。

    等效于 ``solve`` 但隐藏所有长参数：
        vulnclaw go http://target
        vulnclaw go 10742 --type crypto
        vulnclaw go target --goal "get a shell" --model ds
    """
    resolved_goal = goal or _("cli.default_goal")
    # 显式 --goal 优先; 仅在用户没给 goal 时才用 type 预设
    if type and not goal:
        type_goal = {
            "crypto": "solve the crypto challenge and output the flag",
            "web": "find and exploit the web vulnerability, capture the flag",
            "rev": "reverse the binary and recover the flag",
            "misc": "solve the forensics/misc challenge and output the flag",
            "pwn": "exploit the binary and get the flag",
        }.get(type.lower())
        if type_goal:
            resolved_goal = type_goal
    console.print(
        f"[*] go: target={target} | goal={resolved_goal} | model={model}"
        + (f" | type={type}" if type else "")
    )
    solve(
        **_solve_defaults(
            target=target,
            goal=resolved_goal,
            max_steps=240,
            resume=True,
            model=model,
        )
    )


@app.command()
def persistent(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    rounds: int = typer.Option(
        0, "--rounds", "-r", help="Rounds per cycle (0=use config, default 100)"
    ),
    cycles: int = typer.Option(0, "--cycles", "-c", help="Max cycles (0=use config, default 10)"),
    no_report: bool = typer.Option(
        False, "--no-report", help="Disable auto report after each cycle"
    ),
    # [新增] 2026-06-10 Nyaecho - TUI自然语言驱动: 允许通过 --prompt 传入自定义提示词覆盖自动生成的prompt
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom natural language prompt (overrides auto-generated prompt)"
    ),
    only_port: Optional[int] = typer.Option(
        None, "--only-port", help="Restrict testing to a single port"
    ),
    only_host: Optional[str] = typer.Option(
        None, "--only-host", help="Restrict testing to a single host"
    ),
    only_path: Optional[str] = typer.Option(
        None, "--only-path", help="Restrict testing to a single path"
    ),
    blocked_host: Optional[str] = typer.Option(
        None, "--blocked-host", help="Explicitly blocked host"
    ),
    blocked_path: Optional[str] = typer.Option(
        None, "--blocked-path", help="Explicitly blocked path"
    ),
    allow_actions: Optional[str] = typer.Option(
        None, "--allow-actions", help="Comma-separated allowed actions"
    ),
    block_actions: Optional[str] = typer.Option(
        None, "--block-actions", help="Comma-separated blocked actions"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(
        None, "--snapshot", help="Resume from a specific target snapshot id"
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(None, "--target-type", help="Override target type"),
    mount: bool = typer.Option(False, "--mount", help="Use mount ingress mode"),
    repair: bool = typer.Option(False, "--repair", help="Repair a corrupt run"),
    force_fresh: bool = typer.Option(False, "--force-fresh", help="Start a fresh run"),
    no_import: bool = typer.Option(False, "--no-import", help="Do not import legacy state"),
) -> None:
    """Run a persistent authorized pentest across multiple cycles."""
    from vulnclaw.agent.core import PersistentCycleResult

    config = load_config()
    if not has_llm_credentials(config.llm):
        err_console.print("[!] Configure LLM credentials first (api_key or auth_mode).")
        raise typer.Exit(1)

    # Resolve parameters (CLI override -> config defaults)
    rounds_per_cycle = rounds if rounds > 0 else config.session.persistent_rounds_per_cycle
    max_cycles = cycles if cycles > 0 else config.session.persistent_max_cycles
    auto_report = config.session.persistent_auto_report and not no_report

    console.print(
        Panel(
            f"Target: [bold]{target}[/]\n"
            f"Rounds per cycle: [bold]{rounds_per_cycle}[/]\n"
            f"Max cycles: [bold]{max_cycles}[/] {'(unlimited)' if max_cycles == 0 else ''}\n"
            f"Auto report: {'[green]on[/]' if auto_report else '[yellow]off[/]'}\n"
            f"Max total rounds: [bold]{rounds_per_cycle * max_cycles if max_cycles > 0 else 'unlimited'}[/]",
            title="Persistent Pentest",
            border_style="cyan",
        )
    )

    run_context = _run_context_kwargs(
        run_name=run_name,
        resume_run_name=resume_run,
        runs_dir=runs_dir,
        additional_targets=additional_targets,
        target_type=target_type,
        mount=mount,
        repair=repair,
        force_fresh=force_fresh,
        no_import=no_import,
    )
    task_request = TaskCreateRequest(
        command="persistent",
        target=target,
        prompt=prompt,
        resume=resume,
        snapshot_id=snapshot,
        **run_context,
        options=TaskOptions(
            rounds_per_cycle=rounds_per_cycle,
            max_cycles=max_cycles,
            auto_report=auto_report,
            **_scope_option_kwargs(locals()),
        ),
    )
    try:
        task = prepare_task(task_request)
    except ValueError as exc:
        err_console.print(f"[!] {exc}")
        raise typer.Exit(1) from exc

    # Track stats
    all_cycle_results: list[PersistentCycleResult] = []
    interrupted = False

    def _on_cycle_step(round_num: int, cycle_num: int, result) -> None:
        """Real-time output for each step within a cycle."""
        console.print(f"[dim]-- Cycle {cycle_num} | Round {round_num} --[/]")
        # TerminalStreamSink 已实时流式显示，回调不重复打印
        console.print()

    def _on_cycle_complete(cycle_num: int, cycle_result: PersistentCycleResult) -> None:
        """Callback after each cycle completes."""
        all_cycle_results.append(cycle_result)
        console.print(
            Panel(
                f"Cycle {cycle_num} completed\n"
                f"   Steps executed: {cycle_result.total_steps}\n"
                f"   Total findings: {cycle_result.total_findings}\n"
                f"   New findings: {cycle_result.new_findings}\n"
                f"   Report: {cycle_result.report_path or 'not generated'}",
                title=f"Cycle {cycle_num} Result",
                border_style="green" if cycle_result.new_findings == 0 else "red",
            )
        )
        console.print()

    async def _run():
        async def runner(agent, _config):
            sink = TerminalStreamSink(console, _config.session.show_thinking)
            return await run_task_action(
                agent,
                task,
                on_cycle_step=_on_cycle_step,
                on_cycle_complete=_on_cycle_complete,
                stream_sink=sink,
            )

        return await _run_cli_orchestrated_task(
            command="persistent",
            target=target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **run_context,
        )

    try:
        orchestrated = asyncio.run(_run())
    except KeyboardInterrupt:
        interrupted = True
        console.print("\n[!] User interrupted persistent pentest")
        orchestrated = None

    summary = (
        orchestrated.summary
        if orchestrated
        else {
            "findings_count": 0,
            "executed_steps": 0,
        }
    )
    total_findings = summary["findings_count"]
    total_steps = summary["executed_steps"]
    completed_cycles = len(all_cycle_results)

    console.print()
    console.print(
        Panel(
            f"{'Interrupted by user' if interrupted else 'Testing completed'}\n\n"
            f"  Completed cycles: [bold]{completed_cycles}[/]\n"
            f"  Steps executed: [bold]{total_steps}[/]\n"
            f"  Findings: [bold]{total_findings}[/]",
            title="Persistent Pentest Summary",
            border_style="red" if total_findings > 0 else "green",
        )
    )

    if auto_report and all_cycle_results:
        console.print("\n[bold]Cycle Reports[/]:")
        for cr in all_cycle_results:
            if cr.report_path and "failed" not in str(cr.report_path).lower():
                console.print(f"  Cycle {cr.cycle_num}: {cr.report_path}")


@app.command()
def recon(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    # [新增] 2026-06-10 Nyaecho - TUI自然语言驱动: 允许通过 --prompt 传入自定义提示词覆盖自动生成的prompt
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom natural language prompt (overrides auto-generated prompt)"
    ),
    only_port: Optional[int] = typer.Option(
        None, "--only-port", help="Restrict testing to a single port"
    ),
    only_host: Optional[str] = typer.Option(
        None, "--only-host", help="Restrict testing to a single host"
    ),
    only_path: Optional[str] = typer.Option(
        None, "--only-path", help="Restrict testing to a single path"
    ),
    blocked_host: Optional[str] = typer.Option(
        None, "--blocked-host", help="Explicitly blocked host"
    ),
    blocked_path: Optional[str] = typer.Option(
        None, "--blocked-path", help="Explicitly blocked path"
    ),
    allow_actions: Optional[str] = typer.Option(
        None, "--allow-actions", help="Comma-separated allowed actions"
    ),
    block_actions: Optional[str] = typer.Option(
        None, "--block-actions", help="Comma-separated blocked actions"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(
        None, "--snapshot", help="Resume from a specific target snapshot id"
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(None, "--target-type", help="Override target type"),
    mount: bool = typer.Option(False, "--mount", help="Use mount ingress mode"),
    repair: bool = typer.Option(False, "--repair", help="Repair a corrupt run"),
    force_fresh: bool = typer.Option(False, "--force-fresh", help="Start a fresh run"),
    no_import: bool = typer.Option(False, "--no-import", help="Do not import legacy state"),
    stream: bool = typer.Option(
        False, "--stream", help="Emit newline-delimited JSON events for the Rust TUI"
    ),
) -> None:
    """Run reconnaissance only."""
    run_context = _run_context_kwargs(
        run_name=run_name,
        resume_run_name=resume_run,
        runs_dir=runs_dir,
        additional_targets=additional_targets,
        target_type=target_type,
        mount=mount,
        repair=repair,
        force_fresh=force_fresh,
        no_import=no_import,
    )
    task_request = TaskCreateRequest(
        command="recon",
        target=target,
        prompt=prompt,
        resume=resume,
        snapshot_id=snapshot,
        **run_context,
        options=TaskOptions(**_scope_option_kwargs(locals())),
    )
    try:
        task = prepare_task(task_request)
    except ValueError as exc:
        err_console.print(f"[!] {exc}")
        raise typer.Exit(1) from exc

    async def _run():
        async def runner(agent, _config):
            if stream:
                from vulnclaw.cli._helpers import JsonlStreamSink

                sink = JsonlStreamSink(sys.stdout, _config.session.show_thinking)
            else:
                sink = TerminalStreamSink(console, _config.session.show_thinking)
            # TerminalStreamSink 已实时流式显示，不重复 console.print
            return await run_task_action(agent, task, stream_sink=sink)

        await _run_cli_orchestrated_task(
            command="recon",
            target=target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **run_context,
        )

    asyncio.run(_run())
    if stream:
        from vulnclaw.cli._helpers import emit_complete_event

        emit_complete_event(sys.stdout, summary="recon done", findings=[])


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    ports: Optional[str] = typer.Option(None, help="Port range, e.g. 80,443,8080"),
    # [新增] 2026-06-10 Nyaecho - TUI自然语言驱动: 允许通过 --prompt 传入自定义提示词覆盖自动生成的prompt
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom natural language prompt (overrides auto-generated prompt)"
    ),
    only_port: Optional[int] = typer.Option(
        None, "--only-port", help="Restrict testing to a single port"
    ),
    only_host: Optional[str] = typer.Option(
        None, "--only-host", help="Restrict testing to a single host"
    ),
    only_path: Optional[str] = typer.Option(
        None, "--only-path", help="Restrict testing to a single path"
    ),
    blocked_host: Optional[str] = typer.Option(
        None, "--blocked-host", help="Explicitly blocked host"
    ),
    blocked_path: Optional[str] = typer.Option(
        None, "--blocked-path", help="Explicitly blocked path"
    ),
    allow_actions: Optional[str] = typer.Option(
        None, "--allow-actions", help="Comma-separated allowed actions"
    ),
    block_actions: Optional[str] = typer.Option(
        None, "--block-actions", help="Comma-separated blocked actions"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(
        None, "--snapshot", help="Resume from a specific target snapshot id"
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(None, "--target-type", help="Override target type"),
    mount: bool = typer.Option(False, "--mount", help="Use mount ingress mode"),
    repair: bool = typer.Option(False, "--repair", help="Repair a corrupt run"),
    force_fresh: bool = typer.Option(False, "--force-fresh", help="Start a fresh run"),
    no_import: bool = typer.Option(False, "--no-import", help="Do not import legacy state"),
    stream: bool = typer.Option(
        False, "--stream", help="Emit newline-delimited JSON events for the Rust TUI"
    ),
) -> None:
    """Run vulnerability scanning only."""
    run_context = _run_context_kwargs(
        run_name=run_name,
        resume_run_name=resume_run,
        runs_dir=runs_dir,
        additional_targets=additional_targets,
        target_type=target_type,
        mount=mount,
        repair=repair,
        force_fresh=force_fresh,
        no_import=no_import,
    )
    task_request = TaskCreateRequest(
        command="scan",
        target=target,
        prompt=prompt,
        resume=resume,
        snapshot_id=snapshot,
        **run_context,
        options=TaskOptions(
            ports=ports,
            **_scope_option_kwargs(locals()),
        ),
    )
    try:
        task = prepare_task(task_request)
    except ValueError as exc:
        err_console.print(f"[!] {exc}")
        raise typer.Exit(1) from exc

    async def _run():
        async def runner(agent, _config):
            if stream:
                from vulnclaw.cli._helpers import JsonlStreamSink

                sink = JsonlStreamSink(sys.stdout, _config.session.show_thinking)
            else:
                sink = TerminalStreamSink(console, _config.session.show_thinking)
            # TerminalStreamSink 已实时流式显示，不重复 console.print
            return await run_task_action(agent, task, stream_sink=sink)

        await _run_cli_orchestrated_task(
            command="scan",
            target=target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **run_context,
        )

    asyncio.run(_run())
    if stream:
        from vulnclaw.cli._helpers import emit_complete_event

        emit_complete_event(sys.stdout, summary="scan done", findings=[])


@app.command("network-scan")
def network_scan(
    target: Optional[str] = typer.Argument(
        None, help="目标主机/IP/CIDR，默认使用当前连接的 Wi-Fi 子网"
    ),
    profile: str = typer.Option(
        "adaptive",
        "--profile",
        help="网络扫描画像：adaptive、fast、thorough、stealth",
    ),
    ports: Optional[str] = typer.Option(None, "--ports", help="端口范围，如 80,443,1-1000"),
    max_rounds: int = typer.Option(
        0, "--max-rounds", help="Agent 后续跟进轮数（0=使用配置默认值）"
    ),
    parallel_agents: int = typer.Option(
        1,
        "--parallel-agents",
        min=1,
        help="在已发现的攻击面上并行派生的子 Agent 数量（1 表示不启用并行）",
    ),
    parallel_depth: int = typer.Option(
        1,
        "--parallel-depth",
        min=1,
        help="子 Agent 攻击面发现的有界波次数",
    ),
    worker_rounds: int = typer.Option(
        3,
        "--worker-rounds",
        min=1,
        help="每个子 Agent worker 的执行轮数",
    ),
    surface_limit: int = typer.Option(
        20,
        "--surface-limit",
        min=1,
        help="用于子 Agent 并行派生的最大攻击面数量",
    ),
    safe_probes: bool = typer.Option(
        True,
        "--safe-probes/--no-safe-probes",
        help="nmap 扫描后默认仅执行非破坏性的验证探测",
    ),
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom natural language prompt (overrides auto-generated prompt)"
    ),
    only_port: Optional[int] = typer.Option(
        None, "--only-port", help="Restrict testing to a single port"
    ),
    only_host: Optional[str] = typer.Option(
        None, "--only-host", help="Restrict testing to a single host"
    ),
    blocked_host: Optional[str] = typer.Option(
        None, "--blocked-host", help="Explicitly blocked host"
    ),
    allow_actions: Optional[str] = typer.Option(
        None, "--allow-actions", help="Comma-separated allowed actions"
    ),
    block_actions: Optional[str] = typer.Option(
        None, "--block-actions", help="Comma-separated blocked actions"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(
        None, "--snapshot", help="Resume from a specific target snapshot id"
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(None, "--target-type", help="Override target type"),
    mount: bool = typer.Option(False, "--mount", help="Use mount ingress mode"),
    repair: bool = typer.Option(False, "--repair", help="Repair a corrupt run"),
    force_fresh: bool = typer.Option(False, "--force-fresh", help="Start a fresh run"),
    no_import: bool = typer.Option(False, "--no-import", help="Do not import legacy state"),
    stream: bool = typer.Option(
        False, "--stream", help="Emit newline-delimited JSON events for the Rust TUI"
    ),
) -> None:
    """运行基于 nmap 的网络扫描，并对薄弱环节进行跟进。"""
    normalized_profile = profile.strip().lower()
    if normalized_profile not in {"adaptive", "fast", "thorough", "stealth"}:
        err_console.print(f"[!] {_('cli.invalid_profile')}")
        raise typer.Exit(1)

    detected_wifi = None
    scan_target = target.strip() if target else ""
    if not scan_target:
        from vulnclaw.agent.network_scan import detect_connected_wifi_target

        try:
            detected_wifi = detect_connected_wifi_target()
            scan_target = detected_wifi.cidr
        except RuntimeError as exc:
            err_console.print(f"[!] {exc}")
            raise typer.Exit(1)

    port_hint = f" limited to ports {ports}" if ports else ""
    follow_up = (
        "Then prioritize weak links and perform safe, non-destructive verification probes only."
        if safe_probes
        else "Then summarize weak links without running follow-up probes."
    )
    task_prompt = prompt if prompt else (
        f"Perform an authorized {normalized_profile} network scan against {scan_target}{port_hint}. "
        f"Use the nmap_scan tool with profile={normalized_profile}"
        f"{f' and ports={ports}' if ports else ''}. "
        f"{follow_up} Record open services and candidate weak-link findings in target state. "
        "Do not brute force credentials, run destructive payloads, or perform post-exploitation."
    )
    task_prompt = _append_cli_constraints_compat(
        task_prompt,
        only_port,
        only_host,
        None,
        blocked_host,
        None,
    )

    effective_allow_actions = allow_actions
    effective_block_actions = block_actions
    if safe_probes and not allow_actions and not block_actions:
        effective_allow_actions = "recon,scan"
    task_prompt = _append_action_constraints(
        task_prompt, effective_allow_actions, effective_block_actions
    )

    violation = validate_action_constraints("scan", extract_task_constraints(task_prompt))
    if violation is not None:
        err_console.print(f"[!] {violation}")
        raise typer.Exit(1)

    console.print(
        Panel(
            f"目标: [bold]{scan_target}[/]\n"
            + (
                f"Wi-Fi 接口: [bold]{detected_wifi.interface}[/] ({detected_wifi.address})\n"
                if detected_wifi
                else ""
            )
            +
            f"画像: [bold]{normalized_profile}[/]\n"
            f"端口: [bold]{ports or '画像默认'}[/]\n"
            f"跟进策略: [bold]{'安全探测' if safe_probes else '仅摘要'}[/]\n"
            f"并行 Agent 数: [bold]{parallel_agents}[/]"
            + (
                f"（深度 {parallel_depth}，每个 worker {worker_rounds} 轮）"
                if parallel_agents > 1
                else ""
            ),
            title="网络扫描",
            border_style="cyan",
        )
    )

    async def _run():
        async def runner(agent, _config):
            if stream:
                from vulnclaw.cli._helpers import JsonlStreamSink

                sink = JsonlStreamSink(sys.stdout, _config.session.show_thinking)
            else:
                sink = TerminalStreamSink(console, _config.session.show_thinking)
            rounds = max_rounds if max_rounds > 0 else _config.session.max_rounds
            if parallel_agents > 1:
                from vulnclaw.agent.parallel_agents import run_parallel_pentest

                def agent_factory():
                    return agent.__class__(_config, getattr(agent, "mcp_manager", None))

                return await run_parallel_pentest(
                    agent,
                    agent_factory=agent_factory,
                    user_input=task_prompt,
                    target=scan_target,
                    discovery_rounds=rounds,
                    worker_rounds=worker_rounds,
                    max_agents=parallel_agents,
                    max_depth=parallel_depth,
                    surface_limit=surface_limit,
                    stream_sink=sink,
                )
            return await agent.auto_pentest(
                task_prompt,
                target=scan_target,
                max_rounds=rounds,
                stream_sink=sink,
            )

        await _run_cli_orchestrated_task(
            command="network-scan",
            target=scan_target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **_run_context_kwargs(
                run_name=run_name,
                resume_run_name=resume_run,
                runs_dir=runs_dir,
                additional_targets=additional_targets,
                target_type=target_type,
                mount=mount,
                repair=repair,
                force_fresh=force_fresh,
                no_import=no_import,
            ),
        )

    asyncio.run(_run())
    if stream:
        from vulnclaw.cli._helpers import emit_complete_event

        emit_complete_event(sys.stdout, summary="network scan done", findings=[])


@app.command()
def exploit(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    cve: Optional[str] = typer.Option(None, help="Specific CVE to exploit"),
    cmd: str = typer.Option("id", help="Command to execute for verification"),
    # [新增] 2026-06-10 Nyaecho - TUI自然语言驱动: 允许通过 --prompt 传入自定义提示词覆盖自动生成的prompt
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom natural language prompt (overrides auto-generated prompt)"
    ),
    only_port: Optional[int] = typer.Option(
        None, "--only-port", help="Restrict testing to a single port"
    ),
    only_host: Optional[str] = typer.Option(
        None, "--only-host", help="Restrict testing to a single host"
    ),
    only_path: Optional[str] = typer.Option(
        None, "--only-path", help="Restrict testing to a single path"
    ),
    blocked_host: Optional[str] = typer.Option(
        None, "--blocked-host", help="Explicitly blocked host"
    ),
    blocked_path: Optional[str] = typer.Option(
        None, "--blocked-path", help="Explicitly blocked path"
    ),
    allow_actions: Optional[str] = typer.Option(
        None, "--allow-actions", help="Comma-separated allowed actions"
    ),
    block_actions: Optional[str] = typer.Option(
        None, "--block-actions", help="Comma-separated blocked actions"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(
        None, "--snapshot", help="Resume from a specific target snapshot id"
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(None, "--target-type", help="Override target type"),
    mount: bool = typer.Option(False, "--mount", help="Use mount ingress mode"),
    repair: bool = typer.Option(False, "--repair", help="Repair a corrupt run"),
    force_fresh: bool = typer.Option(False, "--force-fresh", help="Start a fresh run"),
    no_import: bool = typer.Option(False, "--no-import", help="Do not import legacy state"),
    stream: bool = typer.Option(
        False, "--stream", help="Emit newline-delimited JSON events for the Rust TUI"
    ),
) -> None:
    """Run exploitation only."""
    run_context = _run_context_kwargs(
        run_name=run_name,
        resume_run_name=resume_run,
        runs_dir=runs_dir,
        additional_targets=additional_targets,
        target_type=target_type,
        mount=mount,
        repair=repair,
        force_fresh=force_fresh,
        no_import=no_import,
    )
    task_request = TaskCreateRequest(
        command="exploit",
        target=target,
        prompt=prompt,
        resume=resume,
        snapshot_id=snapshot,
        **run_context,
        options=TaskOptions(
            cve=cve,
            cmd=cmd,
            **_scope_option_kwargs(locals()),
        ),
    )
    try:
        task = prepare_task(task_request)
    except ValueError as exc:
        err_console.print(f"[!] {exc}")
        raise typer.Exit(1) from exc

    async def _run():
        async def runner(agent, _config):
            if stream:
                from vulnclaw.cli._helpers import JsonlStreamSink

                sink = JsonlStreamSink(sys.stdout, _config.session.show_thinking)
            else:
                sink = TerminalStreamSink(console, _config.session.show_thinking)
            # TerminalStreamSink 已实时流式显示，不重复 console.print
            return await run_task_action(agent, task, stream_sink=sink)

        await _run_cli_orchestrated_task(
            command="exploit",
            target=target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **run_context,
        )

    asyncio.run(_run())
    if stream:
        from vulnclaw.cli._helpers import emit_complete_event

        emit_complete_event(sys.stdout, summary="exploit done", findings=[])


@app.command()
def report(
    session: str = typer.Argument(
        ..., help="Path to session JSON file or target when used with --target"
    ),
    target_mode: bool = typer.Option(
        False, "--target", help="Interpret argument as target and generate report from target state"
    ),
    run_dir: Optional[str] = typer.Option(
        None,
        "--run-dir",
        help=(
            "Run directory holding this session's evidence "
            "(default: resolved from the session's run_id)"
        ),
    ),
    pdf: bool = typer.Option(
        False, "--pdf", help="Also export the report to PDF (requires the vulnclaw[pdf] extra)"
    ),
    pdf_out: str = typer.Option(
        "", "--pdf-out", help="PDF output path (default: the report path with a .pdf suffix)"
    ),
) -> None:
    """Generate a report from a session file or target state."""
    # Report bodies call _() for localized text; initialize i18n from the
    # configured language so non-interactive runs honor session.language
    # instead of falling back to the process locale (VULNCLAW_LANG/LANG).
    from vulnclaw.i18n import init_i18n

    report_config = load_config()
    init_i18n(config=report_config)

    if target_mode:
        from vulnclaw.report.generator import generate_report_from_target_state

        state = load_target_state(session)
        if not state:
            err_console.print(f"[!] Target state not found: {session}")
            raise typer.Exit(1)
        report_path = generate_report_from_target_state(state, run_dir=run_dir)
    else:
        from vulnclaw.report.generator import generate_report_from_file

        report_path = generate_report_from_file(session, run_dir=run_dir)
    console.print(f"[+] Report generated: {report_path}")

    if pdf:
        from pathlib import Path

        from vulnclaw.report.pdf_exporter import export_pdf

        out = Path(pdf_out) if pdf_out else Path(report_path).with_suffix(".pdf")
        try:
            markdown = Path(report_path).read_text(encoding="utf-8")
            export_pdf(markdown, out, title="VulnClaw Report")
        except RuntimeError as exc:
            err_console.print(f"[!] {exc}")
            raise typer.Exit(1) from exc
        console.print(f"[+] PDF exported: {out}")


def _print_cli_manual(topic: Optional[str], output_format: str) -> None:
    """Print the packaged CLI manual, normalizing user-facing errors."""
    try:
        console.out(render_manual(output_format, topic), end="")
    except ValueError as exc:
        err_console.print(f"[!] {exc}")
        err_console.print(f"    Available topics: {', '.join(available_topics())}")
        raise typer.Exit(1) from exc


@app.command("manual")
def manual_command(
    topic: Optional[str] = typer.Argument(
        None, help="Optional manual topic, e.g. run, solve, network-scan, config"
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text, markdown, man",
    ),
) -> None:
    """Print the full VulnClaw CLI manual."""
    _print_cli_manual(topic, output_format)


@app.command("man")
def man_command(
    topic: Optional[str] = typer.Argument(
        None, help="Optional manual topic, e.g. run, solve, network-scan, config"
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text, markdown, man",
    ),
) -> None:
    """Alias for 'vulnclaw manual'."""
    _print_cli_manual(topic, output_format)


# 鈹€鈹€ Config sub-command group 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

config_app = typer.Typer(help="Manage configuration")
app.add_typer(config_app, name="config")


@config_app.callback(invoke_without_command=True)
def config_root(ctx: typer.Context) -> None:
    """Open the interactive config editor when no subcommand is provided."""
    if ctx.resilient_parsing or ctx.invoked_subcommand is not None:
        return
    from vulnclaw.cli.tui import run_config_tui

    run_config_tui()


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key in dot notation, e.g. llm.api_key"),
    value: str = typer.Argument(..., help="Config value"),
) -> None:
    """Set a config value."""
    set_config_value(key, value)
    console.print(
        f"[+] Set {key} = {'***' if 'key' in key.lower() or 'pass' in key.lower() else value}"
    )


@config_app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Config key in dot notation"),
) -> None:
    """Get a config value.

    The traversal lives in :func:`get_config_value`, because ``config get`` is not the
    only reader and the shapes differ: ``platforms.ctf2.enabled`` and
    ``mcp.servers.chrome-devtools.enabled`` sit in dicts / ``extra="allow"`` sections,
    which a bare ``getattr`` chain cannot reach. A missing key is an operator error,
    not a crash: report it and exit non-zero.
    """
    from vulnclaw.config.settings import get_config_value

    try:
        value = get_config_value(key)
    except KeyError:
        err_console.print(f"[red]未知配置键：{key}[/red]")
        raise typer.Exit(2) from None
    value = value if not hasattr(value, "model_dump") else value.model_dump()
    if isinstance(value, str) and ("key" in key.lower() or "pass" in key.lower()):
        value = value[:8] + "..." if len(value) > 8 else "***"
    console.print(f"{key} = {value}")


@config_app.command("list")
def config_list() -> None:
    """List all configuration values."""
    import yaml as _yaml

    config = load_config()
    raw = config.model_dump(mode="json")
    console.print(_yaml.dump(raw, default_flow_style=False, allow_unicode=True))


@config_app.command("provider")
def config_provider(
    name: Optional[str] = typer.Argument(
        None, help="Provider name to switch to (e.g. minimax, deepseek)"
    ),
    list_all: bool = typer.Option(False, "--list", "-l", help="List all available providers"),
) -> None:
    """View or switch the configured LLM provider."""
    if list_all or name is None:
        providers = list_providers()
        current_config = load_config()
        current_provider = current_config.llm.provider

        console.print("[bold]Available LLM Providers[/]")
        console.print()
        for p in providers:
            is_current = p["provider"] == current_provider
            marker = " [green](current)[/]" if is_current else ""
            console.print(f"  [bold cyan]{p['provider']}[/]{marker}")
            console.print(f"    Label: {p['label']}")
            console.print(f"    URL:  [dim]{p['base_url']}[/]")
            console.print(f"    Model: [dim]{p['default_model']}[/]")
            console.print()
        console.print("[dim]Use vulnclaw config provider <name> to switch providers.[/]")
        return

    # Switch provider
    from vulnclaw.config.schema import PROVIDER_PRESETS, LLMProvider

    # Validate provider name
    try:
        provider_enum = LLMProvider(name.lower())
    except ValueError:
        console.print(f"[!] Unknown provider: [bold]{name}[/]")
        console.print(f"    Available: {', '.join(p.value for p in LLMProvider)}")
        console.print("    Tip: use [bold]custom[/] for a manual base_url and model.")
        raise typer.Exit(1)

    config = load_config()
    config = apply_provider_preset(config, name.lower())
    save_config(config)

    preset = PROVIDER_PRESETS.get(provider_enum, {})
    label = preset.get("label", name)
    console.print(f"[+] Switched LLM provider to [bold cyan]{label}[/]")
    console.print(f"    Base URL: [dim]{config.llm.base_url}[/]")
    console.print(f"    Model:    [dim]{config.llm.model}[/]")

    if not has_llm_credentials(config.llm):
        console.print()
        console.print(
            "[yellow]Set credentials first: [bold]vulnclaw config set llm.api_key <your-key>[/] "
            "or configure keyless auth (llm.auth_mode = env/file/command/wif)[/]"
        )


@config_app.command("model")
def config_model(
    name: Optional[str] = typer.Argument(
        None, help="Model alias: zhipu | ds (shallow), or bare"
    ),
    level: Optional[str] = typer.Argument(
        None, help="Thinking level: low | high | max (default: low)"
    ),
    deep: bool = typer.Option(
        False, "--deep", "-d", help="Use the provider's deeper model (ds -> pro)"
    ),
) -> None:
    """快速切换模型厂商 + API key + 思考档位。

    用法:
        vulnclaw config model                 # 显示当前
        vulnclaw config model zhipu           # zhipu glm-5.3 + thinking=low + zhipu key
        vulnclaw config model zhipu high      # zhipu glm-5.3 + thinking=high
        vulnclaw config model ds              # deepseek-flash + thinking=low + ds key
        vulnclaw config model ds --deep       # deepseek-v4-pro + thinking=low
        vulnclaw config model ds --deep max   # deepseek-v4-pro + thinking=max
    """
    if name is None:
        llm = load_config().llm
        console.print(f"[bold]当前模型:[/] {llm.provider} / {llm.model}")
        console.print(f"    thinking_disabled: {llm.thinking_disabled}")
        console.print(f"    reasoning_effort: {getattr(llm, 'reasoning_effort', '')}")
        console.print(
            "[dim]切换: vulnclaw config model <zhipu|ds> [low|high|max] [--deep][/]"
        )
        return

    # 解析 provider 和是否 deep
    provider = name.strip().lower()
    if provider not in {"zhipu", "ds"}:
        console.print(f"[!] 未知模型别名: {provider} (支持: zhipu | ds)")
        raise typer.Exit(1)

    # 解析 thinking 档位
    thinking = (level or "low").strip().lower()
    if thinking not in {"low", "high", "max"}:
        console.print(f"[!] thinking 档位必须是 low/high/max, 得到: {thinking}")
        raise typer.Exit(1)

    # 模型映射
    _MODEL_MAP = {
        "zhipu": {
            "shallow": "glm-5.3",
            "deep": "glm-5.3",  # zhipu 只有 glm-5.3, 深浅靠 thinking 档位
            "base_url": "https://open.bigmodel.cn/api/paas/v4",
        },
        "ds": {
            "shallow": "deepseek-flash",
            "deep": "deepseek-v4-pro",
            "base_url": "https://api.deepseek.com/v1",
        },
    }
    m = _MODEL_MAP[provider]
    model = m["deep"] if deep else m["shallow"]

    config = load_config()
    llm = config.llm
    prev_provider = llm.provider
    llm.provider = provider
    llm.model = model
    llm.base_url = m["base_url"]
    # thinking: 档位 low/high/max; zhipu 用 extra_body, deepseek 忽略
    llm.thinking_disabled = False
    llm.reasoning_effort = thinking
    # 切换 API key(从 provider_keys 读, 缺失则保留当前)
    keys = getattr(llm, "provider_keys", {}) or {}
    if provider in keys and keys[provider]:
        llm.api_key = keys[provider]
        # key_pool() 优先用 api_keys 池, 不同步会导致旧厂商 key 继续生效。
        # 换厂商时旧池子全是旧厂商 key, 直接替换; 同厂商重跑则只把目标 key
        # 提到首位, 保住手动配置的多 key 轮换池。
        pool = [k.strip() for k in (llm.api_keys or []) if k and k.strip()]
        new_key = keys[provider].strip()
        if prev_provider != provider or not pool:
            llm.api_keys = [new_key]
        else:
            llm.api_keys = [new_key] + [k for k in pool if k != new_key]
    save_config(config)

    console.print(
        f"[+] 已切换: [bold cyan]{provider}[/] / [bold]{model}[/] "
        f"thinking=[bold]{thinking}[/]"
    )
    console.print(f"    base_url: {llm.base_url}")
    if provider in keys and keys[provider]:
        console.print(f"    api_key: {llm.api_key[:8]}...")
    else:
        console.print(
            f"[yellow]    provider_keys 里没有 {provider} 的 key, 保持当前 api_key. "
            f"用 `vulnclaw config set llm.provider_keys.{provider} <key>` 配置.[/]"
        )


# 鈹€鈹€ Init command 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


@app.command()
def init() -> None:
    """Initialize VulnClaw config."""
    from vulnclaw.config.settings import ensure_dirs

    ensure_dirs()

    config = load_config()
    save_config(config)
    console.print(_("cli.init.config_created"))
    console.print(_("cli.init.dirs_initialized"))
    console.print(_("cli.init.dir_sessions"))
    console.print(_("cli.init.dir_kb"))
    console.print(_("cli.init.dir_skills"))
    console.print()
    console.print(_("cli.init.next_steps"))
    console.print(_("cli.init.step_provider"))
    console.print(_("cli.init.step_api_key"))
    console.print(_("cli.init.step_cli"))
    console.print(_("cli.init.step_tui"))


# 鈹€鈹€ Login / Logout commands 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


@app.command()
def login(
    proxy_url: Optional[str] = typer.Option(
        None,
        "--proxy-url",
        help="External OpenAI-compatible proxy base_url (disables the built-in one)",
    ),
    no_browser: bool = typer.Option(
        False, "--no-browser", help="Print the URL instead of opening a browser"
    ),
    set_default: bool = typer.Option(
        True, "--set-default/--no-set-default", help="Set llm.auth_mode=oauth on success"
    ),
) -> None:
    """Sign in with your ChatGPT subscription (Codex "Sign in with ChatGPT").

    Opens the ChatGPT consent page in your browser, stores the resulting
    refreshable token, and enables the built-in proxy that bridges
    chat.completions to the ChatGPT backend — so VulnClaw just works afterwards.

    ⚠️ This reuses OpenAI's first-party Codex OAuth client. Using a ChatGPT
    subscription through a non-official client may violate OpenAI's Terms of
    Service and can get your account restricted. You proceed at your own risk.
    """
    from vulnclaw.config.token_provider import (
        CHATGPT_CLIENT_ID,
        CHATGPT_TOKEN_URL,
        OAuthError,
        perform_chatgpt_login,
    )

    llm = load_config().llm

    err_console.print(
        "[yellow][!] Sign in with ChatGPT reuses OpenAI's first-party Codex OAuth "
        "client. Using a ChatGPT subscription through a non-official client may "
        "violate OpenAI's Terms of Service and can get your account restricted. "
        "You are proceeding at your own risk.[/]"
    )
    try:
        bundle = perform_chatgpt_login(open_browser=not no_browser)
    except OAuthError as exc:
        err_console.print(f"[!] ChatGPT sign-in failed: {exc}")
        raise typer.Exit(1)

    # Wire config so resolve/refresh works against the Codex token endpoint.
    set_config_value("llm.oauth_token_url", CHATGPT_TOKEN_URL)
    set_config_value("llm.oauth_client_id", CHATGPT_CLIENT_ID)
    if set_default:
        set_config_value("llm.auth_mode", "oauth")
    # The ChatGPT backend serves its own model family — gpt-4o won't work.
    if (llm.model or "").lower() in ("", "gpt-4o", "gpt-5", "gpt-5-codex"):
        set_config_value("llm.model", "gpt-5.5")

    if proxy_url:
        # User supplied an external proxy: use it, disable the built-in one.
        set_config_value("llm.base_url", proxy_url.rstrip("/"))
        set_config_value("llm.chatgpt_auto_proxy", "false")
    else:
        # Default: built-in proxy auto-starts on demand — zero setup.
        set_config_value("llm.chatgpt_auto_proxy", "true")

    tok = bundle.get("access_token", "")
    masked = (tok[:6] + "…" + tok[-4:]) if len(tok) > 12 else "(received)"
    console.print("[green]Signed in with ChatGPT.[/]")
    console.print(f"  Access token: [dim]{masked}[/]  (refreshes automatically)")
    if bundle.get("account_id"):
        console.print(f"  Account id: [dim]{bundle['account_id']}[/]")
    console.print()
    if proxy_url:
        console.print(f"  base_url set to external proxy: [dim]{proxy_url.rstrip('/')}[/]")
    else:
        console.print(
            "  [green]Built-in ChatGPT proxy enabled — it starts automatically.[/]\n"
            "  [dim]No external proxy needed. The bridge to OpenAI's ChatGPT backend "
            "is experimental; if a call fails, the error shows the backend response "
            "so you can adjust llm.model or the VULNCLAW_CHATGPT_* env vars.[/]"
        )
    console.print("  Run [bold]vulnclaw[/] to start.")


@app.command()
def logout() -> None:
    """Remove stored OAuth tokens (browser sign-in)."""
    from vulnclaw.config.token_provider import logout_oauth

    if logout_oauth():
        console.print("[green]Signed out — stored OAuth tokens removed.[/]")
    else:
        console.print("[yellow]No stored OAuth tokens to remove.[/]")


# 鈹€鈹€ Doctor command 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


@app.command()
def doctor() -> None:
    """Inspect the VulnClaw runtime environment."""
    import shutil

    # 修改者: Nyaecho
    # 修改时间: 2026-07-08
    # 修改原因: V6 修复 — 从 mcp/diagnostics 导入，消除 CLI→Web 依赖。
    from vulnclaw.mcp.diagnostics import get_mcp_diagnostics

    console.print("[bold]VulnClaw Environment Check[/]")
    console.print()

    # Check Python
    console.print(f"  Python: [green]{sys.version.split()[0]}[/]")

    # Check Node.js
    node_path = shutil.which("node")
    if node_path:
        import subprocess

        try:
            # Pinned codec: without it the inherited locale decodes the child's
            # output, and an undecodable byte leaves stdout as None -- so this
            # printed a bare "[green]None[/]" or crashed on .strip().
            result = run_text([node_path, "--version"], timeout=5)
            console.print(f"  Node.js: [green]{(result.stdout or '').strip()}[/]")
        except Exception:
            console.print("  Node.js: [yellow]check failed[/]")
    else:
        console.print("  Node.js: [red]not installed[/] (required for some MCP services)")

    # Check npx
    npx_path = shutil.which("npx")
    console.print(
        f"  npx: [{'green' if npx_path else 'red'}]{'installed' if npx_path else 'missing'}[/]"
    )

    # Check uvx
    uvx_path = shutil.which("uvx")
    console.print(
        f"  uvx: [{'green' if uvx_path else 'yellow'}]{'installed' if uvx_path else 'missing'}[/]"
    )

    # Check nmap
    nmap_path = shutil.which("nmap")
    console.print(
        f"  nmap: [{'green' if nmap_path else 'yellow'}]{'installed' if nmap_path else 'optional/missing'}[/]"
    )

    # Check config
    config = load_config()
    console.print()
    console.print("[bold]LLM Config[/]:")
    has_key = has_llm_credentials(config.llm)
    auth_mode = (config.llm.auth_mode or "static").lower()
    console.print(f"  Provider: [bold cyan]{config.llm.provider}[/]")
    console.print(f"  Auth Mode: [bold]{auth_mode}[/]")
    cred_label = "configured" if has_key else "not set"
    console.print(
        f"  Credentials: [{'green' if has_key else 'red'}]{cred_label}[/]"
    )
    console.print(f"  Base URL: [dim]{config.llm.base_url}[/]")
    console.print(f"  Model: [dim]{config.llm.model}[/]")

    # Check MCP servers
    console.print()
    console.print("[bold]MCP Services[/]:")
    mcp_diag = get_mcp_diagnostics()
    console.print(f"  Registered: [bold]{mcp_diag.total_services}[/] services")
    console.print(f"  Tools: [bold]{mcp_diag.tool_count}[/] exposed")

    for item in mcp_diag.services:
        status = "[green]enabled[/]" if item.enabled else "[dim]disabled[/]"
        priority_label = {0: "P0", 1: "P1", 2: "P2"}.get(item.priority, "??")
        running = "[green]running[/]" if item.running else "[yellow]registered[/]"
        capability = "[green]exec[/]" if item.can_execute else "[yellow]schema-only[/]"
        console.print(
            f"  {item.name}: {status} [{priority_label}] {running} mode={item.execution_mode} {capability} tools={item.tool_count}"
        )
        if item.error:
            label = item.last_error_type or "error"
            console.print(f"    [red]{label}[/]: {item.error}")

    console.print(
        "[dim]doctor shows MCP registration state and exposed tools. fetch/memory run in local mode; most other services are still placeholders.[/]"
    )
    console.print(
        "[yellow]python_execute is a high-risk experimental capability. It is not a strong sandbox; use it only in authorized or controlled environments.[/]"
    )
    console.print(
        "[dim]The knowledge-base update flow is live; retrieval enhancements can continue independently.[/]"
    )

    console.print()
    if has_key:
        console.print("[green]Environment ready. Run [bold]vulnclaw[/] to start.[/]")
    else:
        console.print(
            "[yellow]Set credentials first: [bold]vulnclaw config set llm.api_key <key>[/] "
            "or keyless auth (llm.auth_mode = env/file/command/wif)[/]"
        )


# 鈹€鈹€ KB command 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

kb_app = typer.Typer(help="Security knowledge base commands")
app.add_typer(kb_app, name="kb")

experience_app = typer.Typer(help="Review distilled cross-session experience lessons")
app.add_typer(experience_app, name="experience")

target_state_app = typer.Typer(help="Manage target history state")
app.add_typer(target_state_app, name="target-state")

plugins_app = typer.Typer(help="Inspect and run vulnerability detection plugins")
app.add_typer(plugins_app, name="plugins")


def _parse_kv_options(pairs: Optional[list[str]]) -> dict[str, object]:
    """把 --option key=value（可重复）解析为 dict，value 优先按 JSON 解析。"""
    import json as _json

    options: dict[str, object] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise typer.BadParameter(f"Expected key=value, got: {pair}")
        key, _, raw = pair.partition("=")
        key = key.strip()
        raw = raw.strip()
        try:
            options[key] = _json.loads(raw)
        except (ValueError, TypeError):
            options[key] = raw
    return options


@plugins_app.command("list")
def plugins_list(
    stage: Optional[str] = typer.Option(None, "--stage", help="Filter by stage"),
    tag: Optional[str] = typer.Option(None, "--tag", help="Filter by tag"),
) -> None:
    """List registered detection plugins."""
    from rich.table import Table

    from vulnclaw.plugins import registry

    plugin_classes = registry.list()
    if stage:
        try:
            plugin_classes = registry.by_stage(stage)
        except ValueError:
            err_console.print(f"[!] Unknown stage: {stage}")
            raise typer.Exit(1) from None
    if tag:
        tag_set = {p.plugin_id for p in registry.by_tag(tag)}
        plugin_classes = [p for p in plugin_classes if p.plugin_id in tag_set]

    if not plugin_classes:
        console.print("[yellow]No plugins match the filter.[/yellow]")
        return

    table = Table(title="VulnClaw Plugins", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("Stages")
    table.add_column("Risk")
    table.add_column("Destructive", justify="center")
    for plugin_cls in sorted(plugin_classes, key=lambda p: p.plugin_id):
        meta = plugin_cls.metadata()
        table.add_row(
            meta["plugin_id"],
            meta["name"],
            ", ".join(meta["stages"]),
            meta["default_risk"],
            "⚠️" if meta["destructive"] else "-",
        )
    console.print(table)


@plugins_app.command("info")
def plugins_info(plugin_id: str = typer.Argument(..., help="Plugin id")) -> None:
    """Show full metadata for a single plugin."""
    import json as _json

    from vulnclaw.plugins import registry

    plugin_cls = registry.get(plugin_id)
    if plugin_cls is None:
        err_console.print(f"[!] Plugin not found: {plugin_id}")
        raise typer.Exit(1)
    console.print_json(_json.dumps(plugin_cls.metadata(), ensure_ascii=False))


@plugins_app.command("run")
def plugins_run(
    plugin_id: str = typer.Argument(..., help="Plugin id to run"),
    target: str = typer.Option("", "--target", help="Target host/IP/URL"),
    stage: str = typer.Option("discovery", "--stage", help="Plugin stage"),
    option: Optional[list[str]] = typer.Option(
        None, "--option", "-o", help="Plugin option key=value (repeatable, value parsed as JSON)"
    ),
    input_file: Optional[str] = typer.Option(
        None, "--input", help="JSON file merged into plugin options"
    ),
    allow_destructive: bool = typer.Option(
        False, "--allow-destructive", help="Permit destructive plugins"
    ),
    session_file: Optional[str] = typer.Option(
        None, "--session", help="Merge findings into this SessionState JSON and save it"
    ),
    as_json: bool = typer.Option(False, "--json", help="Print the raw PluginResult as JSON"),
) -> None:
    """Run a plugin against supplied data (builtin plugins only analyze provided input)."""
    import json as _json
    from pathlib import Path

    from rich.table import Table

    from vulnclaw.plugins import PluginContext, PluginStage, create_builtin_runtime
    from vulnclaw.plugins.integration import merge_plugin_results_into_session

    try:
        stage_value = PluginStage(stage)
    except ValueError:
        err_console.print(f"[!] Unknown stage: {stage}")
        raise typer.Exit(1) from None

    options = _parse_kv_options(option)
    if input_file:
        path = Path(input_file)
        if not path.exists():
            err_console.print(f"[!] Input file not found: {input_file}")
            raise typer.Exit(1)
        try:
            payload = _json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            err_console.print(f"[!] Failed to read input file: {exc}")
            raise typer.Exit(1) from None
        if isinstance(payload, dict):
            options.update(payload)
        else:
            options["input"] = payload

    config = load_config()
    runtime = create_builtin_runtime(config)
    context = PluginContext(
        target=target,
        stage=stage_value,
        options=options,
        allow_destructive=allow_destructive,
    )

    result = asyncio.run(runtime.execute(plugin_id, context))

    if as_json:
        console.print_json(result.model_dump_json())
    else:
        if result.skipped:
            console.print(f"[yellow]⊘ Skipped[/yellow] ({result.error_type}): {result.error}")
        elif result.error:
            console.print(f"[red]✗ Error[/red] ({result.error_type}): {result.error}")
        for message in result.messages:
            console.print(f"  [dim]{message}[/dim]")
        if result.findings:
            table = Table(title=f"{plugin_id} findings", show_lines=True)
            table.add_column("Risk", style="magenta", no_wrap=True)
            table.add_column("Title")
            table.add_column("Type")
            table.add_column("Confidence", justify="right")
            for finding in result.findings:
                table.add_row(
                    finding.risk.value,
                    finding.title,
                    finding.vuln_type or "-",
                    f"{finding.confidence:.2f}",
                )
            console.print(table)
        elif not result.error:
            console.print("[green]✓[/green] Plugin ran; no findings.")

    if session_file:
        session_path = Path(session_file)
        from vulnclaw.agent.context import SessionState

        session = SessionState.load(session_path) if session_path.exists() else SessionState()
        added = merge_plugin_results_into_session(session, result)
        session.save(session_path)
        console.print(f"[+] Merged {added} finding(s) into {session_file}")


@kb_app.command("update")
def kb_update() -> None:
    """Update the knowledge base."""
    console.print("[*] Updating knowledge base...")
    from vulnclaw.kb.store import KnowledgeStore
    from vulnclaw.kb.updater import seed_knowledge_base

    store = KnowledgeStore()
    before_stats = store.get_stats()
    seed_knowledge_base(store)
    after_stats = store.get_stats()

    before_total = sum(before_stats.values())
    after_total = sum(after_stats.values())
    delta = after_total - before_total
    category_summary = ", ".join(f"{cat}={count}" for cat, count in sorted(after_stats.items()))

    console.print(f"[+] Knowledge base updated: +{delta} entries")
    console.print(f"    Categories: {category_summary or 'empty'}")


@kb_app.command("status")
def kb_status() -> None:
    """Show the knowledge base retrieval backend status."""
    from vulnclaw.kb.retriever import KnowledgeRetriever, RetrieverStatus
    from vulnclaw.kb.store import KnowledgeStore

    store = KnowledgeStore()
    retriever = KnowledgeRetriever(store=store)
    status = retriever.get_status()
    detail = retriever.get_status_detail()
    stats = store.get_stats()
    total = sum(stats.values())
    category_summary = ", ".join(f"{cat}={count}" for cat, count in sorted(stats.items()))

    if status == RetrieverStatus.CHROMADB_ACTIVE:
        line = f"[green]{_('cli.kb_active')}[/green]"
    elif status == RetrieverStatus.KEYWORD_FALLBACK:
        line = f"[yellow]{_('cli.kb_fallback')}[/yellow]"
    else:
        line = f"[red]{_('cli.kb_disabled')}[/red]"

    console.print(
        Panel(
            f"{line}\n"
            f"Backend: [bold]{status.value}[/]\n"
            f"Detail: {detail or 'n/a'}\n"
            f"Entries: [bold]{total}[/] ({category_summary or 'empty'})\n"
            f"{_('cli.kb_semantic_hint')}",
            title="KB Status",
            border_style="cyan",
        )
    )


@app.command("learn")
def learn(
    run_name: str = typer.Argument(..., help="Completed run name to distill into pending lessons"),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
) -> None:
    """Distill an existing run on demand (for reruns and backfill)."""

    _emit_op_result(
        experience_ops.distill_run(run_name, config=load_config(), runs_dir=runs_dir)
    )


@app.command("feedback")
def feedback(
    run: str = typer.Argument(..., help="Completed run name"),
    rating: int = typer.Option(
        ..., "--rating", "-r", help="Operator rating from 1 (poor) to 5 (excellent)"
    ),
    notes: str = typer.Option(..., "--notes", "-n", help="Operator notes for lesson distillation"),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
) -> None:
    """Attach or update an operator assessment for a completed run."""

    _emit_op_result(
        experience_ops.save_run_feedback(
            run, rating=rating, notes=notes, config=load_config(), runs_dir=runs_dir
        )
    )


def _emit_op_result(result: "experience_ops.OpResult") -> None:
    """Print a shared-op result, routing failures to typer.Exit(1)."""
    if result.ok:
        console.print(result.renderable)
        return
    err_console.print(result.renderable)
    raise typer.Exit(1)


@experience_app.command("list")
@experience_app.command("review")
def experience_list() -> None:
    """List lessons awaiting human review."""
    _emit_op_result(experience_ops.render_pending_lessons())


@experience_app.command("show")
def experience_show(lesson_id: str = typer.Argument(..., help="Lesson id")) -> None:
    """Show full lesson text and evidence provenance."""
    _emit_op_result(experience_ops.render_lesson(lesson_id))


@experience_app.command("approve")
def experience_approve(lesson_id: str = typer.Argument(..., help="Lesson id")) -> None:
    """Approve a lesson so future matching runs may retrieve it."""
    _emit_op_result(experience_ops.set_lesson_status(lesson_id, "approved"))


@experience_app.command("reject")
def experience_reject(lesson_id: str = typer.Argument(..., help="Lesson id")) -> None:
    """Reject a lesson so it cannot influence future runs."""
    _emit_op_result(experience_ops.set_lesson_status(lesson_id, "rejected"))


@experience_app.command("edit")
def experience_edit(
    lesson_id: str = typer.Argument(..., help="Lesson id"),
    context: Optional[str] = typer.Option(None, "--context", help="Replacement retrieval context"),
    lesson_text: Optional[str] = typer.Option(
        None, "--lesson", help="Replacement transferable instruction"
    ),
) -> None:
    """Amend context and/or lesson text without changing provenance or status."""
    _emit_op_result(
        experience_ops.edit_lesson(lesson_id, context=context, lesson=lesson_text)
    )


@target_state_app.command("list")
def target_state_list(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
) -> None:
    """List target snapshots."""
    snapshots = list_target_snapshots(target)
    if not snapshots:
        console.print(f"[-] No snapshots found for: {target}")
        raise typer.Exit(1)

    console.print(f"[bold]Target snapshots[/]: {target}")
    for item in snapshots[:20]:
        console.print(
            f"  {item['snapshot_id']} | v{item.get('schema_version', 1)} | {item['last_command']} | "
            f"steps={item['executed_steps']} verified={item['verified_findings']} pending={item['pending_findings']}"
        )


@target_state_app.command("preview")
def target_state_preview_cmd(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    snapshot_id: Optional[str] = typer.Option(
        None, "--snapshot", help="Preview a specific snapshot id"
    ),
) -> None:
    """Show a resume preview for the target state."""
    preview = get_target_state_preview(target, snapshot_id=snapshot_id)
    if not preview:
        console.print(f"[-] No target state found: {target}")
        raise typer.Exit(1)

    console.print(
        Panel(
            f"Target: [bold]{preview['target']}[/]\n"
            f"Schema: [bold]v{preview['schema_version']}[/]\n"
            f"Phase: [bold]{preview['phase'] or 'unknown'}[/]\n"
            f"Resume strategy: [bold]{preview['resume_strategy'] or 'none'}[/]\n"
            f"Reason: {preview['resume_reason'] or 'n/a'}\n"
            f"Findings: {preview['verified_count']} verified / {preview['pending_count']} pending / {preview['findings_count']} total",
            title="Target Preview",
            border_style="cyan",
        )
    )

    if preview.get("priority_targets"):
        console.print("[bold]Priority targets[/]:")
        for item in preview["priority_targets"][:5]:
            console.print(f"  - {item}")
    if preview.get("priority_recon_assets"):
        console.print("[bold]Priority recon assets[/]:")
        for item in preview["priority_recon_assets"][:5]:
            console.print(f"  - {item}")
    if preview.get("next_actions"):
        console.print("[bold]Next actions[/]:")
        for item in preview["next_actions"][:5]:
            console.print(f"  - {item}")


@target_state_app.command("diff")
def target_state_diff_cmd(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    from_snapshot_id: str = typer.Argument(..., help="Base snapshot id"),
    to_snapshot_id: Optional[str] = typer.Option(
        None, "--to", help="Compare against another snapshot or current state"
    ),
) -> None:
    """Show differences between two target-state snapshots."""
    diff = diff_target_state_snapshots(target, from_snapshot_id, to_snapshot_id=to_snapshot_id)
    if not diff:
        console.print(f"[-] Unable to diff target state: {target}")
        raise typer.Exit(1)

    console.print(
        Panel(
            f"Target: [bold]{diff['target']}[/]\n"
            f"From: [bold]{diff['from_snapshot_id']}[/] -> To: [bold]{diff['to_snapshot_id']}[/]\n"
            f"Schema: v{diff['schema_version_from']} -> v{diff['schema_version_to']}\n"
            f"Resume strategy: {diff['resume_strategy_from'] or 'none'} -> {diff['resume_strategy_to'] or 'none'}",
            title="Target Diff",
            border_style="magenta",
        )
    )

    for title, items in (
        ("Added findings", diff.get("added_findings", [])),
        ("Removed findings", diff.get("removed_findings", [])),
        ("Updated findings", diff.get("updated_findings", [])),
        ("Added recon assets", diff.get("added_recon_assets", [])),
        ("Removed recon assets", diff.get("removed_recon_assets", [])),
        ("Added steps", diff.get("added_steps", [])),
        ("Removed steps", diff.get("removed_steps", [])),
        ("Added notes", diff.get("added_notes", [])),
        ("Removed notes", diff.get("removed_notes", [])),
    ):
        if items:
            console.print(f"[bold]{title}[/]:")
            for item in items[:10]:
                console.print(f"  - {item}")


@target_state_app.command("rollback")
def target_state_rollback_cmd(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    snapshot_id: str = typer.Argument(..., help="Snapshot id to restore"),
) -> None:
    """Rollback target state to a snapshot."""
    path = rollback_target_state(target, snapshot_id)
    if not path:
        console.print(f"[-] Snapshot not found: {snapshot_id}")
        raise typer.Exit(1)
    console.print(f"[+] Rolled back target state: {target}")
    console.print(f"    Snapshot: {snapshot_id}")


@target_state_app.command("clear")
def target_state_clear_cmd(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
) -> None:
    """Clear target state."""
    ok = clear_target_state(target)
    if not ok:
        console.print(f"[-] No target state found: {target}")
        raise typer.Exit(1)
    console.print(f"[+] Cleared target state: {target}")




@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        help="Show version and exit.",
        is_eager=True,
    ),
    show_manual: bool = typer.Option(
        False,
        "--man",
        "--manual",
        help="Show the full CLI manual and exit.",
        is_eager=True,
    ),
    resume_run_name: Optional[str] = typer.Option(
        None,
        "--resume",
        help="Resume an exact saved run by run name.",
    ),
    runs_dir: Optional[str] = typer.Option(
        None,
        "--runs-dir",
        help="Run-directory root for --resume.",
    ),
    repair: bool = typer.Option(
        False,
        "--repair",
        help="Repair a corrupt run by rolling back to the last valid snapshot.",
    ),
) -> None:
    """Open the classic CLI/REPL by default."""
    if version:
        console.print(__version__)
        raise typer.Exit()
    if show_manual:
        _print_cli_manual(None, "text")
        raise typer.Exit()
    if ctx.invoked_subcommand is None and resume_run_name:
        _resume_saved_run(resume_run_name, runs_dir=runs_dir, repair=repair)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        _run_repl()


def _resume_saved_run(
    run_name: str,
    *,
    runs_dir: Optional[str] = None,
    repair: bool = False,
) -> None:
    from vulnclaw.run_context import RunCorruptError, load_run_context

    config = load_config()
    try:
        run_context = load_run_context(
            run_name,
            runs_dir=runs_dir,
            config=config,
            repair=repair,
        )
    except RunCorruptError as exc:
        err_console.print(f"[!] {exc}")
        raise typer.Exit(1) from exc

    targets = run_context.manifest.get("targets", [])
    first_target = targets[0] if isinstance(targets, list) and targets else {}
    if not isinstance(first_target, dict) or not first_target.get("input"):
        err_console.print(f"[!] Run {run_name} has no resumable target in run.json")
        raise typer.Exit(1)

    target = str(first_target["input"])
    command = str(run_context.manifest.get("command") or "run")
    if not has_llm_credentials(config.llm):
        err_console.print("[!] Configure LLM credentials first (api_key or auth_mode).")
        raise typer.Exit(1)

    async def _run():
        async def runner(agent, shared_config):
            sink = TerminalStreamSink(console, shared_config.session.show_thinking)
            prompt = (
                f"Continue the saved VulnClaw run {run_name} for {target}. "
                "Resume from the loaded checkpoint and continue the authorized task."
            )
            return await agent.chat(prompt, target=target, stream_sink=sink)

        return await _run_cli_orchestrated_task(
            command=command,
            target=target,
            resume=True,
            snapshot=None,
            runner=runner,
            resume_run_name=run_name,
            runs_dir=runs_dir,
            repair=repair,
        )

    asyncio.run(_run())



@app.command()
def repl() -> None:
    """Start the classic natural-language REPL."""
    _run_repl()


@app.command()
def tui(
    target: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help="Pre-fill the authorized target for the TUI.",
    ),
    mode: str = typer.Option(
        "standard",
        "--mode",
        "-m",
        help="Pre-fill check mode: quick, standard, deep, continuous.",
    ),
    only_port: Optional[int] = typer.Option(
        None,
        "--only-port",
        help="Pre-fill a single allowed test port.",
    ),
    only_host: Optional[str] = typer.Option(
        None,
        "--only-host",
        help="Pre-fill a single allowed host.",
    ),
    only_path: Optional[str] = typer.Option(
        None,
        "--only-path",
        help="Pre-fill a single allowed path.",
    ),
    blocked_host: Optional[str] = typer.Option(
        None,
        "--blocked-host",
        help="Pre-fill an explicitly blocked host.",
    ),
    blocked_path: Optional[str] = typer.Option(
        None,
        "--blocked-path",
        help="Pre-fill an explicitly blocked path.",
    ),
    allow_actions: Optional[str] = typer.Option(
        None,
        "--allow-actions",
        help="Pre-fill comma-separated allowed actions.",
    ),
    block_actions: Optional[str] = typer.Option(
        None,
        "--block-actions",
        help="Pre-fill comma-separated blocked actions.",
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume target history."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Render the launch summary and exit without starting a task.",
    ),
    once: bool = typer.Option(
        False,
        "--once",
        help="Render the TUI dashboard once and exit (useful for smoke tests).",
    ),
) -> None:
    """Open the terminal UI workbench."""
    from vulnclaw.cli.tui import (
        MODES,
        build_state_from_options,
        build_task_draft,
        render_task_summary,
        run_tui,
    )

    if mode not in MODES:
        err_console.print("[!] Unknown TUI mode. Use one of: quick, standard, deep, continuous")
        raise typer.Exit(1)

    state = build_state_from_options(
        target=target or "",
        mode=mode,  # type: ignore[arg-type]
        only_host=only_host or "",
        only_port=only_port,
        only_path=only_path or "",
        blocked_host=blocked_host or "",
        blocked_path=blocked_path or "",
        allow_actions=allow_actions,
        block_actions=block_actions,
        resume=resume,
    )

    if dry_run:
        console.out(render_task_summary(build_task_draft(state)), end="")
        return

    if once and target:
        from vulnclaw.cli.tui import render_tui_home

        console.out(render_tui_home(state), end="")
        return

    run_tui(once=once, initial_state=state)


@app.command()
def web(
    host: str = typer.Option(
        "127.0.0.1", "--host", help="Web server host (default: localhost only)"
    ),
    port: int = typer.Option(7788, "--port", help="Web server port"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Validate and print launch info without starting the server"
    ),
    allow_remote: bool = typer.Option(
        False, "--allow-remote", help="Explicitly allow binding the Web UI to a non-local address"
    ),
) -> None:
    """Run the local Web UI."""
    if not _is_loopback_bind_host(host):
        if not allow_remote:
            err_console.print(
                "[!] Refusing to bind the Web UI to a non-local address without --allow-remote."
            )
            raise typer.Exit(1)
        console.print(
            "[yellow]Warning: keep the Web UI bound to 127.0.0.1 unless you know what you're doing.[/]"
        )

    from vulnclaw.web.app import FASTAPI_AVAILABLE

    console.print(
        Panel(
            f"Host: [bold]{host}[/]\n"
            f"Port: [bold]{port}[/]\n"
            f"FastAPI: [{'green' if FASTAPI_AVAILABLE else 'yellow'}]{'installed' if FASTAPI_AVAILABLE else 'missing'}[/]\n"
            f"URL: [bold]http://{host}:{port}[/]",
            title="VulnClaw Web UI",
            border_style="cyan",
        )
    )

    if dry_run:
        console.print("[green]Web UI dry-run completed.[/]")
        return

    if not FASTAPI_AVAILABLE:
        err_console.print(
            "[!] FastAPI is missing. Install with [bold]pip install vulnclaw\\[web][/]."
        )
        raise typer.Exit(1)

    try:
        import uvicorn
    except ImportError:
        err_console.print(
            "[!] uvicorn is missing. Install with [bold]pip install vulnclaw\\[web][/]."
        )
        raise typer.Exit(1)

    from vulnclaw.web.app import create_app
    from vulnclaw.web.auth import generate_token

    token = generate_token()
    if allow_remote:
        # Non-loopback clients (which includes every browser reaching a
        # container through Docker's port NAT) must authenticate. The UI cannot
        # send a bearer header, so opening this URL once swaps the token for a
        # session cookie; the browser carries it from then on.
        browser_host = "127.0.0.1" if host in {"0.0.0.0", "::", "[::]"} else host
        console.print(
            Panel(
                f"Open this URL once to sign the browser in:\n"
                f"[bold]http://{browser_host}:{port}/?token={token}[/]\n\n"
                f"Token: [bold]{token}[/]\n"
                f"[dim]For API clients: Authorization: Bearer {token}[/]",
                title="Web UI Auth Token",
                border_style="yellow",
            )
        )

    uvicorn.run(create_app(), host=host, port=port, log_level="info")


def _is_loopback_bind_host(host: str) -> bool:
    """Return True when a requested bind host is loopback-only."""
    normalized = host.strip().strip("[]").lower()
    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        import ipaddress

        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


if __name__ == "__main__":
    app()
