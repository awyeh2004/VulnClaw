"""``vulnclaw run`` / ``solve`` / ``go`` / ``persistent`` / ``recon`` / ``scan`` /
``network-scan`` / ``exploit`` / ``report`` —— 编排型命令族。

从 :mod:`vulnclaw.cli.main` 拆出（2026-10-12）。按本仓库既有约定（``retest_cmd.py``），
这里定义**普通函数**，由 ``main.py`` 用 ``app.command()(...)`` 注册 —— ``app`` 仍只在
main.py，注册名/顺序逐条不变。

这些命令体读 ``main`` 上若干名字（``load_config``、``_run_cli_orchestrated_task``、
``_generate_report_for_target``、``has_llm_credentials``），测试会对 ``cli.main.<name>``
打补丁，故一律经 :func:`vulnclaw.cli.repl._from_main` 在调用时解析。

``_SOLVE_DECLARED_DEFAULTS`` 与 ``_solve_defaults`` 同住本模块：前者在 import 时**一次性**
从真正的 ``solve`` 签名抓取（测试事后把 ``main.solve`` 换成 stub 也能命中此常量）。
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any, Optional

import typer
from rich.panel import Panel

from vulnclaw import headless
from vulnclaw.agent.constraint_policy import validate_action_constraints
from vulnclaw.agent.input_analysis import extract_task_constraints
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
from vulnclaw.cli.repl import (
    _emit_competition_writeup,
    _emit_solve_report_if_completed,
    _from_main,
    _run_context_kwargs,
    _run_non_interactive,
    _scope_option_kwargs,
    _validate_headless_choices,
)
from vulnclaw.config.schema import ENGINE_CHOICES
from vulnclaw.i18n import _
from vulnclaw.target_state.store import load_target_state
from vulnclaw.task_service import (
    TaskCreateRequest,
    TaskOptions,
    prepare_task,
    run_task_action,
)


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
    config = _from_main("load_config")()

    # A bad target / scan-mode / fail-on / scope-mode is a misconfiguration:
    # exit 1 (never a silent green run).
    if not target or not target.strip():
        err_console.print("[!] A non-empty target is required.")
        raise typer.Exit(headless.EXIT_ERROR)
    bad_choice = _validate_headless_choices(scan_mode, fail_on, scope_mode)
    if bad_choice is not None:
        err_console.print(f"[!] {bad_choice}")
        raise typer.Exit(headless.EXIT_ERROR)
    if not _from_main("has_llm_credentials")(config.llm):
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

        result = await _from_main("_run_cli_orchestrated_task")(
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

    report_path = _from_main("_generate_report_for_target")(target, output_path=output)
    console.print(_("cli.report_generated", path=report_path))


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
    config = _from_main("load_config")()
    if not _from_main("has_llm_credentials")(config.llm):
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

        return await _from_main("_run_cli_orchestrated_task")(
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
    _from_main("solve")(
        **_solve_defaults(
            target=target,
            goal=resolved_goal,
            max_steps=240,
            resume=True,
            model=model,
        )
    )


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

    config = _from_main("load_config")()
    if not _from_main("has_llm_credentials")(config.llm):
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

        return await _from_main("_run_cli_orchestrated_task")(
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

        await _from_main("_run_cli_orchestrated_task")(
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

        await _from_main("_run_cli_orchestrated_task")(
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

        await _from_main("_run_cli_orchestrated_task")(
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

        await _from_main("_run_cli_orchestrated_task")(
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

    report_config = _from_main("load_config")()
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
