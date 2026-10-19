"""``vulnclaw`` REPL loop, its slash/command helpers, and target-intent mining.

Split out of :mod:`vulnclaw.cli.main` (2026-10-12). ``main.py`` keeps the Typer
``app`` object and re-exports every name below so existing imports (tests reach
in for ``_apply_local_path_constraints``, ``_extract_target_from_input``,
``_repl_has_in_progress_run``…) keep resolving unchanged.

Contents:

* solve/report emission helpers used by the REPL *and* the ``solve`` command;
* the classic interactive REPL (``_run_repl`` and everything it calls);
* the headless/run option helpers the sub-commands share;
* target-intent mining (which target, if any, the operator's message names) —
  the REPL calls nine of these functions, so they live beside it.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

import typer
from rich.panel import Panel
from rich.text import Text

from vulnclaw import headless
from vulnclaw.agent.input_analysis import (
    _citation_url_spans,
    _is_cited_candidate,
    _is_plausible_host,
    detect_target,
)
from vulnclaw.agent.solver import _looks_like_quiz
from vulnclaw.cli import experience_ops
from vulnclaw.cli._helpers import (
    TerminalStreamSink,
    _make_solve_event_printer,
    _print_agent_output,
    _print_banner,
    console,
    err_console,
    format_llm_user_error,
)
from vulnclaw.config.token_provider import has_llm_credentials
from vulnclaw.i18n import _
from vulnclaw.i18n.phases import localized_phase_name
from vulnclaw.repl_runner import run_repl_call
from vulnclaw.task_service import SCOPE_FIELDS


def _from_main(name: str) -> Any:
    """Resolve a name from :mod:`vulnclaw.cli.main` at call time.

    Split-out code that tests and callers patch on the facade module (``main``)
    must read that attribute *now*, not the copy this module imported at import
    time — otherwise ``monkeypatch.setattr(cli_main, "load_config", …)`` silently
    no-ops for the moved function (the same reason ``tools/ocr.py`` re-resolves
    ``_OCR_READER_CACHE`` from ``builtin_tools``). ``main`` reads this module to
    build its facade, so the import is function-local to avoid a cycle.
    """
    from vulnclaw.cli import main

    return getattr(main, name)


def _emit_solve_report_if_completed(agent: Any, config: Any) -> str:
    """Generate and optionally print the replay report for a completed solve run."""

    state = getattr(getattr(getattr(agent, "context", None), "state", None), "agent_state", None)
    if state is None or not getattr(state, "completed", False):
        return ""
    session = getattr(config, "session", None)
    if session is not None and not getattr(session, "solve_auto_report", True):
        return ""
    try:
        from vulnclaw.report.solve_report import generate_solve_report

        report_path = generate_solve_report(state)
        report_text = report_path.read_text(encoding="utf-8")
    except Exception as exc:
        console.print(Panel(f"{_('cli.auto_solve_report_generation_failed')}: {exc}", title="Solve Report", border_style="red"))
        return ""

    console.print(
        Panel(
            f"{_('cli.auto_review_report_saved')}:\n{report_path}",
            title="Solve Report",
            border_style="cyan",
        )
    )
    if session is None or getattr(session, "solve_report_show", True):
        console.print(Text(report_text), soft_wrap=True)
    return str(report_path)


def _resolve_team_meta_from_gcs() -> tuple[str, str]:
    """Fetch overall rank and solved-challenge count from the competition API.

    Returns ``(rank, solved_count)`` as strings. rank comes from
    ``answer-panel/overview`` (``stageRank``); solved_count is the number of
    ``hasSolved`` entries across the exercise corpus. Best-effort: returns
    empty strings on any failure so callers can fall back to env vars.
    """
    import asyncio

    try:
        from vulnclaw.platforms import registry
        from vulnclaw.platforms.bootstrap import ensure_adapters

        ensure_adapters()

        async def _fetch() -> tuple[str, str]:
            # Through the adapter layer: any configured platform that exposes a
            # scoreboard can answer, and the CTF2-only/legacy naming no longer
            # decides who is asked.
            for adapter in registry.configured_adapters().values():
                try:
                    overview = await adapter.overview()
                except Exception:
                    continue
                rank = str(overview.get("stageRank") or "")
                solved = 0
                try:
                    for corpus in await adapter.list_corpora():
                        try:
                            challenges = await adapter.list_challenges(corpus.ref)
                        except Exception:
                            continue
                        solved += sum(1 for c in challenges if c.solved)
                except Exception:
                    pass
                if rank or solved:
                    return rank, str(solved)
            return "", ""

        return asyncio.run(_fetch())
    except Exception:
        return "", ""


def _emit_competition_writeup(agent: Any, config: Any, writeup_dir: Path) -> Optional[str]:
    """Write a single-challenge competition writeup with text-evidence (no screenshots).

    Uses the completed AgentState to render the solution chain, key evidence
    excerpts with exact line numbers (as screenshot stand-ins), and the scripts
    the agent wrote. Team info comes from the environment; the model name is
    taken from the active LLM config.
    """
    from pathlib import Path

    state = getattr(getattr(getattr(agent, "context", None), "state", None), "agent_state", None)
    if state is None or not getattr(state, "completed", False):
        return None
    if writeup_dir is not None and not isinstance(writeup_dir, Path):
        writeup_dir = Path(writeup_dir)
    try:
        from vulnclaw.report.writeup import (
            WriteupMeta,
            default_writeup_dir,
            generate_writeup,
            render_evidence_popup,
        )
    except Exception as exc:
        console.print(
            Panel(f"{_('cli.auto_writeup_generation_failed')}: {exc}", title="Writeup", border_style="red")
        )
        return None

    model_name = ""
    if getattr(config, "llm", None) is not None:
        model_name = str(getattr(config.llm, "model", "") or "")
    team_name = os.environ.get("VULNCLAW_TEAM_NAME", "").strip()
    rank = os.environ.get("VULNCLAW_TEAM_RANK", "").strip()
    solved_count = os.environ.get("VULNCLAW_TEAM_SOLVED", "").strip()
    # When the rank / solved-count env vars are unset, try to fetch them from
    # the competition API so the writeup header is populated automatically:
    # rank = overview.stageRank (overall), solved_count = number of solved.
    # Not gated on "GCS configured" any more -- that gate made a missing legacy
    # platform look identical to "no team meta was asked for". The resolver owns
    # the decision and now considers every configured platform.
    if not rank or not solved_count:
        try:
            auto_rank, auto_solved = _resolve_team_meta_from_gcs()
            if not rank:
                rank = auto_rank
            if not solved_count:
                solved_count = auto_solved
        except Exception:
            pass
    meta = WriteupMeta(
        team_name=team_name,
        rank=rank,
        solved_count=solved_count,
        total_tokens=int(getattr(state, "llm_usage_prompt_tokens", 0) or 0)
        + int(getattr(state, "llm_usage_completion_tokens", 0) or 0),
        model_name=model_name,
        exercise_name=getattr(state, "origin", ""),
    )
    try:
        resolved_dir = writeup_dir if writeup_dir is not None else Path(default_writeup_dir())
        resolved_dir.mkdir(parents=True, exist_ok=True)
        report_path = generate_writeup(state, meta=meta, output_path=resolved_dir)
    except Exception as exc:
        console.print(
            Panel(f"{_('cli.auto_writeup_generation_failed')}: {exc}", title="Writeup", border_style="red")
        )
        return None

    console.print(
        Panel(
            f"{_('cli.auto_writeup_saved')}:\n{report_path}",
            title="Writeup",
            border_style="green",
        )
    )
    try:
        popup = render_evidence_popup(state)
        if popup:
            console.print(Panel(popup, title="Evidence Lines", border_style="cyan"))
    except Exception:
        pass
    return str(report_path)


# ── REPL ──────────────────────────────────────────────────────────────


def _repl_last_run_finished(agent: Any) -> bool:
    """Whether the agent's last autonomous run reached its own end.

    Distinguishes "there is nothing to replay" from "the launch text is still
    valid to retry". ``_repl_has_in_progress_run`` answers the sibling question
    (is there a run worth resuming); this one answers "did the previous run
    already finish", which is the guard the empty-Enter replay path needs.

    Conservative by design: an agent whose state cannot be read reports NOT
    finished, so the worst case is the old behaviour (a retry) rather than
    silently dropping a legitimate retry.
    """
    try:
        state = agent.context.state.agent_state
        return bool(getattr(state, "completed", False))
    except Exception:
        return False


def _repl_has_in_progress_run(agent: Any) -> bool:
    """Return True when the agent still holds an unfinished autonomous run
    (evidence gathered / blackboard populated) that Enter should resume in place
    rather than re-launch from scratch."""
    try:
        state = agent.context.state.agent_state
        if getattr(state, "completed", False):
            return False
        if getattr(state, "evidence", None) or getattr(state, "tool_calls", None):
            return True
        bb = getattr(agent.runtime, "blackboard", None)
        if bb is not None and bb.all_nodes():
            return True
    except Exception:
        return False
    return False


def _prepare_repl_target(
    agent, requested_target: str, current_target: Optional[str], current_phase: str
) -> tuple[str, str, bool]:
    """Prepare REPL state for a target switch and optionally restore history."""
    target = requested_target.strip()
    if not target:
        return current_target or "", current_phase, False

    if current_target and current_target != target:
        console.print(
            _("cli.target_switch").format(from_target = current_target,to_target = target) #数据库存在i18n字符串 未使用
        )
        agent.reset_context()
        current_phase = agent.session_state.phase.value

    restore_result = _from_main("apply_target_state_to_agent")(agent, target)
    current_phase = restore_result.phase or agent.session_state.phase.value
    # The restore REPLACED the state object; re-arm persistence.
    _ensure_repl_checkpoint_callback(agent)
    return target, current_phase, restore_result.restored


#: The task carrying the most recent REPL run, recorded when it ends with the
#: deliberate CancelledError→KeyboardInterrupt conversion from
#: ``repl_runner.run_repl_call``. Holding the reference lets the exit path
#: retrieve the exception (``Task.exception()``) so asyncio does not print
#: "Task exception was never retrieved" with a full traceback at teardown
#: (TECH-DEBT ## 3 ②b). Cleared only once a retrieval attempt succeeds.
_REPL_INTERRUPTED_TASK: Optional["asyncio.Task[Any]"] = None

_LOGGER = logging.getLogger(__name__)


def _checkpoint_repl_agent(agent: Any, reason: str) -> Optional[str]:
    """Persist the REPL's live session state to the target store.

    The command path persists at durable boundaries via
    ``orchestrator.checkpoint`` (installed callback + explicit
    run_start/run_complete/interrupt calls). REPL solves call ``agent.solve``
    directly and used to leave ``targets/<id>/state.json`` frozen at run_start —
    measured 2026-10-15: the Solve panel said 目标达成 while the saved state still
    had ``completed=False`` and no findings, so restoring that target later
    produced the stale snapshot (TECH-DEBT ## 3 ①). Never raises: a state-write
    failure must not kill the REPL.
    """
    state = getattr(agent, "session_state", None)
    target = str(getattr(state, "target", "") or "")
    if state is None or not target:
        return None
    try:
        from vulnclaw.target_state.store import save_target_state

        path = save_target_state(
            target,
            state,
            command="repl",
            runtime=getattr(agent, "runtime", None),
            checkpoint_reason=reason,
            # Merging write. The natural-language target-adoption branch
            # (``_should_switch_target`` / the first-adoption ``elif`` below) sets
            # ``current_target`` without calling ``apply_target_state_to_agent``, so
            # the in-memory state can be a strict SUBSET of what is already on disk
            # for that target. A non-merging write replaced it wholesale -- measured
            # 2026-10-16: a stored finding went from ``['SQLi in /login']`` to ``[]``.
            # The command path can use ``merge_existing=False`` because it hydrates
            # first; this one must not.
            merge_existing=True,
        )
        return str(path)
    except Exception as exc:  # noqa: BLE001 — persistence is best-effort
        _LOGGER.debug("repl checkpoint failed (%s): %s", reason, exc)
        return None


def _ensure_repl_checkpoint_callback(agent: Any) -> None:
    """Install the boundary-checkpoint callback on the agent's CURRENT state.

    ``apply_target_state_to_agent`` REPLACES ``agent.context.state`` on every
    target restore, so the callback must be (re)installed after restores —
    idempotent by design. Boundaries mirror the command path (step_complete /
    finding_added / phase_transition …); each one persists through
    ``save_target_state``.
    """
    state = getattr(agent, "session_state", None)
    if state is None:
        return
    state.set_checkpoint_callback(
        lambda _state, reason: _checkpoint_repl_agent(agent, reason)
    )


def _retrieve_interrupted_task() -> None:
    """Retrieve the recorded run task's exception so asyncio stops warning.

    ``Task.exception()`` marks the exception retrieved, which is what stops
    asyncio from printing "Task exception was never retrieved" at GC. Two cases
    must NOT clear the reference, one must:

    * still-pending — ``InvalidStateError``; keep the ref for the teardown retry;
    * cancelled — ``exception()`` raises ``CancelledError`` (a ``BaseException``,
      so a bare ``except Exception`` misses it and it would escape the caller).
      It has already marked the task retrieved by then, so the ref is cleared;
    * otherwise the exception is returned and the ref is cleared.
    """
    global _REPL_INTERRUPTED_TASK
    task = _REPL_INTERRUPTED_TASK
    if task is None:
        return
    try:
        task.exception()
    except asyncio.InvalidStateError:
        return  # pending — keep the ref for the teardown retry
    except asyncio.CancelledError:
        pass  # cancelled: already marked retrieved by exception()
    except Exception:  # pragma: no cover - defensive: never let teardown raise
        return
    _REPL_INTERRUPTED_TASK = None


async def _run_repl_agent_call(agent, *, call, after_result) -> None:
    """Run a REPL agent call and hand each result back to a caller hook."""
    global _REPL_INTERRUPTED_TASK
    try:
        await run_repl_call(call=call, after_result=after_result)
    except KeyboardInterrupt:
        # Typically the deliberate CancelledError→KeyboardInterrupt conversion
        # inside run_repl_call; record the task so the exit path can retrieve
        # the exception (TECH-DEBT ## 3 ②b), then let the interrupt propagate.
        _REPL_INTERRUPTED_TASK = asyncio.current_task()
        raise


def _localized_phase_label(phase: Any) -> str:
    """Return a display-only phase label for the active UI language."""
    raw = getattr(phase, "value", phase)
    return localized_phase_name(str(raw or "").strip())


def _make_repl_prompt_session() -> Any:
    """Build a prompt_toolkit session with the skill palette, or None if unavailable.

    Returns None when stdin is not a TTY (pipes, CI, ``--once`` smoke tests) or
    prompt_toolkit cannot attach, so the REPL falls back to plain input.
    """
    debug = bool(os.environ.get("VULNCLAW_DEBUG_INPUT"))
    try:
        if not sys.stdin.isatty():
            if debug:
                console.print(f"[dim]({_('cli.slash_palette_off')})[/]")
            return None
        from prompt_toolkit import PromptSession

        from vulnclaw.cli.tui import build_repl_slash_completer, build_repl_slash_style

        session = PromptSession(
            completer=build_repl_slash_completer(),
            complete_while_typing=True,
            style=build_repl_slash_style(),
        )

        # `complete_while_typing` reopens the menu on insertion but not on
        # deletion, so backspacing to a bare '/' leaves it closed. Re-trigger
        # completion on any change while the line still starts with '/'.
        def _reopen_palette_on_edit(buff: Any) -> None:
            if buff.complete_state is None and buff.text.startswith("/"):
                buff.start_completion(select_first=False)

        session.default_buffer.on_text_changed += _reopen_palette_on_edit

        if debug:
            console.print(f"[dim]({_('cli.slash_palette_on')})[/]")
        return session
    except Exception as exc:
        # Surface the reason instead of silently dropping to plain input.
        from rich.markup import escape as _esc

        console.print(f"[yellow](slash palette unavailable: {_esc(str(exc))})[/]")
        return None


def _read_repl_line(
    pt_session: Any,
    target: Optional[str],
    phase: str,
    auto_mode: bool,
) -> str:
    """Read one REPL line, using the slash palette when a session is available."""
    console = _from_main("console")
    phase_label = _localized_phase_label(phase)
    if pt_session is None:
        prompt_parts = []
        if target:
            prompt_parts.append(f"[bold cyan]{target}[/]")
        prompt_parts.append(f"[dim]{phase_label}[/]")
        if auto_mode:
            prompt_parts.append("[bold yellow]AUTO[/]")
        prompt_str = " | ".join(prompt_parts) if prompt_parts else "vulnclaw"
        return console.input(f"vulnclaw {prompt_str}> ")

    import html as _html

    from prompt_toolkit.formatted_text import HTML

    parts = []
    if target:
        parts.append(f"<ansicyan><b>{_html.escape(target)}</b></ansicyan>")
    parts.append(f"<ansibrightblack>{_html.escape(phase_label)}</ansibrightblack>")
    if auto_mode:
        parts.append("<ansiyellow><b>AUTO</b></ansiyellow>")
    body = " | ".join(parts) if parts else "vulnclaw"
    return pt_session.prompt(HTML(f"vulnclaw {body}<b>&gt; </b>"))


def _run_repl_command(
    name: str,
    args: str,
    agent: Any,
    config: Any,
    *,
    mcp_manager: Any = None,
) -> Any:
    """Execute a built-in classic-REPL slash command.

    Returns the (possibly reloaded) config so the caller can keep using it.
    """
    if name == "config":
        from vulnclaw.cli.tui import run_config_tui

        run_config_tui()
        # The editor writes to disk; reload and rebind the running agent so
        # provider/model/key changes take effect without restarting.
        new_config = _from_main("load_config")()
        agent.apply_config(new_config)
        console.print(
            f"[green]✓[/] {_('cli.config_reloaded')}: "
            f"{new_config.llm.provider}/{new_config.llm.model}"
        )
        return new_config

    if name == "language":
        return _repl_switch_language(args, agent, config)

    if name == "mode":
        from vulnclaw.agent.exec_gate import get_execution_gate

        gate = get_execution_gate(config)
        target = args.strip().lower()
        if not target:
            console.print(
                f"[bold]Permission mode[/]: {gate.mode} "
                "(ask | auto_review | full_access)"
            )
            return config
        try:
            new_mode = gate.set_mode(target, source="cli")
        except ValueError as exc:
            console.print(f"[red]✗[/] {exc}")
            return config
        console.print(f"[green]✓[/] Permission mode set to [bold]{new_mode}[/]")
        if new_mode == "auto_review":
            console.print(
                "[yellow]⚠ auto_review: trusted read-only commands run without "
                "approval; everything else still prompts. Extend the table via "
                "safety.trusted_commands.[/]"
            )
        elif new_mode == "full_access":
            console.print(
                "[yellow]⚠ full_access executes without per-request approval; "
                "injected content can drive arbitrary execution.[/]"
            )
        return config

    if name == "wizard":
        from vulnclaw.cli.wizard import run_setup_wizard

        result = run_setup_wizard(
            console=console,
            mcp_manager=mcp_manager,
            agent=agent,
        )
        if result.config is not None:
            return result.config
        return _from_main("load_config")()

    if name == "experience":
        _from_main("_repl_experience")(args)
        return config

    if name == "learn":
        _from_main("_repl_learn")(args, config)
        return config

    if name == "feedback":
        _from_main("_repl_feedback")(args, config)
        return config

    return config


def _print_op_result(result: "experience_ops.OpResult") -> None:
    """Print a shared-op result in the REPL without unwinding the loop."""
    if result.ok:
        console.print(result.renderable)
    else:
        err_console.print(result.renderable)


def _repl_experience(args: str) -> None:
    """Handle ``/experience [list|show|approve|reject|edit] ...`` in the REPL."""
    import shlex

    body = args.strip()
    if not body:
        _print_op_result(experience_ops.render_pending_lessons())
        return

    parts = body.split(maxsplit=1)
    sub = parts[0].lower()
    rest = parts[1].strip() if len(parts) > 1 else ""

    if sub in ("list", "review"):
        _print_op_result(experience_ops.render_pending_lessons())
        return
    if sub == "show":
        if not rest:
            err_console.print("[!] Usage: /experience show <lesson-id>")
            return
        _print_op_result(experience_ops.render_lesson(rest.split()[0]))
        return
    if sub in ("approve", "reject"):
        if not rest:
            err_console.print(f"[!] Usage: /experience {sub} <lesson-id>")
            return
        status = "approved" if sub == "approve" else "rejected"
        _print_op_result(experience_ops.set_lesson_status(rest.split()[0], status))
        return
    if sub == "edit":
        try:
            tokens = shlex.split(rest)
        except ValueError as exc:
            err_console.print(f"[!] Could not parse arguments: {exc}")
            return
        if not tokens:
            err_console.print(
                "[!] Usage: /experience edit <lesson-id> "
                "[--context <text>] [--lesson <text>]"
            )
            return
        lesson_id = tokens[0]
        context_val, lesson_val, flag_error = _parse_edit_flags(tokens[1:])
        if flag_error:
            err_console.print(f"[!] {flag_error}")
            return
        if context_val is None and lesson_val is None:
            err_console.print(
                "[!] Provide --context and/or --lesson, "
                'e.g. /experience edit L1 --lesson "prefer double-write bypass"'
            )
            return
        _print_op_result(
            experience_ops.edit_lesson(lesson_id, context=context_val, lesson=lesson_val)
        )
        return

    err_console.print(
        "[!] Unknown /experience action. "
        "Use list | show <id> | approve <id> | reject <id> | edit <id> ..."
    )


_EDIT_FLAGS = ("--context", "--lesson")


def _parse_edit_flags(
    tokens: list[str],
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract ``--context`` / ``--lesson`` values from tokenized edit args.

    Returns ``(context, lesson, error)``. A flag whose value is missing or is
    itself another flag is an error rather than a silently swallowed typo:
    ``edit L1 --lesson --context foo`` must not persist the literal lesson
    text ``--context``, since an approved lesson is injected into later runs.
    """
    context_val: Optional[str] = None
    lesson_val: Optional[str] = None
    i = 0
    while i < len(tokens):
        flag = tokens[i]
        if flag not in _EDIT_FLAGS:
            return None, None, (
                f"Unexpected argument: {flag} "
                '(quote multi-word values, e.g. --lesson "two words")'
            )
        if i + 1 >= len(tokens) or tokens[i + 1] in _EDIT_FLAGS:
            return None, None, f"{flag} needs a value."
        if flag == "--context":
            context_val = tokens[i + 1]
        else:
            lesson_val = tokens[i + 1]
        i += 2
    return context_val, lesson_val, None


def _repl_learn(args: str, config: Any) -> None:
    """Handle ``/learn <run-name>`` in the REPL."""
    run_name = args.strip().split()[0] if args.strip() else ""
    if not run_name:
        err_console.print("[!] Usage: /learn <run-name>")
        return
    _print_op_result(experience_ops.distill_run(run_name, config=config))


def _repl_feedback(args: str, config: Any) -> None:
    """Handle ``/feedback <run-name> <rating 1-5> <notes...>`` in the REPL."""
    parts = args.strip().split(maxsplit=2)
    if len(parts) < 3:
        err_console.print("[!] Usage: /feedback <run-name> <rating 1-5> <notes>")
        return
    run_name, rating_raw, notes = parts[0], parts[1], parts[2]
    try:
        rating = int(rating_raw)
    except ValueError:
        err_console.print(f"[!] Rating must be an integer 1-5, got: {rating_raw}")
        return
    _print_op_result(
        experience_ops.save_run_feedback(run_name, rating=rating, notes=notes, config=config)
    )


def _repl_switch_language(args: str, agent: Any, config: Any) -> Any:
    """Switch the interface language from the classic REPL."""
    from vulnclaw.cli.tui import _SUPPORTED_LANGUAGES, rebuild_translations
    from vulnclaw.i18n import init_i18n, set_language_pref

    lang = args.strip().lower()
    if lang not in _SUPPORTED_LANGUAGES:
        console.print(
            "[yellow]Usage:[/] /language <"
            + " | ".join(_SUPPORTED_LANGUAGES)
            + f">  (current: {config.session.language})"
        )
        return config

    config.session.language = lang
    _from_main("save_config")(config)
    set_language_pref(lang)
    init_i18n(lang=lang if lang != "auto" else None, config=config)
    rebuild_translations()
    agent.apply_config(config)
    console.print(f"[green]✓[/] {_('cli.language_set_to')} [bold]{lang}[/].")
    return config


def _run_repl() -> None:
    """Run the interactive REPL loop."""
    from vulnclaw.agent.core import AgentCore
    from vulnclaw.mcp.lifecycle import MCPLifecycleManager

    _print_banner()

    config = _from_main("load_config")()
    if not has_llm_credentials(config.llm):
        console.print(_("cli.no_api_key"))
        console.print(_("cli.choose_provider"))
        console.print(_("cli.set_env_var"))
        console.print()
        console.print(_("cli.offline_mode"))

    # Initialize MCP lifecycle manager
    mcp_manager = MCPLifecycleManager(config)
    started = mcp_manager.start_enabled_servers()
    console.print(_("cli.mcp_registered", count=started))
    # Report any servers that failed to attach so the user knows immediately
    for srv_name, srv_state in mcp_manager.registry.get_all_servers().items():
        if srv_state.health_status in ("degraded", "unavailable") and srv_state.execution_mode in ("placeholder",):
            err_msg = getattr(srv_state, "error", "") or ""
            if err_msg:
                console.print(f"[yellow]  ⚠ {srv_name}: {err_msg[:120]}[/yellow]")

    # Initialize agent
    agent = AgentCore(config, mcp_manager)
    # Persist durable boundaries to the target store (TECH-DEBT ## 3 ①); the
    # restore path replaces the state object, so _prepare_repl_target reinstalls.
    _ensure_repl_checkpoint_callback(agent)

    # ExecutionGate: interactive REPL on a real TTY gets the trusted
    # approval channel; dangerous-tool executions prompt y/N.
    from vulnclaw.cli.approval_channel import install_cli_approval_channel

    install_cli_approval_channel(config)

    console.print(_("cli.welcome"))
    console.print()

    # Track current target
    current_target: Optional[str] = None
    current_phase: str = "Ready"
    exit_requested = False
    auto_mode_active = False
    _last_ctrlc_time = 0.0
    last_auto_input: str = ""

    # Interactive slash palette: skills under '/', flag skills under '/.'.
    # Falls back to plain input when there is no TTY (pipes, CI smoke tests).
    _pt_session = _make_repl_prompt_session()

    while True:
        try:
            # Read input (slash palette when interactive, plain prompt otherwise)
            user_input = _read_repl_line(
                _pt_session, current_target, current_phase, auto_mode_active
            ).strip()

            if not user_input:
                if _repl_has_in_progress_run(agent):
                    # A run was interrupted mid-flight: pressing Enter resumes it
                    # in-place (same origin/goal, blackboard + evidence preserved)
                    # instead of replaying the raw launch text from scratch.
                    user_input = _("cli.resume_in_progress_prompt")
                    # The generic resume prompt carries no task signal, so quiz
                    # detection (directive + gate exemption) would be lost on
                    # resume; re-attach it from the original launch input.
                    if last_auto_input and _looks_like_quiz(last_auto_input):
                        user_input += _("cli.resume_quiz_suffix")
                    console.print(f"[dim]↻ {_('cli.resuming_auto_pentest')}[/]")
                elif last_auto_input and not _repl_last_run_finished(agent):
                    # No live run to resume, but the previous launch text survived
                    # (it was interrupted before the run started, e.g. during a
                    # start-up LLM call). Replaying it is the intended "try again".
                    #
                    # The `_repl_last_run_finished` guard is the fix for the
                    # 2026-10-06 report: a COMPLETED run used to leave its launch
                    # text here, so an empty Enter re-ran the finished task — and
                    # because the operator's new line had just been eaten by the
                    # Ctrl+C exit-confirm, it looked like the agent ignored them
                    # and "solved the old challenge again on its own".
                    user_input = last_auto_input
                    console.print(f"[dim]↻ {_('cli.resuming_auto_pentest')}: {last_auto_input[:60]}...[/]")
                else:
                    continue

            if user_input.lower() in ("/compact", "compact"):
                summary = agent.context.compact_messages(note="User requested /compact.")
                console.print(
                    _("cli.compressed_earlier_context").format(var_001 = len(summary))
                )
                continue

            # Handle slash commands: '/' selects a skill, '/.' a flag skill.
            if user_input.startswith("/"):
                from vulnclaw.cli.tui import dispatch_repl_slash

                result = dispatch_repl_slash(user_input)
                if result.kind == "message":
                    console.print(result.text)
                    continue
                if result.kind == "target":
                    current_target, current_phase, restored_loaded = _prepare_repl_target(
                        agent, result.value, current_target, current_phase
                    )
                    if restored_loaded:
                        console.print(_("cli.target_restored", target=current_target))
                    console.print(_("cli.target_set", target=current_target))
                    continue
                if result.kind == "command":
                    config = _run_repl_command(
                        result.value,
                        result.text,
                        agent,
                        config,
                        mcp_manager=mcp_manager,
                    )
                    continue
                # result.kind == "run": fall through with the rewritten prompt.
                user_input = result.text

            # Handle built-in commands
            cmd_lower = user_input.lower()

            if cmd_lower in ("exit", "quit", "q"):
                console.print(_("cli.bye"))
                break

            elif cmd_lower == "help":
                _print_help()
                continue

            elif cmd_lower == "status":
                _print_status(agent, mcp_manager, current_target, current_phase, config)
                continue

            elif cmd_lower.startswith("target "):
                current_target, current_phase, restored_loaded = _prepare_repl_target(
                    agent,
                    user_input[7:].strip(),
                    current_target,
                    current_phase,
                )
                if restored_loaded:
                    console.print(_("cli.target_restored", target=current_target))
                console.print(_("cli.target_set", target=current_target))
                continue

            elif cmd_lower == "clear":
                current_target = None
                current_phase = "Ready"
                auto_mode_active = False
                last_auto_input = ""
                agent.reset_context()
                console.print(_("cli.conversation_cleared"))
                continue

            elif cmd_lower == "tools":
                tools = mcp_manager.list_available_tools()
                if tools:
                    console.print(_("cli.available_tools"))
                    for tool in tools:
                        console.print(f"  - {tool}")
                else:
                    console.print(_("cli.no_tools"))
                continue

            elif cmd_lower.startswith("report"):
                report_target = user_input[len("report") :].strip() or current_target
                if not report_target:
                    console.print(_("cli.no_target_for_report"))
                    continue

                report_path = _from_main("_generate_report_for_target")(
                    report_target,
                    current_session=agent.session_state
                    if agent.session_state.target == report_target
                    else None,
                    report_format=config.session.report_format,
                    run_dir=getattr(agent, "run_dir", None) or None,
                )
                console.print(_("cli.report_generated", path=report_path))
                continue

            elif cmd_lower.startswith("persistent"):
                explicit_target = user_input[len("persistent") :].strip()
                persistent_target = explicit_target or current_target
                if not persistent_target:
                    console.print(
                        _("cli.host_no_set")
                    )
                    continue

                current_target, current_phase, restored_loaded = _prepare_repl_target(
                    agent,
                    persistent_target,
                    current_target,
                    current_phase,
                )
                persistent_target = current_target
                if restored_loaded:
                    console.print(_("cli.target_restored", target=persistent_target))

                from vulnclaw.agent.core import PersistentCycleResult

                rounds_per_cycle = config.session.persistent_rounds_per_cycle
                max_cycles = config.session.persistent_max_cycles
                auto_report = config.session.persistent_auto_report

                console.print(
                    Panel(
                        f"Target: [bold]{persistent_target}[/]\n"
                        f"Rounds per cycle: [bold]{rounds_per_cycle}[/]\n"
                        f"Max cycles: [bold]{max_cycles}[/]\n"
                        f"Auto report: {'[green]on[/]' if auto_report else '[yellow]off[/]'}",
                        title="Persistent Pentest",
                        border_style="cyan",
                    )
                )

                persistent_prompt = (
                    f"Perform an authorized persistent penetration test against {persistent_target}. "
                    + _("cli.target_within_range_and_explicitly_authorized")
                )

                all_cycle_results: list[PersistentCycleResult] = []

                def _on_persistent_step(round_num: int, cycle_num: int, result) -> None:
                    console.print(f"[dim]-- Cycle {cycle_num} | Round {round_num} --[/]")
                    # TerminalStreamSink 已实时流式显示，回调不重复打印
                    console.print()
                    nonlocal current_target, current_phase
                    if result.target:
                        current_target = result.target
                    if result.phase:
                        current_phase = result.phase

                def _on_persistent_cycle(
                    cycle_num: int, cycle_result: PersistentCycleResult
                ) -> None:
                    all_cycle_results.append(cycle_result)
                    console.print(
                        Panel(
                            f"Cycle {cycle_num} completed\n"
                            f"   Total findings: {cycle_result.total_findings}\n"
                            f"   New findings: {cycle_result.new_findings}\n"
                            f"   Report: {cycle_result.report_path or 'not generated'}",
                            title=f"Cycle {cycle_num}",
                            border_style="green" if cycle_result.new_findings == 0 else "red",
                        )
                    )
                    console.print()

                try:

                    async def _run_persistent():
                        await mcp_manager._preinit_chrome_devtools()
                        sink = TerminalStreamSink(console, config.session.show_thinking)
                        return await agent.persistent_pentest(
                            user_input=persistent_prompt,
                            target=persistent_target,
                            rounds_per_cycle=rounds_per_cycle,
                            max_cycles=max_cycles,
                            auto_report=auto_report,
                            on_cycle_step=_on_persistent_step,
                            on_cycle_complete=_on_persistent_cycle,
                            stream_sink=sink,
                        )

                    asyncio.run(_run_persistent())
                    if auto_report and not all_cycle_results:
                        partial_report = _from_main("_generate_report_for_target")(
                            persistent_target,
                            current_session=agent.session_state,
                            report_format=config.session.report_format,
                            run_dir=getattr(agent, "run_dir", None) or None,
                        )
                        console.print(_("cli.partial_report", path=partial_report))
                except KeyboardInterrupt:
                    console.print(f"\n{_('persistent.interrupted_message')}")
                    if agent.session_state.findings:
                        try:
                            final_report = _from_main("_generate_report_for_target")(
                                persistent_target,
                                current_session=agent.session_state,
                                report_format=config.session.report_format,
                                run_dir=getattr(agent, "run_dir", None) or None,
                            )
                            console.print(_("persistent.final_report", path=final_report))
                        except Exception as exc:
                            console.print(_("persistent.failed_final_report", exc=exc))

                # Summary
                tf = len(agent.session_state.findings)
                console.print(
                    _("persistent.finished_summary", cycles=len(all_cycle_results), findings=tf)
                )
                continue

            elif cmd_lower == "think":
                # Toggle think tag display
                config.session.show_thinking = not config.session.show_thinking
                state_str = (
                    "[green]shown[/]" if config.session.show_thinking else "[yellow]hidden[/]"
                )
                console.print(f"[*] Thinking visibility: {state_str}")
                console.print(_("cli.thinking_toggle_hint"))
                continue

            elif cmd_lower == "think on":
                config.session.show_thinking = True
                console.print(_("cli.thinking_shown"))
                continue

            elif cmd_lower == "think off":
                config.session.show_thinking = False
                console.print(_("cli.thinking_hidden"))
                continue

            # Handle auto mode persistence: exit auto mode on explicit commands
            if auto_mode_active and user_input.lower().strip() in (
                "chat", "manual", "exit auto", "单轮", "手动",
            ):
                auto_mode_active = False
                last_auto_input = ""
                console.print(_("cli.auto_mode_exited"))
                is_auto_mode = False
            elif auto_mode_active:
                from vulnclaw.cli.user_intent import (
                    continue_task_prompt,
                    is_affirmative_continue,
                    is_conversational_checkin,
                )

                # Sticky auto mode must not swallow readiness check-ins
                # ("ready to begin?") — answer first via single-turn chat.
                if is_conversational_checkin(user_input):
                    is_auto_mode = False
                elif is_affirmative_continue(user_input):
                    is_auto_mode = True
                    user_input = continue_task_prompt(last_auto_input, current_target)
                else:
                    is_auto_mode = True
            else:
                # Route to agent and detect whether this should be an autonomous loop
                is_auto_mode = _should_auto_pentest(user_input, current_target)

            # Detect target switch and reset context if the user mentions a new target.
            # Copilot mode (VULNCLAW_REPL_NO_AUTO) mines nothing — see the helper.
            new_target = _mined_target_for_session(user_input)
            if _should_switch_target(user_input, new_target, current_target):
                console.print(_("cli.target_switch", from_target=current_target, to_target=new_target))
                current_target = new_target
                current_phase = "Recon"
                agent.reset_context()
                # Reset auto mode on target switch
                auto_mode_active = False
                last_auto_input = ""
            elif (
                new_target
                and not current_target
                and not _is_api_path_prose(new_target)
                and not _is_cited_target(user_input, new_target)
            ):
                # round13 F4: the first-adoption branch needs the same API-path
                # gate as the switch guard — without it a first message citing
                # bare API-path prose ("/storage/...") still locked the run to
                # a literal path target + strict local constraints (the exact
                # first-shot variant of the 2026-10-01 PrizeEscrow postmortem).
                # The citation gate is the same story one round later: a FIRST
                # message that is nothing but a pasted challenge description must
                # not adopt its documentation URL as the session target either.
                current_target = new_target
                current_phase = "Ready"

            # Local file/path targets get a hard scope guard so the run cannot
            # traverse the whole disk or scan the operator's own network.
            if _is_local_path_target(current_target or ""):
                _apply_local_path_constraints(agent, current_target)

            # Save last auto input for resume on empty Enter
            if is_auto_mode:
                last_auto_input = user_input

            try:
                if is_auto_mode:
                    # Autonomous pentest loop
                    console.print(_("cli.enter_auto_mode"))
                    console.print()

                    # 默认走目标驱动 solve 引擎；engine=rounds 时回退到旧固定轮数循环
                    if getattr(config.session, "engine", "solve") == "solve":
                        async def _run_auto():
                            await mcp_manager._preinit_chrome_devtools()
                            sink = TerminalStreamSink(console, config.session.show_thinking)

                            async def call():
                                return await agent.solve(
                                    user_input,
                                    target=current_target,
                                    max_steps=config.session.solve_max_steps,
                                    max_tool_rounds=config.session.solve_max_tool_rounds,
                                    stream_sink=sink,
                                    on_event=_make_solve_event_printer(console),
                                )

                            async def after_result(result):
                                agent_state = agent.context.state.agent_state.get_summary()
                                done = agent_state.get("completed")
                                console.print()
                                console.print(
                                    Panel(
                                        f"{_('cli.goal_achieved') if done else _('cli.goal_not_achieved')} — "
                                        f"steps={agent_state.get('steps', 0)} "
                                        f"evidence={agent_state.get('evidence', 0)} "
                                        f"tools={agent_state.get('tool_calls', 0)}\n"
                                        f"{_('cli.reason')}: {agent_state.get('complete_reason') or _('cli.reason_not_complete')}",
                                        title="Solve",
                                        border_style="green" if done else "yellow",
                                    )
                                )
                                if done:
                                    _emit_solve_report_if_completed(agent, config)

                            await _run_repl_agent_call(agent, call=call, after_result=after_result)

                        _ensure_repl_checkpoint_callback(agent)
                        try:
                            asyncio.run(_run_auto())
                        except KeyboardInterrupt:
                            # Persist the interrupted run too (the command path
                            # checkpoints "interrupt"); the exception still
                            # propagates to the REPL interrupt handling.
                            _checkpoint_repl_agent(agent, "interrupt")
                            _retrieve_interrupted_task()
                            raise
                        # The panel can say 目标达成 while the saved state sits at
                        # run_start — persist the finished run. TECH-DEBT ## 3 ①:
                        # panel-done ⇒ state must update.
                        _checkpoint_repl_agent(agent, "run_complete")
                        auto_mode_active = True
                        console.print(_("cli.auto_mode_hint"))
                        continue

                    async def _run_auto():
                        sink = TerminalStreamSink(console, config.session.show_thinking)
                        async def call():
                            def on_step(round_num, result):
                                nonlocal current_target, current_phase
                                console.print(f"[dim]-- Round {round_num} --[/]")
                                console.print()
                                if result.target:
                                    current_target = result.target
                                if result.phase:
                                    current_phase = result.phase

                            return await agent.auto_pentest(
                                user_input,
                                target=current_target,
                                max_rounds=config.session.max_rounds,
                                on_step=on_step,
                                stream_sink=sink,
                            )

                        async def after_result(results):
                            if results:
                                total_findings = len(agent.session_state.findings)
                                total_steps = len(agent.session_state.executed_steps)
                                console.print()
                                console.print(
                                    Panel(
                                        f"{_('auto_pentest.finished')}\n"
                                        f"{_('auto_pentest.rounds', rounds=len(results))}\n"
                                        f"{_('auto_pentest.steps', steps=total_steps)}\n"
                                        f"{_('auto_pentest.findings', findings=total_findings)}",
                                        title=_("auto_pentest.title"),
                                        border_style="green" if total_findings == 0 else "red",
                                    )
                                )

                                if any(
                                    token in user_input.lower()
                                    for token in (
                                        "输出",
                                        "保存",
                                        "写到",
                                        "导出",
                                        "save",
                                        "write",
                                        "export",
                                    )
                                ):
                                    _auto_save_recon_report(agent, user_input, config)

                        await _run_repl_agent_call(agent, call=call, after_result=after_result)

                    _ensure_repl_checkpoint_callback(agent)
                    try:
                        asyncio.run(_run_auto())
                    except KeyboardInterrupt:
                        _checkpoint_repl_agent(agent, "interrupt")
                        _retrieve_interrupted_task()
                        raise
                    _checkpoint_repl_agent(agent, "run_complete")
                    auto_mode_active = True
                    # The run finished on its own (not interrupted), so there is
                    # nothing to resume: clearing the launch text is what stops a
                    # later empty Enter from silently re-playing the whole task.
                    # Measured 2026-10-06: after a completed CTF2 solve the operator
                    # typed a NEW task, lost that line to the Ctrl+C exit-confirm,
                    # pressed Enter, and the REPL re-ran the OLD challenge instead
                    # of asking (the agent looked like it ignored the operator).
                    last_auto_input = ""
                    console.print(_("cli.auto_mode_hint"))

                else:
                    # Single-turn chat
                    async def _run_agent():
                        await mcp_manager._preinit_chrome_devtools()
                        sink = TerminalStreamSink(console, config.session.show_thinking)
                        async def call():
                            return await agent.chat(user_input, target=current_target, stream_sink=sink)

                        async def after_result(result):
                            nonlocal current_target, current_phase
                            if result:
                                # Copilot mode keeps the operator's target: the agent
                                # reports what it mined from the paste (see helper).
                                current_target = _target_after_agent_result(
                                    current_target, result.target
                                )
                                if result.phase:
                                    current_phase = result.phase
                                # 流式输出已由 TerminalStreamSink 实时显示；仅补印 sink 未显示的错误
                                if result.output and result.output.startswith("[!]"):
                                    _print_agent_output(result.output, config)

                        await _run_repl_agent_call(agent, call=call, after_result=after_result)

                    _ensure_repl_checkpoint_callback(agent)
                    asyncio.run(_run_agent())
                    _checkpoint_repl_agent(agent, "chat_complete")

            except KeyboardInterrupt:
                if is_auto_mode:
                    # KEEP auto mode active after an interrupt (round-11 UX
                    # finding: clearing the flag here meant the agent stopped
                    # self-resuming after every Ctrl+C — the operator had to
                    # re-trigger autonomous mode by hand each time). Sticky
                    # auto stays on; an empty Enter resumes the in-flight run
                    # via _repl_has_in_progress_run, and "exit auto"/"manual"
                    # remains the explicit way out.
                    console.print()
                    console.print(_("cli.interrupted"))
                    console.print(_("cli.auto_resume_hint"))
                else:
                    console.print(f"\n{_('cli.interrupted')}")
            except Exception as e:
                # Escape Rich markup chars in exception message to prevent MarkupError
                from rich.markup import escape as rich_escape

                console.print(_("cli.error", msg=rich_escape(format_llm_user_error(e))))

        except KeyboardInterrupt:
            now = time.monotonic()
            if exit_requested and (now - _last_ctrlc_time) < 3.0:
                console.print(_("cli.bye"))
                break
            exit_requested = True
            _last_ctrlc_time = now
            console.print(f"\n{_('cli.press_again')}")
        except EOFError:
            break

    # Retrieve any recorded interrupt exception so asyncio does not print
    # "Task exception was never retrieved" at teardown (TECH-DEBT ## 3 ②b).
    _retrieve_interrupted_task()

    # Cleanup — suppress SIGINT to prevent re-trigger during threading shutdown
    import signal

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    mcp_manager.stop_all()
    console.print("[dim]MCP services stopped.[/]")


def _print_help() -> None:
    """Print REPL help."""
    help_text = f"""
 [bold]{_("help.commands")}[/]:
  {_("help.target")}
  {_("help.status")}
  {_("help.tools")}
  {_("help.report")}
  {_("help.think")}
  {_("help.think_on_off")}
  {_("help.persistent")}
  {_("help.persistent_host")}
  {_("help.clear")}
  {_("help.chat")}
  {_("help.help")}
  {_("help.exit")}

 [bold]{_("help.auto_mode")}[/]:
  {_("help.auto_mode_desc")}
  {_("help.auto_mode_example")}
  {_("help.auto_mode_stays")}

 [bold]{_("help.persistent_mode")}[/]:
  {_("help.persistent_mode_desc")}
  {_("help.persistent_cli")}
  {_("help.persistent_repl")}

 [bold]{_("help.learning")}[/]:
  {_("help.learning_desc")}
  {_("help.learning_experience")}
  {_("help.learning_learn")}
  {_("help.learning_feedback")}

 [bold]{_("help.examples")}[/]:
  {_("help.example_pentest")}
  {_("help.example_scan")}
  {_("help.example_vuln")}
  {_("help.example_exploit")}
  {_("help.example_report")}
"""
    console.print(Panel(help_text, title=_("help.title"), border_style="cyan"))


def _print_status(agent, mcp_manager, target, phase, config) -> None:
    """Print current session status."""
    think_state = "[green]shown[/]" if config.session.show_thinking else "[yellow]hidden[/]"
    phase_label = _localized_phase_label(phase)
    console.print(
        Panel(
            f"{_('status.target', target=target or 'Not set')}\n"
            f"{_('status.phase', phase=phase_label)}\n"
            f"{_('status.mcp_services', count=mcp_manager.running_count())}\n"
            f"{_('status.tools', count=len(mcp_manager.list_available_tools()))}\n"
            f"{_('status.thinking', state=think_state)}",
            title=_("status.title"),
            border_style="green",
        )
    )


# ── Headless / run-option helpers shared by the sub-commands ──────────


def _validate_headless_choices(
    scan_mode: str, fail_on: str, scope_mode: str
) -> Optional[str]:
    """Return an error message for a bad headless choice, else ``None``."""
    if scan_mode not in headless.SCAN_MODES:
        return f"--scan-mode must be one of: {', '.join(headless.SCAN_MODES)}"
    if fail_on not in headless.FAIL_ON_MODES:
        return f"--fail-on must be one of: {', '.join(headless.FAIL_ON_MODES)}"
    if scope_mode not in headless.SCOPE_MODES:
        return f"--scope-mode must be one of: {', '.join(headless.SCOPE_MODES)}"
    return None


def _run_non_interactive(
    *,
    target: str,
    output: Optional[str],
    profile: "headless.ScanProfile",
    scan_mode: str,
    scope_mode: str,
    fail_on: str,
    run_coro_factory,
    classification_holder: dict,
    run_dir_holder: Optional[dict] = None,
) -> None:
    """Drive a headless run: no prompts, structured output, exit-code contract.

    Any crash during the scan exits :data:`headless.EXIT_ERROR` (1) — a broken
    scan never exits 0. On completion the finding set is mapped to an exit code
    under ``--fail-on`` and a ``summary.json`` is written into the run directory.

    Artifacts (report + summary.json) land in the *same* run directory the agent
    wrote its evidence into (``agent.run_dir``, reported back through
    ``run_dir_holder``), so the report reader resolves the run's own
    ``evidence/`` tree. Only when no run directory reached the agent (e.g. a
    legacy/read-only flow) do we synthesise the deterministic headless path.
    """
    from datetime import datetime

    try:
        asyncio.run(run_coro_factory())
    except typer.Exit:
        raise
    except BaseException as exc:  # noqa: BLE001 - CI must see a nonzero exit, not a traceback
        err_console.print(f"[!] Scan did not complete: {type(exc).__name__}: {exc}")
        raise typer.Exit(headless.EXIT_ERROR) from exc

    classification = classification_holder.get("classification") or headless.FindingClassification(
        verified=0, candidates=0
    )
    exit_code = headless.determine_exit_code(classification, fail_on)

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    authoritative = str((run_dir_holder or {}).get("run_dir") or "")
    if authoritative:
        run_dir = Path(authoritative)
    else:
        run_dir = headless.run_directory(_from_main("RUNS_DIR"), target, run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    # Converge the two run layouts (D4): a scan run must carry the same skeleton
    # as a RunContext run, above all ``evidence/``, because the reader no longer
    # falls back to another run's store.
    from vulnclaw.run_context import ensure_run_layout

    ensure_run_layout(run_dir)
    # Co-locate the report inside the run directory unless the caller pinned a
    # path with --output, so all structured output for a run lives in one place.
    report_output = output or str(run_dir / "report.md")
    report_path = _from_main("_generate_report_for_target")(
        target, output_path=report_output, run_dir=str(run_dir)
    )

    summary = headless.build_run_summary(
        target=target,
        scan_mode=scan_mode,
        scope_mode=scope_mode,
        fail_on=fail_on,
        profile=profile,
        classification=classification,
        exit_code=exit_code,
        report_path=str(report_path),
    )
    summary_path = headless.write_run_artifacts(run_dir, summary)

    console.print(
        f"[*] findings: verified={classification.verified} "
        f"candidates={classification.candidates} | "
        f"exit={exit_code} ({headless.exit_code_meaning(exit_code)})"
    )
    console.print(f"[*] run artifacts: {summary_path}")
    console.print(_("cli.report_generated", path=report_path))
    raise typer.Exit(exit_code)


def _run_context_kwargs(
    *,
    run_name: Optional[str] = None,
    resume_run_name: Optional[str] = None,
    runs_dir: Optional[str] = None,
    additional_targets: Optional[list[str]] = None,
    target_type: Optional[str] = None,
    mount: bool = False,
    repair: bool = False,
    force_fresh: bool = False,
    no_import: bool = False,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if run_name:
        kwargs["run_name"] = run_name
    if resume_run_name:
        kwargs["resume_run_name"] = resume_run_name
    if runs_dir:
        kwargs["runs_dir"] = runs_dir
    if additional_targets:
        kwargs["additional_targets"] = additional_targets
    if target_type:
        kwargs["target_type"] = target_type
    if mount:
        kwargs["mount"] = mount
    if repair:
        kwargs["repair"] = repair
    if force_fresh:
        kwargs["force_fresh"] = force_fresh
    if no_import:
        kwargs["no_import"] = no_import
    return kwargs


def _scope_option_kwargs(values: dict[str, Any]) -> dict[str, Any]:
    return {field: values.get(field) for field in SCOPE_FIELDS}


def _print_run_completion_summary(summary: dict[str, Any]) -> None:
    run_name = summary.get("run_name")
    run_dir = summary.get("run_dir")
    if not run_name or not run_dir:
        return
    artifacts = summary.get("artifact_locations", {})
    console.print(
        Panel(
            f"Run: [bold]{run_name}[/]\n"
            f"Directory: [bold]{run_dir}[/]\n"
            f"Findings: [bold]{summary.get('verified_count', 0)} verified / "
            f"{summary.get('pending_count', 0)} pending / "
            f"{summary.get('candidate_count', 0)} candidate[/]\n"
            f"Artifacts: findings={artifacts.get('findings', '')} "
            f"reports={artifacts.get('reports', '')} evidence={artifacts.get('evidence', '')}\n"
            f"Resume: [bold]{summary.get('resume_command', '')}[/]\n"
            f"Exit: [bold]{summary.get('exit_code', 0)}[/] "
            f"({summary.get('exit_meaning', 'completed')})",
            title="Run Summary",
            border_style="green" if summary.get("exit_code", 0) == 0 else "yellow",
        )
    )


# ── Target-intent mining (which target does this message name?) ───────


def _repl_no_auto() -> bool:
    """True when the operator pinned the REPL to single-turn chat.

    ``VULNCLAW_REPL_NO_AUTO=1`` (also true/yes/on) is the **copilot-mode** switch: a
    human drives the target console and pastes command output back, so the REPL must
    answer in one turn instead of starting the autonomous loop.

    Field motivation (2026-10-09 rehearsal): an incident-response paste always carries
    paths such as ``/usr/sbin/cron`` or ``/tmp/.x/.kworker``, and the local-path branch
    at the end of :func:`_should_auto_pentest` extracts a "target" from them (a cron
    line ``*/3 * * * *`` yields ``/3``), so *every* pasted message re-entered the
    autonomous loop. Unset keeps the previous behaviour byte-for-byte.
    """
    return os.environ.get("VULNCLAW_REPL_NO_AUTO", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _mined_target_for_session(user_input: str) -> Optional[str]:
    """Session target mined from the operator's message, if any.

    In copilot mode (:func:`_repl_no_auto`) **nothing is mined**: the operator drives
    the target console and pastes its output back, and such a paste would otherwise
    set the session target to a path taken from the dump (measured 2026-10-09:
    ``/usr/sbin/cron``, plus ``/3`` from a ``*/3 * * * *`` cron line). Mine nothing and
    let the operator set a target deliberately with the ``target`` command when one is
    actually wanted — a pasted terminal dump never is one.
    """
    if _repl_no_auto():
        return None
    return _extract_target_from_input(user_input)


def _target_after_agent_result(current: Optional[str], reported: Optional[str]) -> Optional[str]:
    """Session target after one single-turn chat.

    Copilot mode keeps the operator's target untouched: the agent reports back whatever
    *it* mined out of the pasted dump (measured 2026-10-09: ``access.log`` and
    ``/usr/sbin/cron``), and adopting that would silently retarget the session off a
    log line. Outside copilot mode this is the previous behaviour, ``reported or
    current`` -- the same "only overwrite when the agent reported one" rule as before.
    """
    if _repl_no_auto():
        return current
    return reported or current


def _should_auto_pentest(user_input: str, current_target: Optional[str]) -> bool:
    """Determine if user input should trigger autonomous pentest loop.

    Triggers when:
    - User explicitly asks for a full pentest with a target
    - User mentions a target plus action keywords like "渗透测试" or "打一下"
    - User asks to solve a CTF / find a flag with a target
    - User asks for information gathering / recon / OSINT with a target
    - A target is present + multi-step task indicators
    """
    from vulnclaw.cli.user_intent import is_conversational_checkin

    # Operator opt-out (copilot mode): never take the autonomous path. Checked before
    # every other branch so a pasted terminal dump cannot re-enter the solve loop.
    if _repl_no_auto():
        return False

    # Readiness / meta questions (e.g. "ready to begin bug hunting?") get a
    # spoken answer first — never jump straight into the solve tool loop.
    if is_conversational_checkin(user_input):
        return False

    input_lower = user_input.lower()

    # A CTF2 practice task is autonomous by nature: it names a practice ground and
    # a challenge and expects the solve loop (ctf2 MCP tools + platform_submit).
    # Its ids are UUIDs, so the target-gated keyword branch below would reject it
    # and drop the turn into single-turn chat.
    if _ctf2_task_ref(user_input):
        return True

    # Explicit auto-mode triggers
    auto_keywords = [
        "渗透测试",
        "进行渗透",
        "做渗透",
        "打一下",
        "全面测试",
        "pentest",
        "full test",
        "auto",
        "自主渗透模式",
        "自主模式",
        "找出flag",
        "找到flag",
        "拿flag",
        "get flag",
        "find flag",
        "解题",
        "做题",
        "答题",
        "知识竞赛",
        "挑战",
        "challenge",
        "ctf",
        "弱口令",
        "爆破",
        "绕过",
        "bypass",
        "brute",
        "搜集",
        "收集",
        "信息收集",
        "侦察",
        "recon",
        "reconnaissance",
        "社工",
        "osint",
        "情报",
        "intelligence",
        "分析目标",
        "目标分析",
        "资产发现",
        "目录扫描",
        "探测",
        "探索",
        "调查",
        "investigate",
        "enumerate",
        "全面分析",
        "深度分析",
        "详细分析",
        "全面扫描",
        "子域名",
        "subdomain",
    ]

    # Single-step queries should NOT trigger auto mode
    single_step_keywords = [
        "生成报告",
        "report",
        "help",
        "帮助",
    ]

    # If it's clearly a single-step query, don't auto-loop
    # But if it also has auto keywords, still go auto (e.g. "收集信息并生成报告")
    if any(kw in input_lower for kw in single_step_keywords) and not any(
        kw in input_lower for kw in auto_keywords
    ):
        return False

    # If it has auto-mode keywords, trigger auto loop
    if any(kw in input_lower for kw in auto_keywords):
        # Must have a target (either in input or already set). The input side goes
        # through _has_actionable_target so a cited documentation URL is not counted
        # as one (see that function).
        has_target = bool(current_target) or _has_actionable_target(user_input)
        return has_target

    # Local file/path targets are multi-step analysis jobs by nature: a path,
    # an archive (zip/tar/…), or a file-like token with an explicit task verb.
    local_target = _extract_target_from_input(user_input)
    if local_target and _is_local_path_target(local_target):
        return True

    # Fallback: has target + multi-step task -> auto
    has_target = bool(current_target) or _has_actionable_target(user_input)
    if has_target:
        multi_step_indicators = [
            "并",
            "然后",
            "输出",
            "保存",
            "写到",
            "导出",
            "所有",
            "全部",
            "完整",
            "详细",
        ]
        if any(ind in input_lower for ind in multi_step_indicators):
            return True

    return False


def _is_local_path_target(target: str) -> bool:
    """Return True when a target is a local file/directory path, not a network host.

    Guards the autonomous loop so a local file analysis job is NOT treated as a
    network scan target (no host/port discovery, no outbound scanning of the
    machine's own network from a local-file prompt).
    """
    import re

    if not target:
        return False
    # Windows drive path / POSIX absolute / home / dot-relative
    if re.match(r"^[A-Za-z]:[\\/]", target) or target.startswith(("/", "~/", "./", "../", ".\\")):
        return True
    # Bare token with a file-ish extension
    if re.search(r"\.(?:zip|tar|gz|7z|rar|png|jpg|jpeg|gif|bmp|txt|log|pcap|py|php|bin|iso|docx?|xlsx?|pdf)$", target, flags=re.IGNORECASE):
        return True
    return False


def _apply_local_path_constraints(agent: Any, target: str) -> None:
    """Scope an autonomous run to a local file/path target so it cannot touch the
    rest of the machine (no full-disk traversal, no local network scanning).

    Sets ``allowed_paths`` to the target (plus its parent when the target is a
    directory) and blocks loopback/private ranges so a local-file task never
    turns into an outbound network recon against the operator's own network.

    The private-range entries are **CIDR**: the earlier spellings (``"10."``,
    ``"192.168."``) were inert, because ``host_in_scope`` matches a bare IP
    pattern exactly and has no prefix form — measured 2026-10-08, the guard
    blocked nothing while reading as if it blocked three ranges.

    A failure here is reported rather than swallowed. This is the only place a
    local-file task gets its network lockdown, and the guard is installed *before*
    the autonomous loop starts, so a silent failure would hand the run an
    unscoped machine while the operator believes the sweep is confined to the
    target -- the exact opposite of what a guard is for.
    """
    if not _is_local_path_target(target):
        return
    try:
        from vulnclaw.config.domain_models import TaskConstraints

        tc: TaskConstraints = agent.context.state.task_constraints
        tc.strict_mode = True
        if target and target not in tc.allowed_paths:
            tc.allowed_paths.append(target)
        for host in (
            "localhost",
            "127.0.0.0/8",
            "::1",
            "0.0.0.0",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ):
            if host not in tc.blocked_hosts:
                tc.blocked_hosts.append(host)
    except Exception as exc:
        err_console.print(
            f"[!] 本地路径任务的网络封锁未能安装（{exc}）——"
            "本次运行将不受本地文件作用域限制，请核实后重试",
            highlight=False,
        )


#: The CTF2 practice-ground task sentence the platform hands the operator, e.g.
#: ``用 ctf2 工具解练习场 <practice_id> 的题目 <challenge_id>：<name>…``. Both ids
#: are bare UUIDs, so every generic target pattern below (URL / local path /
#: file-with-extension / IP / domain) misses the sentence -- and a sentence with
#: no extractable target fails ``_should_auto_pentest``'s target gate and drops
#: the turn into single-turn chat, never reaching the solve loop where the ctf2
#: MCP tools and ``platform_submit`` live (2026-10-06: an afternoon of solves
#: went through the ref-token/``solve`` path, while the same task pasted into the
#: REPL only chatted).


_CTF2_UUID = (
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_CTF2_PRACTICE_RE = re.compile(rf"练习场[:：\s]*({_CTF2_UUID})")
_CTF2_CHALLENGE_RE = re.compile(rf"题目[:：\s]*({_CTF2_UUID})")


def _ctf2_task_ref(user_input: str) -> Optional[str]:
    """Ref token for a CTF2 practice task sentence, else None.

    Returns ``ctf2:practice:<practice_id>:<challenge_id>`` -- the SAME identity the
    dedicated ``vulnclaw ctf2`` hand-off and the platform's own ``solve --target``
    use (see the ctf2 command's ``ref_token``). Identity has to match or the reuse
    chain splits: a note captured through the REPL is looked up by a
    platform-launched run of the same challenge, and vice versa. Falls back to the
    bare practice id when the sentence names no challenge.

    Deliberately preferred over the generic patterns below: a pasted task sentence
    often carries a URL from the challenge DESCRIPTION (``环境来源与官方说明:
    https://github.com/vulhub/...``), which used to be mined as the target --
    filing the run's notes under ``github.com`` and authorising scope on a
    documentation link.
    """
    text = str(user_input or "")
    practice = _CTF2_PRACTICE_RE.search(text)
    if not practice:
        return None
    challenge = _CTF2_CHALLENGE_RE.search(text)
    if challenge:
        return f"ctf2:practice:{practice.group(1)}:{challenge.group(1)}"
    return practice.group(1)


def _extract_target_from_input(user_input: str) -> Optional[str]:
    """Extract target from user input string.

    Local file/directory paths are recognized FIRST so they are never
    mis-parsed as hostnames (e.g. ``C:\\Users\\伟\\Downloads\\misc2.zip`` or a
    bare ``misc2.zip`` must stay a local file target, not a fake domain).
    """
    import re

    stripped = user_input.strip()
    if not stripped:
        return None

    # 0) CTF2 practice task: recognised first -- no pattern below can see a bare
    #    UUID, and the challenge description such a sentence usually carries holds
    #    a documentation URL that must not become the target.
    ctf2_ref = _ctf2_task_ref(stripped)
    if ctf2_ref:
        return ctf2_ref

    # 1) URL (with optional port) — must be checked before the POSIX-path branch
    #    so "https://example.com" is never clipped to "/example.com".
    url_match = re.search(r"(https?://[a-zA-Z0-9][-a-zA-Z0-9.:]*)", stripped)
    if url_match:
        return url_match.group(1).rstrip("/")

    # 2) Local absolute/relative paths (Windows drive, POSIX, home). Detect
    #    before the bare-file/domain rules so a path never becomes a fake host.
    #    The POSIX branch only accepts a single leading slash followed by ASCII
    #    path characters (``/home/...``), and never swallows the ``//`` of a
    #    scheme-less URI nor a stray ``/`` in prose such as "黑板/证据".
    local_path_match = re.search(
        r"((?:[A-Za-z]:[\\/]|~[/\\]|\.\.?[/\\]|\.\\)[^\s，,；;、]+"
        r"|(?<![A-Za-z0-9:])/[A-Za-z0-9._][A-Za-z0-9._~%+\\/-]*)",
        stripped,
        flags=re.IGNORECASE,
    )
    if local_path_match:
        return local_path_match.group(1).rstrip("\\/")

    # 3) A bare token with a file-ish extension (zip, tar, gz, png, txt, …)
    #    is a local file target, not a domain. The stem is Unicode-aware but
    #    never contains spaces, so "请分析 target.zip 的漏洞" still mines only
    #    "target.zip". The lookbehind refuses a start that is the tail of a
    #    bigger word/path (CJK counts as ``\w``), so "…使用console.log" never
    #    mines "console.log" here.
    for file_like_match in re.finditer(
        r"(?<![\w\-.])"
        r"((?:[^\W\d_\u4e00-\u9fff][\w.\-]*"
        r"|[\u4e00-\u9fff][\u4e00-\u9fff0-9_.\-]*)"
        r"\.(?:zip|tar|gz|7z|rar|png|jpg|jpeg|gif|bmp|txt|log|pcap|py|php|bin|iso|docx?|xlsx?|pdf))\b",
        stripped,
        flags=re.IGNORECASE,
    ):
        return file_like_match.group(1).strip()

    # 4) IP address
    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", stripped)
    if ip_match:
        return ip_match.group(1)
    # 5) Domain — same two guards the agent layer's ``detect_target`` already
    #    carries (input_analysis): the lookbehind refuses a candidate that is
    #    the tail of a bigger word (CJK counts as \w, so "…使用console.log"
    #    never mines a "host"), and ``_is_plausible_host`` rejects version
    #    strings ("glibc 2.27"). The REPL copy lacked both — measured
    #    2026-10-15, a pasted brief's "建议使用console.log" retargeted a session.
    for domain_match in re.finditer(
        r"(?<![\w*.])([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)", stripped
    ):
        candidate = domain_match.group(1)
        if _is_plausible_host(candidate):
            return candidate
    return None


def _has_actionable_target(user_input: str) -> bool:
    """Whether the message names a target the run may actually act on.

    One authority for a question three layers ask. The citation gate refuses to
    *retarget* onto a pasted documentation URL and the scope miner skips it, but the
    auto-mode gate read "has a target" straight off ``_extract_target_from_input`` --
    which returns the FIRST candidate, i.e. the doc link in a pasted description. The
    same URL was therefore "not a target" for the switch guard and "a target" for auto
    mode: a description carrying nothing BUT its source citation went auto with no
    endpoint named anywhere (2026-10-06 merge).

    ``detect_target`` is the agent layer's answer to this exact question and skips
    cited references, so both layers now share one verdict instead of two rule chains.
    Local artefacts remain targets -- it never looks at paths -- and a non-cited first
    candidate is accepted as-is, so only the "cited URL is the only candidate" case
    changes verdict.
    """
    first = _extract_target_from_input(user_input)
    if first and (_is_local_path_target(first) or not _is_cited_target(user_input, first)):
        return True
    return detect_target(user_input) is not None


def _is_cited_target(user_input: str, target: Optional[str]) -> bool:
    """Whether ``target`` is a cited documentation/source URL rather than a target.

    Pasted task descriptions carry their source material as prose ("环境来源与官方说明:
    https://github.com/vulhub/...") and the URL that follows is a citation. Acting on it
    once replaced a live session target with the doc host, reset the context, dropped auto
    mode — and, because the same URL was mined as the run's scope, the real endpoint named
    later in the very same description was then refused with "[constraint_violation] Host
    ... is outside allowed scope [github.com]" (2026-10-06 GeoServer CVE-2024-36401
    postmortem). Consumed by BOTH the target-switch guard and the first-adoption branch,
    the same way ``_is_api_path_prose`` is.
    """
    if not user_input or not target:
        return False
    return _is_cited_candidate(
        user_input,
        target,
        user_input.find(target),
        _citation_url_spans(user_input),
    )


def _is_api_path_prose(target: str) -> bool:
    """A single-segment POSIX path ("/storage", "/logs", "/session") extracted
    from a task description is API-path prose, not a target: acting on it once
    replaced a live HTTP target with a literal path AND applied local path
    constraints that locked every real request out of scope (2026-10-01
    PrizeEscrow postmortem). Consumed by BOTH the target-switch guard and the
    first-adoption branch (round13 F4: the first message was the remaining
    variant that still locked the run).

    Matching runs on the whitespace-stripped input with ``re.fullmatch``:
    ``$`` alone also matches just before a string-final newline, which let
    artifacts like ``"/logs\\n\\n"`` slip past as adoptable targets
    (round13 low note).
    """
    import re

    return bool(re.fullmatch(r"/[A-Za-z0-9_.\-{}]+", str(target or "").strip()))


def _should_switch_target(
    user_input: str, new_target: Optional[str], current_target: Optional[str]
) -> bool:
    """Whether mentioning ``new_target`` should reset the session context.

    A pasted knowledge-quiz question often cites bare IPs/domains (e.g.
    "192.168.1.1 属于哪类地址") or full URLs in its stem ("判断题：
    https://www.12377.cn 是…"); those are quiz content, not a target switch —
    never reset the session context on them. A URL combined with explicit
    retarget phrasing ("改打 http://x" / "切换到 http://x") IS a real switch.
    Genuine mid-quiz retargeting to a bare IP can still use the ``target``
    command.

    A *cited* documentation URL (``环境来源与官方说明: https://github.com/vulhub/...``)
    is likewise never a retarget: pasting a challenge description used to switch the
    session off the live endpoint onto the doc host, reset the context and drop auto
    mode, and the doc host was mined as the run's whole scope on top of that
    (2026-10-06 GeoServer CVE-2024-36401 postmortem). An explicit operator retarget can
    still use the ``target`` command.
    """
    import re

    if not new_target or not current_target or new_target == current_target:
        return False
    if _is_api_path_prose(new_target):
        return False
    if _is_cited_target(user_input, new_target):
        return False
    if not _looks_like_quiz(user_input):
        return True
    if new_target.startswith(("http://", "https://")):
        return bool(
            re.search(r"改打|切换到|切换目标|换成|目标改为|换个目标|转打", user_input)
        )
    return False


def _auto_save_recon_report(agent, user_input: str, config) -> None:
    """Auto-save a recon report after auto_pentest completes when user requested file output."""
    import re
    from datetime import datetime

    try:
        state = agent.session_state
        target = state.target or "unknown"

        # Determine output path
        # Check if user specified a path
        path_match = re.search(
            r"(?:保存到|写到|输出到|导出到|save to|write to|output to|export to)\s*([^\s,，]+)",
            user_input,
            re.IGNORECASE,
        )
        if path_match:
            output_path = path_match.group(1)
        else:
            safe_name = re.sub(r"[^\w]", "_", target)[:30]
            date_str = datetime.now().strftime("%Y%m%d_%H%M")
            output_path = str(config.session.output_dir / f"{safe_name}_recon_{date_str}.md")

        from vulnclaw.report.generator import generate_report

        generate_report(
            state,
            output_path,
            report_format=config.session.report_format,
        )

        console.print(f"\n[+] Recon report saved: {output_path}")

    except Exception as e:
        console.print(f"\n[!] Failed to auto-save report: {e}")
