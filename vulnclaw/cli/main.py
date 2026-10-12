"""VulnClaw CLI main entry point with REPL and sub-commands."""

# ruff: noqa: E402

from __future__ import annotations

import asyncio
import os
import sys
from typing import Optional


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

from vulnclaw import __version__
from vulnclaw import headless  # noqa: F401 — re-export / attribute anchor (tests read cli.main.headless.EXIT_*)
from vulnclaw.cli import experience_ops

# === Stream Output Renderer ===
# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: S2 修复 — 共享辅助函数已移至 cli/_helpers.py。
from vulnclaw.cli._helpers import (  # noqa: F401 — _generate_report_for_target / _make_solve_event_printer kept as monkeypatch anchors
    TerminalStreamSink,
    _generate_report_for_target,
    _make_solve_event_printer,
    _run_cli_orchestrated_task,
    console,
    err_console,
)
from vulnclaw.cli.manual import available_topics, render_manual
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


# ── 编排命令族（cli/commands_run.py）—— 注册 + 原样 re-export ───────────────
from vulnclaw.cli.commands_run import (  # noqa: F401 — re-export
    _SOLVE_DECLARED_DEFAULTS,
    _cli_value,
    _is_typer_sentinel,
    _signature_defaults,
    _solve_defaults,
    _typer_sentinel_types,
    exploit,
    go,
    network_scan,
    persistent,
    recon,
    report,
    run,
    scan,
    solve,
)

# 注册顺序逐条保持：run、solve 在平台三件套之前；go/persistent/… 在其后
# （它们原定义在 ctf2/gcs/competition 之后）。名字与 Typer 默认派生一致。
app.command()(run)
app.command()(solve)




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


# go/persistent/recon/scan/network-scan/exploit/report —— 在平台三件套之后注册
app.command("go")(go)
app.command()(persistent)
app.command()(recon)
app.command()(scan)
app.command("network-scan")(network_scan)
app.command()(exploit)
app.command()(report)


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

# ── Config sub-command group（cli/commands_config.py）—— 注册 + 原样 re-export ──
from vulnclaw.cli.commands_config import (  # noqa: F401 — re-export
    config_app,
    config_get,
    config_list,
    config_model,
    config_provider,
    config_root,
    config_set,
)

app.add_typer(config_app, name="config")


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

# ── KB / experience / target-state / plugins 子命令组（cli/commands_admin.py）──
from vulnclaw.cli.commands_admin import (  # noqa: F401 — re-export
    _emit_op_result,
    _parse_kv_options,
    experience_app,
    experience_edit,
    experience_list,
    experience_show,
    experience_approve,
    experience_reject,
    feedback,
    kb_app,
    kb_status,
    kb_update,
    learn,
    plugins_app,
    plugins_info,
    plugins_list,
    plugins_run,
    target_state_app,
    target_state_clear_cmd,
    target_state_diff_cmd,
    target_state_list,
    target_state_preview_cmd,
    target_state_rollback_cmd,
)

app.add_typer(kb_app, name="kb")
app.add_typer(experience_app, name="experience")
app.add_typer(target_state_app, name="target-state")
app.add_typer(plugins_app, name="plugins")

app.command("learn")(learn)
app.command("feedback")(feedback)





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
