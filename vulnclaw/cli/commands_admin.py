"""``vulnclaw kb`` / ``experience`` / ``target-state`` / ``plugins`` —— 运维型子命令组。

从 :mod:`vulnclaw.cli.main` 拆出（2026-10-12）。模块自带各 ``*_app``，
``main.py`` 用 ``app.add_typer(...)`` 逐个注册（与 evidence_cmd 同约定），顺序不变。

``load_config`` 与 ``apply_target_state_to_agent`` 经
:func:`vulnclaw.cli.repl._from_main` 调用时解析：测试把它们 patch 在 ``cli.main`` 上。
"""

from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.panel import Panel

from vulnclaw.cli import experience_ops
from vulnclaw.cli._helpers import console, err_console
from vulnclaw.cli.repl import _from_main
from vulnclaw.i18n import _
from vulnclaw.target_state.store import (
    clear_target_state,
    diff_target_state_snapshots,
    get_target_state_preview,
    list_target_snapshots,
    load_target_state,
    rollback_target_state,
)


kb_app = typer.Typer(help="Security knowledge base commands")

experience_app = typer.Typer(help="Review distilled cross-session experience lessons")

target_state_app = typer.Typer(help="Manage target history state")

plugins_app = typer.Typer(help="Inspect and run vulnerability detection plugins")


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

    config = _from_main("load_config")()
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


def learn(
    run_name: str = typer.Argument(..., help="Completed run name to distill into pending lessons"),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
) -> None:
    """Distill an existing run on demand (for reruns and backfill)."""

    _emit_op_result(
        experience_ops.distill_run(run_name, config=_from_main("load_config")(), runs_dir=runs_dir)
    )


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
            run, rating=rating, notes=notes, config=_from_main("load_config")(), runs_dir=runs_dir
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
