"""``vulnclaw retest`` —— 复测（A1）的命令行入口。

设计上和仓库其余命令保持同一形状（typer 子命令、纯文本输出、失败用非零退出码），
但把状态权威放在 :mod:`vulnclaw.retest.store` 里：CLI 只做「读 findings → 发起/结案 →
打印」，**默认不写回 run 目录里的 findings.json**，避免把已发布的运行产物改成另一种样子。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from vulnclaw.config.domain_models import VulnerabilityFinding
from vulnclaw.retest import service
from vulnclaw.retest.store import (
    RetestConflictError,
    RetestNotFoundError,
    RetestStore,
    RetestStoreError,
)

console = Console()


def _resolve_findings_file(raw: str) -> Path:
    """Accept either a ``findings.json`` or the run directory that holds one."""

    path = Path(raw)
    if path.is_dir():
        candidate = path / "findings.json"
        if not candidate.exists():
            raise typer.BadParameter(f"no findings.json under {path}")
        return candidate
    if not path.exists():
        raise typer.BadParameter(f"findings file not found: {path}")
    return path


def _load_finding(findings_path: str, finding_id: str) -> VulnerabilityFinding:
    document = json.loads(_resolve_findings_file(findings_path).read_text(encoding="utf-8"))
    entries = document.get("findings") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise typer.BadParameter("findings file has no 'findings' list")
    for entry in entries:
        if str(entry.get("finding_id", "")) == finding_id:
            return VulnerabilityFinding.model_validate(entry)
    raise typer.BadParameter(f"finding {finding_id!r} not present in {findings_path}")


def _parse_constraints(raw: str) -> dict[str, str]:
    """``scope=example.test,methods=POST`` → ``{"scope": "example.test", ...}``."""

    parsed: dict[str, str] = {}
    for chunk in (raw or "").split(","):
        key, sep, value = chunk.partition("=")
        if sep and key.strip():
            parsed[key.strip()] = value.strip()
    return parsed


def retest_command(
    finding_id: Optional[str] = typer.Argument(
        None, help="要复测的 finding id（配合 --list / --sweep 时可省略）"
    ),
    findings: Optional[str] = typer.Option(
        None, "--findings", "-f", help="findings.json 或其所在 run 目录"
    ),
    verdict: Optional[str] = typer.Option(
        None, "--verdict", "-v", help="写入第一轮结论：reproduced | fixed | inconclusive"
    ),
    note: str = typer.Option("", "--note", help="结论依据（一句话，会写进记录）"),
    constraints: str = typer.Option(
        "", "--constraints", "-c", help="原任务约束 k=v 逗号分隔，例：scope=example.test,methods=POST"
    ),
    list_records: bool = typer.Option(False, "--list", help="列出已记录的复测会话"),
    sweep: bool = typer.Option(False, "--sweep", help="把遗留的 running 会话封成 stopped（不自动重放）"),
    store_dir: Optional[str] = typer.Option(None, "--store", help="复测存储目录（默认 <配置目录>/retests）"),
) -> None:
    """复测一条已上报的结论：发起 → 最小定向复测 → 记录三选一结论。

    只有「已完成且结论为 fixed」才会把 finding 的处置状态翻成 fixed；reproduced /
    inconclusive 只留痕。报告门槛（verification_status）不受影响。
    """

    store = RetestStore(store_dir)

    try:
        if sweep:
            stamped = store.stop_orphans()
            console.print(f"[yellow]已封存 {len(stamped)} 条遗留复测会话[/yellow]" + (f"：{', '.join(stamped)}" if stamped else ""))

        if list_records:
            records = store.all_records()
            if not records:
                console.print("（还没有任何复测记录）")
                return
            for record in records:
                verdict = record.verdict or "-"
                console.print(
                    f"{record.finding_id}  round={record.round}  status={record.status.value}"
                    f"  verdict={verdict}  id={record.retest_id}"
                )
            return

        if not finding_id:
            console.print("[red]缺少 finding id（或改用 --list / --sweep）[/red]")
            raise typer.Exit(2)
        if not findings:
            console.print("[red]需要 --findings <findings.json|run 目录> 才能定位这条 finding[/red]")
            raise typer.Exit(2)

        finding = _load_finding(findings, finding_id)
        parsed_constraints = _parse_constraints(constraints)

        if verdict:
            # 结论必须挂在一条复测会话上：没有会话就先用当前 finding 开一条（冻结快照），
            # 已有会话则沿用 — 绝不覆盖第一轮已有的结论（store 会拒绝）。
            if not store.history(finding_id):
                service.start_retest(finding, store, constraints=parsed_constraints)
            record = store.conclude(finding_id, verdict=verdict, note=note)
            flipped = service.apply_verdict(finding, record)
            console.print(
                f"[green]复测结论已记录[/green]：{finding_id} → {record.verdict}"
                f"（{record.retest_id}）"
            )
            console.print(
                "处置状态已翻转为 fixed（仅 completed+fixed）"
                if flipped
                else "处置状态未变（复测只留痕；报告门槛不受影响）"
            )
            return

        record = service.start_retest(finding, store, constraints=parsed_constraints)
        console.print(f"[green]复测会话[/green] {record.retest_id}（round {record.round}，status {record.status.value}）")
        console.print(service.build_retest_brief(finding, constraints=parsed_constraints))
        console.print("[dim]结论落地：vulnclaw retest <findings-id> --findings … --verdict fixed|reproduced|inconclusive[/dim]")
    except (RetestConflictError, RetestNotFoundError, RetestStoreError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
