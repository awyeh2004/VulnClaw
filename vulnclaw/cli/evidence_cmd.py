"""``vulnclaw evidence`` —— 证据维护子命令（缺口 1 / 2 的暴露面）。

三个动作都只在**显式给定**的 run 目录 / findings 文件上生效：

* ``gc``      —— 调度一次（或 dry-run 看一遍）某 run 孤立 blob 的回收；
* ``unbind``  —— 按 snapshot 解绑一条证据（默认只看不写，``--write`` 才落盘）；
* ``reorder`` —— 按完整 handle 列表重排绑定（同上，``--write`` 才落盘）。

设计纪律：默认 dry-run。解绑会削弱报告的证据面，重排会改变引用顺序 —— 两者都
要求 ``--write`` 才是真的动手，避免一条命令就把已发布 run 的结论改掉。
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from vulnclaw.cli.findings_io import (
    FindingsFileError,
    load_finding,
    save_finding,
)
from vulnclaw.traffic.binding import (
    EvidenceBindError,
    reorder_finding_evidence,
    unbind_finding_evidence,
)
from vulnclaw.traffic.maintenance import collect_run_evidence, plan_run_evidence_gc

console = Console()

evidence_app = typer.Typer(
    name="evidence",
    help="证据维护：GC 孤立 blob / 解绑 / 重排（默认只看不写）",
    no_args_is_help=True,
)


@evidence_app.command("gc")
def gc(
    run_dir: str = typer.Argument(..., help="run 目录（只作用于该 run 的 evidence/）"),
    grace_days: float = typer.Option(1.0, "--grace-days", help="宽限期：比这更年轻的孤立 blob 不动"),
    dry_run: bool = typer.Option(False, "--dry-run", help="只列出会被删除的 digest，不删"),
) -> None:
    """回收该 run 里「无人引用且已过宽限期」的证据 blob。"""

    grace_seconds = max(0.0, grace_days) * 24 * 60 * 60
    if dry_run:
        stale = plan_run_evidence_gc(run_dir, grace_seconds=grace_seconds)
        console.print(f"[yellow]dry-run[/yellow]：{len(stale)} 个孤立 blob 会被删除")
        for digest in stale:
            console.print(f"  {digest}")
        return

    removed = collect_run_evidence(run_dir, grace_seconds=grace_seconds)
    console.print(f"[green]已回收 {len(removed)} 个孤立 blob[/green]")
    for digest in removed:
        console.print(f"  {digest}")


@evidence_app.command("unbind")
def unbind(
    finding_id: str = typer.Argument(..., help="findings 里的 finding_id"),
    findings: str = typer.Option(..., "--findings", "-f", help="findings.json 或其所在 run 目录"),
    snapshot: str = typer.Option(..., "--snapshot", "-s", help="要解绑的 snapshot_id（或旧式 request_id）"),
    write: bool = typer.Option(False, "--write", help="真的落盘（默认只看结果）"),
) -> None:
    """解绑一条证据引用；会 bump evidence_version（即使没匹配上也算被考虑过）。"""

    try:
        finding = load_finding(findings, finding_id)
        outcome = unbind_finding_evidence(finding, snapshot_id=snapshot)
    except (FindingsFileError, EvidenceBindError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    console.print(outcome.describe())
    if outcome.duplicates:
        console.print("[yellow]没有匹配到该 snapshot（绑定未变化，版本未 bump）[/yellow]")
    if not write:
        console.print("[dim]未落盘；加 --write 才写入 findings.json[/dim]")
        return
    path = save_finding(findings, finding)
    console.print(f"[green]已写回 {path}[/green]")


@evidence_app.command("reorder")
def reorder(
    finding_id: str = typer.Argument(..., help="findings 里的 finding_id"),
    findings: str = typer.Option(..., "--findings", "-f", help="findings.json 或其所在 run 目录"),
    handles: str = typer.Option(..., "--handles", help="完整 handle 列表（逗号分隔，必须一个不少）"),
    write: bool = typer.Option(False, "--write", help="真的落盘（默认只看结果）"),
) -> None:
    """按完整 handle 列表重排绑定；列表不完整 / 有未知 handle 一律拒绝。"""

    order = [chunk.strip() for chunk in str(handles).split(",") if chunk.strip()]
    try:
        finding = load_finding(findings, finding_id)
        outcome = reorder_finding_evidence(finding, handles=order)
    except (FindingsFileError, EvidenceBindError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    console.print(outcome.describe())
    if not write:
        console.print("[dim]未落盘；加 --write 才写入 findings.json[/dim]")
        return
    path = save_finding(findings, finding)
    console.print(f"[green]已写回 {path}[/green]")
