"""GC 的调度（缺口 1）：只有「显式 run 目录」能触发回收，且收尾路径永不抛。

``EvidenceStore.collect()`` 的实现一直是对的，缺的是**调度**与**边界**：它是唯一
会删证据的入口，所以这里钉住三件事 —— 没有 run 上下文时一个 blob 都不动；坏索引
时不删（引用集不可信）；run 收尾调用它不会让 run 失败。
"""

from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path

import vulnclaw
from vulnclaw.traffic.evidence import EvidenceStore
from vulnclaw.traffic.maintenance import collect_run_evidence, plan_run_evidence_gc
from vulnclaw.traffic.paths import evidence_dir, resolve_evidence_store
from vulnclaw.traffic.store import TrafficStore
from tests.traffic.test_evidence_store import _exchange


def _stores(run_dir: Path) -> tuple[TrafficStore, EvidenceStore]:
    root = evidence_dir(run_dir)
    return TrafficStore(root / "traffic"), EvidenceStore(root)


def _pin_one(run_dir: Path, *, pinned_at: float = 1.0):
    traffic, evidence = _stores(run_dir)
    record = traffic.record(_exchange(), source="proxy")
    return evidence, evidence.pin(traffic, record.request_id, pinned_at=pinned_at)


def _orphan(evidence: EvidenceStore, *, mtime: float, body: bytes = b"orphan body") -> str:
    """Forge an unreferenced blob and backdate it, as a re-bind would leave behind."""

    digest = hashlib.sha256(body).hexdigest()
    evidence._write_blob(body)
    os.utime(evidence._blob_path(digest), (mtime, mtime))
    return digest


# ── 边界：绝不在没有 run 上下文时删东西 ──────────────────────────────────────


def test_no_run_dir_never_deletes_from_the_global_store(tmp_path, monkeypatch):
    """``run_dir=None`` 会落到 CONFIG_DIR/evidence —— 一次误删就是别人的证据。"""

    monkeypatch.setenv("VULNCLAW_EVIDENCE_DIR", str(tmp_path / "global-evidence"))
    global_store = resolve_evidence_store(None)
    digest = _orphan(global_store, mtime=1.0)

    assert collect_run_evidence(None, now=10**9, grace_seconds=0) == []
    assert global_store._blob_path(digest).exists()


def test_missing_store_is_a_noop(tmp_path):
    assert collect_run_evidence(tmp_path / "no-such-run", now=10**9, grace_seconds=0) == []


def test_store_without_an_index_is_left_alone(tmp_path):
    """没有索引行 = 没有任何引用，此时"孤立"的判据会把所有 blob 都算成孤立。"""

    evidence, _ = _pin_one(tmp_path / "run")
    evidence.index_path.unlink()
    digest = _orphan(evidence, mtime=1.0)

    assert collect_run_evidence(tmp_path / "run", now=10**9, grace_seconds=0) == []
    assert evidence._blob_path(digest).exists()


def test_a_broken_index_row_disables_gc_instead_of_losing_evidence(tmp_path):
    """坏行会让引用集不完整：宁可少删，也不能删掉还有索引行的证据。"""

    run_dir = tmp_path / "run"
    evidence, snapshot = _pin_one(run_dir)
    digest = _orphan(evidence, mtime=1.0)
    with evidence.index_path.open("a", encoding="utf-8") as handle:
        handle.write("{ this row is truncated\n")

    assert plan_run_evidence_gc(run_dir, now=10**9, grace_seconds=0) == []
    assert collect_run_evidence(run_dir, now=10**9, grace_seconds=0) == []
    assert evidence._blob_path(digest).exists()
    assert evidence.request_body(snapshot.snapshot_id)


# ── 正向：收该收的，留该留的，且只作用于这一个 run ────────────────────────────


def test_collect_removes_the_runs_aged_orphan_and_keeps_references(tmp_path):
    run_a, run_b = tmp_path / "run-a", tmp_path / "run-b"
    evidence_a, snapshot_a = _pin_one(run_a)
    orphan = _orphan(evidence_a, mtime=1.0)
    evidence_b, snapshot_b = _pin_one(run_b)

    removed = collect_run_evidence(run_a, now=10**9, grace_seconds=3600)

    assert removed == [orphan]
    assert not evidence_a._blob_path(orphan).exists()
    assert evidence_a.response_body(snapshot_a.snapshot_id)  # 被引用的留着
    assert evidence_b.request_body(snapshot_b.snapshot_id)  # 另一个 run 没被碰


def test_referenced_blobs_survive_any_age(tmp_path):
    run_dir = tmp_path / "run"
    evidence, snapshot = _pin_one(run_dir)
    for digest in (snapshot.request_sha256, snapshot.response_sha256):
        os.utime(evidence._blob_path(digest), (1.0, 1.0))

    assert collect_run_evidence(run_dir, now=10**9, grace_seconds=3600) == []
    assert evidence.response_body(snapshot.snapshot_id)


def test_orphan_inside_the_grace_window_is_spared(tmp_path):
    run_dir = tmp_path / "run"
    evidence, _ = _pin_one(run_dir, pinned_at=100.0)
    digest = _orphan(evidence, mtime=100.0 + 60)

    assert collect_run_evidence(run_dir, now=100.0 + 120, grace_seconds=3600) == []
    assert evidence._blob_path(digest).exists()


def test_dry_run_reports_exactly_what_the_real_run_deletes(tmp_path):
    run_dir = tmp_path / "run"
    evidence, _ = _pin_one(run_dir)
    orphan = _orphan(evidence, mtime=1.0)

    planned = plan_run_evidence_gc(run_dir, now=10**9, grace_seconds=3600)
    assert planned == [orphan]
    assert evidence._blob_path(orphan).exists()  # dry-run 不删

    assert collect_run_evidence(run_dir, now=10**9, grace_seconds=3600) == planned


# ── 调度：run 收尾真的会调它，且不会拖垮 run ────────────────────────────────


class _FakeRunContext:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.events: list[tuple[str, dict]] = []

    def append_event(self, name: str, payload: dict) -> None:
        self.events.append((name, payload))


def test_teardown_helper_never_raises_on_a_missing_run(tmp_path):
    from vulnclaw.orchestrator import _collect_run_evidence

    _collect_run_evidence(_FakeRunContext(tmp_path / "gone"))  # 不抛


def test_teardown_helper_records_what_it_reclaimed(tmp_path):
    from vulnclaw.orchestrator import _collect_run_evidence

    run_dir = tmp_path / "run"
    evidence, _ = _pin_one(run_dir)
    _orphan(evidence, mtime=1.0)
    context = _FakeRunContext(run_dir)

    _collect_run_evidence(context)

    assert context.events and context.events[0][0] == "evidence_gc"


def test_teardown_helper_swallows_a_broken_context(tmp_path):
    """连事件都写不进去时，收尾也不能把异常抛回 run 主流程。"""

    from vulnclaw.orchestrator import _collect_run_evidence

    class _Broken(_FakeRunContext):
        def append_event(self, name: str, payload: dict) -> None:
            raise RuntimeError("event log is gone")

    run_dir = tmp_path / "run"
    evidence, _ = _pin_one(run_dir)
    _orphan(evidence, mtime=1.0)

    _collect_run_evidence(_Broken(run_dir))  # 不抛


def test_the_completed_branch_of_the_run_is_where_gc_is_scheduled():
    """源码级钉子：调度点必须在「run 已 durable 标为 completed」的同一分支里。"""

    source = (Path(vulnclaw.__file__).parent / "orchestrator.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    # 唯一的受约束入口：整个文件里只准有一处直接调 collect_run_evidence
    direct = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "collect_run_evidence"
    ]
    assert len(direct) == 1, "GC 入口必须只有一处（那条带 run_dir 守卫的包装函数）"

    finishers = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for call in ast.walk(node):
            if isinstance(call, ast.Call) and getattr(call.func, "id", "") == "mark_run_status":
                if "completed" in ast.unparse(call.args[-1:] or call):
                    finishers.append(node)
                    break
    assert len(finishers) == 1, "run 的 completed 收尾只应有一处"
    scheduled = [
        getattr(call.func, "id", "")
        for call in ast.walk(finishers[0])
        if isinstance(call, ast.Call)
    ]
    assert "_collect_run_evidence" in scheduled, "completed 分支必须调度证据 GC"
