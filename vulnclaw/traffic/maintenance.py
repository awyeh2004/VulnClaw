"""证据维护动作：给 GC 一个受约束的调度入口（缺口 1）。

``EvidenceStore.collect()`` 的实现本身是安全的 —— 它只删「没有任何索引行引用 +
超过 grace 窗口」的 blob。真正的风险在**谁来调、在哪个目录上调**：``run_dir=None``
会落到 ``CONFIG_DIR/evidence``（跨 run 的全局根，见 ``traffic/paths.py``），一次误删
就是别人的证据。所以这里只暴露两个受约束的入口：

* :func:`collect_run_evidence` —— 只针对**单个 run**、best-effort、永不抛（run 收尾用）；
* :func:`plan_run_evidence_gc` —— 同一判据但**不删任何东西**（``--dry-run`` / 审计用），
  与 :meth:`EvidenceStore.stale_digests` 共用一条谓词，不会各自漂移。
"""

from __future__ import annotations

from pathlib import Path

from vulnclaw.traffic.evidence import DEFAULT_GRACE_SECONDS
from vulnclaw.traffic.paths import resolve_evidence_store


def collect_run_evidence(
    run_dir: str | Path | None = None,
    *,
    grace_seconds: float = DEFAULT_GRACE_SECONDS,
    now: float | None = None,
) -> list[str]:
    """Best-effort GC of ONE run's evidence store; returns the removed digests.

    Never raises and never touches the global (``run_dir is None``) root: a run
    teardown must not be able to fail a whole run, and "no run context" must never
    mean "every run's evidence". A store with no index row is left alone too --
    nothing is referenced there, so the predicate would call every blob stale.
    """

    if run_dir is None:
        return []
    try:
        store = resolve_evidence_store(run_dir)
        if not store.has_index():
            return []
        if store.index_problems():
            # 索引有坏行 → 引用集不完整，任何"无人引用"的判断都不可信。
            # 宁可少删（blob 只是占磁盘），也不能把还有索引行的证据删掉。
            return []
        return store.collect(now=now, grace_seconds=grace_seconds)
    except Exception:
        return []


def plan_run_evidence_gc(
    run_dir: str | Path | None = None,
    *,
    grace_seconds: float = DEFAULT_GRACE_SECONDS,
    now: float | None = None,
) -> list[str]:
    """What :func:`collect_run_evidence` *would* delete, without deleting it.

    Carries the same guards as :func:`collect_run_evidence` (no run dir / no index /
    broken index → ``[]``), so a dry-run can never promise a deletion the real run
    would refuse, or the other way round.
    """

    if run_dir is None:
        return []
    store = resolve_evidence_store(run_dir)
    if not store.has_index() or store.index_problems():
        return []
    return store.stale_digests(now=now, grace_seconds=grace_seconds)
