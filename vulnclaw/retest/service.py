"""复测服务：冻结快照、最小定向复测 brief、以及唯一的处置翻转点。

借鉴自 ARTEX ``agent/retester.go`` 的语义（不抄代码）：

* 复测校验的是「这条已经上报的结论现在还成立吗」，不是「把原任务重跑一遍」；
* 复测必须在**原任务的约束**下做（scope / 方法 / 速率），不能顺手扩大打击面；
* 结论三选一，且**只有 completed + fixed** 才改变 finding 的处置状态
  （``lifecycle_status = "fixed"``）。``reproduced`` / ``inconclusive`` 只留痕，不动
  处置，也绝不动 ``verification_status``（那是报告/SARIF 的门槛，复测无权改）。
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Mapping

from vulnclaw.config.domain_models import (
    RetestRecord,
    RetestStatus,
    RetestVerdict,
    VulnerabilityFinding,
)
from vulnclaw.retest.store import RetestStore

#: 复测只认这三个结论（写进 brief，也用于自检）。
RETEST_VERDICTS: tuple[str, ...] = tuple(v.value for v in RetestVerdict)


def _stamp(now: datetime | None = None) -> str:
    return (now or datetime.now()).isoformat()


def finding_fingerprint(finding: VulnerabilityFinding) -> str:
    """Stable identity of the finding *as reported* — lets a reader spot drift."""

    basis = "|".join(
        str(part or "")
        for part in (
            finding.finding_id,
            finding.title,
            finding.vuln_type,
            finding.target,
            finding.endpoint,
        )
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def snapshot_for_finding(
    finding: VulnerabilityFinding,
    *,
    constraints: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The frozen basis of a retest round: finding identity + the original constraints."""

    return {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "severity": finding.severity,
        "vuln_type": finding.vuln_type,
        "target": finding.target,
        "endpoint": finding.endpoint,
        "method": finding.method,
        "evidence_version": finding.evidence_version,
        "finding_fingerprint": finding_fingerprint(finding),
        "constraints": dict(constraints or {}),
        "frozen_at": _stamp(now),
    }


def build_retest_brief(
    finding: VulnerabilityFinding,
    *,
    constraints: Mapping[str, Any] | None = None,
) -> str:
    """The retester's task text: a *minimal* directed probe, not a re-run."""

    scope = ", ".join(f"{k}={v}" for k, v in (constraints or {}).items()) or "同原任务"
    endpoint = finding.endpoint or finding.target or "(未记录)"
    return (
        "复测任务（最小定向复测，不是重跑原任务）\n"
        f"目标结论：{finding.title}（{finding.severity} / {finding.vuln_type}）\n"
        f"位置：{endpoint}"
        + (f" [{finding.method}]" if finding.method else "")
        + "\n"
        f"原始约束：{scope}\n"
        "要求：\n"
        "1. 只做能区分「结论还成立吗」的最小探测；不要重跑原任务，不要重新做侦察。\n"
        "2. 严格留在上述约束内，不扩大 scope、不修改其他 finding、不动目标状态。\n"
        f"3. 结论必须是其中之一：{' / '.join(RETEST_VERDICTS)}。\n"
        "4. 只回一条结论 + 支撑它的证据；证据不足就报 inconclusive，不要猜。\n"
    )


def start_retest(
    finding: VulnerabilityFinding,
    store: RetestStore,
    *,
    constraints: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> RetestRecord:
    """Open the finding's retest session (idempotent — see :meth:`RetestStore.start`)."""

    return store.start(
        finding.finding_id,
        snapshot=snapshot_for_finding(finding, constraints=constraints, now=now),
        now=now,
    )


def _remember(finding: VulnerabilityFinding, record: RetestRecord) -> bool:
    """Append ``record`` to the history unless already there. Returns whether it was added.

    Both the history entry and the ``verification_note`` must be keyed on this:
    a record applied twice (a caller that retries, or folds the same verdict onto
    a finding it already folded) otherwise duplicated the note while the history
    stayed deduplicated.
    """

    if any(existing.retest_id == record.retest_id for existing in finding.retest_history):
        return False
    finding.retest_history.append(record)
    return True


def apply_verdict(
    finding: VulnerabilityFinding,
    record: RetestRecord | None,
) -> bool:
    """Fold a concluded record onto the finding. Returns whether the disposition flipped.

    Fixed → ``lifecycle_status = "fixed"`` plus a note. Everything else (running, follow-up
    rounds, reproduced, inconclusive) only leaves a trace in ``retest_history``.
    """

    if record is None:
        return False
    if record.status is not RetestStatus.COMPLETED:
        return False
    first_time = _remember(finding, record)
    if not record.is_fixed:
        return False

    finding.lifecycle_status = "fixed"
    if not first_time:
        # Same record folded twice: history was already deduplicated, so the note
        # must be too. Keep the disposition flip reported as before.
        return True
    detail = record.note or "复测未复现"
    note = f"复测（第 {record.round} 轮）：已修复 — {detail}"
    finding.verification_note = (
        f"{finding.verification_note} | {note}" if finding.verification_note else note
    )
    return True
