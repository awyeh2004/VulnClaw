"""Retest service: 冻结快照 + 「只有 completed+fixed 才翻转处置状态」.

Round-3 (2026-10-09) port of ARTEX ``agent/retester.go`` 的语义内核：
复测校验的是「这条结论还成立吗」，不是「重跑一遍原任务」；结论只在第一轮成立时可用，
且只有 fixed 才改变 finding 的处置状态（reproduced / inconclusive 一律不动）。
"""

from __future__ import annotations

import pytest

from vulnclaw.config.domain_models import RetestStatus, VulnerabilityFinding
from vulnclaw.retest import service
from vulnclaw.retest.store import RetestStore


def _finding(**overrides) -> VulnerabilityFinding:
    base = {
        "title": "SQL injection in /login",
        "severity": "High",
        "vuln_type": "SQLi",
        "description": "unparameterised query",
        "evidence": "sqlmap payload returned 5 rows",
        "remediation": "parameterise",
        "target": "http://example.test",
        "endpoint": "http://example.test/login",
        "verification_status": "verified",
        "lifecycle_status": "verified",
        "verified": True,
    }
    base.update(overrides)
    return VulnerabilityFinding(**base)


def test_start_retest_freezes_finding_and_constraints_into_the_record(tmp_path):
    store = RetestStore(tmp_path)
    finding = _finding()

    record = service.start_retest(
        finding,
        store,
        constraints={"scope": "example.test", "methods": ["POST"]},
    )

    assert record.snapshot["finding_id"] == finding.finding_id
    assert record.snapshot["endpoint"] == "http://example.test/login"
    assert record.snapshot["constraints"] == {"scope": "example.test", "methods": ["POST"]}
    assert record.snapshot["frozen_at"]
    # 第二次调用拿到的还是同一份冻结快照（复测期间 finding 改了也不影响本次结论）
    again = service.start_retest(finding, store)
    assert again.retest_id == record.retest_id
    assert again.snapshot == record.snapshot


def test_brief_is_a_minimal_retest_not_a_rerun(tmp_path):
    brief = service.build_retest_brief(
        _finding(), constraints={"scope": "example.test"}
    )

    assert "最小" in brief
    assert "example.test" in brief
    for verdict in ("reproduced", "fixed", "inconclusive"):
        assert verdict in brief
    # 不能把「重跑原任务」当成复测
    assert "不要重跑原任务" in brief
    assert "不修改其他 finding" in brief


def test_apply_verdict_flips_disposition_only_for_completed_and_fixed(tmp_path):
    store = RetestStore(tmp_path)
    finding = _finding()

    running = service.start_retest(finding, store)
    assert service.apply_verdict(finding, running) is False
    assert finding.lifecycle_status == "verified"  # 未完成不得翻转

    service.start_retest(finding, store)
    done = store.conclude(finding.finding_id, verdict="fixed", note="返回 401")

    assert service.apply_verdict(finding, done) is True
    assert finding.lifecycle_status == "fixed"
    assert "复测" in finding.verification_note
    assert [r.retest_id for r in finding.retest_history] == [done.retest_id]


@pytest.mark.parametrize("verdict", ["reproduced", "inconclusive"])
def test_non_fixed_verdicts_leave_the_disposition_untouched(tmp_path, verdict):
    store = RetestStore(tmp_path)
    finding = _finding()
    service.start_retest(finding, store)
    record = store.conclude(finding.finding_id, verdict=verdict, note="still vulnerable")

    assert service.apply_verdict(finding, record) is False
    assert finding.lifecycle_status == "verified"
    assert finding.verification_status == "verified"  # 报告门槛不受复测影响
    assert finding.retest_history[-1].verdict == verdict


def test_apply_verdict_is_idempotent_per_record(tmp_path):
    store = RetestStore(tmp_path)
    finding = _finding()
    service.start_retest(finding, store)
    done = store.conclude(finding.finding_id, verdict="fixed", note="返回 401")

    service.apply_verdict(finding, done)
    note_after_first = finding.verification_note
    service.apply_verdict(finding, done)

    assert len(finding.retest_history) == 1
    # The history was deduplicated but the note used to be appended again, so a
    # record folded twice produced "…| 复测（第 1 轮）：已修复 …" twice (2026-10-10 audit).
    assert finding.verification_note == note_after_first
    assert finding.verification_note.count("复测（第 1 轮）") == 1


def test_follow_up_round_never_moves_the_disposition(tmp_path):
    store = RetestStore(tmp_path)
    finding = _finding()
    service.start_retest(finding, store)
    store.conclude(finding.finding_id, verdict="reproduced")
    follow_up = store.follow_up(finding.finding_id, question="确认一下还在吗")

    assert service.apply_verdict(finding, follow_up) is False
    assert finding.lifecycle_status == "verified"


def test_snapshot_keeps_the_evidence_version_so_a_rewrite_is_visible(tmp_path):
    store = RetestStore(tmp_path)
    finding = _finding(evidence_version=3)

    record = service.start_retest(finding, store)

    assert record.snapshot["evidence_version"] == 3
    finding.evidence_version = 4
    assert store.history(finding.finding_id)[0].snapshot["evidence_version"] == 3


def test_store_start_is_idempotent_across_service_calls(tmp_path):
    store = RetestStore(tmp_path)
    finding = _finding()

    first = service.start_retest(finding, store)
    second = service.start_retest(finding, store)

    assert second.status is RetestStatus.RUNNING
    assert second.retest_id == first.retest_id
    assert len(store.history(finding.finding_id)) == 1
