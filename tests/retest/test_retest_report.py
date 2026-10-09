"""报告侧纯增量：findings.json 带出复测历史，且复测不改变已验证/报告门槛."""

from __future__ import annotations

from vulnclaw.agent.context import SessionState
from vulnclaw.config.domain_models import VulnerabilityFinding
from vulnclaw.report.findings_output import build_findings_document, is_report_included
from vulnclaw.retest import service
from vulnclaw.retest.store import RetestStore


def _finding(**overrides) -> VulnerabilityFinding:
    base = {
        "title": "SQL injection in /login",
        "severity": "High",
        "vuln_type": "SQLi",
        "description": "unparameterised query",
        "evidence": "payload returned 5 rows",
        "remediation": "parameterise",
        "target": "http://example.test",
        "verification_status": "verified",
        "lifecycle_status": "verified",
        "verified": True,
    }
    base.update(overrides)
    return VulnerabilityFinding(**base)


def test_findings_document_carries_the_retest_history(tmp_path):
    store = RetestStore(tmp_path)
    finding = _finding()
    session = SessionState(target="http://example.test")
    session.add_finding(finding)

    service.start_retest(finding, store, constraints={"scope": "example.test"})
    done = store.conclude(finding.finding_id, verdict="fixed", note="已打成 401")
    service.apply_verdict(finding, done)

    document = build_findings_document(session, version="test")
    entry = next(f for f in document["findings"] if f["finding_id"] == finding.finding_id)

    assert entry["lifecycle_status"] == "fixed"
    assert [r["verdict"] for r in entry["retest_history"]] == ["fixed"]
    assert entry["retest_history"][0]["snapshot"]["constraints"] == {"scope": "example.test"}


def test_fixed_findings_get_their_own_lifecycle_bucket(tmp_path):
    store = RetestStore(tmp_path)
    finding = _finding()
    session = SessionState(target="http://example.test")
    session.add_finding(finding)
    service.start_retest(finding, store)
    service.apply_verdict(finding, store.conclude(finding.finding_id, verdict="fixed"))

    document = build_findings_document(session, version="test")

    assert document["summary"]["fixed"] == 1
    # fixed 是处置状态、不是验证状态：finding 该进报告还是进（门槛只看 verification_status）
    assert [f["finding_id"] for f in document["verified"]] == [finding.finding_id]


def test_retest_never_moves_the_report_gate(tmp_path):
    store = RetestStore(tmp_path)
    finding = _finding()
    service.start_retest(finding, store)
    done = store.conclude(finding.finding_id, verdict="fixed")
    service.apply_verdict(finding, done)

    # 报告/SARIF 门槛只看 verification_status，复测不得把它推开
    assert is_report_included(finding)
    assert finding.verification_status == "verified"


def test_unverified_finding_is_not_promoted_by_a_fixed_retest(tmp_path):
    store = RetestStore(tmp_path)
    finding = _finding(verification_status="pending", lifecycle_status="candidate", verified=False)
    service.start_retest(finding, store)
    done = store.conclude(finding.finding_id, verdict="fixed")

    assert service.apply_verdict(finding, done) is True
    # 复测只标注「已修复」，不把未验证的结论升级进报告
    assert finding.lifecycle_status == "fixed"
    assert not is_report_included(finding)
