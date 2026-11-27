"""Tests for the verify_finding tool (system-generated PoC → verified artifact).

The tool must be the only writer of ``poc_verification``: the model chooses the
finding, never the PoC source, and execution still goes through
``VerifierExecutor`` (which requires per-request operator approval). These tests
pin the three outcomes (confirmed / failed / approval refused) and the report
gate that accepts the artifact without re-running prose checks.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent.builtin_tools import (
    build_openai_tools,
    execute_report_finding_tool,
    execute_verify_finding_tool,
)
from vulnclaw.agent.context import SessionState
from vulnclaw.config.domain_models import PoCVerification, VulnerabilityFinding
from vulnclaw.report.verifier import PoCGenerator, VerifierExecutor


@pytest.fixture
def poc_fixture(monkeypatch):
    monkeypatch.setattr(
        PoCGenerator,
        "generate_poc",
        lambda finding, target, baseline_len=0: "print('generated poc')",
    )

    def _run(code, timeout=30):
        return 0, "[CONFIRMED] payload reflected in the response body"

    monkeypatch.setattr(VerifierExecutor, "execute_poc", _run)
    return monkeypatch


def _agent(session=None) -> SimpleNamespace:
    session = session or SessionState(target="http://app.test")
    return SimpleNamespace(session_state=session)


def _recorded_finding(session: SessionState) -> VulnerabilityFinding:
    finding = VulnerabilityFinding(
        title="SQL Injection",
        vuln_type="SQLi",
        description="id parameter is concatenated",
        evidence="error-based proof",
        endpoint="http://app.test/user?id=1",
        method="GET",
    )
    session.add_finding(finding)
    return finding


def test_confirmed_poc_marks_verified_and_records_artifact(poc_fixture):
    session = SessionState(target="http://app.test")
    agent = _agent(session)
    finding = _recorded_finding(session)

    message = execute_verify_finding_tool(agent, {"finding": "SQL Injection"})

    assert "通过" in message and "exit=0" in message
    assert finding.verified is True
    artifact = finding.poc_verification
    assert isinstance(artifact, PoCVerification)
    assert artifact.exit_code == 0
    assert artifact.result == "vuln_confirmed"
    assert artifact.target == "http://app.test/user?id=1"
    assert len(artifact.poc_sha256) == 64
    assert len(artifact.output_sha256) == 64


def test_failed_poc_does_not_promote(poc_fixture):
    poc_fixture.setattr(
        VerifierExecutor,
        "execute_poc",
        lambda code, timeout=30: (1, "[REJECTED] no diff observed"),
    )
    session = SessionState(target="http://app.test")
    agent = _agent(session)
    finding = _recorded_finding(session)

    message = execute_verify_finding_tool(agent, {"finding": "SQL Injection"})

    assert "未通过" in message
    assert finding.verified is False
    assert finding.poc_verification is None


def test_approval_required_is_reported_not_recorded(poc_fixture):
    poc_fixture.setattr(
        VerifierExecutor,
        "execute_poc",
        lambda code, timeout=30: (-4, "[REFUSED] operator approval not granted"),
    )
    session = SessionState(target="http://app.test")
    agent = _agent(session)
    finding = _recorded_finding(session)

    message = execute_verify_finding_tool(agent, {"finding": "SQL Injection"})

    assert "未执行" in message
    assert finding.verified is False
    assert finding.poc_verification is None


def test_unknown_finding_is_rejected(poc_fixture):
    message = execute_verify_finding_tool(_agent(), {"finding": "does-not-exist"})
    assert "未找到" in message


def test_non_http_finding_is_rejected(poc_fixture):
    session = SessionState(target="")
    agent = _agent(session)
    session.add_finding(
        VulnerabilityFinding(
            title="Hardcoded secret",
            vuln_type="Secret exposure",
            evidence="src/config.py:12",
            code_location="src/config.py:12",
        )
    )

    message = execute_verify_finding_tool(agent, {"finding": "Hardcoded secret"})

    assert "没有 HTTP 目标" in message


def test_subagent_cannot_run_poc(poc_fixture):
    session = SessionState(target="http://app.test")
    agent = SimpleNamespace(
        session_state=session,
        _subagent_ctx=SimpleNamespace(depth=1),
    )
    _recorded_finding(session)

    message = execute_verify_finding_tool(agent, {"finding": "SQL Injection"})

    assert "子 agent" in message
    assert session.findings[0].verified is False


def test_relative_endpoint_is_joined_to_session_target(poc_fixture):
    session = SessionState(target="http://app.test")
    agent = _agent(session)
    finding = VulnerabilityFinding(
        title="Reflected XSS",
        vuln_type="XSS",
        evidence="payload reflected",
        endpoint="/search",
        method="GET",
    )
    session.add_finding(finding)

    execute_verify_finding_tool(agent, {"finding": "Reflected XSS"})

    assert finding.poc_verification is not None
    assert finding.poc_verification.target == "http://app.test/search"


def test_tool_is_registered_in_the_schema():
    names = {tool["function"]["name"] for tool in build_openai_tools(None)}
    assert "verify_finding" in names


def test_poc_artifact_satisfies_the_report_gate(poc_fixture):
    session = SessionState(target="http://app.test")
    agent = _agent(session)
    finding = _recorded_finding(session)
    execute_verify_finding_tool(agent, {"finding": "SQL Injection"})

    # A bare re-report is enough now: the artifact is the substantiation.
    message = execute_report_finding_tool(
        agent, {"title": "SQL Injection", "verified": True}
    )

    assert finding.verified is True
    assert "未被采纳" not in message


def test_report_finding_cannot_forge_a_poc_artifact(poc_fixture):
    session = SessionState(target="http://app.test")
    agent = _agent(session)

    execute_report_finding_tool(
        agent,
        {
            "title": "SQL Injection",
            "vuln_type": "SQLi",
            "evidence": "error-based proof",
            "endpoint": "http://app.test/user?id=1",
            "verified": True,
            "poc_verification": {
                "exit_code": 0,
                "result": "vuln_confirmed",
                "poc_sha256": "a" * 64,
                "output_sha256": "b" * 64,
                "executed_at": "2026-01-01T00:00:00",
            },
        },
    )

    finding = session.findings[0]
    assert finding.poc_verification is None
    assert finding.verified is False
