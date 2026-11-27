"""Task-done gate for findings: verified requires a code-created artifact.

``report_finding(verified=true)`` used to be promotable by prose alone: any one of
``evidence`` / ``vuln_type`` / ``remediation`` was enough. That is the same
self-certification failure the CTF completion gate exists to prevent, moved to
the report/SARIF gate.

The rule pinned here:

- HTTP/runtime findings need at least one capture bound by
  ``traffic_bind_evidence`` (a content-addressed snapshot created by code).
- SAST/audit findings may instead carry ``code_location`` — they have no traffic
  to bind.
- Everything else stays a candidate, with a message naming the next step.
"""

from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.agent.builtin_tools import execute_report_finding_tool
from vulnclaw.agent.context import SessionState
from vulnclaw.config.domain_models import EvidenceRef, VulnerabilityFinding
from vulnclaw.traffic import tools as traffic_tools
from vulnclaw.traffic.binding import BindOutcome


def _agent() -> SimpleNamespace:
    return SimpleNamespace(session_state=SessionState(target="example.com"))


def test_verified_without_bound_evidence_is_downgraded():
    agent = _agent()

    message = execute_report_finding_tool(
        agent,
        {
            "title": "Reflected XSS in /search",
            "vuln_type": "XSS",
            "evidence": "payload reflected unencoded in the response body",
            "endpoint": "https://example.com/search",
            "method": "GET",
            "verified": True,
            "verification_note": "replayed by hand",
        },
    )

    finding = agent.session_state.findings[0]
    assert finding.verified is False
    assert "未被采纳" in message
    assert "traffic_bind_evidence" in message
    assert "code_location" in message


def test_verified_with_bound_capture_is_accepted():
    agent = _agent()
    existing = VulnerabilityFinding(
        title="Reflected XSS in /search",
        vuln_type="XSS",
        evidence="payload reflected unencoded",
        endpoint="https://example.com/search",
        method="GET",
    )
    existing.evidence_refs.append(
        EvidenceRef(kind="http_capture", request_id="req-1", snapshot_id="snap-1")
    )
    agent.session_state.add_finding(existing)

    message = execute_report_finding_tool(
        agent,
        {
            "title": "Reflected XSS in /search",
            "vuln_type": "XSS",
            "evidence": "payload reflected unencoded",
            "endpoint": "https://example.com/search",
            "method": "GET",
            "verified": True,
        },
    )

    assert agent.session_state.findings[0].verified is True
    assert "已标记为已验证" in message


def test_code_location_findings_keep_the_prose_path():
    """SAST findings have no traffic to bind; code_location is their artifact."""
    agent = _agent()

    execute_report_finding_tool(
        agent,
        {
            "title": "Hardcoded credential in config loader",
            "vuln_type": "Secret exposure",
            "evidence": "src/config.py:12 falls back to a committed password",
            "code_location": "src/config.py:12",
            "verified": True,
        },
    )

    assert agent.session_state.findings[0].verified is True


def test_bound_capture_does_not_rescue_a_bare_report():
    """Binding is necessary but the intake-quarantine signals are still required."""
    agent = _agent()
    existing = VulnerabilityFinding(title="Bare claim")
    existing.evidence_refs.append(EvidenceRef(kind="http_capture", request_id="req-1"))
    agent.session_state.add_finding(existing)

    message = execute_report_finding_tool(
        agent,
        {"title": "Bare claim", "verified": True},
    )

    assert agent.session_state.findings[0].verified is False
    assert "没有任何可核查的依据" in message


def _attach_capture(session, *, url: str | None, method: str | None) -> None:
    session.findings[0].evidence_refs.append(
        EvidenceRef(
            kind="http_capture",
            request_id="req-1",
            snapshot_id="snap-1",
            url=url,
            method=method,
        )
    )


def test_capture_for_another_endpoint_is_rejected():
    agent = _agent()
    existing = VulnerabilityFinding(
        title="IDOR in /user",
        vuln_type="IDOR",
        evidence="object B returned",
        endpoint="https://app.test/user",
        method="GET",
    )
    agent.session_state.add_finding(existing)
    _attach_capture(agent.session_state, url="https://app.test/admin", method="GET")

    message = execute_report_finding_tool(
        agent,
        {
            "title": "IDOR in /user",
            "vuln_type": "IDOR",
            "evidence": "object B returned",
            "endpoint": "https://app.test/user",
            "method": "GET",
            "verified": True,
        },
    )

    assert agent.session_state.findings[0].verified is False
    assert "不一致" in message


def test_method_mismatch_is_rejected():
    agent = _agent()
    existing = VulnerabilityFinding(
        title="Broken access control in /user",
        vuln_type="IDOR",
        evidence="object B returned",
        endpoint="https://app.test/user",
        method="GET",
    )
    agent.session_state.add_finding(existing)
    _attach_capture(agent.session_state, url="https://app.test/user", method="POST")

    execute_report_finding_tool(
        agent,
        {
            "title": "Broken access control in /user",
            "vuln_type": "IDOR",
            "evidence": "object B returned",
            "endpoint": "https://app.test/user",
            "method": "GET",
            "verified": True,
        },
    )

    assert agent.session_state.findings[0].verified is False


def test_collection_endpoint_accepts_concrete_object_capture():
    """``/api/users`` may be proven by ``/api/users/42`` — the common IDOR shape."""
    agent = _agent()
    existing = VulnerabilityFinding(
        title="IDOR in /api/users",
        vuln_type="IDOR",
        evidence="object 42 returned",
        endpoint="https://app.test/api/users",
        method="GET",
    )
    agent.session_state.add_finding(existing)
    _attach_capture(agent.session_state, url="https://app.test/api/users/42", method="GET")

    execute_report_finding_tool(
        agent,
        {
            "title": "IDOR in /api/users",
            "vuln_type": "IDOR",
            "evidence": "object 42 returned",
            "endpoint": "https://app.test/api/users",
            "method": "GET",
            "verified": True,
        },
    )

    assert agent.session_state.findings[0].verified is True


def test_template_endpoint_skips_location_matching():
    agent = _agent()
    existing = VulnerabilityFinding(
        title="IDOR in user object",
        vuln_type="IDOR",
        evidence="object 42 returned",
        endpoint="https://app.test/api/users/{id}",
        method="GET",
    )
    agent.session_state.add_finding(existing)
    _attach_capture(agent.session_state, url="https://app.test/api/users/42", method="GET")

    execute_report_finding_tool(
        agent,
        {
            "title": "IDOR in user object",
            "vuln_type": "IDOR",
            "evidence": "object 42 returned",
            "endpoint": "https://app.test/api/users/{id}",
            "method": "GET",
            "verified": True,
        },
    )

    assert agent.session_state.findings[0].verified is True


def test_legacy_capture_without_location_still_promotes():
    agent = _agent()
    existing = VulnerabilityFinding(
        title="XSS in /search",
        vuln_type="XSS",
        evidence="payload reflected",
        endpoint="https://app.test/search",
        method="GET",
    )
    agent.session_state.add_finding(existing)
    _attach_capture(agent.session_state, url=None, method=None)

    execute_report_finding_tool(
        agent,
        {
            "title": "XSS in /search",
            "vuln_type": "XSS",
            "evidence": "payload reflected",
            "endpoint": "https://app.test/search",
            "method": "GET",
            "verified": True,
        },
    )

    assert agent.session_state.findings[0].verified is True


def test_binding_tells_the_model_how_to_promote(monkeypatch):
    finding = SimpleNamespace(title="XSS", verified=False)

    def fake_bind(_finding, *, traffic_store, evidence_store, specs):
        return BindOutcome(
            title=_finding.title,
            version=1,
            added=("snap-1",),
            duplicates=(),
            bindings=1,
            signature="sig",
        )

    monkeypatch.setattr(traffic_tools, "bind_finding_evidence", fake_bind)

    message = traffic_tools.traffic_bind_evidence_text(
        finding,
        traffic_store=None,
        evidence_store=None,
        specs=[{"request_id": "req-1"}],
    )

    assert "仍未验证" in message
    assert "report_finding" in message
