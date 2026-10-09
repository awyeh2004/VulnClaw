"""The agent-facing binding tool -- the writer that closes the evidence loop.

Before this existed, ``EvidenceRef``/``http_capture`` was modelled, exported to
SARIF and rendered, but nothing could create one: ``traffic_list`` handed the
model a ``request_id`` and there was no way to cite it. These tests cover the
lookup, the rejection paths, and the end-to-end payoff (bind via the tool, then
see the proof in the generated report).
"""

from __future__ import annotations

from vulnclaw.agent.builtin_tools import execute_traffic_bind_tool
from vulnclaw.agent.context import TaskConstraints, VulnerabilityFinding
from vulnclaw.config.domain_models import evidence_binding_signature
from vulnclaw.traffic.models import CapturedExchange, CapturedRequest, CapturedResponse
from vulnclaw.traffic.store import TrafficStore


class _Session:
    def __init__(self, evidence_dir):
        self.target = "http://app.test"
        self.evidence_dir = evidence_dir
        self.task_constraints = TaskConstraints()
        self.findings: list[VulnerabilityFinding] = []


class _Agent:
    def __init__(self, evidence_dir, run_dir=None):
        self.session_state = _Session(evidence_dir)
        self.run_dir = run_dir
        self.active_role = None
        self.mcp_manager = None


def _capture(traffic: TrafficStore, url: str) -> str:
    return traffic.record(
        CapturedExchange(
            request=CapturedRequest(method="GET", url=url, headers={"Host": "app.test"}),
            response=CapturedResponse(status=500, body=b"SQL syntax error near ''1'"),
        ),
        source="proxy",
    ).request_id


def _agent_with_finding(tmp_path, *, title="SQL Injection in /user") -> tuple[_Agent, TrafficStore]:
    run_dir = tmp_path / "run"
    evidence_dir = run_dir / "evidence"
    traffic = TrafficStore(evidence_dir / "traffic")
    agent = _Agent(str(evidence_dir), run_dir=str(run_dir))
    finding = VulnerabilityFinding(
        title=title,
        severity="High",
        vuln_type="SQLi",
        evidence="injectable",
        remediation="parameterize",
    )
    finding.finding_id = finding._generate_finding_id()
    finding.mark_verified()
    agent.session_state.findings.append(finding)
    return agent, traffic


# ── finding lookup ──────────────────────────────────────────────────────────


def test_binds_by_finding_id(tmp_path):
    agent, traffic = _agent_with_finding(tmp_path)
    finding = agent.session_state.findings[0]
    request_id = _capture(traffic, "http://app.test/user?id=1'")

    out = execute_traffic_bind_tool(
        agent,
        {
            "finding": finding.finding_id,
            "evidence": [{"request_id": request_id, "role": "proof", "note": "error-based"}],
        },
    )

    assert "已为" in out and "SQL Injection in /user" in out
    assert finding.evidence_version == 1
    assert finding.evidence_refs[0].role == "proof"
    assert finding.evidence_refs[0].note == "error-based"


def test_binds_by_title_substring(tmp_path):
    agent, traffic = _agent_with_finding(tmp_path)
    finding = agent.session_state.findings[0]

    out = execute_traffic_bind_tool(
        agent,
        {
            "finding": "sql injection",
            "evidence": [{"request_id": _capture(traffic, "http://app.test/a")}],
        },
    )

    assert "已为" in out
    assert len(finding.evidence_refs) == 1


def test_accepts_bare_request_id_strings(tmp_path):
    """A model told to "cite the request_id" will send the simplest shape."""
    agent, traffic = _agent_with_finding(tmp_path)
    finding = agent.session_state.findings[0]

    execute_traffic_bind_tool(
        agent,
        {"finding": "SQL Injection", "evidence": [_capture(traffic, "http://app.test/a")]},
    )

    assert len(finding.evidence_refs) == 1


def test_unknown_finding_is_reported_with_the_available_titles(tmp_path):
    agent, _ = _agent_with_finding(tmp_path)

    out = execute_traffic_bind_tool(agent, {"finding": "nope", "evidence": ["x"]})

    assert "没有匹配" in out
    assert "SQL Injection in /user" in out


def test_ambiguous_title_is_refused_rather_than_guessed(tmp_path):
    """Binding proof to the wrong finding is worse than asking again."""
    agent, _ = _agent_with_finding(tmp_path)
    twin = VulnerabilityFinding(title="SQL Injection in /admin", severity="High")
    twin.finding_id = twin._generate_finding_id()
    agent.session_state.findings.append(twin)

    out = execute_traffic_bind_tool(agent, {"finding": "SQL Injection", "evidence": ["x"]})

    assert "匹配到多个" in out
    assert all(not f.evidence_refs for f in agent.session_state.findings)


def test_missing_finding_argument_is_reported(tmp_path):
    agent, _ = _agent_with_finding(tmp_path)
    out = execute_traffic_bind_tool(agent, {"evidence": ["x"]})
    assert "缺少 finding" in out


def test_agent_with_no_findings_says_so(tmp_path):
    evidence_dir = tmp_path / "run" / "evidence"
    agent = _Agent(str(evidence_dir))
    out = execute_traffic_bind_tool(agent, {"finding": "anything", "evidence": ["x"]})
    assert "还没有任何漏洞发现" in out


# ── rejection paths keep the finding intact ─────────────────────────────────


def test_unknown_request_id_is_rejected_and_changes_nothing(tmp_path):
    agent, traffic = _agent_with_finding(tmp_path)
    finding = agent.session_state.findings[0]
    good = _capture(traffic, "http://app.test/a")

    out = execute_traffic_bind_tool(
        agent,
        {
            "finding": "SQL Injection",
            "evidence": [{"request_id": good}, {"request_id": "deadbeefdeadbeef"}],
        },
    )

    assert "被拒绝" in out
    assert "deadbeefdeadbeef" in out
    assert finding.evidence_refs == []
    assert finding.evidence_version == 0


def test_unknown_role_is_rejected_and_changes_nothing(tmp_path):
    agent, traffic = _agent_with_finding(tmp_path)
    finding = agent.session_state.findings[0]

    out = execute_traffic_bind_tool(
        agent,
        {
            "finding": "SQL Injection",
            "evidence": [{"request_id": _capture(traffic, "http://app.test/a"), "role": "exploit"}],
        },
    )

    assert "被拒绝" in out
    assert finding.evidence_refs == []


def test_missing_evidence_argument_is_rejected(tmp_path):
    agent, _ = _agent_with_finding(tmp_path)
    out = execute_traffic_bind_tool(agent, {"finding": "SQL Injection"})
    assert "被拒绝" in out


# ── the payoff ──────────────────────────────────────────────────────────────


def test_bound_evidence_reaches_the_report_after_the_capture_log_is_gone(tmp_path):
    """Tool bind -> reclaim the capture log -> the report still proves it.

    Uses the real ``SessionState`` (not the lightweight dummy above) because the
    point is the whole chain: the tool writes the binding and the report
    generator reads it back. Both find the run's evidence tree through the run
    directory alone -- the agent's injected ``run_dir`` anchor and the report's
    ``output_path`` -- with no ``VULNCLAW_EVIDENCE_DIR`` crutch. The pinned
    snapshot must outlive the deleted capture log.
    """
    import shutil

    from vulnclaw.agent.context import SessionState
    from vulnclaw.i18n import current_lang, init_i18n
    from vulnclaw.report.generator import generate_report

    run_dir = tmp_path / "run"
    evidence_dir = run_dir / "evidence"
    traffic = TrafficStore(evidence_dir / "traffic")

    finding = VulnerabilityFinding(
        title="SQL Injection in /user",
        severity="High",
        vuln_type="SQLi",
        evidence="injectable",
        remediation="parameterize",
    )
    finding.mark_verified()

    session = SessionState(target="http://app.test")
    session.add_finding(finding)

    agent = _Agent(str(evidence_dir), run_dir=str(run_dir))
    agent.session_state = session

    request_id = _capture(traffic, "http://app.test/user?id=1'")
    out = execute_traffic_bind_tool(
        agent,
        {
            "finding": finding.finding_id,
            "evidence": [{"request_id": request_id, "role": "proof", "note": "the payload"}],
        },
    )
    assert "已为" in out

    # Reclaim the capture log; the pinned snapshot must carry the proof alone.
    shutil.rmtree(evidence_dir / "traffic")

    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        text = generate_report(
            session, output_path=str(run_dir / "report.md")
        ).read_text(encoding="utf-8")
    finally:
        init_i18n(lang=previous_lang)

    assert "GET /user?id=1' HTTP/1.1" in text
    assert "SQL syntax error near" in text
    assert "证明请求" in text
    assert "the payload" in text


def test_rebinding_through_the_tool_keeps_the_original_note(tmp_path):
    agent, traffic = _agent_with_finding(tmp_path)
    finding = agent.session_state.findings[0]
    request_id = _capture(traffic, "http://app.test/a")

    execute_traffic_bind_tool(
        agent,
        {"finding": "SQL Injection", "evidence": [{"request_id": request_id, "role": "proof",
                                                   "note": "operator wording"}]},
    )
    out = execute_traffic_bind_tool(
        agent,
        {"finding": "SQL Injection", "evidence": [{"request_id": request_id, "role": "baseline"}]},
    )

    assert len(finding.evidence_refs) == 1
    assert finding.evidence_refs[0].role == "proof"
    assert finding.evidence_refs[0].note == "operator wording"
    assert finding.evidence_version == 1
    assert "已绑定过" in out
    assert evidence_binding_signature(finding.evidence_refs)
