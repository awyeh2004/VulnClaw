"""A2 end-to-end: capture -> bind -> evidence index -> report, on real code.

This is the integration seam A2 exists for. Everything else in `tests/traffic`
tests one link; this file walks the whole chain the way a live run does, with a
stub target (no network, no LLM), so the chain is verifiable at zero token cost.

Two distinct properties are pinned here, and the difference matters:

* ``TestChainIsIntact`` -- the *library* chain works: a captured exchange can be
  durably pinned to a verified finding and rendered in the report, and the proof
  survives the capture log being reclaimed. This is what the earlier per-link
  tests cover individually; here they run in one pass so a regression in the
  seam between them cannot hide.

* ``TestAgentCanActuallyDriveIt`` -- the *agent* chain works: the model has a
  tool that CREATES a finding. Measured 2026-10-09: it did not. `findings_report`
  and `findings_diff` are both read-only, `blackboard_record_answer` writes an
  ``ir-answer`` answer card (filtered out of reports by ``is_answer_card``), and
  every other finding came from ``finding_parser`` regex-extracting model prose.
  So ``traffic_bind_evidence`` required "report the finding first", no tool could
  report one, and the whole A2 payoff was unreachable from the model's seat --
  four live runs produced 4/4 answer cards and zero bindable findings.
"""

from __future__ import annotations

import shutil

import pytest

from vulnclaw.agent.context import EvidenceRef, SessionState, VulnerabilityFinding
from vulnclaw.report.generator import generate_report
from vulnclaw.traffic.binding import bind_finding_evidence
from vulnclaw.traffic.evidence import EvidenceStore
from vulnclaw.traffic.models import CapturedExchange, CapturedRequest, CapturedResponse
from vulnclaw.traffic.store import TrafficStore

INJECTED_URL = "http://app.test/user?id=1'"
ERROR_BODY = b"SQL syntax error near ''1'"


def _run_layout(tmp_path):
    """A run directory laid out the way the orchestrator lays one out."""
    from vulnclaw.run_context import ensure_run_layout

    run_dir = tmp_path / "runs" / "2026-10-09-scan-app"
    run_dir.mkdir(parents=True)
    ensure_run_layout(run_dir)
    return run_dir


def _capture(traffic: TrafficStore, url: str) -> str:
    return traffic.record(
        CapturedExchange(
            request=CapturedRequest(method="GET", url=url, headers={"Host": "app.test"}),
            response=CapturedResponse(status=500, body=ERROR_BODY),
        ),
        source="proxy",
    ).request_id


class TestChainIsIntact:
    """The library chain, walked end to end in one pass."""

    def test_capture_bind_report_survives_the_capture_log_being_reclaimed(self, tmp_path):
        run_dir = _run_layout(tmp_path)
        traffic = TrafficStore(run_dir / "evidence" / "traffic")
        evidence = EvidenceStore(run_dir / "evidence")

        baseline = _capture(traffic, "http://app.test/user?id=1")
        proof = _capture(traffic, INJECTED_URL)

        finding = VulnerabilityFinding(
            title="SQL Injection in /user",
            severity="High",
            vuln_type="SQLi",
            description="id parameter is injectable",
            evidence="error-based proof",
            remediation="parameterize the query",
        )
        outcome = bind_finding_evidence(
            finding,
            traffic_store=traffic,
            evidence_store=evidence,
            specs=[
                {"request_id": baseline, "role": "baseline", "note": "normal account"},
                {"request_id": proof, "role": "proof", "note": "payload triggers the error"},
            ],
        )
        assert outcome.version == 1
        assert isinstance(finding.evidence_refs[0], EvidenceRef)
        finding.mark_verified(note="confirmed via error-based injection")

        # The capture log goes away (run isolation reclaims it); the binding must
        # keep the proof: this is the snapshot layer's entire reason to exist.
        shutil.rmtree(run_dir / "evidence" / "traffic")

        session = SessionState(target="http://app.test")
        session.add_finding(finding)
        report_path = generate_report(
            session, output_path=str(run_dir / "report.md"), run_dir=str(run_dir)
        )
        text = report_path.read_text(encoding="utf-8")

        assert "GET /user?id=1' HTTP/1.1" in text, "the pinned request survives the log"
        assert "SQL syntax error near" in text, "the pinned response body survives the log"
        assert finding.evidence_refs[1].snapshot_id in text, "report cites the durable handle"

    def test_an_unbound_finding_renders_without_http_blocks(self, tmp_path):
        """The negative control: no binding, no fabricated proof."""
        run_dir = _run_layout(tmp_path)
        finding = VulnerabilityFinding(
            title="Missing security headers",
            severity="Low",
            vuln_type="Misconfig",
            evidence="no HSTS/CSP on the login page",
        )
        finding.mark_verified()

        session = SessionState(target="http://app.test")
        session.add_finding(finding)
        report_path = generate_report(
            session, output_path=str(run_dir / "report.md"), run_dir=str(run_dir)
        )
        text = report_path.read_text(encoding="utf-8")

        assert "Missing security headers" in text
        assert "```http" not in text, "no binding means no HTTP proof block"


class TestAgentCanActuallyDriveIt:
    """The agent-facing half: can the MODEL create the finding that A2 binds to?

    This is where the chain was broken in practice. The tests below fail on the
    pre-fix tree (no ``report_finding`` tool exists) and pass once the model has
    a finding-write verb.
    """

    def test_the_model_has_a_finding_write_tool(self):
        from vulnclaw.agent.builtin_tools import build_openai_tools

        names = {t["function"]["name"] for t in build_openai_tools(None)}
        assert "report_finding" in names, (
            "the model cannot create a finding: traffic_bind_evidence requires one, "
            "and without a write verb the whole A2 chain is unreachable from the "
            "model's seat (measured 2026-10-09: 4/4 runs produced answer cards only)"
        )

    def test_agent_reported_finding_is_bindable_in_one_pass(self, tmp_path):
        """The full loop through the agent-facing tools, no manual wiring.

        report_finding -> traffic_list (get the request_id) -> traffic_bind_evidence
        -> report. Nothing here calls the library directly except to read the
        report back, which is the point: this is what a live run does.
        """
        from vulnclaw.agent.builtin_tools import execute_report_finding_tool, execute_traffic_bind_tool
        from vulnclaw.traffic.tools import dispatch_traffic_tool

        run_dir = _run_layout(tmp_path)
        session = SessionState(target="http://app.test")
        agent = _AgentStub(session, run_dir)

        traffic = TrafficStore(run_dir / "evidence" / "traffic")
        proof = _capture(traffic, INJECTED_URL)

        # 1. The model reports the vulnerability (the missing verb).
        out = execute_report_finding_tool(
            agent,
            {
                "title": "SQL Injection in /user",
                "severity": "High",
                "vuln_type": "SQLi",
                "description": "the id parameter is concatenated into the SQL query",
                "remediation": "use parameterized queries",
                "verified": True,
            },
        )
        assert "SQL Injection in /user" in out
        assert len(session.findings) == 1, f"finding not recorded: {out}"

        # 2. The model lists captures and sees the request_id (it does not guess).
        listing = dispatch_traffic_tool(traffic, "traffic_list", {})
        assert proof in listing, "traffic_list must surface the request_id to cite"

        # 3. The model binds that capture as proof of the finding it just reported.
        bind_out = execute_traffic_bind_tool(
            agent,
            {
                "finding": "SQL Injection in /user",
                "evidence": [{"request_id": proof, "role": "proof", "note": "error-based"}],
            },
        )
        assert "绑定" in bind_out and "拒绝" not in bind_out, bind_out

        # 4. The report carries the proof, with no manual binding anywhere.
        report_path = generate_report(
            session, output_path=str(run_dir / "report.md"), run_dir=str(run_dir)
        )
        text = report_path.read_text(encoding="utf-8")
        assert "SQL Injection in /user" in text
        assert "```http" in text and "GET /user?id=1' HTTP/1.1" in text

    def test_report_finding_rejects_an_empty_title(self, tmp_path):
        from vulnclaw.agent.builtin_tools import execute_report_finding_tool

        run_dir = _run_layout(tmp_path)
        session = SessionState(target="http://app.test")
        agent = _AgentStub(session, run_dir)

        out = execute_report_finding_tool(agent, {"title": "   "})
        assert "拒绝" in out or "title" in out.lower()
        assert session.findings == [], "a rejected report must not create a finding"


class TestReportFindingRecordsTheTruth:
    """Re-reporting is how a finding gets promoted; it must not lie, or duplicate.

    Measured on the tree that introduced ``report_finding`` (2026-10-09 audit),
    the natural live order -- report the bug when you find it, report again once
    you have exploited it -- could not promote anything:

    * ``add_finding``'s exact finding_id dedup returns False *without* applying
      its keep-the-stronger-evidence rule, so the second report was silently
      dropped while the tool still answered "已记为已验证漏洞";
    * when the second report carried a URL its generated id changed, so the same
      bug was filed a SECOND time instead;
    * and a bare ``verified=true`` report put a row marked ✅ 已验证 into the
      report whose own title said "[未验证]" and whose body said it had no
      evidence at all.
    """

    #: A finding with real substance -- the shape a model reports after exploiting.
    CANDIDATE = {
        "title": "SQL Injection",
        "severity": "High",
        "vuln_type": "SQLi",
        "description": "the id parameter is concatenated into the SQL query",
        "remediation": "use parameterized queries",
    }

    def _agent(self, run_dir=None):
        session = SessionState(target="http://app.test")
        return session, _AgentStub(session, run_dir)

    def test_a_bare_verified_report_is_recorded_as_a_candidate(self):
        from vulnclaw.agent.builtin_tools import execute_report_finding_tool

        session, agent = self._agent()
        out = execute_report_finding_tool(
            agent, {"title": "SQL Injection in /user", "verified": True}
        )

        assert len(session.findings) == 1
        assert session.findings[0].verified is False
        assert session.findings[0].lifecycle_status == "needs_manual_review"
        assert session.get_verified_findings() == [], (
            "a verified claim with nothing to check against must not reach the report"
        )
        assert "未被采纳" in out, out

    def test_re_reporting_promotes_the_existing_finding_instead_of_dropping_it(self):
        from vulnclaw.agent.builtin_tools import execute_report_finding_tool

        session, agent = self._agent()
        execute_report_finding_tool(agent, dict(self.CANDIDATE))

        upgraded = dict(self.CANDIDATE)
        upgraded["verified"] = True
        upgraded["evidence"] = "error-based proof: the payload dumped the users table"
        out = execute_report_finding_tool(agent, upgraded)

        assert len(session.findings) == 1, f"the re-report filed a second finding: {out}"
        assert session.findings[0].verified is True, out
        assert [f.title for f in session.get_verified_findings()] == ["SQL Injection"]
        assert not session.findings[0].title.startswith("[未验证]"), (
            "a promoted finding must not stay labelled 未验证"
        )
        assert "已更新" in out and "未新增重复记录" in out, out

    def test_re_reporting_with_a_url_in_the_evidence_does_not_file_a_second_finding(self):
        from vulnclaw.agent.builtin_tools import execute_report_finding_tool

        session, agent = self._agent()
        execute_report_finding_tool(agent, dict(self.CANDIDATE))

        # The second report cites a URL, so its generated finding_id changes from
        # "SQLi" to "SQLi_/user?id=1": identity cannot rest on the id alone.
        upgraded = dict(self.CANDIDATE)
        upgraded["verified"] = True
        upgraded["evidence"] = "GET /user?id=1 -> 500 SQL syntax error near ''1''"
        execute_report_finding_tool(agent, upgraded)

        assert len(session.findings) == 1, "the same bug was filed twice"
        assert session.findings[0].verified is True

    def test_a_promoted_finding_renders_as_verified_without_contradicting_itself(self, tmp_path):
        from vulnclaw.agent.builtin_tools import execute_report_finding_tool

        run_dir = _run_layout(tmp_path)
        session, agent = self._agent(run_dir)
        execute_report_finding_tool(agent, dict(self.CANDIDATE))
        upgraded = dict(self.CANDIDATE)
        upgraded["verified"] = True
        upgraded["evidence"] = "error-based proof"
        execute_report_finding_tool(agent, upgraded)

        report = generate_report(
            session, output_path=str(run_dir / "report.md"), run_dir=str(run_dir)
        )
        text = report.read_text(encoding="utf-8")

        assert "SQL Injection" in text
        assert "[未验证]" not in text, "the report showed a ✅ 已验证 row titled 未验证"
        assert "缺少验证证据" not in text, "the verified section carried the no-evidence advisory"

    def test_re_reporting_without_a_severity_does_not_downgrade(self):
        from vulnclaw.agent.builtin_tools import execute_report_finding_tool

        session, agent = self._agent()
        execute_report_finding_tool(
            agent,
            {
                "title": "RCE in upload",
                "severity": "Critical",
                "vuln_type": "RCE",
                "evidence": "whoami returned www-data",
            },
        )

        # `severity` defaults to Medium, so "only move up" has to mean it: a
        # re-report that never names a severity must not knock Critical down.
        execute_report_finding_tool(
            agent, {"title": "RCE in upload", "vuln_type": "RCE", "evidence": "id"}
        )
        assert session.findings[0].severity == "Critical"

    def test_a_bare_re_report_does_not_deny_a_finding_that_is_already_verified(self):
        from vulnclaw.agent.builtin_tools import execute_report_finding_tool

        session, agent = self._agent()
        upgraded = dict(self.CANDIDATE)
        upgraded["verified"] = True
        upgraded["evidence"] = "error-based proof"
        execute_report_finding_tool(agent, upgraded)

        # The refusal note is about THIS report's substance; the answer must not
        # contradict its own "当前已标记为已验证" state line.
        out = execute_report_finding_tool(agent, {"title": "SQL Injection", "verified": True})

        assert session.findings[0].verified is True
        assert "已标记为已验证" in out
        assert "未被采纳" not in out, out

    def test_an_ir_answer_card_is_never_merged_into(self):
        from vulnclaw.agent.builtin_tools import execute_report_finding_tool
        from vulnclaw.config.domain_models import ANSWER_CARD_VULN_TYPE

        session, agent = self._agent()
        card = VulnerabilityFinding(
            title="Q1 attacker IP", severity="Info", vuln_type=ANSWER_CARD_VULN_TYPE
        )
        session.add_finding(card, skip_dedup=True)

        # Same title as the card: a report must never rewrite the answer sheet.
        execute_report_finding_tool(
            agent,
            {"title": "Q1 attacker IP", "vuln_type": "SQLi", "evidence": "x", "verified": True},
        )

        assert card.vuln_type == ANSWER_CARD_VULN_TYPE
        assert card.verified is False, "a vulnerability report promoted an answer card"
        assert card.evidence == ""


class _AgentStub:
    """Minimal agent surface the traffic/report tools read: run_dir + session."""

    def __init__(self, session, run_dir):
        self.session_state = session
        self.run_dir = str(run_dir)
        self.active_role = None
        self.mcp_manager = None
