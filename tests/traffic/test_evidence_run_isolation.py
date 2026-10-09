"""Cross-run isolation of the evidence tree: the writer and the reader must agree.

The defect this guards: the traffic bind tool wrote captures into a
process-wide ``CONFIG_DIR/evidence/traffic`` store (it read ``evidence_dir`` off
the session, which ``SessionState`` never had), so a later run -- or a
concurrent one -- read the previous run's captures. Every test here pins a
*a second* run in the picture and asserts it cannot see the first run's proof.
"""

from __future__ import annotations

from pathlib import Path

from vulnclaw.agent.builtin_tools import resolve_evidence_store, resolve_traffic_store
from vulnclaw.agent.context import SessionState, VulnerabilityFinding
from vulnclaw.report.generator import generate_report
from vulnclaw.traffic.evidence import EvidenceStore
from vulnclaw.traffic.models import CapturedExchange, CapturedRequest, CapturedResponse


class _Session:
    """Legacy session double that carries an evidence dir (the pre-run_dir seam)."""

    def __init__(self, evidence_dir=None):
        self.target = "http://app.test"
        self.evidence_dir = evidence_dir
        self.findings: list[VulnerabilityFinding] = []


class _Agent:
    """An agent with the orchestrator-injected ``run_dir`` anchor."""

    def __init__(self, run_dir="", evidence_dir=None):
        self.run_dir = run_dir
        self.session_state = _Session(evidence_dir)
        self.active_role = None
        self.mcp_manager = None


def _capture(traffic, url: str) -> str:
    return traffic.record(
        CapturedExchange(
            request=CapturedRequest(method="GET", url=url, headers={"Host": "app.test"}),
            response=CapturedResponse(status=500, body=b"SQL syntax error near ''1'"),
        ),
        source="proxy",
    ).request_id


# ── the writer: agent.run_dir wins over any session-level carrier ───────────────


def test_capture_writer_prefers_the_agents_run_dir(tmp_path):
    """A stale session carrier must not out-vote the live run anchor."""
    agent = _Agent(
        run_dir=str(tmp_path / "runs" / "r2"),
        evidence_dir=str(tmp_path / "stale" / "evidence"),
    )
    store = resolve_traffic_store(agent)
    assert Path(store.index_path).parent == tmp_path / "runs" / "r2" / "evidence" / "traffic"


def test_pin_writer_prefers_the_agents_run_dir(tmp_path):
    agent = _Agent(
        run_dir=str(tmp_path / "runs" / "r2"),
        evidence_dir=str(tmp_path / "stale" / "evidence"),
    )
    store = resolve_evidence_store(agent)
    assert Path(store.base_dir) == tmp_path / "runs" / "r2" / "evidence"
