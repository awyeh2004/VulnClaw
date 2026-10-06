"""Tests for bounded parallel agent coordination."""

from __future__ import annotations

import pytest

from vulnclaw.agent.agent_graph import AgentGraph, AgentOutcome, AgentStatus, FanOutCaps
from vulnclaw.agent.context import SessionState, VulnerabilityFinding
from vulnclaw.agent.parallel_agents import (
    extract_attack_surfaces,
    merge_session_state,
    run_parallel_pentest,
)


class FakeAgent:
    def __init__(self) -> None:
        self.session_state = SessionState(target="192.168.1.0/24")
        self.calls: list[str] = []

    async def auto_pentest(self, prompt, target=None, max_rounds=0, stream_sink=None):
        self.calls.append(prompt)
        if "authorized fast network scan" in prompt:
            self.session_state.recon_data["network_services"] = [
                {
                    "host": "192.168.1.10",
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                },
                {
                    "host": "192.168.1.20",
                    "port": 445,
                    "protocol": "tcp",
                    "service": "microsoft-ds",
                },
            ]
            return ["root-discovery"]

        self.session_state.add_finding(
            VulnerabilityFinding(
                title=f"Surface reviewed {len(self.calls)}",
                severity="Info",
                vuln_type="surface-review",
                evidence=prompt,
            )
        )
        self.session_state.notes.append("worker note")
        return ["worker-result"]


def test_extract_attack_surfaces_from_network_state_and_findings():
    state = SessionState(target="192.168.1.0/24")
    state.recon_data["network_services"] = [
        {"host": "192.168.1.10", "port": 22, "protocol": "tcp", "service": "ssh"},
        {"host": "192.168.1.10", "port": 22, "protocol": "tcp", "service": "ssh"},
    ]
    state.recon_data["network_scans"] = [
        {
            "weak_links": [
                {"target": "192.168.1.20:445", "reason": "SMB exposed"},
            ]
        }
    ]
    state.add_finding(
        VulnerabilityFinding(
            title="Web finding",
            vuln_type="web",
            evidence="Observed at http://192.168.1.30/admin",
        )
    )

    surfaces = extract_attack_surfaces(state)

    assert [surface.target for surface in surfaces] == [
        "192.168.1.10:22",
        "192.168.1.20:445",
        "http://192.168.1.30/admin",
    ]


@pytest.mark.asyncio
async def test_run_parallel_pentest_fans_out_and_merges_worker_state():
    root = FakeAgent()
    children: list[FakeAgent] = []

    def factory():
        child = FakeAgent()
        children.append(child)
        return child

    result = await run_parallel_pentest(
        root,
        agent_factory=factory,
        user_input="Perform an authorized fast network scan against 192.168.1.0/24.",
        target="192.168.1.0/24",
        discovery_rounds=1,
        worker_rounds=2,
        max_agents=2,
        max_depth=1,
    )

    assert result.root_results == ["root-discovery"]
    assert result.waves_completed == 1
    assert [surface.target for surface in result.surfaces] == [
        "192.168.1.10:22",
        "192.168.1.20:445",
    ]
    assert len(children) == 2
    assert len(root.session_state.findings) == 2
    assert root.session_state.notes == ["worker note"]
    assert all("Investigate this surface only" in child.calls[0] for child in children)


@pytest.mark.asyncio
async def test_surface_wave_strategy_drives_agent_graph(tmp_path):
    root = FakeAgent()

    def factory():
        return FakeAgent()

    graph = AgentGraph(
        tmp_path / "agents",
        caps=FanOutCaps(max_concurrent=2, max_total=10, max_depth=1),
    )

    result = await run_parallel_pentest(
        root,
        agent_factory=factory,
        user_input="Perform an authorized fast network scan against 192.168.1.0/24.",
        target="192.168.1.0/24",
        discovery_rounds=1,
        worker_rounds=2,
        max_agents=2,
        max_depth=1,
        graph=graph,
    )

    # Existing callers still get the same fan-out result.
    assert result.waves_completed == 1
    assert len(root.session_state.findings) == 2

    # The graph is now the durable source of truth: root + one node per surface.
    snapshot = graph.view_graph()
    assert snapshot.root_id == graph.root_id
    worker_nodes = [n for n in snapshot.nodes if n.parent_id == graph.root_id]
    assert len(worker_nodes) == 2

    # merge_session_state ran as the child-finish hook → children finished.
    assert all(n.status == AgentStatus.DONE for n in worker_nodes)
    assert all(n.outcome == AgentOutcome.FINISHED for n in worker_nodes)

    # Every child done → root_finish accepted (fail-loud rule satisfied).
    root_node = graph.get_node(graph.root_id)
    assert root_node.status == AgentStatus.DONE
    assert root_node.outcome == AgentOutcome.FINISHED


@pytest.mark.asyncio
async def test_surface_wave_strategy_honors_max_total_cap(tmp_path):
    root = FakeAgent()

    def factory():
        return FakeAgent()

    # max_total=2 leaves room for the root + exactly one worker; the second
    # surface's create_agent is rejected and that child must not run.
    graph = AgentGraph(
        tmp_path / "agents",
        caps=FanOutCaps(max_concurrent=2, max_total=2, max_depth=1),
    )

    await run_parallel_pentest(
        root,
        agent_factory=factory,
        user_input="Perform an authorized fast network scan against 192.168.1.0/24.",
        target="192.168.1.0/24",
        discovery_rounds=1,
        worker_rounds=2,
        max_agents=2,
        max_depth=1,
        graph=graph,
    )

    snapshot = graph.view_graph()
    worker_nodes = [n for n in snapshot.nodes if n.parent_id == graph.root_id]
    assert len(worker_nodes) == 1  # second surface rejected by max_total
    assert len(root.session_state.findings) == 1  # rejected child never merged
    assert graph.get_node(graph.root_id).outcome == AgentOutcome.FINISHED


def test_extract_attack_surfaces_skips_answer_cards():
    """Round-10 #1 follow-up: an answer card's description IS the answer; mining it would
    dispatch the answer sheet to child agents as attack surfaces."""
    state = SessionState(target="127.0.0.1:2224")
    state.add_finding(
        VulnerabilityFinding(
            title="Q1: 攻击者 IP 是什么？",
            severity="Info",
            vuln_type="ir-answer",
            description="http://evil.example.com/steal",
            evidence="203.0.113.77",
        )
    )

    assert extract_attack_surfaces(state) == []


def test_merge_session_state_keeps_adjacent_answer_cards():
    """All answer cards share finding_id "ir-answer"; a plain merge dedup would keep only
    the first, silently losing the rest of a child's answer sheet."""
    parent = SessionState(target="127.0.0.1:2224")
    child = SessionState(target="127.0.0.1:2224")
    for i in range(3):
        child.add_finding(
            VulnerabilityFinding(
                title=f"Q{i + 1}: 问题",
                severity="Info",
                vuln_type="ir-answer",
                description=f"answer-{i}",
            ),
            skip_dedup=True,
        )

    merge_session_state(parent, child)

    assert len(parent.findings) == 3


def test_merge_twice_does_not_duplicate_answer_cards():
    """Round-11 #5 / round-12 F1: skip_dedup means a second (parent, child)
    merge would copy the answer cards again — same-question cards already on
    the parent must be skipped (keyed on normalized question text)."""
    from types import SimpleNamespace

    from vulnclaw.agent.parallel_agents import merge_session_state
    from vulnclaw.config.domain_models import VulnerabilityFinding

    parent_findings: list = []
    seen_ids: set = set()

    def fake_add_finding(finding, skip_dedup=False):
        # mirror SessionState.add_finding's first (exact-id) dedup layer
        if not skip_dedup and finding.finding_id in seen_ids:
            return False
        seen_ids.add(finding.finding_id)
        parent_findings.append(finding)
        return True

    parent = SimpleNamespace(
        findings=parent_findings, recon_data={}, notes={}, executed_steps=[],
        add_finding=fake_add_finding,
        _notify_checkpoint=lambda *a, **k: None,
    )
    card_q1 = VulnerabilityFinding(title="Q1: 攻击者 IP", vuln_type="ir-answer",
                                   description="203.0.113.77")
    card_q2 = VulnerabilityFinding(title="Q2: 首次入侵时间", vuln_type="ir-answer",
                                   description="2026-09-19 03:41")
    real_vuln = VulnerabilityFinding(title="RCE on /api", vuln_type="RCE",
                                     description="real vuln")
    child = SimpleNamespace(findings=[card_q1, card_q2, real_vuln],
                            recon_data={}, notes={}, executed_steps=[],
                            step_records=[])

    merge_session_state(parent, child)
    first = len(parent_findings)
    merge_session_state(parent, child)  # same parent+child merged a second time

    cards = [f for f in parent_findings if f.vuln_type == "ir-answer"]
    assert len(cards) == 2, f"duplicated on re-merge: {len(cards)} cards"
    assert first == 3  # 2 cards + 1 real vuln
    # the plain vulnerability keeps default dedup semantics (skipped on re-merge)
    assert parent_findings.count(real_vuln) == 1


def test_merge_same_number_wording_drift_merges_not_drops():
    """Round-12 F1: same question number with drifted wording merges the
    child card's evidence into the parent card instead of being dropped —
    a competition sheet has exactly one Q1."""
    from types import SimpleNamespace

    from vulnclaw.agent.parallel_agents import merge_session_state
    from vulnclaw.config.domain_models import VulnerabilityFinding

    parent_findings: list = []
    seen_ids: set = set()

    def fake_add_finding(finding, skip_dedup=False):
        if not skip_dedup and finding.finding_id in seen_ids:
            return False
        seen_ids.add(finding.finding_id)
        parent_findings.append(finding)
        return True

    parent = SimpleNamespace(
        findings=parent_findings, recon_data={}, notes={}, executed_steps=[],
        add_finding=fake_add_finding,
        _notify_checkpoint=lambda *a, **k: None,
    )
    child = SimpleNamespace(
        findings=[
            VulnerabilityFinding(title="Q1:攻击者IP", vuln_type="ir-answer",
                                 description="203.0.113.77", evidence="ev-parent"),
            VulnerabilityFinding(title="Q1:攻击者的IP是什么", vuln_type="ir-answer",
                                 description="203.0.113.77 + port 8080", evidence="ev-child"),
        ],
        recon_data={}, notes={}, executed_steps=[], step_records=[],
    )
    merge_session_state(parent, child)

    cards = [f for f in parent_findings if f.vuln_type == "ir-answer"]
    assert len(cards) == 1, f"same-number card duplicated: {[f.title for f in cards]}"
    assert "ev-parent" in cards[0].evidence and "ev-child" in cards[0].evidence


def test_merge_same_question_merges_evidence():
    """Round-12 F1 leg 2: a same-question card from the child merges its
    evidence into the parent card instead of being dropped wholesale."""
    from types import SimpleNamespace

    from vulnclaw.agent.parallel_agents import merge_session_state
    from vulnclaw.config.domain_models import VulnerabilityFinding

    parent_findings: list = []
    seen_ids: set = set()

    def fake_add_finding(finding, skip_dedup=False):
        if not skip_dedup and finding.finding_id in seen_ids:
            return False
        seen_ids.add(finding.finding_id)
        parent_findings.append(finding)
        return True

    parent = SimpleNamespace(
        findings=parent_findings, recon_data={}, notes={}, executed_steps=[],
        add_finding=fake_add_finding,
        _notify_checkpoint=lambda *a, **k: None,
    )
    child = SimpleNamespace(
        findings=[
            VulnerabilityFinding(title="Q1: 攻击者 IP 是什么", vuln_type="ir-answer",
                                 description="203.0.113.77", evidence="ev-A"),
            # same question, drifted spelling + NEW evidence the parent lacks
            VulnerabilityFinding(title="Q1:攻击者的IP是什么？", vuln_type="ir-answer",
                                 description="203.0.113.77", evidence="ev-B-new"),
        ],
        recon_data={}, notes={}, executed_steps=[], step_records=[],
    )
    merge_session_state(parent, child)

    cards = [f for f in parent_findings if f.vuln_type == "ir-answer"]
    assert len(cards) == 1, f"same-question card duplicated: {len(cards)}"
    assert "ev-A" in cards[0].evidence and "ev-B-new" in cards[0].evidence, (
        f"child evidence lost on merge: {cards[0].evidence!r}"
    )


def test_merge_non_q_prefixed_card_does_not_duplicate():
    """Round-12 F1 leg 3: cards whose title has no 'Q<n>' prefix (e.g.
    '1. 攻击者IP') get the same double-merge protection via the normalized
    question-text key — the old number-keyed guard returned '' for them."""
    from types import SimpleNamespace

    from vulnclaw.agent.parallel_agents import merge_session_state
    from vulnclaw.config.domain_models import VulnerabilityFinding

    parent_findings: list = []
    seen_ids: set = set()

    def fake_add_finding(finding, skip_dedup=False):
        if not skip_dedup and finding.finding_id in seen_ids:
            return False
        seen_ids.add(finding.finding_id)
        parent_findings.append(finding)
        return True

    parent = SimpleNamespace(
        findings=parent_findings, recon_data={}, notes={}, executed_steps=[],
        add_finding=fake_add_finding,
        _notify_checkpoint=lambda *a, **k: None,
    )
    child = SimpleNamespace(
        findings=[
            VulnerabilityFinding(title="1. 攻击者IP", vuln_type="ir-answer",
                                 description="203.0.113.77"),
        ],
        recon_data={}, notes={}, executed_steps=[], step_records=[],
    )
    merge_session_state(parent, child)
    merge_session_state(parent, child)  # second merge

    cards = [f for f in parent_findings if f.vuln_type == "ir-answer"]
    assert len(cards) == 1, f"non-Q card duplicated on re-merge: {len(cards)}"


def test_merge_numbered_unnumbered_pair_folds():
    """Round-14 F-C: the Q<n> marker is part of the stored title, so a mixed
    numbered/unnumbered pair ("Q1: 攻击者IP" vs "攻击者IP") matched neither
    the number leg nor the exact-text leg and merge kept both cards. The
    number-stripped fallback leg (mirroring record_answer) must fold them."""
    from types import SimpleNamespace

    from vulnclaw.agent.parallel_agents import merge_session_state
    from vulnclaw.config.domain_models import VulnerabilityFinding

    parent_findings: list = [
        VulnerabilityFinding(title="攻击者IP", vuln_type="ir-answer",
                             description="203.0.113.77", evidence="ev-parent"),
    ]
    seen_ids: set = set()

    def fake_add_finding(finding, skip_dedup=False):
        if not skip_dedup and finding.finding_id in seen_ids:
            return False
        seen_ids.add(finding.finding_id)
        parent_findings.append(finding)
        return True

    parent = SimpleNamespace(
        findings=parent_findings, recon_data={}, notes={}, executed_steps=[],
        add_finding=fake_add_finding,
        _notify_checkpoint=lambda *a, **k: None,
    )
    child = SimpleNamespace(
        findings=[
            VulnerabilityFinding(title="Q1: 攻击者IP", vuln_type="ir-answer",
                                 description="203.0.113.77 + port 8080",
                                 evidence="ev-child"),
        ],
        recon_data={}, notes={}, executed_steps=[], step_records=[],
    )
    merge_session_state(parent, child)
    # Round11 observation ⑤ closure: the same (parent, child) pair merged
    # twice must stay ONE card — the predicate re-matches and only merges
    # evidence, whatever the marker shapes on either side.
    merge_session_state(parent, child)

    cards = [f for f in parent_findings if f.vuln_type == "ir-answer"]
    assert len(cards) == 1, f"mixed pair duplicated: {[f.title for f in cards]}"
    assert cards[0].title == "攻击者IP", cards[0].title
    assert "ev-parent" in cards[0].evidence and "ev-child" in cards[0].evidence, (
        f"child evidence lost on merge: {cards[0].evidence!r}"
    )
