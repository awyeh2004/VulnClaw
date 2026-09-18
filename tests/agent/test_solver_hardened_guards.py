"""Code-guaranteed reasoning hygiene: periodic review + empty-board NO_PATH gate.

Both were previously prompt-only ("Periodically run blackboard_review", register
ANGLES) — a model that never engaged left the coverage gate vacuous and facts
unchallenged. These tests pin the deterministic helpers behind the new hooks.
"""

from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.agent.blackboard import Blackboard, NodeStatus
from vulnclaw.agent.solver import _auto_review_blackboard, _no_path_coverage_thin


def _agent_with(bb):
    return SimpleNamespace(runtime=SimpleNamespace(blackboard=bb))


def _state_with_evidence(evidence):
    return SimpleNamespace(evidence=evidence)


def test_coverage_thin_true_for_empty_board():
    bb = Blackboard()
    bb.create_fact("a guess nobody verified")  # candidate, not confirmed
    assert _no_path_coverage_thin(_agent_with(bb)) is True


def test_coverage_thin_false_once_angles_registered():
    bb = Blackboard()
    bb.create_fact("a guess nobody verified")
    bb.create_angle("sqli on login")
    assert _no_path_coverage_thin(_agent_with(bb)) is False


def test_coverage_thin_false_once_two_facts_confirmed():
    bb = Blackboard()
    f1 = bb.create_fact("finding one", evidence_ref="e1")
    f2 = bb.create_fact("finding two", evidence_ref="e2")
    bb.confirm_fact(f1.id)
    bb.confirm_fact(f2.id)
    assert _no_path_coverage_thin(_agent_with(bb)) is False


def test_coverage_thin_false_without_blackboard():
    agent = SimpleNamespace(runtime=SimpleNamespace(blackboard=None))
    assert _no_path_coverage_thin(agent) is False


def test_auto_review_challenges_uncorroborated_fact():
    bb = Blackboard()
    f = bb.create_fact("admin panel reachable at /admin", evidence_ref="e1")
    bb.confirm_fact(f.id)
    state = _state_with_evidence(
        [SimpleNamespace(id="e1", content="port 22 open, banner SSH-2.0")]
    )
    results = _auto_review_blackboard(_agent_with(bb), state)
    assert any("CHALLENGED" in r for r in results)
    assert bb.get_node(f.id).status == NodeStatus.CHALLENGED


def test_auto_review_silent_when_fact_witnessed():
    bb = Blackboard()
    f = bb.create_fact("admin panel reachable at /admin", evidence_ref="e1")
    bb.confirm_fact(f.id)
    state = _state_with_evidence(
        [SimpleNamespace(id="e1", content="GET /admin -> 200; the admin panel is reachable and rendered")]
    )
    assert _auto_review_blackboard(_agent_with(bb), state) == []


def test_auto_review_no_blackboard_no_findings():
    agent = SimpleNamespace(runtime=SimpleNamespace(blackboard=None))
    assert _auto_review_blackboard(agent, _state_with_evidence([])) == []


# ── completion gate LOCK nudge ───────────────────────────────────────────


def test_lock_nudge_rejects_once_then_allows():
    from vulnclaw.agent.solver import _blackboard_lock_missing

    bb = Blackboard()
    agent = _agent_with(bb)
    assert _blackboard_lock_missing(agent) is True
    bb.set_lock("heap UAF, flag in /flag")
    assert _blackboard_lock_missing(agent) is False


def test_lock_nudge_never_blocks_without_blackboard():
    from vulnclaw.agent.solver import _blackboard_lock_missing

    agent = SimpleNamespace(runtime=SimpleNamespace(blackboard=None))
    assert _blackboard_lock_missing(agent) is False
