"""Tests for blackboard review (Muteki port)."""

import pytest

from vulnclaw.agent.blackboard import Blackboard, _run_blackboard_review, NodeType, NodeStatus


def test_review_challenges_unwitnessed_facts():
    bb = Blackboard()
    # Create a confirmed fact with evidence reference
    fact = bb.create_fact("admin panel found", evidence_ref="e001", verified=True)
    # Evidence that doesn't contain the fact
    evidence_by_id = {"e001": "directory listing: index.html, contact.html"}
    
    results = _run_blackboard_review(bb, evidence_by_id)
    assert len(results) > 0
    assert any("CHALLENGED" in r for r in results)


def test_review_merges_superseded_facts():
    bb = Blackboard()
    # Create confirmed fact
    old = bb.create_fact("user: admin", verified=True)
    # Create newer candidate
    new = bb.create_fact("user: admin")
    
    evidence_by_id = {"e001": "user: admin found"}
    
    results = _run_blackboard_review(bb, evidence_by_id)
    assert len(results) > 0
    assert any("MERGED" in r for r in results)
    # Old fact should be superseded
    assert bb.get_node(old.id).status == NodeStatus.SUPERSEDED


def test_review_flagged_rejected_intents():
    bb = Blackboard()
    intent = bb.create_intent("brute force login")
    bb.reject_intent(intent.id, "WAF blocks")
    
    evidence_by_id = {}
    results = _run_blackboard_review(bb, evidence_by_id)
    assert len(results) > 0
    assert any("FLAGGED" in r for r in results)