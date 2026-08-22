"""Tests for the whitelist-style completion gate (Muteki port).

The gate must NOT reject a fully-grounded flag just because its content happens
to contain a substring that parses as an unknown evidence id (e.g.
``CTF2{8ff2d98e-e990-...}`` contains ``e990``). Rejection stays for flags that
are NOT grounded in evidence.
"""

import re

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.agent.solver import _completion_gate


def _make_flag_state(evidence_text: str) -> AgentState:
    st = AgentState(goal="capture the flag and output it")
    st.evidence = [
        type("Ev", (), {"content": evidence_text, "id": "e008", "evidence_id": "e008"})()
    ]
    return st


def test_flag_containing_evidence_like_substring_passes():
    """A grounded flag whose body contains 'e990' must still complete."""
    flag = "CTF2{8ff2d98e-e990-4604-9235-f012e1b8cb80}"
    st = _make_flag_state(f"0 union select group_concat(flag) -> {flag}")
    ok, reason, _ = _completion_gate(st, f"FINAL: Flag: {flag} (evidence e008)")
    assert ok, reason


def test_ungrounded_flag_still_rejected():
    """A flag not present in evidence is still rejected (no regression)."""
    st = _make_flag_state("login ok, nothing else")
    ok, reason, _ = _completion_gate(st, "FINAL: Flag: DASCTF{local_verify}")
    assert not ok
    assert "not present in tool evidence" in reason


def test_placeholder_flag_rejected():
    st = _make_flag_state("got flag{...} placeholder")
    ok, reason, _ = _completion_gate(st, "FINAL: Flag: flag{...}")
    assert not ok


def test_unknown_citation_is_soft_note_not_rejection():
    """Unknown cited ids become a note appended to the accepted result."""
    flag = "DASCTF{real_grounded_flag_123}"
    st = _make_flag_state(f"output: {flag}")
    ok, reason, cited = _completion_gate(st, f"FINAL: Flag: {flag} (evidence e999)")
    assert ok
    assert "e999" in reason  # surfaced as a soft note
    assert cited == ["e999"]


def test_missing_flag_in_flag_goal_rejected():
    st = _make_flag_state("some evidence here e001")
    ok, reason, _ = _completion_gate(st, "FINAL: the port is open")
    assert not ok
