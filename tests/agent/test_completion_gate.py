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


# ── visible incompleteness: an opening brace must be observed to CLOSE ──────
#
# 2026-10-09 (鸡公煲 rehearsal): a flag split into six 7-char fragments was assembled
# from only five, and the model supplied the missing `}` itself. It matched the flag
# regex AND looked grounded, because the model had already written that exact string into
# a blackboard note whose tool result counts as evidence. The platform rejected it.
# These tests pin the tell: the brace, and a UUID body that is short its last group.


def test_five_of_six_fragments_is_refused_even_though_it_looks_grounded():
    # Same SHAPE as the real incident (8-4-4-4-6) but a synthetic body: the real value is
    # a per-instance flag and has no business being stored in the repo.
    flag = "CTF2{01234567-89ab-cdef-0123-456789}"
    st = _make_flag_state(f"note: Full flag = {flag}\n")
    ok, reason, _ = _completion_gate(st, f"FINAL: {flag} (evidence e008)")
    assert not ok
    assert "TRUNCATED" in reason
    assert "12" in reason  # says what a UUID last group should be


def test_complete_uuid_flag_still_completes():
    flag = "CTF2{8ff2d98e-e990-4604-9235-f012e1b8cb80}"
    st = _make_flag_state(f"leaked: {flag}")
    ok, reason, _ = _completion_gate(st, f"FINAL: Flag: {flag} (evidence e008)")
    assert ok, reason


def test_unclosed_candidate_says_not_to_supply_the_brace():
    """No complete flag, only an opening-brace fragment: name the missing brace."""
    st = _make_flag_state("evidence so far: CTF2{01234567-89ab-cdef-0123")
    ok, reason, _ = _completion_gate(
        st, "FINAL: assembled so far CTF2{01234567-89ab-cdef-0123 (缺尾段)"
    )
    assert not ok
    assert "UNCLOSED" in reason
    assert "brace" in reason


def test_completeness_check_is_narrow():
    """Wide enough shapes must pass untouched -- this runs on the completion path."""
    from vulnclaw.agent.ctf_mode import flag_completeness_issues

    complete = [
        "CTF2{8ff2d98e-e990-4604-9235-f012e1b8cb80}",   # full UUID
        "GKCTF{9cf21dda-34be-4f6c-a629-9c4647981ad7}",  # full UUID, other prefix
        "D0g3{3466b11de8894198af3636c5bd1efce2}",       # 32 hex, no dashes
        "flag{189ff9e5b743ae95f940a6ccc6dbd9ab}",       # 32 hex
        "flag{fil3_ext3nsi0ns_4r3nt_r34l}",             # prose-shaped body
        "SETCTF{Fi9ht1ng_3ItH_V1rUs}",
    ]
    for flag in complete:
        assert flag_completeness_issues(f"answer says {flag}", [flag]) == [], flag

    # a masked fingerprint is not an unclosed candidate
    assert flag_completeness_issues("note: CTF2{0123…6789}", []) == []
    # ...but these two shapes are (synthetic bodies, same shapes as the real incident)
    assert flag_completeness_issues("x", ["CTF2{01234567-89ab-cdef-0123-456789}"])
    assert flag_completeness_issues("只有 CTF2{01234567-89ab-cdef-0123 这一段", [])
