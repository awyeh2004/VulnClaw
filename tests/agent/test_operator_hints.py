"""--hint must reach AgentState.operator_hints, not compact_summary.

Measured 2026-10-21: ``9ea529b`` wrote operator hints into
``AgentState.compact_summary``. That field is rendered behind an ``elif``
(skipped once ``context_digest.summary`` is non-empty) and is overwritten
wholesale by ``update_context_digest`` during auto-compaction
(``context_auto_compact`` defaults ON). So the hint died mid-run -- on exactly
the long, stuck runs an operator gives hints to. It now lives in
``operator_hints``, which compaction never touches.

The ``" | "`` join used to sit in solver; hints are now per-line strings in a
list, so two hints can never be confused with one containing the separator.
"""

from __future__ import annotations

from vulnclaw.agent import solver


class _FakeState:
    def __init__(self) -> None:
        self.operator_hints: list[str] = []
        self.compact_summary = ""
        self.correction_hints: list[str] = []


def test_hints_land_on_the_operator_hints_field():
    state = _FakeState()
    solver._record_operator_hints(state, ["flag may be CTF2{}", "check the pcap"])

    assert state.operator_hints == ["flag may be CTF2{}", "check the pcap"], state.operator_hints
    # The old location must stay empty: writing it is what made auto-compaction
    # erase the hint.
    assert state.compact_summary == "", state.compact_summary


def test_a_hint_that_is_the_separator_join_is_one_hint_not_two():
    """A hint containing ' | ' must not be split into two hints."""
    state = _FakeState()
    solver._record_operator_hints(state, ["a | b"])
    assert state.operator_hints == ["a | b"], state.operator_hints


def test_whitespace_only_and_duplicate_hints_are_dropped():
    state = _FakeState()
    solver._record_operator_hints(state, ["   ", "", "same", "same"])

    assert state.operator_hints == ["same"], state.operator_hints


def test_hints_are_clipped_to_one_prompt_safe_line():
    state = _FakeState()
    solver._record_operator_hints(state, ["x" * 5000 + "\nsecond line"])

    assert len(state.operator_hints) == 1
    assert "\n" not in state.operator_hints[0]
    assert len(state.operator_hints[0]) <= 400


def test_calling_without_hints_touches_nothing():
    state = _FakeState()
    state.operator_hints = ["already here"]
    solver._record_operator_hints(state, None)
    assert state.operator_hints == ["already here"]


def test_real_agent_state_accepts_and_roundtrips_hints():
    from vulnclaw.agent.agent_state import AgentState

    state = AgentState(operator_hints=["check the pcap"])
    assert state.operator_hints == ["check the pcap"]

    restored = AgentState.model_validate(state.model_dump())
    assert restored.operator_hints == ["check the pcap"]

    state.reset_for_goal(origin="test", goal="new goal")
    assert state.operator_hints == []


def test_the_solver_records_hints_on_the_real_agent_state():
    from vulnclaw.agent.agent_state import AgentState

    state = AgentState()
    solver._record_operator_hints(state, ["check the pcap"])
    assert state.operator_hints == ["check the pcap"]
