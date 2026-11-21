"""Every solve exit must declare a machine-readable stop reason.

Motivation (measured 2026-10-21): a run refused because another process held the
solve lock printed "⊘ 未达成 ... 原因: 仍未达到完成条件" with ``steps=0``. The
branch set only ``SolveResult.reason``; the CLI prints
``agent_state.complete_reason``. Twice that read as "the agent did nothing" and
cost a manual investigation.

These tests pin the two halves of the fix:
- the enum covers every exit and its values are stable strings,
- the CLI/status renderer prints the code next to the sentence, and keeps
  printing old runs (no ``stop_reason``) exactly as before.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.cli.status_display import format_stop_status
from vulnclaw.config.domain_models import StopReason


class TestStopReasonEnum:
    def test_values_are_plain_strings(self):
        # Run records are JSON; a str-Enum that serialises as "StopReason.X"
        # would break every consumer that compares against "lock_held".
        for member in StopReason:
            assert isinstance(member.value, str)
            assert member.value == member.value.strip()
            assert member.value == member.value.lower()

    def test_values_are_unique(self):
        values = [m.value for m in StopReason]
        assert len(values) == len(set(values))

    def test_every_measured_exit_has_a_code(self):
        # One entry per exit path in solver.solve/_solve_impl. Adding a new
        # termination without a code should fail here first.
        required = {
            "completed",
            "token_budget",
            "runaway",
            "lock_held",
            "stall_evidence_only",
            "stall_no_action",
            "stall_path",
            "waiting_user",
            "finalize_error",
            "repeated_errors",
        }
        assert required == {m.value for m in StopReason}


class TestAgentStateCarriesCode:
    def test_default_is_empty_for_old_runs(self):
        # Pre-existing run JSON has no stop_reason; it must deserialise to ""
        # and keep rendering the old way.
        assert AgentState().stop_reason == ""

    def test_mark_complete_sets_completed_code(self):
        state = AgentState()
        state.mark_complete("flag accepted")
        assert state.completed is True
        assert state.stop_reason == StopReason.COMPLETED.value
        assert state.complete_reason == "flag accepted"

    def test_code_survives_summary(self):
        state = AgentState()
        state.complete_reason = "another solve run is active for this target"
        state.stop_reason = StopReason.LOCK_HELD.value
        summary = state.get_summary()
        assert summary["stop_reason"] == "lock_held"
        assert summary["complete_reason"] == "another solve run is active for this target"

    def test_reset_for_goal_clears_code(self):
        state = AgentState()
        state.completed = True
        state.complete_reason = "done"
        state.stop_reason = StopReason.COMPLETED.value
        state.reset_for_goal(origin="http://x", goal="new goal")
        assert state.stop_reason == ""


class TestStatusRendering:
    def test_code_prefixes_sentence(self):
        rendered = format_stop_status(
            {
                "stop_reason": "lock_held",
                "complete_reason": "another solve run is active for this target",
            }
        )
        assert rendered == "lock_held (another solve run is active for this target)"

    def test_old_run_without_code_renders_sentence_only(self):
        rendered = format_stop_status(
            {"stop_reason": "", "complete_reason": "token budget exhausted"}
        )
        assert rendered == "token budget exhausted"

    def test_old_run_without_anything_renders_placeholder(self):
        rendered = format_stop_status({"stop_reason": "", "complete_reason": ""})
        # The i18n placeholder, whichever language is active. Just prove it is
        # non-empty and not a code.
        assert rendered
        assert "(" not in rendered

    def test_reads_agent_state_objects_too(self):
        # commands_run holds the summary dict; solve_report and the REPL hold
        # the live object. One renderer serves both.
        state = AgentState()
        state.complete_reason = "stalled with no untried path remaining"
        state.stop_reason = StopReason.STALL_PATH.value
        assert format_stop_status(state) == (
            "stall_path (stalled with no untried path remaining)"
        )


class TestLockRefusalIsLegible:
    """The exact regression: a lock-blocked run must not look like a no-op."""

    def test_lock_blocked_run_reports_its_cause(self, tmp_path, monkeypatch):
        from vulnclaw.agent import solver as solver_mod

        holder = {"pid": 4242, "started": "2026-10-21T10:00:00"}
        monkeypatch.setattr(solver_mod, "_acquire_solve_lock", lambda origin: holder)

        state = AgentState()
        state.origin = "http://target"

        class _Ctx:
            pass

        class _Inner:
            def __init__(self):
                self.agent_state = state

        class _Agent:
            context = _Ctx()

        agent = _Agent()
        agent.context.state = _Inner()

        import asyncio

        result = asyncio.run(
            solver_mod.solve(agent, origin="http://target", goal="get flag")
        )

        assert result.completed is False
        assert result.steps == 0
        assert "another solve run is active" in result.reason
        # Both the sentence and the code land where the CLI reads them.
        assert state.complete_reason == result.reason
        assert state.stop_reason == StopReason.LOCK_HELD.value
        rendered = format_stop_status(state.get_summary())
        assert rendered.startswith("lock_held (")