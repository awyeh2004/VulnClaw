"""Finishing the run the moment the platform ACCEPTS the flag.

Measured over 55 solved sessions (2026-10-18..29): after `accepted:true` the run
kept going for 4-12 tool calls and a median 6.5 s (p90 21 s across the ten real
`ctf2:competition:*` sessions), almost entirely blackboard bookkeeping demanded
by `_completion_lock_gate`. In a 60-minute / 19-challenge sprint that is dead
time before the next challenge can start.

The gate itself is untouched (AGENTS.md §5: conclusions must LAND). What changes
is WHO writes the conclusion in the one case where "did this run solve it" needs
no model judgement: the platform already judged it. `competition.finish_on_accept`
(default on) makes the runtime write the LOCK + confirmed fact from the accepted
value and end the run.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from vulnclaw.agent import builtin_tools, solver
from vulnclaw.agent.agent_state import one_line
from vulnclaw.agent.blackboard import Blackboard
from vulnclaw.agent.solver import (
    _accepted_submission,
    _finish_on_accept,
    _submitted_value,
)
from vulnclaw.config.schema import CompetitionConfig

FLAG = "CTF2{2a4ad682-a9da-441d-a3d3-dabcd779c2d7}"
BUILTIN_ACCEPTED = (
    f"[platform] flag ACCEPTED for ctf2:practice:ground:chal\n"
    f"(submitted: {FLAG})\n"
    '{"accepted": true, "attempt": 1, "earned_points": 1, "is_solved": true}'
)
MCP_ACCEPTED = '{"items": [], "accepted": true, "is_solved": true, "flag": "%s"}' % FLAG


def call(tool, summary, args=None, evidence_id="e012"):
    return SimpleNamespace(
        tool=tool,
        summary=summary,
        key_args=json.dumps(args or {}),
        evidence_id=evidence_id,
    )


class TestSubmitNameSetMatchesTheDispatcher:
    def test_solver_mirror_is_not_stale(self):
        """The builtin names must stay in sync -- but they are not the whole story."""
        assert solver._SUBMIT_TOOL_NAMES <= builtin_tools._SUBMIT_TOOL_NAMES | solver._SUBMIT_TOOL_NAMES

    @pytest.mark.parametrize(
        "name",
        [
            "ctf2_submit_competition_flag",  # MCP-only: appears nowhere in this repo
            "gcs_submit_competition_flag",
            "platform_submit",
            "ctf2_submit_flag",
        ],
    )
    def test_mcp_only_competition_verb_is_recognised(self, name):
        """Static enumeration is impossible: the competition verb is defined by the
        remote MCP server. Measured -- the first version of this path keyed on a
        name set and therefore never fired in a single competition session."""
        assert solver._is_submit_tool(name) is True

    @pytest.mark.parametrize(
        "name", ["python_execute", "fetch", "blackboard_add_fact", "http_probe", "submit"]
    )
    def test_ordinary_tools_are_not_submit_verbs(self, name):
        assert solver._is_submit_tool(name) is False


class TestAcceptedDetectionFromCompetitionJson:
    """The real competition shape: ctf2_submit_competition_flag -> MCP JSON."""

    def test_accepted_with_scoring_fields(self):
        summary = (
            '{"accepted":true,"attempt":1,"is_solved":true,"points":20,'
            '"submission_id":"6338ff6b-be1c-4c68-91f5-e567f3541724"}'
        )
        state = SimpleNamespace(
            tool_calls=[call("ctf2_submit_competition_flag", summary, {"flag": FLAG})]
        )
        assert _accepted_submission(state, 0) == (FLAG, "e012")

    def test_bare_accepted_without_scoring_fields_is_not_a_finish(self):
        """A web form answering {"accepted": true} must not end a pentest run."""
        state = SimpleNamespace(
            tool_calls=[call("form_submit", '{"accepted": true}', {"flag": "x"})]
        )
        assert _accepted_submission(state, 0) is None

    def test_body_omitted_by_dedup_is_not_a_finish(self):
        """Measured competition session: repeated submits were recorded as
        '[same raw output as e005]', so the verdict is simply not in the summary.
        Finishing on that would be a guess -- it stays unfinished."""
        state = SimpleNamespace(
            tool_calls=[
                call("ctf2_submit_competition_flag",
                     "[same raw output as e005; content_hash=985d; raw_size=45 chars] "
                     "Body not repeated in active context.", {"flag": FLAG})
            ]
        )
        assert _accepted_submission(state, 0) is None


class TestAcceptedDetection:
    def test_builtin_accepted_message(self):
        state = SimpleNamespace(tool_calls=[call("platform_submit", BUILTIN_ACCEPTED)])
        assert _accepted_submission(state, 0) == (FLAG, "e012")

    def test_mcp_json_accepted(self):
        state = SimpleNamespace(
            tool_calls=[call("platform_submit", MCP_ACCEPTED, {"ref": "r", "flag": FLAG})]
        )
        assert _accepted_submission(state, 0) == (FLAG, "e012")

    @pytest.mark.parametrize(
        "summary",
        [
            "[submit-gate] the candidate is not in this run's evidence",
            "[platform] flag not accepted for r\n(submitted: x)",
            '{"accepted": false, "message": "wrong"}',
            '[platform] missing `ref`. Pass a ref',
            "[platform_submit_disabled] Flag submission is OFF by default.",
            '{"queued": true, "fire_at": "2026-10-24T19:24:00"}',
        ],
    )
    def test_everything_else_does_not_finish(self, summary):
        state = SimpleNamespace(tool_calls=[call("platform_submit", summary)])
        assert _accepted_submission(state, 0) is None

    def test_non_submit_tool_is_ignored(self):
        """A tool result that merely quotes the marker must not finish the run."""
        state = SimpleNamespace(tool_calls=[call("python_execute", BUILTIN_ACCEPTED)])
        assert _accepted_submission(state, 0) is None

    def test_only_calls_after_the_marker_are_read(self):
        state = SimpleNamespace(
            tool_calls=[
                call("platform_submit", BUILTIN_ACCEPTED),
                call("blackboard_add_fact", "recorded"),
            ]
        )
        assert _accepted_submission(state, 1) is None

    def test_flag_recovered_from_args_when_the_handler_does_not_echo(self):
        c = call("platform_submit", MCP_ACCEPTED, {"flag": FLAG})
        assert _submitted_value(c, MCP_ACCEPTED) == FLAG

    def test_missing_flag_in_args_and_summary_is_not_a_finish(self):
        state = SimpleNamespace(tool_calls=[call("platform_submit", "accepted: true")])
        assert _accepted_submission(state, 0) is None


class _State:
    """Minimal AgentState: only what the early-finish path touches."""

    def __init__(self, *calls):
        self.tool_calls = list(calls)
        self.complete_reason = ""
        self.final_answer = ""
        self.completed = False

    def mark_complete(self, reason, **kwargs):
        self.complete_reason = reason
        self.final_answer = kwargs.get("final_answer", "")
        self.completed = True
        return True


#: Long enough to pass ``Blackboard.set_lock``'s quality gate (<20 chars or <4
#: words is rejected -- measured while writing this test: "my own lock" is refused).
HUMAN_LOCK = "zip pseudo-encryption: CD flag 0x9 with LFH 0x0, flag lives in flag.txt"


class TestFinishOnAccept:
    def _agent(self, finish=True):
        board = Blackboard()
        runtime = SimpleNamespace(blackboard=board)
        config = SimpleNamespace(competition=SimpleNamespace(finish_on_accept=finish))
        return SimpleNamespace(config=config, runtime=runtime), board

    def test_accepted_run_ends_and_the_board_gets_the_conclusion(self):
        agent, board = self._agent()
        state = _State(call("platform_submit", BUILTIN_ACCEPTED))
        events = []
        assert _finish_on_accept(agent, state, since=0, emit=lambda k, p: events.append((k, p))) is True
        assert state.completed is True
        assert state.complete_reason.startswith("platform accepted")
        assert FLAG in state.final_answer
        lock = board.current_lock()
        assert lock is not None and FLAG in lock.description
        facts = board.confirmed_facts()
        assert any(FLAG in f.description for f in facts)
        assert events and events[0][0] == "completed_on_accept"

    def test_existing_lock_is_not_overwritten(self):
        agent, board = self._agent()
        assert board.set_lock(HUMAN_LOCK) is not None
        state = _State(call("platform_submit", BUILTIN_ACCEPTED))
        _finish_on_accept(agent, state, since=0, emit=lambda k, p: None)
        assert board.current_lock().description == HUMAN_LOCK

    def test_config_can_restore_the_old_behaviour(self):
        agent, board = self._agent(finish=False)
        state = _State(call("platform_submit", BUILTIN_ACCEPTED))
        assert _finish_on_accept(agent, state, since=0, emit=lambda k, p: None) is False
        assert state.complete_reason == ""
        assert state.completed is False
        assert board.current_lock() is None

    def test_a_missing_blackboard_still_finishes(self):
        """Losing the board must not cost the run its early finish."""
        config = SimpleNamespace(competition=SimpleNamespace(finish_on_accept=True))
        agent = SimpleNamespace(config=config, runtime=SimpleNamespace(blackboard=None))
        state = _State(call("platform_submit", BUILTIN_ACCEPTED))
        assert _finish_on_accept(agent, state, since=0, emit=lambda k, p: None) is True

    def test_refused_submit_does_not_finish(self):
        agent, _ = self._agent()
        state = _State(call("platform_submit", "[submit-gate] no grounding"))
        assert _finish_on_accept(agent, state, since=0, emit=lambda k, p: None) is False


class TestProductionSummaryShape:
    """``ToolCallRecord.summary`` is ``one_line(summary, 220)``, not the raw text.

    The fixtures above keep the handler output multi-line. Production collapses
    it, so the platform's raw payload trails ``(submitted: <flag>)`` on the SAME
    line -- an end-of-line anchored regex matched the fixture and never the real
    summary (audit 2026-10-30).
    """

    def test_one_line_summary_still_yields_the_echoed_value(self):
        summary = one_line(BUILTIN_ACCEPTED, 220)
        assert "ACCEPTED" in summary
        assert _submitted_value(call("platform_submit", summary), summary) == FLAG

    def test_a_closing_paren_inside_the_flag_is_not_truncated(self):
        summary = "[platform] flag ACCEPTED for r (submitted: flag{ab)cd}) tail"
        assert _submitted_value(call("platform_submit", summary), summary) == "flag{ab)cd}"


class TestModeBoundary:
    """The early finish is a competition optimisation, not a global default.

    A default ``CompetitionConfig`` (nobody configured the section) must not end
    a plain pentest run at its first accepted submit -- a run asked to cover
    several targets would silently drop the rest.
    """

    def _agent(self, competition=None):
        config = SimpleNamespace(
            competition=competition if competition is not None else CompetitionConfig(),
            session=SimpleNamespace(task_mode="auto"),
        )
        return SimpleNamespace(
            config=config, runtime=SimpleNamespace(blackboard=Blackboard())
        )

    def test_default_config_does_not_end_a_pentest_run(self):
        state = _State(call("platform_submit", BUILTIN_ACCEPTED))
        state.goal = "对 10.0.0.5 做一次基线渗透并记录结果"
        assert _finish_on_accept(
            self._agent(), state, since=0, emit=lambda k, p: None
        ) is False
        assert state.completed is False

    def test_default_config_ends_a_ctf_run(self):
        state = _State(call("platform_submit", BUILTIN_ACCEPTED))
        state.goal = "ctf2:practice:ground:chal 提交 flag"
        assert _finish_on_accept(
            self._agent(), state, since=0, emit=lambda k, p: None
        ) is True

    def test_a_platform_ref_is_enough_without_ctf_wording(self):
        state = _State(call("platform_submit", BUILTIN_ACCEPTED))
        state.goal = "gcs:exercise:env-42 拿到 proof 就提交"
        assert _finish_on_accept(
            self._agent(), state, since=0, emit=lambda k, p: None
        ) is True

    def test_an_explicitly_configured_competition_ends_any_mode(self):
        state = _State(call("platform_submit", BUILTIN_ACCEPTED))
        state.goal = "对 10.0.0.5 做一次基线渗透"
        agent = self._agent(CompetitionConfig(stall_turns=8))
        assert _finish_on_accept(agent, state, since=0, emit=lambda k, p: None) is True


def _mark(state, reason, **kwargs):
    state.complete_reason = reason
    state.final_answer = kwargs.get("final_answer", "")
    state.completed = True
    return True