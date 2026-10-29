"""Skipping the bookkeeping turn, bounded by how cheap the run was.

`finish_on_accept` needs a platform verdict; a hand-submitted competition
(强网杯) never produces one, so the run still pays the `_completion_lock_gate`
turn. Measured on a local LSB challenge: 1 tool call to solve, then a 17.8 s
bookkeeping turn inside a 19.6 s run (91 %).

That turn is not waste in general -- it is where the model writes the [miss]
angles that make the note worth recalling -- so the switch is opt-in AND bounded
by call count: only a challenge that fell over in a call or two, whose note adds
nothing, takes the shortcut. The anti-guess gate runs first and is untouched.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent import solver
from vulnclaw.agent.blackboard import Blackboard
from vulnclaw.agent.solver import _grounded_finish_allowed, _record_conclusion
from vulnclaw.config.schema import CompetitionConfig

FLAG = "flag{7d39d64fb69346d7e61a115317013da2}"


def _agent(*, on=False, below=3):
    competition = CompetitionConfig(
        finish_on_grounded_flag=on, finish_when_calls_below=below
    )
    return SimpleNamespace(
        config=SimpleNamespace(competition=competition),
        runtime=SimpleNamespace(blackboard=Blackboard()),
    )


def _state(calls):
    return SimpleNamespace(
        tool_calls=[SimpleNamespace(tool="python_execute")] * calls
    )


class TestDecisionTable:
    def test_off_by_default(self):
        assert _grounded_finish_allowed(_agent(on=False), _state(1)) is False

    @pytest.mark.parametrize("calls", [0, 1, 2])
    def test_on_and_below_the_bound(self, calls):
        assert _grounded_finish_allowed(_agent(on=True, below=3), _state(calls)) is True

    @pytest.mark.parametrize("calls", [3, 4, 40])
    def test_on_but_at_or_above_the_bound(self, calls):
        """A run that took real work keeps its bookkeeping turn: that is where the
        [miss] angles come from."""
        assert _grounded_finish_allowed(_agent(on=True, below=3), _state(calls)) is False

    def test_zero_bound_means_no_bound(self):
        assert _grounded_finish_allowed(_agent(on=True, below=0), _state(50)) is True

    def test_missing_config_fails_closed(self):
        assert _grounded_finish_allowed(SimpleNamespace(config=None), _state(0)) is False

    def test_missing_competition_section_fails_closed(self):
        agent = SimpleNamespace(config=SimpleNamespace(competition=None))
        assert _grounded_finish_allowed(agent, _state(0)) is False


class TestConfigDefaults:
    def test_schema_defaults_are_off_and_bounded(self):
        competition = CompetitionConfig()
        assert competition.finish_on_grounded_flag is False
        assert competition.finish_when_calls_below == 3

    def test_negative_bound_is_rejected(self):
        with pytest.raises(Exception):
            CompetitionConfig(finish_when_calls_below=-1)


class TestConclusionRecording:
    def test_records_lock_and_fact_when_the_board_is_empty(self):
        agent = _agent()
        _record_conclusion(agent, flag=FLAG, evidence_id="e001", source="grounded final answer")
        board = agent.runtime.blackboard
        lock = board.current_lock()
        assert lock is not None and FLAG in lock.description
        assert any(FLAG in f.description for f in board.confirmed_facts())

    def test_does_not_replace_a_model_authored_lock(self):
        agent = _agent()
        human_lock = "zip pseudo-encryption: CD flag 0x9 with LFH 0x0, flag lives in flag.txt"
        assert agent.runtime.blackboard.set_lock(human_lock) is not None
        _record_conclusion(agent, flag=FLAG, evidence_id="e001", source="grounded final answer")
        assert agent.runtime.blackboard.current_lock().description == human_lock

    def test_missing_board_is_not_an_error(self):
        _record_conclusion(
            SimpleNamespace(runtime=SimpleNamespace(blackboard=None)),
            flag=FLAG,
            evidence_id="",
            source="grounded final answer",
        )


class TestTheGateItselfIsUnchanged:
    def test_lock_gate_still_fires_when_the_switch_is_off(self):
        agent = _agent(on=False)
        state = SimpleNamespace(lock_nudge_count=0)
        assert solver._completion_lock_gate(agent, state) is True
        assert state.lock_nudge_count == 1

    def test_anti_guess_gate_runs_before_any_of_this(self):
        """`_completion_gate` rejecting is enough on its own: an ungrounded flag
        never reaches the bookkeeping decision."""
        from vulnclaw.agent.agent_state import AgentState

        state = AgentState(origin="local.png", goal="capture the flag")
        ok, reason, _ = solver._completion_gate(state, "FINAL: flag{deadbeefcafe}")
        assert ok is False and reason