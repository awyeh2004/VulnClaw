"""The path-stall fingerprint must track PROGRESS, not activity.

Calibration from live runs, which is what makes this signal worth having:

* the two successful solves finished in 3 and 6 steps, with real progress on every
  one of them;
* a failed run probed one SSRF surface for about an hour, producing evidence on
  essentially every turn while making no progress whatsoever.

So a signal based on "new evidence" or "new blackboard nodes" stays quiet exactly
when it is needed. What is tested here is that the fingerprint changes only on
theory/coverage changes, and that the guard's escalation path is the user, not a
silent kill.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.blackboard import Blackboard, NodeStatus, NodeType
from vulnclaw.agent.solver import (
    _no_path_coverage_thin,
    _path_progress_fingerprint,
    _stall_guard_decision,
    _stall_turns,
)


class FakeRuntime:
    def __init__(self, blackboard=None):
        self.blackboard = blackboard


class FakeAgent:
    """Only what the helper touches."""

    def __init__(self, blackboard=None, config=None):
        self.runtime = FakeRuntime(blackboard)
        self.config = config


def _bb() -> Blackboard:
    return Blackboard()


class TestFingerprintTracksProgress:
    def test_no_blackboard_is_a_stable_empty_fingerprint(self):
        assert _path_progress_fingerprint(FakeAgent()) == ()

    def test_a_confirmed_fact_changes_it(self):
        bb = _bb()
        before = _path_progress_fingerprint(FakeAgent(bb))
        node = bb.create_fact("the front is openresty", verified=True)
        assert node is not None
        assert _path_progress_fingerprint(FakeAgent(bb)) != before

    def test_a_new_angle_changes_it(self):
        bb = _bb()
        before = _path_progress_fingerprint(FakeAgent(bb))
        bb.create_angle("SSRF to loopback on internal web ports")
        assert _path_progress_fingerprint(FakeAgent(bb)) != before

    def test_deciding_an_angle_changes_it(self):
        """HIT or MISS is progress: the path was actually resolved."""
        bb = _bb()
        angle = bb.create_angle("file:// wrappers to read /flag")
        settled = _path_progress_fingerprint(FakeAgent(bb))
        bb.miss_angle(angle.id)
        assert _path_progress_fingerprint(FakeAgent(bb)) != settled

    def test_an_unconfirmed_fact_does_not_count(self):
        """The busy-but-stuck pattern: proposals pile up, nothing is decided."""
        bb = _bb()
        before = _path_progress_fingerprint(FakeAgent(bb))
        for index in range(5):
            bb.create_fact(f"probe {index} returned the usual page", verified=False)
        assert _path_progress_fingerprint(FakeAgent(bb)) == before

    def test_repeated_probing_keeps_the_fingerprint_stable(self):
        """This is the measured failure mode, reduced to its essence."""
        bb = _bb()
        agent = FakeAgent(bb)
        baseline = _path_progress_fingerprint(agent)
        for _ in range(20):
            # simulating "evidence arrived, but no theory or coverage changed"
            assert _path_progress_fingerprint(agent) == baseline

    def test_changing_the_lock_changes_it(self):
        bb = _bb()
        before = _path_progress_fingerprint(FakeAgent(bb))
        bb.set_lock("the flag service is a sibling container reachable by name")
        assert _path_progress_fingerprint(FakeAgent(bb)) != before


class TestStallLimit:
    def test_uses_competition_stall_turns(self):
        class Competition:
            stall_turns = 5

        class Config:
            competition = Competition()

        assert _stall_turns(FakeAgent(config=Config())) == 5

    def test_defaults_to_eight_without_config(self):
        assert _stall_turns(FakeAgent()) == 8

    @pytest.mark.parametrize("raw", ["nonsense", None, 0, -3])
    def test_a_silly_value_cannot_disable_the_guard(self, raw):
        """A misconfigured limit must not silently switch the guard off."""
        class Competition:
            stall_turns = raw

        class Config:
            competition = Competition()

        assert _stall_turns(FakeAgent(config=Config())) >= 2


class TestStallGuardDecision:
    """An EMPTY blackboard must never be read as "every path has been tried".

    Measured failure mode: while an environment provisions, the model polls
    platform_read_env — a tool call, so the observation-only guard stays quiet —
    and nothing is on the blackboard yet. Zero open ANGLES is then true for the
    trivial reason that there are no angles at all, and the first version asked
    "no untried angle remains": a false premise, followed by stopping the solve.
    """

    def test_below_the_limit_it_says_nothing(self):
        action, message = _stall_guard_decision(
            FakeAgent(_bb()), streak=3, hint_sent=False, thin_windows=0
        )
        assert (action, message) == ("silent", "")

    def test_empty_board_gets_a_hint_instead_of_a_handback(self):
        action, message = _stall_guard_decision(
            FakeAgent(_bb()), streak=8, hint_sent=False, thin_windows=0
        )
        assert action == "hint"
        assert "EMPTY" in message and "ANGLE" in message
        assert "no untried angle remains" not in message

    def test_empty_board_only_asks_after_the_hint_was_ignored(self):
        action, message = _stall_guard_decision(
            FakeAgent(_bb()), streak=16, hint_sent=True, thin_windows=1
        )
        assert action == "ask"
        # The premise has to be the true one: nothing recorded, not "all tried".
        assert "no ANGLE node has been recorded" in message
        assert "no untried angle remains" not in message

    def test_a_board_with_confirmed_facts_is_not_thin(self):
        bb = _bb()
        for index in range(2):
            bb.create_fact(f"confirmed observation {index}", verified=True)
        assert _no_path_coverage_thin(FakeAgent(bb)) is False
        action, message = _stall_guard_decision(
            FakeAgent(bb), streak=9, hint_sent=False, thin_windows=0
        )
        assert action == "ask"
        assert "no untried angle remains" in message

    def test_an_open_angle_means_a_path_is_left(self):
        bb = _bb()
        bb.create_angle("SSRF to loopback on internal web ports")
        action, message = _stall_guard_decision(
            FakeAgent(bb), streak=8, hint_sent=False, thin_windows=0
        )
        assert action == "hint"
        assert "DIFFERENT angle" in message
        # ...and it does not repeat itself every turn.
        again = _stall_guard_decision(
            FakeAgent(bb), streak=9, hint_sent=True, thin_windows=0
        )
        assert again == ("silent", "")

    def test_a_resolved_angle_with_none_open_does_ask(self):
        """This is the case the guard exists for: the path was tried and exhausted."""
        bb = _bb()
        angle = bb.create_angle("file:// wrappers to read /flag")
        bb.miss_angle(angle.id)
        action, message = _stall_guard_decision(
            FakeAgent(bb), streak=8, hint_sent=True, thin_windows=0
        )
        assert action == "ask"
        assert "no untried angle remains" in message

    def test_no_blackboard_is_not_treated_as_thin(self):
        """Without a blackboard there is nothing to judge, so do not block."""
        assert _no_path_coverage_thin(FakeAgent()) is False
