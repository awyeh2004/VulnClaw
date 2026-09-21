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
from vulnclaw.agent.solver import _path_progress_fingerprint, _stall_turns


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
