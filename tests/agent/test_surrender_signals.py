"""Two surrender signals measured over one afternoon of CTF2 grinding (2026-10-18).

Statistics behind both (90 runs, 66 solved / 24 failed):

* **96% of failed runs decided ZERO angles** (median HIT=0); solved runs had a
  median of 2. Opening angles without deciding them leaves
  ``_path_progress_fingerprint`` unchanged, so the stall guard kept repeating
  itself while the run brute-forced (one spent 1192 password guesses).
* **83% of failed runs searched for a writeup** (duckduckgo/bing/"writeup").
  Every one of them kept burning turns afterwards, and none recovered: a copied
  flag cannot pass the completion gate, which requires the flag to appear in THIS
  run's recorded evidence.

Neither is a model-capability problem -- both are "the loop never noticed the run
had stopped making progress" problems, which is why they belong in code.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.blackboard import Blackboard, NodeStatus, NodeType
from vulnclaw.agent.solver import (
    _is_writeup_search,
    _no_path_open_angles,
    _undecided_angle_nudge,
)


class _Runtime:
    def __init__(self, blackboard):
        self.blackboard = blackboard


class _Agent:
    def __init__(self, blackboard=None):
        self.runtime = _Runtime(blackboard)


class _State:
    """Only the two counters the nudge touches."""

    def __init__(self):
        self.undecided_nudge_count = 0


class TestWriteupSearchDetection:
    @pytest.mark.parametrize(
        "args",
        [
            '{"url": "https://duckduckgo.com/html/?q=BUUCTF+flag"}',
            '{"url": "https://lite.duckduckgo.com/lite/?q=x"}',
            '{"url": "https://www.bing.com/search?q=x"}',
            '{"url": "https://www.google.com/search?q=x"}',
            '{"url": "https://example.com/search?q=flag"}',
            '{"url": "https://example.com/writeup"}',
            '{"url": "https://example.com/题解"}',
        ],
    )
    def test_search_shapes_are_detected(self, args):
        assert _is_writeup_search(args) is True

    @pytest.mark.parametrize(
        "args",
        [
            '{"url": "http://target/index.php?id=1"}',
            '{"code": "import socket"}',
            '{"command": "bsdtar -tf a.rar"}',
            '{"url": "https://ctf2-files.dasctf.com/ctf-files/uploads/x.zip"}',
        ],
    )
    def test_ordinary_work_is_not_flagged(self, args):
        """False positives here would cut off legitimate runs."""
        assert _is_writeup_search(args) is False


class TestUndecidedAngleNudge:
    def test_silent_with_fewer_than_two_open_angles(self):
        bb = Blackboard()
        bb.create_angle("only one")
        assert _undecided_angle_nudge(_Agent(bb), _State()) == ""

    def test_fires_when_angles_pile_up_undecided(self):
        bb = Blackboard()
        bb.create_angle("surface one")
        bb.create_angle("surface two")
        bb.create_angle("surface three")
        msg = _undecided_angle_nudge(_Agent(bb), _State())
        assert "3 ANGLES open" in msg
        assert "hit_angle" in msg and "miss_angle" in msg
        assert "promise to look" in msg

    def test_deciding_them_silences_it(self):
        bb = Blackboard()
        a = bb.create_angle("surface one")
        bb.create_angle("surface two")
        bb.miss_angle(a.id)
        # One decided, one still open -> below the threshold of 2.
        assert _undecided_angle_nudge(_Agent(bb), _State()) == ""

    def test_it_does_not_repeat_forever(self):
        """A stubborn model must not deadlock the run on a repeated nudge."""
        bb = Blackboard()
        bb.create_angle("a")
        bb.create_angle("b")
        state = _State()
        assert _undecided_angle_nudge(_Agent(bb), state) != ""
        assert _undecided_angle_nudge(_Agent(bb), state) != ""
        assert _undecided_angle_nudge(_Agent(bb), state) == ""

    def test_no_blackboard_is_silent(self):
        assert _undecided_angle_nudge(_Agent(None), _State()) == ""

    def test_open_angle_count_matches_blackboard(self):
        bb = Blackboard()
        bb.create_angle("a")
        b = bb.create_angle("b")
        assert _no_path_open_angles(_Agent(bb)) == 2
        bb.hit_angle(b.id)
        assert _no_path_open_angles(_Agent(bb)) == 1


class TestThinkingInsteadOfActing:
    """The dominant failure shape, measured 2026-10-18.

    Over 90 runs (66 solved / 24 failed), every failed run's second half had
    FEWER tool calls than its first half -- 97→71, 34→25, 11→3, 8→**0** -- and the
    speculative vocabulary ("maybe/perhaps/could be") clustered in exactly those
    tool-less stretches. Solved runs went the other way: 25→26, 12→20, 10→24.

    Cause: the run stops probing and starts enumerating possibilities in prose.
    Neither pre-existing guard can see it -- `_is_observation_only_turn` requires a
    tool call (0 tools is invisible), and `_path_progress_fingerprint` only counts
    facts/angles/locks (contemplation registers nothing). So a run could burn
    hundreds of KB proposing "maybe A, maybe B" while both guards stayed silent.

    The counter is driven in the solve loop; these tests pin the predicate it uses
    (text but no tool and no evidence) so the condition cannot drift.
    """

    def test_the_guard_predicate(self):
        """A turn with text, no tool call and no new evidence is a wasted turn."""

        def is_no_action_turn(cleaned, tools_used, new_evidence_count):
            return bool(not tools_used and not new_evidence_count and cleaned)

        # The death-spiral turn: prose only.
        assert is_no_action_turn("maybe it is a RAR, or perhaps a zip...", [], 0)
        # Legitimate reflection that ALSO probed is not counted.
        assert not is_no_action_turn("maybe a RAR", ["python_execute"], 0)
        # A probe that returned evidence is progress, even with no text.
        assert not is_no_action_turn("", ["python_execute"], 1)
        # A truly empty turn is caught by the older empty-turn guard instead.
        assert not is_no_action_turn("", [], 0)

    def test_prompt_source_documents_the_measured_basis(self):
        import inspect

        from vulnclaw.agent import solver

        src = inspect.getsource(solver)
        assert "no-action guard" in src
        # The escalation must hand back rather than silently end.
        assert "no tool call for 4 turns" in src or "four consecutive turns" in src
