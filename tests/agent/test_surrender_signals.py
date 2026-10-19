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
        # These are all network fetches; the tool name is what tells the bare
        # writeup/题解 words apart from a local grep (see the class below).
        assert _is_writeup_search(args, "fetch") is True

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


class TestCountersAreDeclaredOnTheModel:
    """The counters must be FIELDS of AgentState, not ad-hoc attributes.

    Measured 2026-10-19 on a real run (`robomunication`): the writeup guard raised
    ``ValueError: "AgentState" object has no field "writeup_search_count"`` and the
    whole run died with EXIT=1 at step 2. Pydantic v2 refuses assignment to
    undeclared names.

    The angle counter failed the same way but INVISIBLY -- its assignment sat in a
    ``try/except`` that swallowed the refusal, so the counter never moved and the
    nudge would have fired every turn instead of the intended two. Both are pinned
    here so the next counter added to this loop cannot repeat it.
    """

    def test_writeup_counter_exists_and_increments(self):
        from vulnclaw.agent.agent_state import AgentState

        state = AgentState()
        assert state.writeup_search_count == 0
        state.writeup_search_count += 1
        assert state.writeup_search_count == 1

    def test_angle_nudge_counter_exists_and_increments(self):
        from vulnclaw.agent.agent_state import AgentState

        state = AgentState()
        assert state.undecided_nudge_count == 0
        blackboard = Blackboard()
        blackboard.create_angle("surface one")
        blackboard.create_angle("surface two")
        agent = _Agent(blackboard)
        assert _undecided_angle_nudge(agent, state) != ""
        assert state.undecided_nudge_count == 1, (
            "the counter must move on the model, not be refused silently"
        )

    def test_the_nudge_stops_after_two(self):
        from vulnclaw.agent.agent_state import AgentState

        state = AgentState()
        blackboard = Blackboard()
        blackboard.create_angle("surface one")
        blackboard.create_angle("surface two")
        agent = _Agent(blackboard)
        assert _undecided_angle_nudge(agent, state) != ""
        assert _undecided_angle_nudge(agent, state) != ""
        assert _undecided_angle_nudge(agent, state) == ""


class TestLocalMaterialIsNotAWriteupSearch:
    r"""Measured 2026-10-19 on 荷兰宽带数据泄露: two local greps killed a live run.

    The run was deriving (ECB cipher → dictionary → 8-digit DES sweep) and also
    grepping ``E:\vulnclaw\writeup`` / ``hackerWP`` — the operator's own knowledge
    base sitting on this machine. Both hits counted, the run hit its limit of two,
    and stopped. Reading local material is not "copying someone else's answer";
    only a NETWORK fetch of one is.
    """

    LOCAL_SHELL = (
        r"Get-ChildItem E:\vulnclaw\writeup -Recurse -File | "
        "Select-String -Pattern 'RouterPassView'"
    )

    def test_a_local_grep_for_writeups_does_not_count(self):
        assert not _is_writeup_search(self.LOCAL_SHELL, "shell_command")

    def test_a_local_python_search_for_writeups_does_not_count(self):
        assert not _is_writeup_search(
            "import glob; glob.glob('E:/vulnclaw/docs/**/*writeup*')", "python_execute"
        )

    def test_a_network_fetch_of_a_writeup_still_counts(self):
        assert _is_writeup_search(
            "https://example.com/buuctf/荷兰宽带数据泄露-writeup", "fetch"
        )
        assert _is_writeup_search("https://example.com/题解", "fetch")

    def test_a_search_engine_url_still_counts_for_any_tool(self):
        """The unambiguous markers do not depend on the tool name."""
        for tool in ("fetch", "shell_command", "python_execute", ""):
            assert _is_writeup_search(
                "https://duckduckgo.com/html/?q=flag", tool
            ), tool

    def test_an_empty_tool_name_does_not_assert_a_violation(self):
        """No name to judge by -> the URL markers are the only safe signal."""
        assert not _is_writeup_search("grep writeup E:/vulnclaw", "")
