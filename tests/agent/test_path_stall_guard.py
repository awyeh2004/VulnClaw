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
    _stall_handback_reason,
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

    def test_opening_an_angle_is_not_progress(self):
        """Registering an angle is a PROMISE to look, not a result.

        This test used to assert the opposite, and that expectation was the defect.
        Measured against a deliberately inert target: an agent registered four angles
        and decided two across 15 minutes and 53 tool results with zero progress, and
        because each registration moved the fingerprint the stall streak reset every
        time -- so the guard could never speak. An unbounded, free action must not be
        able to mask a stall.
        """
        bb = _bb()
        before = _path_progress_fingerprint(FakeAgent(bb))
        for index in range(6):
            bb.create_angle(f"angle {index} nobody will ever decide")
        assert _path_progress_fingerprint(FakeAgent(bb)) == before

    def test_angle_spam_cannot_hold_the_fingerprint_open(self):
        """The full evasion: open angles AND a decided one, repeatedly."""
        bb = _bb()
        agent = FakeAgent(bb)
        baseline = _path_progress_fingerprint(agent)
        for index in range(5):
            bb.create_angle(f"surface {index}")
        assert _path_progress_fingerprint(agent) == baseline

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

    def test_an_open_angle_earns_a_hint_before_a_handback(self):
        """First firing nudges; it does not stop the run."""
        bb = _bb()
        bb.create_angle("SSRF to loopback on internal web ports")
        action, message = _stall_guard_decision(
            FakeAgent(bb), streak=8, hint_sent=False, thin_windows=0
        )
        assert action == "hint"
        assert "DIFFERENT angle" in message

    def test_an_ignored_hint_with_angles_still_open_does_ask(self):
        """The other half of the measured evasion.

        This used to assert ``("silent", "")``: an open angle was taken as proof that
        a path remained, so after one hint the guard went quiet forever. Since an
        agent can mint angles without limit, "an untried angle remains" is always
        true and the handback could never happen -- exactly the "other paths also led
        nowhere, come back to the operator" case the guard exists for.

        The wording must not overclaim: it reports the open-and-undecided count and
        says the blackboard cannot distinguish them.
        """
        bb = _bb()
        bb.create_angle("SSRF to loopback on internal web ports")
        action, message = _stall_guard_decision(
            FakeAgent(bb), streak=9, hint_sent=True, thin_windows=0
        )
        assert action == "ask"
        assert "1 angle(s)" in message
        assert "open and never decided" in message
        # Honest premise: it must NOT claim the search space is exhausted.
        assert "no untried angle remains" not in message

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


class TestHandbackReasonMatchesTheMessage:
    """The reason line and the question must not contradict each other.

    Measured in the verifying run: the handback asked about "3 angle(s) ... open and
    never decided" while the run summary said "no untried path remaining". Both lines
    describe the same event, so a wrong one is a false statement to the operator.
    """

    def test_open_angles_report_the_undecided_angles_reason(self):
        bb = _bb()
        bb.create_angle("surface A")
        bb.create_angle("surface B")
        reason = _stall_handback_reason(FakeAgent(bb))
        assert reason == "stalled with angles registered but none decided"
        assert "no untried path" not in reason

    def test_no_open_angles_reports_the_exhausted_reason(self):
        bb = _bb()
        angle = bb.create_angle("file:// wrappers")
        bb.miss_angle(angle.id)
        assert _stall_handback_reason(FakeAgent(bb)) == "stalled with no untried path remaining"

    def test_an_empty_board_reports_the_empty_board_reason(self):
        assert _stall_handback_reason(FakeAgent(_bb())) == "stalled with an empty blackboard"

    def test_without_a_blackboard_it_does_not_claim_exhaustion(self):
        """No blackboard means "cannot tell", not "everything tried".

        `_no_path_coverage_thin` returns False when there is no blackboard (it cannot
        judge, so it does not block) and `_no_path_open_angles` then reports 0 -- so
        without its own branch this would report exhaustion purely from having nothing
        to look at.
        """
        reason = _stall_handback_reason(FakeAgent())
        assert reason == "stalled with no blackboard to judge coverage from"
        assert "no untried path" not in reason


class TestTheNudgeAsksForADecisionNotJustANewAngle:
    """Measured 2026-10-18: the hint was obeyed only half-way.

    A run hit this exact nudge, created four angles in response, and decided none
    (``create=4 hit=0 miss=0``). `_path_progress_fingerprint` counts DECIDED
    angles, so the guard fired again and the run burned another ~100 KB before an
    operator stopped it. The cause was wording: "record the surfaces you probed as
    ANGLE nodes (mark them HIT/MISS)" put the decision in a parenthetical after
    the action the model executed, and the parenthetical was skipped.

    So the decision is now a separate, FIRST numbered step, and the message says
    outright that an undecided angle changes nothing.
    """

    def test_hint_puts_deciding_before_registering(self):
        action, message = _stall_guard_decision(
            FakeAgent(_bb()), streak=8, hint_sent=False, thin_windows=0
        )
        assert action == "hint"
        decided = message.find("hit_angle")
        registered = message.find("register")
        assert decided != -1 and registered != -1, message
        assert decided < registered, (
            "the decision step must come before 'register new ANGLES': "
            f"{message}"
        )

    def test_hint_says_an_undecided_angle_achieves_nothing(self):
        _, message = _stall_guard_decision(
            FakeAgent(_bb()), streak=8, hint_sent=False, thin_windows=0
        )
        lowered = message.lower()
        assert "never decide" in lowered or "undecided" in lowered
        assert "changes nothing" in lowered or "tells you nothing" in lowered

    def test_handback_asks_to_close_the_open_ones_first(self):
        bb = _bb()
        bb.create_angle("surface one")
        bb.create_angle("surface two")
        action, message = _stall_guard_decision(
            FakeAgent(bb), streak=16, hint_sent=True, thin_windows=0
        )
        assert action == "ask"
        assert "Close those" in message or "close those" in message, message
        assert "hit_angle" in message and "miss_angle" in message


class TestHandbackNamesTheOpenAngles:
    """实测（2026-10-19，robomunication）：模型照做了提醒，但还剩一个角度没关。

    run 在第 8 步听劝建了 LOCK + 3 个角度、第 9 步裁决了 2 个；第 16 步交还时只
    被告知"1 angle(s) open and never decided"，需要自己回想是哪一个 —— 它没做到，
    run 到此结束。节点 id 与描述本来就在内存里，点名是零成本的。
    """

    def test_the_message_lists_id_and_description(self):
        bb = Blackboard()
        keep = bb.create_angle("Read spec images for hidden flag text")
        bb.create_angle("Unrelated surface")
        # Leave exactly one open, decide the other.
        other = [n for n in bb.open_angles() if n.id != keep.id][0]
        bb.miss_angle(other.id)

        action, message = _stall_guard_decision(
            FakeAgent(bb), streak=9, hint_sent=True, thin_windows=0
        )
        assert action == "ask"
        assert keep.id in message, message
        assert "Read spec images" in message, message

    def test_a_fully_decided_board_does_not_get_a_stale_list(self):
        bb = Blackboard()
        a = bb.create_angle("one")
        b = bb.create_angle("two")
        bb.hit_angle(a.id)
        bb.miss_angle(b.id)
        action, message = _stall_guard_decision(
            FakeAgent(bb), streak=9, hint_sent=True, thin_windows=0
        )
        # No open angle -> the "no untried angle remains" branch.
        assert "Still open:" not in message, message


class TestTheHintGetsRoomToBeObeyed:
    """提示后必须留出"遵守"的时间，否则守规的 run 会被杀在动作中途。

    实测（2026-10-20/21，15 个 run）：5 个以
    "stalled with angles registered but none decided" 结束，每个都先跑了 98-116 次
    工具调用（pcap 流重建、摩斯/john、payload 解码）。提示本身要求**两步**：先把
    探过的面标成 HIT/MISS，再登记未试的。模型通常一步开角度、下一步才裁决——
    而原来提示后只隔 1 轮就交还，等于只给了一轮做两步。

    宽限期是有界的（_STALL_HINT_GRACE 轮），而且**开角度仍然不重置 streak**，
    所以"不停开新角度"的规避路径依旧会撞墙。

    2026-10-21 修正的是计数语义，不是宽限的长度：hint 那一轮 age=0；之后每一轮
    silent 才把 age+1。所以 hint 之后**真正有 _STALL_HINT_GRACE 轮**不会交还，
    第 _STALL_HINT_GRACE 轮之后才 ask。原来的实现在判定前先自增，第一个 silent
    轮就已经是 age=1，等于实际只宽限了 _STALL_HINT_GRACE-1 轮——正是那 5 个
    "stalled with angles registered but none decided" 里守规的 run 被杀在动作
    中途的直接原因。
    """

    def _agent(self):
        bb = Blackboard()
        bb.create_angle("a surface")
        return FakeAgent(bb)

    def test_nothing_is_said_during_the_grace_window(self):
        from vulnclaw.agent.solver import _STALL_HINT_GRACE

        for age in range(_STALL_HINT_GRACE):
            action, message = _stall_guard_decision(
                self._agent(), streak=8, hint_sent=True, thin_windows=0, hint_age=age
            )
            assert action == "silent", (age, action)
            assert message == "", message

    def test_the_handback_happens_once_the_grace_is_used_up(self):
        from vulnclaw.agent.solver import _STALL_HINT_GRACE

        action, message = _stall_guard_decision(
            self._agent(),
            streak=8,
            hint_sent=True,
            thin_windows=0,
            hint_age=_STALL_HINT_GRACE,
        )
        assert action == "ask", action
        assert "not advanced" in message

    def test_the_grace_is_bounded(self):
        """只要有界就仍会结束：age 再大也只会 ask，不会回到 silent。"""
        action, _ = _stall_guard_decision(
            self._agent(), streak=99, hint_sent=True, thin_windows=0, hint_age=999
        )
        assert action == "ask"


class TestEveryHandbackPathHonoursTheGrace:
    """宽限必须作用在**每一条**交还路径上，不只是其中一条。

    实测（2026-10-22，萌萌哒的八戒）：提示 17:58:01 发出，17:58:39 就交还 —— 38 秒、
    一轮。原因是我第一版只给"有未裁决角度"那条分支加了宽限，而这次走的是
    "黑板全空"（thin board）分支，它仍然一轮后 ask。同一类缺陷，同一个修复。

    三条路径都要覆盖：thin board、无开角度、有开角度。
    """

    def test_thin_board_goes_silent_during_the_grace(self):
        from vulnclaw.agent.solver import _STALL_HINT_GRACE

        # Empty board = thin; hint already delivered once.
        for age in range(_STALL_HINT_GRACE):
            action, _msg = _stall_guard_decision(
                FakeAgent(_bb()), streak=8, hint_sent=True, thin_windows=1, hint_age=age
            )
            assert action == "silent", (age, action)

    def test_thin_board_hands_back_after_the_grace(self):
        from vulnclaw.agent.solver import _STALL_HINT_GRACE

        action, msg = _stall_guard_decision(
            FakeAgent(_bb()),
            streak=8,
            hint_sent=True,
            thin_windows=1,
            hint_age=_STALL_HINT_GRACE,
        )
        assert action == "ask", action
        assert "blackboard is" in msg

    def test_the_no_open_angle_path_also_waits(self):
        from vulnclaw.agent.solver import _STALL_HINT_GRACE

        bb = Blackboard()
        a = bb.create_angle("closed by this run")
        bb.miss_angle(a.id)
        for age in range(_STALL_HINT_GRACE):
            action, _ = _stall_guard_decision(
                FakeAgent(bb), streak=8, hint_sent=True, thin_windows=0, hint_age=age
            )
            assert action == "silent", (age, action)
