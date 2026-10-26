"""Deferred submission: hold a correct flag until its scoring window.

Why (2026-10-24 1024 sprint rulebook): scoring depends on WHEN the submission
arrives, not only on correctness.

* 「1024 秒闪电战」19:10:24–19:27:28 — every solve inside the window pays DOUBLE;
* 「19:24 卡点题」 — inside 19:24:00–19:24:59 pays full marks, elsewhere half.

The platform timestamps the request, so the only lever is the send time. Telling
the model "wait until 19:24" does not survive a 60-minute budget (it would sit
idle) and a model's sense of wall-clock time is unreliable. So the submit call
itself becomes the hold: the exact arguments are persisted and a background
scheduler fires them at the deadline.

What these tests pin -- each is a way the feature could silently lose a
submission, which is worse than not having the feature at all:

* an empty ``submit_hold_until`` changes nothing (every existing run unaffected);
* a held submit is NOT sent now, and says "queued" rather than "failed" (a model
  told "failed" re-submits or hunts a different flag);
* the same payload queued twice collapses to one entry (the platform gives one
  attempt for a choice question);
* the queue survives a process restart (the run that found the flag may be gone
  by 19:24);
* nothing fires after the submission portal closes (the rulebook counts that as
  an invalid operation);
* a scheduler tick that lands slightly LATE still fires (a 1s delay is still
  inside a 60s window; refusing would lose the double).
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta

import pytest

from vulnclaw.ctf_platform.submit_hold import (
    HeldSubmit,
    SubmitHoldQueue,
    SubmitScheduler,
    parse_local_deadline,
)


def _queue(tmp_path, *, hold_until="", window_end="") -> SubmitHoldQueue:
    return SubmitHoldQueue(
        tmp_path / "queue.json", hold_until=hold_until, window_end=window_end
    )


def _future(minutes=5) -> str:
    return (datetime.now() + timedelta(minutes=minutes)).isoformat(timespec="seconds")


class TestNoDeadlineMeansNoChange:
    def test_an_empty_deadline_never_holds(self, tmp_path):
        q = _queue(tmp_path)
        assert q.should_hold() is False
        assert q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"}) is None

    def test_a_past_deadline_does_not_hold(self, tmp_path):
        """Once the window has opened, new submits must go out immediately."""
        past = (datetime.now() - timedelta(minutes=1)).isoformat(timespec="seconds")
        q = _queue(tmp_path, hold_until=past)
        assert q.should_hold() is False

    def test_garbage_in_the_setting_is_treated_as_no_deadline(self, tmp_path):
        """A typo must not silently drop a submission the operator meant to make."""
        q = _queue(tmp_path, hold_until="not-a-time")
        assert q.hold_deadline is None
        assert q.should_hold() is False


class TestHoldQueuesInsteadOfSending:
    def test_a_future_deadline_holds(self, tmp_path):
        q = _queue(tmp_path, hold_until=_future())
        item = q.enqueue(
            server="ctf2",
            tool="ctf2_submit_competition_flag",
            arguments={"flag": "DASCTF{abc}", "confirmation": True},
        )
        assert item is not None
        assert item.fired is False
        assert item.arguments["flag"] == "DASCTF{abc}"
        assert len(q.pending()) == 1

    def test_the_same_payload_collapses_to_one_entry(self, tmp_path):
        """One attempt per choice question: a retrying model must not spend two."""
        q = _queue(tmp_path, hold_until=_future())
        args = {"flag": "DASCTF{same}", "confirmation": True}
        first = q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments=args)
        second = q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments=args)
        assert first.key == second.key
        assert len(q.pending()) == 1

    def test_a_different_payload_gets_its_own_entry(self, tmp_path):
        q = _queue(tmp_path, hold_until=_future())
        q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "A"})
        q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "B"})
        assert len(q.pending()) == 2


class TestSurvivesARestart:
    def test_the_queue_is_reloaded_from_disk(self, tmp_path):
        """The run that FOUND the flag may be gone by the time the window opens."""
        q = _queue(tmp_path, hold_until=_future())
        q.enqueue(
            server="ctf2",
            tool="ctf2_submit_competition_flag",
            arguments={"flag": "DASCTF{persisted}"},
        )
        reopened = _queue(tmp_path, hold_until=_future())
        pending = reopened.pending()
        assert len(pending) == 1
        assert pending[0].arguments["flag"] == "DASCTF{persisted}"


class TestFiring:
    def _scheduler(self, q, sent):
        async def dispatch(server, tool, arguments):
            sent.append((server, tool, arguments))
            return '{"accepted": true}'

        return SubmitScheduler(q, dispatch)

    def test_nothing_fires_before_the_deadline(self, tmp_path):
        q = _queue(tmp_path, hold_until=_future(5))
        q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"})
        sent: list = []
        sched = self._scheduler(q, sent)
        assert sched.tick() == 0
        assert sent == []

    def test_it_fires_at_the_deadline(self, tmp_path):
        q = _queue(tmp_path, hold_until=_future())
        q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"})
        sent: list = []
        sched = self._scheduler(q, sent)
        after = datetime.now() + timedelta(minutes=10)
        assert sched.tick(now=after) == 1
        assert len(sent) == 1
        assert q.pending() == []

    def test_a_late_tick_still_fires(self, tmp_path):
        """A 1s-late tick is still inside a 60s window; refusing loses the double."""
        q = _queue(tmp_path, hold_until=_future())
        q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"})
        sent: list = []
        sched = self._scheduler(q, sent)
        target = parse_local_deadline(q.pending()[0].fire_at)
        assert sched.tick(now=target + timedelta(seconds=1)) == 1
        assert len(sent) == 1

    def test_it_fires_only_once(self, tmp_path):
        q = _queue(tmp_path, hold_until=_future())
        q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"})
        sent: list = []
        sched = self._scheduler(q, sent)
        after = datetime.now() + timedelta(minutes=10)
        sched.tick(now=after)
        sched.tick(now=after)
        assert len(sent) == 1

    def test_a_closed_portal_drops_instead_of_sending(self, tmp_path):
        """Sending into a closed portal is an invalid operation per the rulebook."""
        hold = _future(5)
        end = (datetime.now() + timedelta(minutes=6)).isoformat(timespec="seconds")
        q = _queue(tmp_path, hold_until=hold, window_end=end)
        q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"})
        sent: list = []
        sched = self._scheduler(q, sent)
        long_after = datetime.now() + timedelta(minutes=30)
        assert sched.tick(now=long_after) == 0
        assert sent == []
        assert "window closed" in q.all_items()[0].error

    def test_a_dispatch_error_is_recorded_as_unknown_without_replay(self, tmp_path):
        q = _queue(tmp_path, hold_until=_future())

        async def boom(server, tool, arguments):
            raise RuntimeError("platform unavailable")

        q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"})
        sched = SubmitScheduler(q, boom)
        after = datetime.now() + timedelta(minutes=10)
        assert sched.tick(now=after) == 0
        assert "platform unavailable" in q.all_items()[0].error
        assert q.pending() == []
        assert q.all_items()[0].status == "unknown"

    @pytest.mark.asyncio
    async def test_started_scheduler_dispatches_on_owner_loop(self, tmp_path):
        q = _queue(tmp_path, hold_until=_future())
        item = q.enqueue(
            server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"}
        )
        item.fire_at = (datetime.now() - timedelta(seconds=1)).isoformat(timespec="seconds")
        seen_loop = []
        delivered = asyncio.Event()

        async def dispatch(server, tool, arguments):
            seen_loop.append(asyncio.get_running_loop())
            delivered.set()
            return "accepted"

        owner_loop = asyncio.get_running_loop()
        sched = SubmitScheduler(q, dispatch, loop_provider=lambda: owner_loop)
        sched.start()
        try:
            await asyncio.wait_for(delivered.wait(), timeout=2)
        finally:
            sched.stop()
        assert seen_loop == [asyncio.get_running_loop()]
        assert q.pending() == []

    def test_persistence_failure_does_not_enqueue(self, tmp_path, monkeypatch):
        from vulnclaw.ctf_platform import submit_hold

        def fail(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(submit_hold, "atomic_write_text", fail)
        q = _queue(tmp_path, hold_until=_future())
        with pytest.raises(submit_hold.SubmitHoldPersistenceError, match="disk full"):
            q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"})
        assert q.pending() == []


class TestToolMatching:
    def test_both_submit_spellings_are_recognised(self):
        from vulnclaw.mcp.lifecycle import _is_submission_tool

        assert _is_submission_tool("ctf2_submit_competition_flag")
        assert _is_submission_tool("ctf2_submit_flag")
        assert _is_submission_tool("gcs_submit_flag")

    def test_readers_are_not_submissions(self):
        from vulnclaw.mcp.lifecycle import _is_submission_tool

        for name in ("ctf2_list_competition_challenges", "ctf2_get_competition_challenge",
                     "platform_submit", "fetch"):
            assert not _is_submission_tool(name), name


# ── Named windows: the 1024 sprint needs TWO departure points ─────────────────
#
# 19:10:24 opens the sprint window (double points, first-blood credit for whoever
# lands first) and 19:24:00–19:24:59 is the 卡点 band (full marks inside, half
# outside). One shared deadline cannot express both: it would either delay the
# first-blood send by however long the model kept working, or send the 卡点
# answer at the sprint opener, which is a different scoring event.


def _windows(tmp_path, *, past_firstblood=True):
    from datetime import datetime, timedelta

    from vulnclaw.ctf_platform.submit_hold import SubmitHoldQueue, SubmitWindow

    base = datetime.now()
    fb = base + (timedelta(seconds=-30) if past_firstblood else timedelta(minutes=2))
    peak = base + timedelta(minutes=10)
    windows = [
        SubmitWindow(name="firstblood", at=fb.isoformat(timespec="seconds")),
        SubmitWindow(
            name="peak",
            at=peak.isoformat(timespec="seconds"),
            until=(peak + timedelta(seconds=59)).isoformat(timespec="seconds"),
        ),
    ]
    return SubmitHoldQueue(tmp_path / "q.json", windows=windows), fb, peak


class TestNamedWindows:
    def test_the_soonest_open_window_is_picked(self, tmp_path):
        # An explicit `until` in the past: without one a window stays open for
        # the implicit 60s grace, so "started 30s ago" is still an open window.
        from datetime import datetime, timedelta

        from vulnclaw.ctf_platform.submit_hold import SubmitHoldQueue, SubmitWindow

        base = datetime.now()
        fb_at = (base - timedelta(minutes=5)).isoformat(timespec="seconds")
        peak_at = base + timedelta(minutes=10)
        q = SubmitHoldQueue(
            tmp_path / "q.json",
            windows=[
                SubmitWindow(name="firstblood", at=fb_at, until=fb_at),
                SubmitWindow(
                    name="peak",
                    at=peak_at.isoformat(timespec="seconds"),
                    until=(peak_at + timedelta(seconds=59)).isoformat(timespec="seconds"),
                ),
            ],
        )
        peak = peak_at
        item = q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"})
        assert item is not None
        assert item.window == "peak"
        assert parse_local_deadline(item.fire_at) == parse_local_deadline(
            peak.isoformat(timespec="seconds")
        )

    def test_an_explicit_window_wins(self, tmp_path):
        q, _fb, peak = _windows(tmp_path, past_firstblood=False)
        item = q.enqueue(
            server="ctf2",
            tool="ctf2_submit_competition_flag",
            arguments={"flag": "x"},
            window="peak",
        )
        assert item.window == "peak"

    def test_only_first_blood_aims_early(self, tmp_path):
        """First blood pays for arriving first; 卡点 pays for landing IN the band.

        A 卡点 submission sent 0.8s early arrives BEFORE the band opens, where the
        rulebook pays half. It aims at the stated second instead; the client-side
        setup of the call already lands it a few hundred ms late.
        """
        from vulnclaw.ctf_platform.submit_hold import SubmitScheduler

        fb = HeldSubmit(
            key="a", server="s", tool="t", arguments={}, fire_at="", created_at="",
            window="firstblood",
        )
        peak = HeldSubmit(
            key="b", server="s", tool="t", arguments={}, fire_at="", created_at="",
            window="peak",
        )
        assert SubmitScheduler._lead_for(peak) == 0.0
        assert SubmitScheduler._lead_for(fb) > 0.0

    def test_each_item_closes_with_its_own_window(self, tmp_path):
        """The 卡点 band closes; a first-blood item must not be judged by it."""
        q, _fb, peak = _windows(tmp_path, past_firstblood=False)
        q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "fb"})
        sent: list = []

        async def dispatch(server, tool, arguments):
            sent.append(arguments["flag"])
            return "ok"

        from vulnclaw.ctf_platform.submit_hold import SubmitScheduler

        sched = SubmitScheduler(q, dispatch)
        # At firstblood time: only the firstblood item is due.
        firstblood_item = [i for i in q.pending() if i.window == "firstblood"][0]
        target = parse_local_deadline(firstblood_item.fire_at)
        sched.tick(now=target + __import__("datetime").timedelta(seconds=1))
        assert sent == ["fb"]

    def test_all_windows_closed_means_send_immediately(self, tmp_path):
        from datetime import datetime, timedelta

        from vulnclaw.ctf_platform.submit_hold import SubmitHoldQueue, SubmitWindow

        past = (datetime.now() - timedelta(minutes=5)).isoformat(timespec="seconds")
        q = SubmitHoldQueue(
            tmp_path / "q.json",
            windows=[SubmitWindow(name="firstblood", at=past, until=past)],
        )
        assert q.should_hold() is False
        assert q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={}) is None

    def test_a_late_hold_still_targets_a_window_that_has_not_closed(self, tmp_path):
        """A flag found at 19:23 must still go into the 19:24 band."""
        from datetime import datetime, timedelta

        from vulnclaw.ctf_platform.submit_hold import SubmitHoldQueue, SubmitWindow

        now = datetime.now()
        q = SubmitHoldQueue(
            tmp_path / "q.json",
            windows=[
                SubmitWindow(name="firstblood", at=(now - timedelta(minutes=13)).isoformat(timespec="seconds")),
                SubmitWindow(
                    name="peak",
                    at=(now + timedelta(minutes=1)).isoformat(timespec="seconds"),
                    until=(now + timedelta(minutes=1, seconds=59)).isoformat(timespec="seconds"),
                ),
            ],
        )
        assert q.should_hold() is True
        item = q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"})
        assert item.window == "peak"

    def test_a_legacy_single_deadline_still_works(self, tmp_path):
        """Existing configs (submit_hold_until) must keep behaving as before."""
        q = _queue(tmp_path, hold_until=_future())
        item = q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"})
        assert item is not None
        assert item.window == ""
        assert item.close_at == ""


# ── What the model is TOLD about the windows ──────────────────────────────────
#
# The queue alone is not enough: a model that does not know a window is coming
# will happily spend the ten minutes before it on the most interesting challenge,
# and then have nothing to submit when the window opens.


class TestThePromptExplainsTheWindows:
    def _agent(self, windows):
        from types import SimpleNamespace

        return SimpleNamespace(
            config=SimpleNamespace(competition=SimpleNamespace(submit_windows=windows))
        )

    def test_no_windows_means_no_instruction(self):
        """Every non-competition run must stay byte-identical."""
        from vulnclaw.agent.solver import _competition_windows_instruction

        assert _competition_windows_instruction(self._agent([])) == ""

    def test_the_windows_are_named_with_their_times(self):
        from vulnclaw.agent.solver import _competition_windows_instruction

        text = _competition_windows_instruction(
            self._agent(
                [
                    {"name": "firstblood", "at": "2026-10-24T19:10:24"},
                    {
                        "name": "peak",
                        "at": "2026-10-24T19:24:00",
                        "until": "2026-10-24T19:24:59",
                    },
                ]
            )
        )
        assert "firstblood" in text and "19:10:24" in text
        assert "peak" in text and "19:24:00" in text

    def test_it_says_to_race_the_easiest_challenge_first(self):
        """An unsolved challenge has nothing to submit when the window opens."""
        from vulnclaw.agent.solver import _competition_windows_instruction

        text = _competition_windows_instruction(
            self._agent([{"name": "firstblood", "at": "2026-10-24T19:10:24"}])
        ).lower()
        assert "easiest" in text
        assert "nothing to submit" in text

    def test_it_says_queued_means_done(self):
        from vulnclaw.agent.solver import _competition_windows_instruction

        text = _competition_windows_instruction(
            self._agent([{"name": "peak", "at": "2026-10-24T19:24:00"}])
        ).lower()
        assert "queued" in text
        assert "do not submit it again" in text


class TestOnlyTheChosenChallengesWait:
    """A window is not always worth holding every flag for.

    Match-day shape (2026-10-24): the 卡点题 is scored by WHEN it lands, so it
    waits; every other challenge pays on solve, and holding those would delay a
    correct answer for nothing.
    """

    def test_an_empty_allow_list_holds_every_challenge(self, tmp_path):
        q = _queue(tmp_path, hold_until=_future())
        assert q.covers("any-challenge-id") is True

    def test_a_non_empty_list_holds_only_its_members(self, tmp_path):
        q = SubmitHoldQueue(
            tmp_path / "queue.json",
            hold_until=_future(),
            hold_challenges=["c47066a1-4e5e-4f2e-bae0-194faedb1532"],
        )
        assert q.covers("c47066a1-4e5e-4f2e-bae0-194faedb1532") is True
        assert q.covers("e599c7be-630c-4a0e-af6d-0fae597c6dd6") is False

    def test_whitespace_in_the_setting_does_not_create_a_ghost_id(self, tmp_path):
        q = SubmitHoldQueue(
            tmp_path / "queue.json",
            hold_until=_future(),
            hold_challenges=[" c47066a1 ", "", "  "],
        )
        assert q.covers("c47066a1") is True
        assert q.covers("") is False

    def test_reconfigure_swaps_the_list(self, tmp_path):
        q = SubmitHoldQueue(tmp_path / "queue.json", hold_until=_future())
        assert q.covers("x") is True
        q.reconfigure(hold_until=_future(), hold_challenges=["x"])
        assert q.covers("x") is True
        assert q.covers("y") is False


class TestTheQueueActuallyGetsFired:
    """Regression, 2026-10-24 sprint.

    In HEAD, ``_start_submit_scheduler`` built a ``SubmitScheduler`` and returned
    without calling ``start()``, so no thread ever ticked. The queue LOOKED armed
    -- an item with a fire_at in the future -- while both the 19:10:24 and the
    19:24:00 deadlines passed in silence; the 卡点题 had to be submitted by hand
    inside its band. Constructing is not starting.
    """

    def test_the_factory_spawns_a_ticking_thread(self, tmp_path, monkeypatch):
        from vulnclaw.mcp import lifecycle

        q = _queue(tmp_path, hold_until=_future())
        q.enqueue(
            server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"}
        )
        monkeypatch.setattr(lifecycle, "_get_submit_hold", lambda: q)

        class Manager:
            _submit_scheduler = None
            _submit_hold = None

            async def _fire_held_submission(self, server, tool, arguments):
                return "ok"

        manager = Manager()
        lifecycle._start_submit_scheduler(manager)
        scheduler = manager._submit_scheduler
        try:
            assert scheduler is not None
            assert scheduler._thread is not None, "start() was never called"
            assert scheduler._thread.is_alive()
        finally:
            scheduler.stop(timeout=1.0)

    def test_a_dead_runs_queue_is_revived_by_any_tool_call(self, tmp_path, monkeypatch):
        """The run that found the flag usually exits long before its window."""
        from vulnclaw.mcp import lifecycle

        q = _queue(tmp_path, hold_until=_future())
        q.enqueue(
            server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"}
        )
        monkeypatch.setattr(lifecycle, "_get_submit_hold", lambda: q)
        started: list = []
        monkeypatch.setattr(lifecycle, "_start_submit_scheduler", started.append)

        manager = object.__new__(lifecycle.MCPLifecycleManager)
        manager._ensure_held_scheduler()
        manager._ensure_held_scheduler()
        assert len(started) == 1, "reviving must not race itself into two threads"

    def test_an_empty_queue_does_not_start_a_firer(self, tmp_path, monkeypatch):
        from vulnclaw.mcp import lifecycle

        q = _queue(tmp_path, hold_until=_future())
        monkeypatch.setattr(lifecycle, "_get_submit_hold", lambda: q)
        started: list = []
        monkeypatch.setattr(lifecycle, "_start_submit_scheduler", started.append)

        manager = object.__new__(lifecycle.MCPLifecycleManager)
        manager._ensure_held_scheduler()
        assert started == []
