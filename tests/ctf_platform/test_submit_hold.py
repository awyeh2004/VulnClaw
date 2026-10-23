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

    def test_a_dispatch_error_is_recorded_not_retried_forever(self, tmp_path):
        q = _queue(tmp_path, hold_until=_future())

        async def boom(server, tool, arguments):
            raise RuntimeError("platform unavailable")

        q.enqueue(server="ctf2", tool="ctf2_submit_competition_flag", arguments={"flag": "x"})
        sched = SubmitScheduler(q, boom)
        after = datetime.now() + timedelta(minutes=10)
        assert sched.tick(now=after) == 0
        assert "platform unavailable" in q.all_items()[0].error
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
