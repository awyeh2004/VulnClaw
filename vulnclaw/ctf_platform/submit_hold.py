"""Deferred flag submission for time-windowed competition scoring.

Why this exists (2026-10-24 1024 sprint rulebook): two of the scoring rules are
decided by WHEN a correct submission lands, not by whether it is correct:

* 「1024 秒闪电战」19:10:24–19:27:28 — every solve in that window is worth DOUBLE;
* 「19:24 卡点题」 — inside 19:24:00–19:24:59 scores full marks, elsewhere half.

The server timestamps the request, so the only lever the agent has is WHEN it
sends. A run that finds the flag at 19:20 and submits at once collects 1x for a
challenge that would have paid 2x four minutes later. Telling the model "wait
until 19:24" does not work: the solve loop would have to sit idle (burning the
60-minute budget) and a model's notion of wall-clock time is unreliable.

So the submit call itself becomes the hold. When ``competition.submit_hold_until``
is set, a submit is not sent: its EXACT arguments are persisted, the model is told
the value is queued, and a background scheduler fires it at that wall-clock moment
through the same dispatch path a normal submit would use.

Design constraints, each measured or rule-driven:

* **Survives the process.** The run that finds the flag is not necessarily the
  process that is still alive at 19:24 (the solve loop may finish first). State
  lives in ``<config>/submit_hold/queue.json``, overwritten atomically.
* **Never after the portal closes.** ``submit_window_end`` is checked before
  firing; a hold whose target is past the end is dropped loudly instead of being
  sent into a closed portal (the rulebook treats that as an invalid operation).
* **One shot per (challenge, payload).** The platform gives one attempt for a
  choice question and a limited number of flag attempts; replaying a held submit
  twice because a scheduler tick raced would waste them.
* **Reported, not silent.** Every hold records why, when it fires, and what the
  platform answered, so the operator can audit after the match.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

#: How many seconds ahead of the target to fire. The platform timestamps arrival,
#: and a request issued exactly at 19:24:00.000 can land at 19:24:00.3 -- inside
#: the window either way, but a LATE tick (GC, a slow dispatch) is the dangerous
#: direction, so the scheduler aims slightly early and re-checks the window.
_FIRE_LEAD_SECONDS = 0.8

#: Scheduler poll interval while something is pending.
_TICK_SECONDS = 0.25


def _now() -> datetime:
    return datetime.now()


def parse_local_deadline(text: str) -> Optional[datetime]:
    """Parse an ISO-8601 local timestamp; ``None`` for empty or malformed input.

    Malformed input is treated as "no deadline" rather than an error: a typo in
    the config must not silently drop a submission the operator meant to make.
    """
    raw = str(text or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    # A naive timestamp is local by definition here (the rulebook's windows are
    # stated in local time), and comparing naive to aware raises, so strip any
    # tzinfo and compare wall-clock to wall-clock.
    return parsed.replace(tzinfo=None)


@dataclass
class HeldSubmit:
    """One submission waiting for its window."""

    key: str
    server: str
    tool: str
    arguments: dict[str, Any]
    fire_at: str
    created_at: str
    fired: bool = False
    result: str = ""
    error: str = ""
    fired_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "server": self.server,
            "tool": self.tool,
            "arguments": self.arguments,
            "fire_at": self.fire_at,
            "created_at": self.created_at,
            "fired": self.fired,
            "result": self.result,
            "error": self.error,
            "fired_at": self.fired_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HeldSubmit":
        return cls(
            key=str(data.get("key", "")),
            server=str(data.get("server", "")),
            tool=str(data.get("tool", "")),
            arguments=dict(data.get("arguments") or {}),
            fire_at=str(data.get("fire_at", "")),
            created_at=str(data.get("created_at", "")),
            fired=bool(data.get("fired")),
            result=str(data.get("result", "")),
            error=str(data.get("error", "")),
            fired_at=str(data.get("fired_at", "")),
        )


class SubmitHoldQueue:
    """Persistent queue of submissions waiting for a time window.

    ``dispatch`` is the coroutine that actually sends one: it is injected so this
    module stays independent of the MCP lifecycle (and testable without a
    platform).
    """

    def __init__(
        self,
        state_path: Optional[os.PathLike | str] = None,
        *,
        hold_until: str = "",
        window_end: str = "",
    ) -> None:
        self.state_path = Path(state_path) if state_path else None
        self._hold_until = hold_until
        self._window_end = window_end
        self._lock = threading.RLock()
        self._items: dict[str, HeldSubmit] = {}
        self._load()

    # -- configuration -----------------------------------------------------

    def reconfigure(self, *, hold_until: str, window_end: str = "") -> None:
        """Update the window without losing what is already queued."""
        with self._lock:
            self._hold_until = hold_until
            self._window_end = window_end

    @property
    def hold_deadline(self) -> Optional[datetime]:
        return parse_local_deadline(self._hold_until)

    @property
    def window_end(self) -> Optional[datetime]:
        return parse_local_deadline(self._window_end)

    def should_hold(self, *, now: Optional[datetime] = None) -> bool:
        """Whether a submit arriving now should be queued rather than sent.

        False once the deadline has passed: after that the queue has already
        fired (or will on the next tick), and a NEW submit -- a corrected flag,
        a second challenge -- must go out immediately or it misses the window it
        was waiting for.
        """
        deadline = self.hold_deadline
        if deadline is None:
            return False
        moment = now or _now()
        return moment < deadline

    # -- queue operations ---------------------------------------------------

    def enqueue(
        self,
        *,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        key: str = "",
    ) -> Optional[HeldSubmit]:
        """Persist a submission for later firing. Returns None when not holding.

        The key defaults to ``tool + sorted(arguments)``, so the SAME payload
        submitted twice while held collapses to one entry: a model that retries
        its submit call must not spend two attempts at 19:24.
        """
        if not self.should_hold():
            return None
        deadline = self.hold_deadline
        assert deadline is not None  # should_hold() guarantees it
        identity = key or self._identity(server, tool, arguments)
        with self._lock:
            existing = self._items.get(identity)
            if existing is not None and not existing.fired:
                return existing
            item = HeldSubmit(
                key=identity,
                server=server,
                tool=tool,
                arguments=dict(arguments),
                fire_at=deadline.isoformat(timespec="seconds"),
                created_at=_now().isoformat(timespec="seconds"),
            )
            self._items[identity] = item
            self._save()
            return item

    @staticmethod
    def _identity(server: str, tool: str, arguments: dict[str, Any]) -> str:
        payload = json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str)
        return f"{server}/{tool}/{payload}"

    def pending(self) -> list[HeldSubmit]:
        with self._lock:
            return [item for item in self._items.values() if not item.fired]

    def all_items(self) -> list[HeldSubmit]:
        with self._lock:
            return list(self._items.values())

    def mark_fired(self, key: str, *, result: str = "", error: str = "") -> None:
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return
            item.fired = True
            item.result = result
            item.error = error
            item.fired_at = _now().isoformat(timespec="seconds")
            self._save()

    def drop(self, key: str, reason: str) -> None:
        """Remove an entry that must never be sent (records why)."""
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return
            item.fired = True
            item.error = f"dropped: {reason}"
            item.fired_at = _now().isoformat(timespec="seconds")
            self._save()

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._save()

    # -- persistence --------------------------------------------------------

    def _load(self) -> None:
        if self.state_path is None or not self.state_path.exists():
            return
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        items = raw.get("items") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            return
        for entry in items:
            if not isinstance(entry, dict):
                continue
            item = HeldSubmit.from_dict(entry)
            if item.key:
                self._items[item.key] = item

    def _save(self) -> None:
        if self.state_path is None:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "items": [item.to_dict() for item in self._items.values()],
            }
            tmp = self.state_path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            tmp.replace(self.state_path)
        except OSError:
            # Losing the audit trail must not abort the run that is trying to
            # submit; the in-memory queue still fires.
            pass


class SubmitScheduler:
    """Fires held submissions at their window, in a background thread.

    Deliberately a plain thread, not an asyncio task: the solve loop owns the
    event loop and may finish (or block on a long tool call) before the window
    opens, and a submission that only fires while some other coroutine yields is
    a submission that does not fire at all.
    """

    def __init__(
        self,
        queue: SubmitHoldQueue,
        dispatch: Callable[[str, str, dict[str, Any]], Awaitable[Any]],
        *,
        on_event: Optional[Callable[[str, dict[str, Any]], None]] = None,
    ) -> None:
        self._queue = queue
        self._dispatch = dispatch
        self._on_event = on_event
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="submit-hold-scheduler", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _emit(self, kind: str, payload: dict[str, Any]) -> None:
        if self._on_event is None:
            return
        try:
            self._on_event(kind, payload)
        except Exception:
            pass

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001 - a scheduler crash must be visible
                self._emit("submit_hold_error", {"error": repr(exc)})
            self._stop.wait(_TICK_SECONDS)

    def tick(self, *, now: Optional[datetime] = None) -> int:
        """Fire everything due. Returns how many submissions were sent."""
        moment = now or _now()
        deadline = self._queue.hold_deadline
        window_end = self._queue.window_end
        fired = 0
        for item in self._queue.pending():
            target = parse_local_deadline(item.fire_at)
            if target is None:
                self._queue.drop(item.key, "unparseable fire_at")
                continue
            if window_end is not None and moment > window_end:
                # The portal is closed. Sending now is an invalid operation;
                # dropping keeps the audit trail and avoids the penalty.
                self._queue.drop(item.key, f"submission window closed at {window_end}")
                self._emit(
                    "submit_hold_dropped",
                    {"key": item.key, "reason": "window closed", "window_end": str(window_end)},
                )
                continue
            if deadline is None:
                continue
            due = target.timestamp() - _FIRE_LEAD_SECONDS
            if moment.timestamp() < due:
                continue
            # Fire even if slightly late: a tick that arrived 1s after the target
            # is still inside a 60s window, and refusing would lose the reward.
            fired += self._fire(item)
        return fired

    def _fire(self, item: HeldSubmit) -> int:
        try:
            import asyncio

            result = asyncio.run(self._dispatch(item.server, item.tool, item.arguments))
        except Exception as exc:  # noqa: BLE001
            self._queue.mark_fired(item.key, error=repr(exc))
            self._emit("submit_hold_failed", {"key": item.key, "error": repr(exc)})
            return 0
        text = str(result)
        self._queue.mark_fired(item.key, result=text[:2000])
        self._emit(
            "submit_hold_fired",
            {"key": item.key, "tool": item.tool, "result": text[:400]},
        )
        return 1
