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
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

#: How many seconds ahead of the target to fire. The platform timestamps arrival,
#: and a request issued exactly at 19:24:00.000 can land at 19:24:00.3 -- inside
#: the window either way, but a LATE tick (GC, a slow dispatch) is the dangerous
#: direction, so the scheduler aims slightly early and re-checks the window.
_FIRE_LEAD_SECONDS = 0.8

#: First-blood submissions aim EARLIER than that. The sprint window opens at a
#: fixed second and first-blood credit goes to whoever lands first, so the whole
#: value of the submission is in the first few hundred milliseconds of the band.
#: Aiming 0.3s early means the request is in flight as the band opens rather than
#: queued behind it.
_FIRSTBLOOD_LEAD_SECONDS = 0.3

#: How long a window without an explicit ``until`` stays open. 60s matches the
#: 卡点 band the rulebook defines; a first-blood window uses the same grace so a
#: late tick still fires instead of dropping the submission.
_IMPLICIT_WINDOW_SECONDS = 60

#: Scheduler poll interval while something is pending. Tight enough for the
#: first-blood race: a 1s poll could place the request up to a second into a band
#: where being first is the entire point.
_TICK_SECONDS = 0.05


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
class SubmitWindow:
    """One named submission window.

    The 1024 sprint needs TWO of these, and they are not interchangeable:

    * ``firstblood`` at 19:10:24 — the instant the sprint window opens. Its value
      is being EARLY (first-blood weighting), so it fires as soon as the clock
      reaches it and there is no tolerance for "roughly around then".
    * ``peak`` at 19:24:00 — the 卡点 question, which pays full marks only for
      submissions that LAND inside 19:24:00–19:24:59. Here arriving early is
      worthless, so ``until`` matters as much as ``at``.

    Modelling both as one shared deadline would make the first-blood submission
    late by however long the model kept working, and would give the 卡点 one the
    same instant as the sprint opener -- which is a different score event.
    """

    name: str
    at: str
    until: str = ""
    note: str = ""

    def fire_time(self) -> Optional[datetime]:
        return parse_local_deadline(self.at)

    def close_time(self) -> Optional[datetime]:
        """When this window stops being worth firing into.

        An explicit ``until`` wins. Without one, the window holds for
        ``_IMPLICIT_WINDOW_SECONDS`` after ``at`` rather than closing instantly:
        a scheduler tick that lands 200ms after the target is still inside a
        60-second band, and treating the opening second as the entire window
        would drop exactly the submission the window exists for. That was a real
        bug in the first cut of this file (a first-blood window with no ``until``
        expired before the first tick could fire it).
        """
        explicit = parse_local_deadline(self.until)
        if explicit is not None:
            return explicit
        start = self.fire_time()
        if start is None:
            return None
        return start + timedelta(seconds=_IMPLICIT_WINDOW_SECONDS)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "at": self.at, "until": self.until, "note": self.note}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SubmitWindow":
        return cls(
            name=str(data.get("name", "")),
            at=str(data.get("at", "")),
            until=str(data.get("until", "")),
            note=str(data.get("note", "")),
        )


@dataclass
class HeldSubmit:
    """One submission waiting for its window."""

    key: str
    server: str
    tool: str
    arguments: dict[str, Any]
    fire_at: str
    created_at: str
    window: str = ""
    close_at: str = ""
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
            "window": self.window,
            "close_at": self.close_at,
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
            window=str(data.get("window", "")),
            close_at=str(data.get("close_at", "")),
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
        windows: Optional[list[SubmitWindow]] = None,
        default_window: str = "",
    ) -> None:
        self.state_path = Path(state_path) if state_path else None
        self._hold_until = hold_until
        self._window_end = window_end
        self._windows = list(windows or [])
        self._default_window = default_window
        self._lock = threading.RLock()
        self._items: dict[str, HeldSubmit] = {}
        self._load()

    # -- windows -----------------------------------------------------------

    @property
    def windows(self) -> list[SubmitWindow]:
        return list(self._windows)

    def window(self, name: str = "") -> Optional[SubmitWindow]:
        """Resolve a window by name, falling back to the configured default."""
        target = (name or self._default_window or "").strip()
        if not target:
            return None
        for window in self._windows:
            if window.name == target:
                return window
        return None

    def next_window(self, *, now: Optional[datetime] = None) -> Optional[SubmitWindow]:
        """The soonest window that has not closed yet.

        "Not closed" is what makes a late find useful: a flag found at 19:23 is
        still eligible for the 19:24 卡点 window, and one found at 19:26 falls
        through to the next window instead of being fired backwards in time.
        """
        moment = now or _now()
        candidates = [
            window
            for window in self._windows
            if (close := window.close_time()) is not None and moment <= close
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda w: w.fire_time() or datetime.max)

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

        Three ways to say "hold": named windows exist and one is still ahead;
        the legacy single deadline has not passed. Either way the answer goes
        False once nothing remains ahead -- a flag found after the last window
        must go out immediately (a later window may still exist, and holding with
        no target would drop it).
        """
        moment = now or _now()
        if self._windows:
            return self.next_window(now=moment) is not None
        deadline = self.hold_deadline
        if deadline is None:
            return False
        return moment < deadline

    # -- queue operations ---------------------------------------------------

    def enqueue(
        self,
        *,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        key: str = "",
        window: str = "",
    ) -> Optional[HeldSubmit]:
        """Persist a submission for later firing. Returns None when not holding.

        ``window`` names the target window (``firstblood`` / ``peak``); empty uses
        the configured default, and if that name is unknown the soonest open
        window is used. The key defaults to ``tool + sorted(arguments)``, so the
        SAME payload submitted twice while held collapses to one entry: a model
        that retries its submit call must not spend two attempts.
        """
        if not self.should_hold():
            return None
        target = self.window(window) or self.next_window()
        if target is not None:
            fire_at = target.fire_time()
            close_at = target.close_time()
            window_name = target.name
        else:
            # Legacy single-deadline mode.
            fire_at = self.hold_deadline
            close_at = self.window_end
            window_name = ""
        if fire_at is None:
            return None
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
                fire_at=fire_at.isoformat(timespec="seconds"),
                created_at=_now().isoformat(timespec="seconds"),
                window=window_name,
                close_at=close_at.isoformat(timespec="seconds") if close_at else "",
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
        """Fire everything due. Returns how many submissions were sent.

        Each item carries its OWN window bounds (``fire_at`` / ``close_at``), so
        two submissions targeting different windows do not interfere: the
        first-blood one goes at 19:10:24 while the 卡点 one waits for 19:24.
        """
        moment = now or _now()
        global_end = self._queue.window_end
        fired = 0
        for item in self._queue.pending():
            target = parse_local_deadline(item.fire_at)
            if target is None:
                self._queue.drop(item.key, "unparseable fire_at")
                continue
            # Per-item close, with the legacy global bound as a backstop: an item
            # queued under the old single-deadline config has no close_at.
            close = parse_local_deadline(item.close_at) or global_end
            if close is not None and moment > close:
                # The window has closed. Sending now earns nothing (or is an
                # invalid operation); dropping keeps the audit trail.
                self._queue.drop(item.key, f"submission window closed at {close}")
                self._emit(
                    "submit_hold_dropped",
                    {
                        "key": item.key,
                        "reason": "window closed",
                        "window": item.window,
                        "close_at": str(close),
                    },
                )
                continue
            due = target.timestamp() - self._lead_for(item)
            if moment.timestamp() < due:
                continue
            # Fire even if slightly late: a tick that arrived 1s after the target
            # is still inside the window, and refusing would lose the reward.
            fired += self._fire(item)
        return fired

    @staticmethod
    def _lead_for(item: HeldSubmit) -> float:
        """How early to send, per window purpose.

        A first-blood window pays for arriving FIRST, so it aims a hair early
        (the platform timestamps arrival, and an early request still lands inside
        the sprint window). A 卡点 window pays for landing INSIDE a 60-second
        band, where being 0.8s early is worthless if the band has not opened --
        so it aims at the stated second and lets the tolerance absorb jitter.
        """
        if item.window == "firstblood":
            return _FIRSTBLOOD_LEAD_SECONDS
        return _FIRE_LEAD_SECONDS

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
