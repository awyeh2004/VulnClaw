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
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from vulnclaw.utils.atomic_write import atomic_write_text, file_lock

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


class SubmitHoldPersistenceError(RuntimeError):
    """The queue could not be durably persisted."""


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
    status: str = "pending"
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
            "status": self.status,
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
            status=str(data.get("status", "submitted" if data.get("fired") else "pending")),
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
        hold_challenges: Optional[list[str]] = None,
    ) -> None:
        self.state_path = Path(state_path) if state_path else None
        self._hold_until = hold_until
        self._window_end = window_end
        self._windows = list(windows or [])
        self._default_window = default_window
        self._hold_challenges = {
            str(cid).strip() for cid in (hold_challenges or []) if str(cid).strip()
        }
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

    def reconfigure(
        self,
        *,
        hold_until: str,
        window_end: str = "",
        windows: Optional[list[SubmitWindow]] = None,
        default_window: str = "",
        hold_challenges: Optional[list[str]] = None,
    ) -> None:
        """Hot-reload config without replacing the durable queue object."""
        with self._lock:
            self._hold_until = hold_until
            self._window_end = window_end
            if windows is not None:
                self._windows = list(windows)
            self._default_window = default_window
            if hold_challenges is not None:
                self._hold_challenges = {
                    str(cid).strip() for cid in hold_challenges if str(cid).strip()
                }


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

    def covers(self, challenge_id: str) -> bool:
        """Whether this challenge's submits belong in the queue at all.

        An empty allow-list keeps the sprint-wide behaviour ("hold whatever
        arrives while a window is ahead"). A non-empty one narrows it to the
        challenges actually scored AT the window -- typically the 卡点题 -- so
        every other flag goes out the moment it is found.
        """
        if not self._hold_challenges:
            return True
        return str(challenge_id or "").strip() in self._hold_challenges

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
        with self._lock, self._state_file_lock():
            self._refresh_from_disk_unlocked()
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
            try:
                self._save_unlocked()
            except OSError as exc:
                self._items.pop(identity, None)
                raise SubmitHoldPersistenceError(
                    f"could not persist held submission: {exc}"
                ) from exc
            return item

    @staticmethod
    def _identity(server: str, tool: str, arguments: dict[str, Any]) -> str:
        payload = json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str)
        return f"{server}/{tool}/{payload}"

    def pending(self) -> list[HeldSubmit]:
        with self._lock:
            self._refresh_from_disk()
            return [
                item
                for item in self._items.values()
                if not item.fired and item.status == "pending"
            ]

    def all_items(self) -> list[HeldSubmit]:
        with self._lock:
            self._refresh_from_disk()
            return list(self._items.values())

    def active_count(self) -> int:
        with self._lock:
            self._refresh_from_disk()
            return sum(1 for item in self._items.values() if not item.fired)

    def claim(self, key: str) -> Optional[HeldSubmit]:
        """Durably claim an item before any network operation.

        The short sidecar lock protects the read/modify/write across managers and
        processes. A failed claim is fail-closed: callers must not send.
        """
        with self._lock, self._state_file_lock():
            self._refresh_from_disk_unlocked()
            item = self._items.get(key)
            if item is None or item.fired or item.status != "pending":
                return None
            item.status = "in_flight"
            try:
                self._save_unlocked()
            except OSError as exc:
                item.status = "pending"
                raise SubmitHoldPersistenceError(
                    f"could not persist in-flight claim: {exc}"
                ) from exc
            return item

    def release_claim(self, key: str, error: str = "") -> None:
        """Return a pre-network claim to pending when the owner loop is absent."""
        with self._lock, self._state_file_lock():
            self._refresh_from_disk_unlocked()
            item = self._items.get(key)
            if item is None or item.status != "in_flight":
                return
            item.status = "pending"
            item.error = error
            self._save_unlocked()

    def mark_fired(self, key: str, *, result: str = "", error: str = "") -> None:
        with self._lock, self._state_file_lock():
            self._refresh_from_disk_unlocked()
            item = self._items.get(key)
            if item is None or item.status in {"submitted", "expired"}:
                return
            item.fired = True
            item.status = "submitted"
            item.result = result
            item.error = error
            item.fired_at = _now().isoformat(timespec="seconds")
            self._save_unlocked()

    def record_failure(self, key: str, error: str) -> None:
        """Record an unknown outcome and make the item ineligible for replay."""
        with self._lock, self._state_file_lock():
            self._refresh_from_disk_unlocked()
            item = self._items.get(key)
            if item is None or item.status in {"submitted", "expired", "unknown"}:
                return
            item.error = error
            item.status = "unknown"
            item.fired = True
            item.fired_at = _now().isoformat(timespec="seconds")
            self._save_unlocked()

    def drop(self, key: str, reason: str) -> None:
        """Remove an entry that must never be sent (records why)."""
        with self._lock, self._state_file_lock():
            self._refresh_from_disk_unlocked()
            item = self._items.get(key)
            if item is None or item.status in {"submitted", "expired", "unknown"}:
                return
            item.fired = True
            item.status = "expired"
            item.error = f"dropped: {reason}"
            item.fired_at = _now().isoformat(timespec="seconds")
            self._save_unlocked()

    def clear(self) -> None:
        with self._lock, self._state_file_lock():
            self._items.clear()
            self._save_unlocked()

    # -- persistence --------------------------------------------------------

    @property
    def _lock_path(self) -> Optional[Path]:
        return self.state_path.with_name(self.state_path.name + ".lock") if self.state_path else None

    @contextmanager
    def _state_file_lock(self):
        if self._lock_path is None:
            yield
        else:
            with file_lock(self._lock_path):
                yield

    def _refresh_from_disk_unlocked(self) -> None:
        if self.state_path is None or not self.state_path.exists():
            return
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        items = raw.get("items") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            return
        loaded: dict[str, HeldSubmit] = {}
        for entry in items:
            if not isinstance(entry, dict):
                continue
            item = HeldSubmit.from_dict(entry)
            if item.key:
                loaded[item.key] = item
        # Keep live pending objects (direct callers/tests may adjust their due time),
        # while importing entries created by another manager. Claims always reload
        # canonically under the file lock before a send.
        for key, item in loaded.items():
            if key not in self._items:
                self._items[key] = item
            elif self._items[key].status != "pending":
                self._items[key] = item

    def _refresh_from_disk(self) -> None:
        with self._state_file_lock():
            self._refresh_from_disk_unlocked()

    def _load(self) -> None:
        with self._lock, self._state_file_lock():
            self._refresh_from_disk_unlocked()
            # A process restart must never replay an ambiguous network call.
            changed = False
            for item in self._items.values():
                if item.status == "in_flight":
                    item.status = "unknown"
                    item.fired = True
                    item.error = item.error or "stale in-flight submission after reload"
                    item.fired_at = item.fired_at or _now().isoformat(timespec="seconds")
                    changed = True
            if changed:
                self._save_unlocked()

    def _save_unlocked(self) -> None:
        if self.state_path is None:
            return
        payload = {"items": [item.to_dict() for item in self._items.values()]}
        atomic_write_text(
            self.state_path,
            json.dumps(payload, ensure_ascii=False, indent=2),
        )

    def _save(self) -> None:
        with self._lock, self._state_file_lock():
            self._save_unlocked()


class SubmitHoldDispatchUnavailable(RuntimeError):
    """The scheduler cannot reach the manager's event loop."""


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
        loop_provider: Optional[Callable[[], Any]] = None,
        idle_grace_ticks: int = 40,
    ) -> None:
        self._queue = queue
        self._dispatch = dispatch
        self._on_event = on_event
        self._loop_provider = loop_provider
        self._idle_grace_ticks = max(1, int(idle_grace_ticks))
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

    def stop(self, *, timeout: float = 1.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, timeout))

    async def astop(self, *, timeout: float = 1.0) -> None:
        """Stop from the owning event loop without blocking that loop."""
        import asyncio

        await asyncio.to_thread(self.stop, timeout=timeout)

    def _emit(self, kind: str, payload: dict[str, Any]) -> None:
        if self._on_event is None:
            return
        try:
            self._on_event(kind, payload)
        except Exception:
            pass

    def _run(self) -> None:
        idle_ticks = 0
        while not self._stop.is_set():
            try:
                pending_before = len(self._queue.pending())
                self.tick()
                if pending_before:
                    idle_ticks = 0
                else:
                    idle_ticks += 1
            except Exception as exc:  # noqa: BLE001 - a scheduler crash must be visible
                self._emit("submit_hold_error", {"error": repr(exc)})
            if idle_ticks >= self._idle_grace_ticks:
                return
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
        # Everything else aims AT the stated second. A 卡点 band opens at a fixed
        # second and pays full marks only inside it, so an early request is worth
        # half; the client-side setup of the call already lands it a few hundred
        # milliseconds late, which the 60s band absorbs happily.
        return 0.0

    def _fire(self, item: HeldSubmit) -> int:
        try:
            claimed = self._queue.claim(item.key)
        except SubmitHoldPersistenceError as exc:
            self._emit("submit_hold_persistence_failed", {"key": item.key, "error": repr(exc)})
            return 0
        if claimed is None:
            return 0
        try:
            result = self._dispatch_on_loop(claimed)
        except SubmitHoldDispatchUnavailable as exc:
            # No network operation was started; bounded retry is safe.
            try:
                self._queue.release_claim(claimed.key, repr(exc))
            except OSError:
                self._emit("submit_hold_persistence_failed", {"key": item.key, "error": repr(exc)})
            self._emit("submit_hold_unavailable", {"key": item.key, "error": repr(exc)})
            return 0
        except Exception as exc:  # noqa: BLE001
            # The coroutine may have reached the platform before raising. Never replay.
            try:
                self._queue.record_failure(claimed.key, repr(exc))
            except OSError:
                self._emit("submit_hold_persistence_failed", {"key": item.key, "error": repr(exc)})
            self._emit("submit_hold_failed", {"key": item.key, "error": repr(exc)})
            return 0
        try:
            self._queue.mark_fired(claimed.key, result=str(result)[:2000])
        except OSError as exc:
            # The send happened; a persistence failure makes its durable outcome unknown.
            try:
                self._queue.record_failure(claimed.key, f"result persistence failed: {exc!r}")
            except OSError:
                pass
            return 0
        text = str(result)
        self._emit(
            "submit_hold_fired",
            {"key": item.key, "tool": item.tool, "result": text[:400]},
        )
        return 1

    def _dispatch_on_loop(self, item: HeldSubmit) -> Any:
        if self._loop_provider is None:
            import asyncio

            return asyncio.run(self._dispatch(item.server, item.tool, item.arguments))
        loop = self._loop_provider()
        if loop is None or loop.is_closed() or not loop.is_running():
            raise SubmitHoldDispatchUnavailable(
                "the owning event loop is not available for this held submission"
            )
        import asyncio

        future = asyncio.run_coroutine_threadsafe(
            self._dispatch(item.server, item.tool, item.arguments), loop
        )
        try:
            # A stuck owner loop must not prevent manager teardown indefinitely.
            return future.result(timeout=max(1.0, _TICK_SECONDS * 20))
        except FutureTimeoutError as exc:
            raise RuntimeError("held submission dispatch timed out; outcome unknown") from exc
        except Exception as exc:
            if loop.is_closed():
                raise SubmitHoldDispatchUnavailable(
                    "the owning event loop closed before the held submission completed"
                ) from exc
            raise
