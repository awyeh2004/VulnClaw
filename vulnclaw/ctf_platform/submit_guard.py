"""Submission guard for CTF platforms.

The competition handbook caps flag submissions per challenge (50) and forbids
brute-forcing flags.  Because every attempt costs quota and a wrong flag may
trigger the platform's risk-control, the guard lets the agent submit a few
flags fully automatically and then escalates to a human confirmation step.

Default policy (all configurable via environment variables):

- ``VULNCLAW_CTF_AUTO_SUBMIT_LIMIT`` (default 3): how many automatic attempts a
  challenge gets before the guard starts asking for human confirmation.
- ``VULNCLAW_CTF_MAX_SUBMIT_LIMIT`` (default 50): hard ceiling from the
  handbook; attempts beyond this are rejected outright.
- ``VULNCLAW_CTF_SUBMIT_STATE`` (optional): JSON file path to persist counters
  across process restarts.  When unset the counters live in memory only.

The guard also deduplicates: retrying the exact same flag that already failed
for a challenge is treated as a likely brute-force and escalated to the human.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


class SubmitGuard:
    """Per-challenge flag submission accounting.

    State shape::

        {"<practice_id>/<challenge_id>": {
            "attempts": int, "accepted": bool, "last_flag": str | None
        }, ...}

    ``allow()`` answers whether a submit may proceed and, when it may not, why.
    ``record()`` accounts for an attempt the caller actually performed.
    """

    def __init__(self, state_path: str | os.PathLike | None = None) -> None:
        self._state_path = Path(state_path) if state_path else None
        self._entries: dict[str, dict] = {}
        self._load()

    # -- lifecycle ---------------------------------------------------------

    def _load(self) -> None:
        if not self._state_path or not self._state_path.exists():
            return
        try:
            raw = json.loads(self._state_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._entries = raw
        except (OSError, ValueError):
            # A corrupt state file must not block submissions entirely.
            self._entries = {}

    def _save(self) -> None:
        if not self._state_path:
            return
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._state_path.write_text(
                json.dumps(self._entries, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError:
            # Persistence is best-effort; the in-memory guard still applies.
            pass

    # -- state access ------------------------------------------------------

    @staticmethod
    def _key(practice_id: str, challenge_id: str) -> str:
        return f"{practice_id}/{challenge_id}"

    def _entry(self, practice_id: str, challenge_id: str) -> dict:
        key = self._key(practice_id, challenge_id)
        entry = self._entries.get(key)
        if entry is None:
            entry = {"attempts": 0, "accepted": False, "last_flag": None}
            self._entries[key] = entry
        return entry

    def attempts(self, practice_id: str, challenge_id: str) -> int:
        return int(self._entry(practice_id, challenge_id).get("attempts", 0))

    def is_accepted(self, practice_id: str, challenge_id: str) -> bool:
        return bool(self._entry(practice_id, challenge_id).get("accepted"))

    # -- policy ------------------------------------------------------------

    def auto_submit_limit(self) -> int:
        raw = os.environ.get("VULNCLAW_CTF_AUTO_SUBMIT_LIMIT", "3").strip()
        try:
            return max(1, int(raw))
        except ValueError:
            return 3

    def max_submit_limit(self) -> int:
        raw = os.environ.get("VULNCLAW_CTF_MAX_SUBMIT_LIMIT", "50").strip()
        try:
            return max(1, int(raw))
        except ValueError:
            return 50

    def allow(
        self, practice_id: str, challenge_id: str, flag: str
    ) -> tuple[bool, str]:
        """Decide whether a submit may proceed and a reason when it may not."""
        entry = self._entry(practice_id, challenge_id)

        if entry.get("accepted"):
            return False, "already solved (an accepted flag is on record)"
        if entry.get("attempts", 0) >= self.max_submit_limit():
            return (
                False,
                f"hard submission limit reached "
                f"({self.max_submit_limit()} attempts)",
            )
        if entry.get("last_flag") == flag and entry.get("attempts", 0) > 0:
            return (
                False,
                "the exact same flag already failed for this challenge "
                "(dedup / anti brute-force)",
            )
        if entry.get("attempts", 0) >= self.auto_submit_limit():
            return (
                False,
                f"after {self.auto_submit_limit()} automatic attempts this "
                "challenge requires human confirmation before another submit",
            )
        return True, ""

    def record(
        self, practice_id: str, challenge_id: str, accepted: bool, flag: str
    ) -> None:
        """Account for a submit that the caller performed."""
        entry = self._entry(practice_id, challenge_id)
        entry["attempts"] = int(entry.get("attempts", 0)) + 1
        entry["last_flag"] = flag
        if accepted:
            entry["accepted"] = True
        self._save()


_default_guard: SubmitGuard | None = None


def get_guard() -> SubmitGuard:
    """Return the process-wide default guard (lazily initialised)."""
    global _default_guard
    if _default_guard is None:
        state = os.environ.get("VULNCLAW_CTF_SUBMIT_STATE", "").strip()
        _default_guard = SubmitGuard(state_path=state or None)
    return _default_guard


def reset_guard() -> None:
    """Drop the cached process-wide guard (mainly for tests)."""
    global _default_guard
    _default_guard = None


def guard_reason_to_message(practice_id: str, challenge_id: str, reason: str) -> str:
    """Wrap a guard denial into an agent-readable escalation message."""
    return (
        "[ctf2_confirm] flag submission for challenge "
        f"{challenge_id} in practice {practice_id} is blocked: {reason}. "
        "Do not retry automatically. Ask the user to review the flag and the "
        "submission history before deciding whether to submit manually."
    )
