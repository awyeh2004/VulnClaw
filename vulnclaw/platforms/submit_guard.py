"""Flag-submission accounting, keyed by ref token.

Moved out of ``ctf_platform`` because the policy is platform-independent, and
because the old two-id signature caused real defects:

* GCS had to call ``guard.allow(str(exercise_id), str(exercise_id), flag)`` --
  one id pushed into two slots purely to satisfy the shape.
* Both platforms shared one process-wide guard whose keys were
  ``f"{practice_id}/{challenge_id}"``, so a CTF2 key and a GCS key could in
  principle collide -- and a collision silently blocks a legitimate submission
  as "already attempted".
* GCS imported the guard from the CTF2 package, so the CTF2 package could not be
  retired without breaking GCS.

Keying on the ref token fixes all three: the key is platform-qualified
(``ctf2:practice:12:345`` vs ``gcs:exercise:10662``) and there is exactly one
argument.

Policy is unchanged (invariant I8): a few fully automatic attempts, then human
confirmation; a hard ceiling; no repeat of a flag that already failed; an
infrastructure failure consumes nothing.  Configuration env vars keep their
existing names.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STATE_VERSION = 2
"""Bumped when the on-disk key format changes; see :func:`migrate_legacy_state`."""

ENV_AUTO_LIMIT = "VULNCLAW_CTF_AUTO_SUBMIT_LIMIT"
ENV_MAX_LIMIT = "VULNCLAW_CTF_MAX_SUBMIT_LIMIT"
ENV_STATE_PATH = "VULNCLAW_CTF_SUBMIT_STATE"

DEFAULT_AUTO_LIMIT = 3
DEFAULT_MAX_LIMIT = 50

_ENTRY_DEFAULTS: dict[str, Any] = {"attempts": 0, "accepted": False, "last_flag": None}


@dataclass(frozen=True)
class MigrationReport:
    """What a legacy state file turned into."""

    entries: dict[str, dict]
    mapped: tuple[tuple[str, str], ...] = ()
    already_current: tuple[str, ...] = ()
    dropped: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.mapped or self.dropped)


def _clean_entry(raw: Any) -> dict | None:
    """Keep only the known fields, with sane types."""
    if not isinstance(raw, dict):
        return None
    entry = dict(_ENTRY_DEFAULTS)
    try:
        entry["attempts"] = max(0, int(raw.get("attempts", 0) or 0))
    except (TypeError, ValueError):
        entry["attempts"] = 0
    entry["accepted"] = bool(raw.get("accepted", False))
    last_flag = raw.get("last_flag")
    entry["last_flag"] = str(last_flag) if last_flag is not None else None
    return entry


def legacy_key_to_token(old_key: str) -> str | None:
    """Translate one pre-refactor ``a/b`` key into a ref token.

    Both old platforms used ``f"{x}/{y}"``: CTF2 as
    ``practice_id/challenge_id``, GCS as ``exercise_id/exercise_id`` (the same
    id twice, because the guard demanded two).  So the discriminator is that
    duplication: **equal numeric parts mean GCS**, anything else means CTF2.

    The residual ambiguity is a CTF2 challenge whose practice id and challenge id
    are the same numeric string; it would be misread as GCS, costing that one
    entry's counters (at most a few extra automatic attempts before escalation).
    Ordering it the other way would misattribute EVERY GCS entry instead.
    """
    text = str(old_key or "").strip()
    if not text or "/" not in text:
        return None
    left, _, right = text.partition("/")
    if not left or not right:
        return None
    if left == right and left.isdigit():
        return f"gcs:exercise:{left}"
    return f"ctf2:practice:{left}:{right}"


def migrate_legacy_state(raw: Any) -> MigrationReport:
    """Accept either state-file generation and return normalized entries.

    Idempotent: feeding the output back in yields the same entries, so a legacy
    file can be read repeatedly without being rewritten.
    """
    if not isinstance(raw, dict):
        return MigrationReport(entries={}, dropped=("(not a mapping)",))

    if "version" in raw and isinstance(raw.get("entries"), dict):
        entries: dict[str, dict] = {}
        dropped: list[str] = []
        for key, value in raw["entries"].items():
            cleaned = _clean_entry(value)
            if cleaned is None:
                dropped.append(str(key))
                continue
            entries[str(key)] = cleaned
        return MigrationReport(
            entries=entries,
            already_current=tuple(sorted(str(k) for k in entries)),
            dropped=tuple(dropped),
        )

    entries = {}
    mapped: list[tuple[str, str]] = []
    dropped = []
    for key, value in raw.items():
        cleaned = _clean_entry(value)
        if cleaned is None:
            dropped.append(str(key))
            continue
        token = legacy_key_to_token(str(key))
        if token is None:
            dropped.append(str(key))
            continue
        entries[token] = cleaned
        mapped.append((str(key), token))
    return MigrationReport(entries=entries, mapped=tuple(mapped), dropped=tuple(dropped))


class SubmitGuard:
    """Per-challenge flag submission accounting, keyed by ref token.

    State shape on disk (generation 2)::

        {"version": 2, "entries": {"<ref token>": {
            "attempts": int, "accepted": bool, "last_flag": str | None}}}

    A generation-1 file is a flat ``{"a/b": {...}}`` mapping and is translated on
    load by :func:`migrate_legacy_state`.
    """

    def __init__(self, state_path: str | os.PathLike | None = None) -> None:
        self.state_path = state_path
        self._entries: dict[str, dict] = {}
        self._migration: MigrationReport | None = None
        self._load()

    # -- lifecycle ---------------------------------------------------------

    def _load(self) -> None:
        path = Path(self.state_path) if self.state_path else None
        if path is None or not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # A corrupt state file must not block submissions entirely.
            self._entries = {}
            return
        report = migrate_legacy_state(raw)
        self._migration = report
        self._entries = report.entries

    def _save(self) -> None:
        path = Path(self.state_path) if self.state_path else None
        if path is None:
            return
        payload = {
            "version": STATE_VERSION,
            "entries": self._entries,
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError:
            # Persistence is best-effort; the in-memory guard still applies.
            pass

    # -- state access ------------------------------------------------------

    def _entry(self, key: str) -> dict:
        token = str(key)
        entry = self._entries.get(token)
        if entry is None:
            entry = dict(_ENTRY_DEFAULTS)
            self._entries[token] = entry
        return entry

    def attempts(self, key: str) -> int:
        return int(self._entry(key).get("attempts", 0))

    def is_accepted(self, key: str) -> bool:
        return bool(self._entry(key).get("accepted"))

    def snapshot(self) -> dict[str, dict]:
        """Copy of the tracked entries (diagnostics, tests)."""
        return {token: dict(entry) for token, entry in self._entries.items()}

    @property
    def migration(self) -> MigrationReport | None:
        """Report from the last load, when the file needed translating."""
        return self._migration

    # -- policy ------------------------------------------------------------

    @staticmethod
    def auto_submit_limit() -> int:
        raw = os.environ.get(ENV_AUTO_LIMIT, str(DEFAULT_AUTO_LIMIT)).strip()
        try:
            return max(1, int(raw))
        except ValueError:
            return DEFAULT_AUTO_LIMIT

    @staticmethod
    def max_submit_limit() -> int:
        raw = os.environ.get(ENV_MAX_LIMIT, str(DEFAULT_MAX_LIMIT)).strip()
        try:
            return max(1, int(raw))
        except ValueError:
            return DEFAULT_MAX_LIMIT

    def allow(self, key: str, flag: str) -> tuple[bool, str]:
        """Decide whether a submit may proceed, and why not when it may not."""
        entry = self._entry(key)

        if entry.get("accepted"):
            return False, "already solved (an accepted flag is on record)"
        if entry.get("attempts", 0) >= self.max_submit_limit():
            return (
                False,
                f"hard submission limit reached ({self.max_submit_limit()} attempts)",
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

    def record(self, key: str, accepted: bool, flag: str) -> None:
        """Account for a submit that the caller actually performed."""
        entry = self._entry(key)
        entry["attempts"] = int(entry.get("attempts", 0)) + 1
        entry["last_flag"] = flag
        if accepted:
            entry["accepted"] = True
        self._save()

    def record_error(self, key: str) -> None:
        """Account for an infrastructure failure (network / platform error).

        Unlike :meth:`record`, this consumes no attempt and does not remember the
        flag: the platform never judged it, so retrying the same flag later must
        not be blocked by the dedup rule.
        """
        self._entry(key)
        self._save()


_default_guard: SubmitGuard | None = None


def get_guard() -> SubmitGuard:
    """Return the process-wide default guard (lazily initialised)."""
    global _default_guard
    if _default_guard is None:
        state = os.environ.get(ENV_STATE_PATH, "").strip()
        _default_guard = SubmitGuard(state_path=state or None)
    return _default_guard


def reset_guard() -> None:
    """Drop the cached process-wide guard (mainly for tests)."""
    global _default_guard
    _default_guard = None


def guard_reason_to_message(key: str, reason: str) -> str:
    """Wrap a guard denial into an agent-readable escalation message.

    Platform-neutral: the old text hardcoded a ``[ctf2_confirm]`` prefix, which
    was simply wrong once GCS went through the same guard.
    """
    return (
        f"[submit_blocked] flag submission for {key} is blocked: {reason}. "
        "Do not retry automatically. Ask the user to review the flag and the "
        "submission history before deciding whether to submit manually."
    )


__all__ = [
    "DEFAULT_AUTO_LIMIT",
    "DEFAULT_MAX_LIMIT",
    "ENV_AUTO_LIMIT",
    "ENV_MAX_LIMIT",
    "ENV_STATE_PATH",
    "STATE_VERSION",
    "MigrationReport",
    "SubmitGuard",
    "get_guard",
    "guard_reason_to_message",
    "legacy_key_to_token",
    "migrate_legacy_state",
    "reset_guard",
]
