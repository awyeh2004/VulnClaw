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
import tempfile
import time
from contextlib import contextmanager
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


# ── crash-safe, multi-process state persistence ──────────────────────────


def _read_entries(path: Path) -> dict[str, dict]:
    """Entries currently on disk ({} when absent or unreadable)."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    entries = raw.get("entries")
    if not isinstance(entries, dict):
        # A pre-versioned file is the legacy flat mapping.
        entries = raw
    cleaned: dict[str, dict] = {}
    for token, value in entries.items():
        entry = _clean_entry(value)
        if entry is not None:
            cleaned[str(token)] = entry
    return cleaned


def _merge_entries(disk: dict[str, dict], memory: dict[str, dict]) -> dict[str, dict]:
    """Union of two views of the counters, taking the *stricter* value.

    Attempts use ``max`` and ``accepted`` is sticky-true: a concurrent writer can
    only ever make the accounting more conservative, so two processes submitting
    for the same key cannot reset each other's budget.
    """
    merged: dict[str, dict] = {}
    for token in set(disk) | set(memory):
        on_disk = disk.get(token) or {}
        in_memory = memory.get(token) or {}
        attempts = max(int(on_disk.get("attempts", 0) or 0), int(in_memory.get("attempts", 0) or 0))
        accepted = bool(on_disk.get("accepted")) or bool(in_memory.get("accepted"))
        entry = dict(_ENTRY_DEFAULTS)
        entry["attempts"] = attempts
        entry["accepted"] = accepted
        entry["last_flag"] = in_memory.get("last_flag") or on_disk.get("last_flag")
        merged[token] = entry
    return merged


def _atomic_write(path: Path, text: str) -> None:
    """Write via a same-directory temp file + rename, so a crash cannot truncate.

    ``os.replace`` is retried on PermissionError: on Windows it fails when the
    destination is briefly open by a concurrent reader (a sharing violation), and
    a single failure here would otherwise drop the caller's increment.
    """
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".submit-state-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        last: OSError | None = None
        for attempt in range(5):
            try:
                os.replace(tmp_name, str(path))
                return
            except PermissionError as exc:  # Windows sharing violation
                last = exc
                time.sleep(0.05 * (attempt + 1))
        if last is not None:
            raise last
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _take_os_lock(fd: int, timeout_s: float) -> None:
    deadline = time.monotonic() + max(0.1, timeout_s)
    while True:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError:
            if time.monotonic() > deadline:
                raise TimeoutError("submit-state guard busy") from None
            time.sleep(0.02)


def _drop_os_lock(fd: int) -> None:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass


@contextmanager
def _state_guard(path: Path, timeout_s: float = 5.0):
    """Serialize read-merge-write across processes (sibling guard file).

    The guard lives beside the state file and is never deleted, so its identity
    is never in question; the OS releases it if the holder dies.
    """
    guard = path.with_name(path.name + ".guard")
    fd = os.open(str(guard), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
        except OSError:
            pass
        _take_os_lock(fd, timeout_s)
    except Exception:
        os.close(fd)
        raise
    try:
        yield
    finally:
        _drop_os_lock(fd)
        try:
            os.close(fd)
        except OSError:
            pass


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

    def _write_entries(self, path: Path, entries: dict[str, dict]) -> None:
        """Atomically persist ``entries`` (temp file + rename)."""
        _atomic_write(
            path,
            json.dumps(
                {"version": STATE_VERSION, "entries": entries},
                ensure_ascii=False,
                indent=2,
            ),
        )

    def _mutate(self, key: str, mutate) -> None:
        """Apply ``mutate`` to one entry with the file as the source of truth.

        Round-5 review N8: the counter used to live only in memory and the file
        was rewritten wholesale, so two processes submitting for the same key
        overwrote each other (and a crash mid-write reset the count, silently
        raising the effective auto-submit budget — the counter is what the cap is
        enforced against). Every mutation therefore re-reads the file inside the
        cross-process guard, so concurrent attempts add up.
        """
        token = str(key)
        path = Path(self.state_path) if self.state_path else None
        if path is None:
            mutate(self._entry(token))
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with _state_guard(path):
                entries = _read_entries(path)
                # Fold in anything this process counts but the file does not have
                # yet (an earlier write failed, or the file was reset). Merging
                # BEFORE the increment is what makes both properties hold:
                # concurrent processes still sum (each reads the latest disk
                # value), and a failed write cannot lose a local increment.
                for other, value in self._entries.items():
                    on_disk = entries.get(other)
                    entries[other] = (
                        _merge_entries({other: on_disk}, {other: value})[other]
                        if on_disk is not None
                        else dict(value)
                    )
                entry = entries.get(token) or dict(_ENTRY_DEFAULTS)
                mutate(entry)
                entries[token] = entry
                self._write_entries(path, entries)
                self._entries = entries
        except OSError:
            # Persistence is best-effort; keep the increment in memory so the
            # next successful write includes it (never lose an attempt).
            mutate(self._entry(token))

    def _refresh(self, key: str) -> None:
        """Pull the authoritative entry for ``key`` from disk into memory.

        Reads need no lock: :func:`_atomic_write` renames into place, so a reader
        sees either the old or the new file, never a partial one.
        """
        path = Path(self.state_path) if self.state_path else None
        if path is None:
            return
        token = str(key)
        on_disk = _read_entries(path).get(token)
        if on_disk is None:
            return
        current = self._entries.get(token)
        merged = _merge_entries({token: on_disk}, {token: current} if current else {})
        self._entries[token] = merged[token]

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
        self._refresh(key)  # another process may have spent an attempt
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

        def _apply(entry: dict) -> None:
            entry["attempts"] = int(entry.get("attempts", 0)) + 1
            entry["last_flag"] = flag
            if accepted:
                entry["accepted"] = True

        self._mutate(key, _apply)

    def record_error(self, key: str) -> None:
        """Account for an infrastructure failure (network / platform error).

        Unlike :meth:`record`, this consumes no attempt and does not remember the
        flag: the platform never judged it, so retrying the same flag later must
        not be blocked by the dedup rule.
        """
        self._mutate(key, lambda entry: None)


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
