"""VulnClaw Agent memory management — short/mid/long-term memory."""

from __future__ import annotations

import json
import os
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional
from uuid import uuid4

from vulnclaw.config.settings import KB_DIR
# One lock implementation for the whole repo (round5 residual item): this module used to
# carry its own copy, which had drifted from `kb/store.py`'s on the lock file's permissions.
from vulnclaw.utils.atomic_write import file_lock as _file_lock
from vulnclaw.utils.atomic_write import replace_with_retry


class MemoryStore:
    """Durable key/value memory plus append-only cold conversation storage."""

    def __init__(
        self,
        store_dir: Optional[Path] = None,
        *,
        archive_max_bytes: int = 64 * 1024 * 1024,
        archive_max_files: int = 8,
    ) -> None:
        self.store_dir = store_dir or KB_DIR / "memory"
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self.archive_max_bytes = max(1024, int(archive_max_bytes))
        self.archive_max_files = max(2, int(archive_max_files))
        self.session_id = uuid4().hex
        self._cache: dict[str, Any] = {}
        self._load()

    @property
    def _memory_file(self) -> Path:
        return self.store_dir / "long_term.json"

    @property
    def _archive_file(self) -> Path:
        return self.store_dir / "conversation_archive.jsonl"

    def new_scope(self) -> str:
        """Start an isolated task scope while retaining the same durable store."""
        self.session_id = uuid4().hex
        return self.session_id

    def _load(self) -> None:
        """Load the small key/value store; archives stay on disk as JSONL."""
        if self._memory_file.exists():
            try:
                with open(self._memory_file, "r", encoding="utf-8") as handle:
                    self._cache = json.load(handle)
            except (json.JSONDecodeError, OSError):
                self._cache = {}

    def _save(self) -> None:
        """Persist the in-memory key/value map atomically, under the store lock.

        Kept for callers that have already merged their change (see :meth:`_mutate`, which
        is what the mutating methods use). Writing ``self._cache`` wholesale is only safe
        when the cache is known to be the freshest state -- which the lock alone does not
        establish.
        """
        with _file_lock(self.store_dir / ".long_term.lock"):
            self._write_locked()

    def _write_locked(self) -> None:
        """Write ``self._cache`` atomically. Caller must hold the store lock."""
        temporary = self.store_dir / f".long_term.{os.getpid()}.{uuid4().hex}.tmp"
        try:
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(self._cache, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            replace_with_retry(temporary, self._memory_file)
            try:
                os.chmod(self._memory_file, 0o600)
            except OSError:
                pass
        finally:
            temporary.unlink(missing_ok=True)

    def _mutate(self, mutate: Callable[[dict[str, Any]], None]) -> None:
        """Read-modify-write the durable map as ONE critical section.

        Round5 residual item: `save`/`delete` mutated the in-memory cache OUTSIDE the lock
        and `_save` then wrote that cache wholesale, so the lock only ever protected the FILE
        write, not the read-modify-write around it. Two stores sharing a directory (another
        process, or a second instance in this one) both loaded the same base state and the
        later writer silently dropped the earlier writer's key -- a lost update with no error
        anywhere. Re-reading inside the lock is what makes the merge correct, and it also
        refreshes this instance's cache with whatever the other writer added.
        """
        with _file_lock(self.store_dir / ".long_term.lock"):
            self._load()
            mutate(self._cache)
            self._write_locked()

    def save(self, key: str, value: Any) -> None:
        def _set(cache: dict[str, Any]) -> None:
            cache[key] = {"value": value, "updated_at": datetime.now().isoformat()}

        self._mutate(_set)

    def retrieve(self, key: str) -> Optional[Any]:
        entry = self._cache.get(key)
        return entry.get("value") if entry else None

    def list_keys(self) -> list[str]:
        return list(self._cache.keys())

    def delete(self, key: str) -> None:
        self._mutate(lambda cache: cache.pop(key, None))

    def search(self, query: str) -> list[tuple[str, Any, float]]:
        results = []
        query_lower = query.lower()
        for key, entry in self._cache.items():
            value_str = json.dumps(entry.get("value", ""), ensure_ascii=False).lower()
            if query_lower in value_str or query_lower in key.lower():
                results.append((key, entry.get("value"), float(value_str.count(query_lower))))
        return sorted(results, key=lambda item: item[2], reverse=True)

    def archive_messages(
        self,
        messages: list[dict[str, Any]],
        *,
        scope: str = "",
        target: str = "",
        kind: str = "history",
    ) -> str:
        """Append one cold-memory record and return its stable identifier."""
        if not messages:
            return ""
        record_id = f"mem-{uuid4().hex[:12]}"
        record = {
            "version": 1,
            "record_id": record_id,
            "archived_at": datetime.now().isoformat(),
            "scope": scope or self.session_id,
            "target": target,
            "kind": kind,
            "messages": messages,
        }
        encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with _file_lock(self.store_dir / ".conversation_archive.lock"):
            encoded_size = len((encoded + "\n").encode("utf-8"))
            if (
                self._archive_file.exists()
                and self._archive_file.stat().st_size + encoded_size > self.archive_max_bytes
            ):
                rotated = self.store_dir / (
                    f"conversation_archive.{datetime.now().strftime('%Y%m%d%H%M%S%f')}."
                    f"{uuid4().hex[:8]}.jsonl"
                )
                replace_with_retry(self._archive_file, rotated)
                self._prune_archive_shards()
            with open(self._archive_file, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(self._archive_file, 0o600)
            except OSError:
                pass
        return record_id

    def _archive_shards(self) -> list[Path]:
        return sorted(
            self.store_dir.glob("conversation_archive*.jsonl"),
            key=lambda path: (path.stat().st_mtime_ns, path.name),
        )

    def _prune_archive_shards(self) -> None:
        shards = self._archive_shards()
        while len(shards) >= self.archive_max_files:
            shards.pop(0).unlink(missing_ok=True)

    def search_messages(
        self,
        query: str,
        *,
        limit: int = 5,
        max_chars: int = 6000,
        scope: str = "",
        target: str = "",
    ) -> list[dict[str, Any]]:
        """Return bounded snippets from matching JSONL records in one task scope."""
        query = str(query or "").strip()
        if not query or not self._archive_file.exists():
            return []
        limit = max(1, min(int(limit), 20))
        max_chars = max(256, int(max_chars))
        matches: deque[tuple[dict[str, Any], str]] = deque(maxlen=limit)
        query_lower = query.lower()
        for archive_file in self._archive_shards():
            with open(archive_file, "r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        record = json.loads(line)
                    except (json.JSONDecodeError, TypeError):
                        continue
                    if scope and record.get("scope") != scope:
                        continue
                    if target and record.get("target") not in {"", target}:
                        continue
                    rendered = json.dumps(record.get("messages", []), ensure_ascii=False)
                    if query_lower not in rendered.lower() and query_lower not in str(
                        record.get("record_id", "")
                    ).lower():
                        continue
                    matches.append((record, rendered))

        remaining = max_chars
        results: list[dict[str, Any]] = []
        for record, rendered in reversed(matches):
            if remaining <= 0:
                break
            allowance = min(remaining, max(256, max_chars // max(1, len(matches))))
            lowered = rendered.lower()
            match_at = lowered.find(query_lower)
            if match_at < 0:
                match_at = 0
            start = max(0, match_at - allowance // 3)
            prefix = "..." if start else ""
            suffix = "..." if start + allowance < len(rendered) else ""
            body_allowance = max(0, allowance - len(prefix) - len(suffix))
            snippet = prefix + rendered[start : start + body_allowance] + suffix
            results.append(
                {
                    "record_id": record.get("record_id", ""),
                    "archived_at": record.get("archived_at", ""),
                    "target": record.get("target", ""),
                    "kind": record.get("kind", "history"),
                    "snippet": snippet,
                }
            )
            remaining -= len(snippet)
        return results
