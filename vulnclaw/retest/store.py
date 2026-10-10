"""复测记录的持久化（A1）。

一次复测会话 = 磁盘上一个 JSON 文件（``<root>/<sanitised finding_id>-<digest>.json``），
内容是 ``{"schema_version": 1, "finding_id": ..., "records": [...]}``。选文件而不是
ARTEX 的 PostgreSQL 表，是因为 VulnClaw 的其余运行数据（sessions / evidence / playbooks）
同样是「配置文件系统」；但 ARTEX 的两条不变量照搬，因为它们是这类数据的正确性来源：

1. **一个 finding 只允许一条复测会话** —— ``start()`` 对同一 finding 幂等，重复请求
   返回既有记录（并保留当时冻结的快照），不会开出第二条并行的复测。
2. **结论只有第一轮能写** —— ``conclude()`` 只接受 ``round == 1`` 且仍在 running 的
   记录；追问轮（``follow_up()``）只附记录。所以「已修复」这句话永远只有一个来源。
3. **不自动重放** —— 进程重启后遗留的 running 记录由 ``stop_orphans()`` 封成
   ``stopped`` 并点名，让上层显式决定是否重开，而不是把一条僵尸 run 当成进行中的复测。
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime
from pathlib import Path

from vulnclaw.config.domain_models import (
    RetestRecord,
    RetestStatus,
    RetestVerdict,
)
from vulnclaw.utils.atomic_write import atomic_write_text, file_lock
from vulnclaw.utils.fs_names import safe_name_component

SCHEMA_VERSION = 1
RETEST_DIR_ENV = "VULNCLAW_RETEST_DIR"
VALID_VERDICTS: tuple[str, ...] = tuple(v.value for v in RetestVerdict)


class RetestStoreError(ValueError):
    """Base class for retest-store failures (all are caller-visible ValueErrors)."""


class RetestNotFoundError(RetestStoreError):
    """No retest session exists for this finding."""


class RetestConflictError(RetestStoreError):
    """The request contradicts the one-session / first-round-only invariants."""


class RetestStoreCorruptError(RetestStoreError):
    """A store file exists but cannot be parsed — named rather than silently emptied."""


def retest_root(override: str | Path | None = None) -> Path:
    """Where retest sessions live: explicit ``override`` > ``$VULNCLAW_RETEST_DIR`` > config dir."""

    if override is not None:
        return Path(override)
    env = os.environ.get(RETEST_DIR_ENV)
    if env:
        return Path(env)
    from vulnclaw.config.settings import CONFIG_DIR

    return CONFIG_DIR / "retests"


def _stamp(now: datetime | None = None) -> str:
    return (now or datetime.now()).isoformat()


class RetestStore:
    """File-backed store of :class:`RetestRecord` sessions keyed by ``finding_id``."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = retest_root(root)

    # ── paths ────────────────────────────────────────────────────────────────

    def _path(self, finding_id: str) -> Path:
        """One stable file per finding; the digest keeps sanitised collisions apart."""

        raw = str(finding_id)
        stem = safe_name_component(raw, fallback="finding")
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]
        return self.root / f"{stem}-{digest}.json"

    def _lock_path(self, finding_id: str) -> Path:
        return self._path(finding_id).with_suffix(".lock")

    # ── read ─────────────────────────────────────────────────────────────────

    def history(self, finding_id: str) -> list[RetestRecord]:
        """Every recorded round for ``finding_id``, oldest first (empty when never retested)."""

        path = self._path(finding_id)
        if not path.exists():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RetestStoreCorruptError(
                f"retest store file is unreadable: {path} ({exc})"
            ) from exc
        records = payload.get("records") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            raise RetestStoreCorruptError(
                f"retest store file has no records list: {path}"
            )
        return [RetestRecord.model_validate(entry) for entry in records]

    def active(self, finding_id: str) -> RetestRecord | None:
        """The one running record, if any."""

        for record in self.history(finding_id):
            if record.status is RetestStatus.RUNNING:
                return record
        return None

    def latest(self, finding_id: str) -> RetestRecord | None:
        history = self.history(finding_id)
        return history[-1] if history else None

    def all_records(self) -> list[RetestRecord]:
        """Every record on disk (newest finding file first is not guaranteed; sorted by time)."""

        records: list[RetestRecord] = []
        if not self.root.exists():
            return records
        for path in sorted(self.root.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise RetestStoreCorruptError(
                    f"retest store file is unreadable: {path} ({exc})"
                ) from exc
            for entry in payload.get("records") or []:
                records.append(RetestRecord.model_validate(entry))
        records.sort(key=lambda r: (r.created_at, r.round))
        return records

    # ── write ────────────────────────────────────────────────────────────────

    def _write(self, finding_id: str, records: list[RetestRecord]) -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "finding_id": str(finding_id),
            "records": [r.model_dump(mode="json") for r in records],
        }
        atomic_write_text(
            self._path(finding_id),
            json.dumps(payload, ensure_ascii=False, indent=2),
        )

    def start(
        self,
        finding_id: str,
        *,
        snapshot: dict | None = None,
        now: datetime | None = None,
    ) -> RetestRecord:
        """Open (or return) the finding's retest session.

        Idempotent: a finding with any existing record gets that record back — the
        snapshot taken at the first start is never re-taken, so a finding edited
        mid-retest cannot move the basis of the round in flight.
        """

        with file_lock(self._lock_path(finding_id)):
            records = self.history(finding_id)
            if records:
                return records[-1]
            stamp = _stamp(now)
            record = RetestRecord(
                retest_id=f"rt-{uuid.uuid4().hex[:12]}",
                finding_id=str(finding_id),
                round=1,
                status=RetestStatus.RUNNING,
                snapshot=dict(snapshot or {}),
                created_at=stamp,
                updated_at=stamp,
            )
            self._write(finding_id, [record])
            return record

    def conclude(
        self,
        finding_id: str,
        *,
        verdict: str,
        note: str = "",
        now: datetime | None = None,
    ) -> RetestRecord:
        """Write the round-1 verdict. Overwriting an existing verdict is refused."""

        if verdict not in VALID_VERDICTS:
            # RetestStoreError, not a bare ValueError: the CLI catches the store's
            # error family and turns it into a one-line message, so a mistyped
            # ``--verdict`` must arrive as one of its members. A bare ValueError
            # passes through to the user as a raw traceback.
            raise RetestStoreError(
                f"unknown retest verdict {verdict!r}; expected one of {VALID_VERDICTS}"
            )
        with file_lock(self._lock_path(finding_id)):
            records = self.history(finding_id)
            if not records:
                raise RetestNotFoundError(f"no retest session for finding {finding_id!r}")
            active = next((r for r in records if r.status is RetestStatus.RUNNING), None)
            if active is None:
                raise RetestConflictError(
                    f"retest for finding {finding_id!r} is already concluded"
                )
            if active.round != 1:
                raise RetestConflictError(
                    "only the first round can carry a verdict; "
                    f"round {active.round} is a follow-up"
                )
            stamp = _stamp(now)
            active.status = RetestStatus.COMPLETED
            active.verdict = verdict
            active.note = note
            active.updated_at = stamp
            active.completed_at = stamp
            self._write(finding_id, records)
            return active

    def follow_up(
        self,
        finding_id: str,
        *,
        question: str = "",
        now: datetime | None = None,
    ) -> RetestRecord:
        """Append a follow-up round. Follow-ups record, they never re-decide."""

        with file_lock(self._lock_path(finding_id)):
            records = self.history(finding_id)
            if not records:
                raise RetestNotFoundError(f"no retest session for finding {finding_id!r}")
            stamp = _stamp(now)
            record = RetestRecord(
                retest_id=f"rt-{uuid.uuid4().hex[:12]}",
                finding_id=str(finding_id),
                round=len(records) + 1,
                status=RetestStatus.COMPLETED,
                note=question,
                snapshot=dict(records[-1].snapshot),
                created_at=stamp,
                updated_at=stamp,
                completed_at=stamp,
            )
            self._write(finding_id, [*records, record])
            return record

    def stop_orphans(self, *, now: datetime | None = None) -> list[str]:
        """Seal leftover running sessions as ``stopped``; returns the affected finding ids."""

        stamped: list[str] = []
        if not self.root.exists():
            return stamped
        for path in sorted(self.root.glob("*.json")):
            with file_lock(path.with_suffix(".lock")):
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    raise RetestStoreCorruptError(
                        f"retest store file is unreadable: {path} ({exc})"
                    ) from exc
                records = [
                    RetestRecord.model_validate(entry) for entry in (payload.get("records") or [])
                ]
                touched = False
                for record in records:
                    if record.status is RetestStatus.RUNNING:
                        record.status = RetestStatus.STOPPED
                        record.updated_at = _stamp(now)
                        touched = True
                if touched:
                    finding_id = str(payload.get("finding_id") or "")
                    self._write(finding_id, records)
                    stamped.append(finding_id)
        return stamped
