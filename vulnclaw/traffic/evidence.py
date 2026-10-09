"""Immutable, content-addressed evidence snapshots, separate from the capture log.

Why this exists
---------------
``evidence/traffic/`` is a *capture log*: append-only, per-run, and disposable.
Findings used to cite it directly through ``EvidenceRef.request_id``, which meant
a report's proof lived in the one directory that is safe to reclaim. Three
concrete failures followed from that:

1. **Evidence vanished silently.** ``report.generator._render_http_captures``
   resolved each ref against the live store and ``continue``-d on a miss, so a
   cleaned-up or foreign-run capture produced no output at all -- the reader
   cannot tell "this finding has no captured proof" from "the proof was
   dropped".
2. **Nothing could write a ref.** ``EvidenceRef``/``http_capture`` was modelled,
   exported to SARIF and rendered, but no tool ever *created* one, so the whole
   path was read-only dead code.
3. **A report could cite evidence it never read.** Bodies were re-read at render
   time with no version, so evidence changing between verification and reporting
   went unnoticed.

This module fixes (1) for real: pinning copies a captured exchange into an
immutable, content-addressed blob store under ``evidence/blobs/`` and records a
small metadata row in ``evidence/snapshots.jsonl``. The copy is what makes a
finding's proof outlive the capture log. Layout, deliberately mirroring the
capture store's append-only idiom (no DB):

    <evidence_root>/
      traffic/                     capture log (reclaimable, unchanged)
        requests.jsonl
        <request_id>/{request,response}
      snapshots.jsonl              pinned evidence index (append-only)
      blobs/<sha[:2]>/<sha>.bin    bodies, addressed by content

Content addressing does two things beyond durability: identical bodies captured
twice occupy one file, and :meth:`EvidenceStore.request_body` can *verify* what
it read against the hash recorded at pin time, which is what lets the renderer
report corruption instead of printing a plausible-looking body that is not the
one that was verified.

Integrity is checked on read, never repaired: a mismatch raises, because a
report that silently substitutes different bytes is worse than one that fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnclaw.utils.atomic_write import (
    append_line_durable,
    atomic_write_text,
    mkdtemp_sibling,
    replace_with_retry,
)

#: Append-only index of pinned snapshots, sibling to the ``traffic/`` capture log.
SNAPSHOTS_FILENAME = "snapshots.jsonl"
#: Content-addressed body store.
BLOBS_SUBDIR = "blobs"
#: Suffix used for the exported byte-for-byte copies.
_BLOB_SUFFIX = ".bin"
#: How long an unreferenced blob survives before :meth:`EvidenceStore.collect`
#: may delete it. Long enough that a report generated right after a finding was
#: edited or merged still resolves its evidence.
DEFAULT_GRACE_SECONDS = 24 * 60 * 60

#: Header/body delimiter in the raw blobs written by
#: :mod:`vulnclaw.traffic.serialization`.
_HEAD_SEP = b"\r\n\r\n"
_HEAD_SEP_LF = b"\n\n"


class EvidenceError(RuntimeError):
    """Base class for evidence-store failures."""


class EvidencePinError(EvidenceError):
    """A captured exchange could not be pinned (unknown id, or no request blob)."""


class EvidenceNotFound(EvidenceError):
    """No snapshot with that id is recorded in the index."""


class EvidenceIntegrityError(EvidenceError):
    """A stored body does not match the hash/length recorded at pin time."""


def is_valid_blob_digest(value: str) -> bool:
    """True when ``value`` is a name this store could have written.

    Blobs are named by the lower-case hex sha256 of their bytes. Anything else
    sitting under ``blobs/`` is foreign -- a stray ``foo.bin.bin`` (whose stem is
    ``foo.bin``), an upper-case name, an editor backup -- and retention walks the
    directory rather than the index, so it has to tell the two apart instead of
    raising on a file that was never ours.
    """
    return len(value) >= 2 and all(c in "0123456789abcdef" for c in value)


def split_head_body(raw: bytes) -> tuple[str, bytes]:
    """Split a raw HTTP blob into its (decoded) head and its body.

    Only the head is kept in the index -- it is what a reader needs to see the
    request line, headers and status without loading a body that may be
    megabytes. The body is addressed by hash instead.
    """
    head, sep, body = raw.partition(_HEAD_SEP)
    if not sep:
        head, _, body = raw.partition(_HEAD_SEP_LF)
    return head.decode("utf-8", "replace"), body


def compute_snapshot_id(
    *,
    source_request_id: str,
    method: str,
    url: str,
    status: int,
    request_sha256: str,
    response_sha256: str,
    response_present: bool,
) -> str:
    """Deterministic snapshot id over the *content* identity of a capture.

    ``captured_at`` / ``pinned_at`` are deliberately excluded: re-pinning the
    same capture must yield the same id so :meth:`EvidenceStore.pin` is
    idempotent and two findings can share one snapshot. Two *different* captures
    of the same method+url will differ here because ``source_request_id`` embeds
    the capture sequence, so a re-issued request is its own snapshot rather than
    silently overwriting the original.
    """
    hasher = hashlib.sha256()
    hasher.update(f"{source_request_id}\n{method}\n{url}\n{status}\n".encode("utf-8", "replace"))
    # The presence flag is hashed explicitly rather than folded into the empty
    # string, so "no response captured" and "response captured with an empty
    # digest" cannot collide onto one snapshot id.
    hasher.update(f"{1 if response_present else 0}\n".encode("ascii"))
    hasher.update(f"{request_sha256}\n".encode("ascii"))
    hasher.update((response_sha256 if response_present else "").encode("ascii"))
    return hasher.hexdigest()[:16]


@dataclass(frozen=True)
class EvidenceSnapshot:
    """One pinned capture: content identity plus the heads needed to read it."""

    snapshot_id: str
    source_request_id: str
    #: Timestamp carried by the capture index (may be empty for legacy rows).
    captured_at: str
    #: When the snapshot was pinned; drives GC grace, not identity.
    pinned_at: float
    method: str
    url: str
    status: int
    content_type: str
    request_head: str
    response_head: str
    request_sha256: str
    response_sha256: str
    request_len: int
    response_len: int
    response_present: bool

    def to_index(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "source_request_id": self.source_request_id,
            "captured_at": self.captured_at,
            "pinned_at": self.pinned_at,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "content_type": self.content_type,
            "request_head": self.request_head,
            "response_head": self.response_head,
            "request_sha256": self.request_sha256,
            "response_sha256": self.response_sha256,
            "request_len": self.request_len,
            "response_len": self.response_len,
            "response_present": self.response_present,
        }

    @classmethod
    def from_index(cls, row: dict[str, Any]) -> "EvidenceSnapshot":
        return cls(
            snapshot_id=str(row.get("snapshot_id", "")),
            source_request_id=str(row.get("source_request_id", "")),
            captured_at=str(row.get("captured_at", "") or ""),
            pinned_at=float(row.get("pinned_at") or 0.0),
            method=str(row.get("method", "")),
            url=str(row.get("url", "")),
            status=int(row.get("status") or 0),
            content_type=str(row.get("content_type", "") or ""),
            request_head=str(row.get("request_head", "") or ""),
            response_head=str(row.get("response_head", "") or ""),
            request_sha256=str(row.get("request_sha256", "") or ""),
            response_sha256=str(row.get("response_sha256", "") or ""),
            request_len=int(row.get("request_len") or 0),
            response_len=int(row.get("response_len") or 0),
            response_present=bool(row.get("response_present")),
        )

    def describe(self) -> str:
        """One-line, display-safe summary for logs and report headers."""
        return f"{self.method} {self.url} -> {self.status}"


class EvidenceStore:
    """Read/write access to one run's pinned-evidence directory.

    ``base_dir`` is the ``evidence/`` root (the parent of ``traffic/``), so the
    blobs and the index sit beside the capture log rather than inside it -- that
    separation is what lets the capture log be reclaimed without touching
    evidence.
    """

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
        self.blobs_dir = self.base_dir / BLOBS_SUBDIR
        self.index_path = self.base_dir / SNAPSHOTS_FILENAME

    # ── blob plumbing ────────────────────────────────────────────────────
    def _blob_path(self, digest: str) -> Path:
        if not is_valid_blob_digest(digest):
            raise EvidenceIntegrityError(f"malformed blob digest: {digest!r}")
        return self.blobs_dir / digest[:2] / f"{digest}{_BLOB_SUFFIX}"

    def _atomic_write_bytes(self, path: Path, data: bytes) -> None:
        """Same-directory temp file, fsync, then a Windows-tolerant rename.

        Mirrors ``atomic_write_text``; duplicated here only because that helper
        takes ``str`` and evidence bodies are bytes.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        handle_fd, tmp_name = mkdtemp_sibling(path)
        try:
            with os.fdopen(handle_fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            replace_with_retry(tmp_name, path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _write_blob(self, data: bytes) -> str:
        """Store ``data`` by content, returning its sha256. Idempotent."""
        digest = hashlib.sha256(data).hexdigest()
        path = self._blob_path(digest)
        if not path.exists():
            self._atomic_write_bytes(path, data)
        return digest

    def _read_blob(self, digest: str, expected_len: int, *, what: str) -> bytes:
        """Read a blob and verify it against what the index recorded.

        Raises rather than repairing: a body that no longer matches the hash it
        was pinned under must never be presented as that evidence.
        """
        path = self._blob_path(digest)
        if not path.exists():
            raise EvidenceIntegrityError(f"{what} blob missing for digest {digest}")
        data = path.read_bytes()
        if len(data) != expected_len:
            raise EvidenceIntegrityError(
                f"{what} blob length mismatch: stored {len(data)}, recorded {expected_len}"
            )
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise EvidenceIntegrityError(
                f"{what} blob hash mismatch: stored {actual}, recorded {digest}"
            )
        return data

    # ── index ────────────────────────────────────────────────────────────
    def entries(self) -> list[dict[str, Any]]:
        """Every index row, in pin order, de-duplicated by snapshot id.

        A row that cannot be parsed is skipped so one truncated append cannot
        hide every good snapshot; :meth:`index_problems` is how a caller reports
        what was dropped instead of quietly losing it.

        De-duplication is exact rather than a heuristic: ``pin`` refuses to
        append a row it can already see, but that check is ``get``-then-``append``
        and not atomic across processes, so two concurrent pins of the same
        capture can interleave and land the same content-derived row twice.
        Keeping the first occurrence keeps every count a report derives from the
        index honest.
        """
        if not self.index_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        with self.index_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                snapshot_id = str(row.get("snapshot_id", "")) if isinstance(row, dict) else ""
                if snapshot_id:
                    if snapshot_id in seen:
                        continue
                    seen.add(snapshot_id)
                rows.append(row)
        return rows

    def snapshots(self) -> list[EvidenceSnapshot]:
        return [EvidenceSnapshot.from_index(row) for row in self.entries()]

    def get(self, snapshot_id: str) -> EvidenceSnapshot | None:
        for row in self.entries():
            if str(row.get("snapshot_id", "")) == snapshot_id:
                return EvidenceSnapshot.from_index(row)
        return None

    def has_index(self) -> bool:
        return self.index_path.exists()

    def index_problems(self) -> list[dict[str, Any]]:
        """Index lines that cannot be read, as ``{line, error, snippet}``.

        :meth:`entries` skips a bad line so one truncated append cannot hide
        every good snapshot. For evidence, silence is the wrong default: a row
        lost to corruption is indistinguishable from a row that was never
        written, which is the exact confusion this layer exists to end. Callers
        that present evidence (the report) use this to name what was dropped.
        """
        if not self.index_path.exists():
            return []
        problems: list[dict[str, Any]] = []
        with self.index_path.open("r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    json.loads(stripped)
                except json.JSONDecodeError as exc:
                    problems.append(
                        {"line": lineno, "error": str(exc), "snippet": stripped[:120]}
                    )
        return problems

    # ── pinning ──────────────────────────────────────────────────────────
    def pin(
        self,
        traffic_store: Any,
        request_id: str,
        *,
        pinned_at: float | None = None,
    ) -> EvidenceSnapshot:
        """Copy a captured exchange into the immutable store.

        Bodies are written *before* the index row is appended, so an index entry
        can never point at a blob that is not on disk yet. Re-pinning an
        identical capture is a no-op that returns the same snapshot.
        """
        entry = traffic_store.find(request_id)
        if entry is None:
            raise EvidencePinError(f"unknown request_id: {request_id!r}")
        request_raw = traffic_store.request_blob(request_id)
        if request_raw is None:
            raise EvidencePinError(f"capture has no request body: {request_id!r}")
        response_raw = traffic_store.response_blob(request_id)
        response_present = response_raw is not None

        request_sha = self._write_blob(request_raw)
        response_sha = self._write_blob(response_raw) if response_present else ""

        request_head, _ = split_head_body(request_raw)
        response_head = ""
        if response_present:
            response_head, _ = split_head_body(response_raw)

        snapshot = EvidenceSnapshot(
            snapshot_id=compute_snapshot_id(
                source_request_id=request_id,
                method=str(entry.get("method", "")),
                url=str(entry.get("url", "")),
                status=int(entry.get("status") or 0),
                request_sha256=request_sha,
                response_sha256=response_sha,
                response_present=response_present,
            ),
            source_request_id=request_id,
            captured_at=str(entry.get("timestamp", "") or ""),
            pinned_at=time.time() if pinned_at is None else pinned_at,
            method=str(entry.get("method", "")),
            url=str(entry.get("url", "")),
            status=int(entry.get("status") or 0),
            content_type=_content_type_from_head(response_head),
            request_head=request_head,
            response_head=response_head,
            request_sha256=request_sha,
            response_sha256=response_sha,
            request_len=len(request_raw),
            response_len=len(response_raw) if response_present else 0,
            response_present=response_present,
        )

        # Idempotent: an identical capture re-pins to the same id, so the row is
        # written once. This check is *not* atomic across processes (that is why
        # `entries()` de-duplicates on read) -- it only avoids the common
        # same-process re-pin landing a second identical line.
        if self.get(snapshot.snapshot_id) is None:
            append_line_durable(
                self.index_path,
                json.dumps(snapshot.to_index(), ensure_ascii=False) + "\n",
            )
        return snapshot

    # ── reading bodies (verified) ────────────────────────────────────────
    def _snapshot_or_raise(self, snapshot_id: str) -> EvidenceSnapshot:
        snapshot = self.get(snapshot_id)
        if snapshot is None:
            raise EvidenceNotFound(f"no snapshot {snapshot_id!r} in {self.index_path}")
        return snapshot

    def request_body(self, snapshot_id: str) -> bytes:
        snapshot = self._snapshot_or_raise(snapshot_id)
        return self._read_blob(snapshot.request_sha256, snapshot.request_len, what="request")

    def response_body(self, snapshot_id: str) -> bytes:
        snapshot = self._snapshot_or_raise(snapshot_id)
        if not snapshot.response_present:
            return b""
        return self._read_blob(snapshot.response_sha256, snapshot.response_len, what="response")

    def request_text(self, snapshot_id: str) -> str:
        """The raw request as stored -- byte-identical to the capture."""
        return self.request_body(snapshot_id).decode("utf-8", "replace")

    def response_text(self, snapshot_id: str) -> str:
        return self.response_body(snapshot_id).decode("utf-8", "replace")

    # ── retention ────────────────────────────────────────────────────────
    def blob_digests(self) -> list[str]:
        """Every digest present on disk, whether or not the index knows it.

        Non-digest names are skipped rather than returned: retention walks the
        directory to find what the index no longer needs, and a foreign file
        (``foo.bin.bin`` has the stem ``foo.bin``) is neither evidence to keep
        nor garbage to collect -- returning it made :meth:`collect` raise
        ``EvidenceIntegrityError`` out of ``_blob_path`` on a file the store
        never wrote.
        """
        if not self.blobs_dir.exists():
            return []
        digests: list[str] = []
        for prefix in sorted(self.blobs_dir.iterdir()):
            if not prefix.is_dir():
                continue
            for blob in sorted(prefix.iterdir()):
                if blob.suffix != _BLOB_SUFFIX:
                    continue
                if is_valid_blob_digest(blob.stem):
                    digests.append(blob.stem)
        return digests

    def referenced_digests(self) -> set[str]:
        """Digests the index still needs, so GC cannot orphan a live snapshot."""
        needed: set[str] = set()
        for snapshot in self.snapshots():
            needed.add(snapshot.request_sha256)
            if snapshot.response_present:
                needed.add(snapshot.response_sha256)
        needed.discard("")
        return needed

    def collect(
        self,
        *,
        now: float | None = None,
        grace_seconds: float = DEFAULT_GRACE_SECONDS,
    ) -> list[str]:
        """Delete unreferenced blobs older than ``grace_seconds``; return digests.

        A digest is unreferenced when no index row needs it -- which can happen
        after a finding is re-bound or deleted. The grace window is what keeps a
        report generated moments after an edit from losing its evidence.
        """
        referenced = self.referenced_digests()
        cutoff = (time.time() if now is None else now) - grace_seconds
        removed: list[str] = []
        for digest in self.blob_digests():
            if digest in referenced:
                continue
            path = self._blob_path(digest)
            try:
                if path.stat().st_mtime > cutoff:
                    continue
            except OSError:
                continue
            try:
                path.unlink()
            except OSError:
                continue
            removed.append(digest)
        return removed

    # ── export ───────────────────────────────────────────────────────────
    def export(self, snapshot_id: str, dest_dir: str | Path) -> Path:
        """Write a self-contained evidence bundle a reviewer can replay by hand.

        Layout:

            <dest_dir>/
              manifest.json     identity, hashes, lengths, heads
              request.bin       the exact stored bytes (authoritative)
              response.bin      the exact stored bytes (when a response was captured)
              request.http      the same message, byte for byte
              response.http     the same message, byte for byte

        ``.bin`` and ``.http`` hold identical bytes; the second name exists only
        because a reviewer (or a tool that opens text) looks for an ``.http``
        file, and the stored message -- head, blank line, body -- is already
        readable. It used to be written as a *reconstruction*, which on Windows
        both duplicated the head (the whole message was passed as the body) and
        doubled every CRLF the head already contained. Copying the verified blob
        makes that class of drift impossible: there is nothing to reconstruct.

        Bodies are read through the verifying accessors, so exporting corrupted
        evidence fails rather than shipping it.
        """
        snapshot = self._snapshot_or_raise(snapshot_id)
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)

        request_body = self.request_body(snapshot_id)
        self._atomic_write_bytes(dest / "request.bin", request_body)
        manifest = snapshot.to_index()

        if snapshot.response_present:
            response_body = self.response_body(snapshot_id)
            self._atomic_write_bytes(dest / "response.bin", response_body)
        else:
            response_body = b""

        self._atomic_write_bytes(dest / "request.http", request_body)
        self._atomic_write_bytes(dest / "response.http", response_body)
        atomic_write_text(
            dest / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
        )
        return dest


def _content_type_from_head(head: str) -> str:
    """Pull ``Content-Type`` out of a raw response head (case-insensitive)."""
    for line in head.splitlines()[1:]:
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() == "content-type":
            return value.strip()
    return ""
