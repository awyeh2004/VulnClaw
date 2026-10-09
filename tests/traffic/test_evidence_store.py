"""The pinned-evidence store: durability, content addressing, verification, GC.

The property these tests exist to protect is the one the capture log cannot
offer: once an exchange is pinned, the finding's proof is independent of
``evidence/traffic/`` and can be verified byte-for-byte on every read.
"""

from __future__ import annotations

import hashlib
import os
import shutil

import pytest

from vulnclaw.traffic.evidence import (
    EvidenceIntegrityError,
    EvidenceNotFound,
    EvidencePinError,
    EvidenceStore,
    compute_snapshot_id,
    split_head_body,
)
from vulnclaw.traffic.models import CapturedExchange, CapturedRequest, CapturedResponse
from vulnclaw.traffic.serialization import raw_request_bytes, raw_response_bytes
from vulnclaw.traffic.store import TrafficStore

SQLI_BODY = b'{"username":"admin\' -- ","password":"x"}'
ERROR_BODY = b"<html>SQL syntax error near '\"'</html>"


def _raw_request(exchange: CapturedExchange) -> bytes:
    """The stored request blob verbatim: head + body, as captured.

    Evidence is stored as the *complete* raw message (not the bare body) so a
    reviewer sees the request line and headers that made the exchange what it
    was -- ``split_head_body`` is what separates them for the index.
    """
    return raw_request_bytes(exchange.request)


def _raw_response(exchange: CapturedExchange) -> bytes:
    assert exchange.response is not None
    return raw_response_bytes(exchange.response)


def _exchange(
    url: str = "https://app.test/login",
    *,
    method: str = "POST",
    body: bytes = SQLI_BODY,
    status: int = 500,
    response_body: bytes | None = ERROR_BODY,
) -> CapturedExchange:
    return CapturedExchange(
        request=CapturedRequest(
            method=method,
            url=url,
            headers={"Host": "app.test", "Content-Type": "application/json"},
            body=body,
        ),
        response=(
            None
            if response_body is None
            else CapturedResponse(
                status=status,
                reason="Internal Server Error",
                headers={"Content-Type": "text/html; charset=utf-8", "Server": "nginx"},
                body=response_body,
            )
        ),
    )


def _stores(tmp_path):
    """A capture store and the pinned-evidence store that sits beside it."""
    root = tmp_path / "evidence"
    return TrafficStore(root / "traffic"), EvidenceStore(root), root


# ── durability: the reason the layer exists ─────────────────────────────────


def test_pinned_evidence_outlives_the_capture_log(tmp_path):
    traffic, evidence, root = _stores(tmp_path)
    exchange = _exchange()
    record = traffic.record(exchange, source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)

    # Reclaim the capture log entirely -- the pinned copy must be unaffected.
    shutil.rmtree(root / "traffic")

    assert evidence.request_body(snapshot.snapshot_id) == _raw_request(exchange)
    assert evidence.response_body(snapshot.snapshot_id) == _raw_response(exchange)
    assert ERROR_BODY.decode() in evidence.response_text(snapshot.snapshot_id)


# ── identity and idempotency ────────────────────────────────────────────────


def test_pin_is_idempotent_and_writes_one_index_row(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")

    first = evidence.pin(traffic, record.request_id)
    second = evidence.pin(traffic, record.request_id)

    assert first.snapshot_id == second.snapshot_id
    assert len(evidence.entries()) == 1


def test_two_captures_of_the_same_request_are_distinct_snapshots(tmp_path):
    """A re-issued request must not overwrite the original's evidence."""
    traffic, evidence, _ = _stores(tmp_path)
    first = traffic.record(_exchange(), source="proxy")
    second = traffic.record(_exchange(), source="manual-replay")

    snap_a = evidence.pin(traffic, first.request_id)
    snap_b = evidence.pin(traffic, second.request_id)

    assert snap_a.snapshot_id != snap_b.snapshot_id
    assert snap_a.source_request_id != snap_b.source_request_id
    assert len(evidence.entries()) == 2


def test_identical_bodies_are_stored_once(tmp_path):
    """Content addressing: the same bytes never occupy two files."""
    traffic, evidence, _ = _stores(tmp_path)
    first = traffic.record(_exchange(), source="proxy")
    duplicate = traffic.record(_exchange(), source="browser")

    snap_a = evidence.pin(traffic, first.request_id)
    snap_b = evidence.pin(traffic, duplicate.request_id)

    assert snap_a.request_sha256 == snap_b.request_sha256
    assert snap_a.response_sha256 == snap_b.response_sha256
    # one request blob + one response blob, despite two snapshots
    assert len(evidence.blob_digests()) == 2


def test_snapshot_id_is_derived_from_content_not_time(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")

    early = evidence.pin(traffic, record.request_id, pinned_at=1.0)
    late = evidence.pin(traffic, record.request_id, pinned_at=999_999.0)

    assert early.snapshot_id == late.snapshot_id
    assert early.pinned_at == 1.0  # the stored row keeps the first pin's time


def test_compute_snapshot_id_ignores_response_identity_when_absent():
    base = dict(
        source_request_id="abc",
        method="GET",
        url="https://app.test/",
        status=0,
        request_sha256="r",
        response_sha256="",
        response_present=False,
    )
    assert compute_snapshot_id(**base) == compute_snapshot_id(**base)
    assert compute_snapshot_id(**base) != compute_snapshot_id(**{**base, "response_present": True})

# ── metadata derived from the raw message ───────────────────────────────────


def test_head_is_split_from_body_and_stays_readable(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)

    assert snapshot.request_head.splitlines()[0] == "POST /login HTTP/1.1"
    assert "Host: app.test" in snapshot.request_head
    # the head must not drag the body along -- it is what the index stores
    assert SQLI_BODY.decode() not in snapshot.request_head
    assert snapshot.response_head.splitlines()[0] == "HTTP/1.1 500 Internal Server Error"


def test_split_head_body_tolerates_lf_only_messages():
    raw = b"GET / HTTP/1.1\nHost: a\n\nbody"
    head, body = split_head_body(raw)
    assert head == "GET / HTTP/1.1\nHost: a"
    assert body == b"body"


def test_content_type_is_extracted_case_insensitively(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)
    assert snapshot.content_type == "text/html; charset=utf-8"


def test_capture_without_a_response_is_pinned_as_request_only(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(response_body=None), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)

    assert snapshot.response_present is False
    assert evidence.response_body(snapshot.snapshot_id) == b""
    assert evidence.response_text(snapshot.snapshot_id) == ""


# ── integrity is verified on read, never repaired ───────────────────────────


def test_tampered_blob_is_refused_rather_than_served(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)

    evidence._blob_path(snapshot.response_sha256).write_bytes(b"something else")
    with pytest.raises(EvidenceIntegrityError):
        evidence.response_body(snapshot.snapshot_id)


def test_truncated_blob_is_refused(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)

    path = evidence._blob_path(snapshot.request_sha256)
    path.write_bytes(path.read_bytes()[:-5])
    with pytest.raises(EvidenceIntegrityError):
        evidence.request_body(snapshot.snapshot_id)


def test_deleted_blob_is_reported_as_an_integrity_failure(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)

    evidence._blob_path(snapshot.response_sha256).unlink()
    with pytest.raises(EvidenceIntegrityError):
        evidence.response_body(snapshot.snapshot_id)


def test_malformed_digest_is_rejected_not_used_as_a_path(tmp_path):
    _, evidence, _ = _stores(tmp_path)
    with pytest.raises(EvidenceIntegrityError):
        evidence._blob_path("../../etc/passwd")


# ── errors ──────────────────────────────────────────────────────────────────


def test_unknown_request_id_cannot_be_pinned(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    with pytest.raises(EvidencePinError):
        evidence.pin(traffic, "deadbeefdeadbeef")


def test_unknown_snapshot_id_raises(tmp_path):
    _, evidence, _ = _stores(tmp_path)
    with pytest.raises(EvidenceNotFound):
        evidence.request_body("nope")


# ── retention ───────────────────────────────────────────────────────────────


def _age_blob(evidence: EvidenceStore, digest: str, *, mtime: float) -> None:
    """Backdate a blob so the GC's mtime-based grace window is deterministic.

    ``collect`` judges an unreferenced blob by its file mtime -- the last time it
    was written -- because the file store has nowhere else to record when a blob
    became unreferenced. Tests must therefore set the mtime rather than rely on
    the wall clock.
    """
    os.utime(evidence._blob_path(digest), (mtime, mtime))


def test_collect_keeps_referenced_blobs_regardless_of_age(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id, pinned_at=1.0)

    # Age every blob far past any grace window: references still protect them.
    for digest in (snapshot.request_sha256, snapshot.response_sha256):
        _age_blob(evidence, digest, mtime=1.0)

    assert evidence.collect(now=10**9, grace_seconds=3600) == []
    assert evidence.request_body(snapshot.snapshot_id) == _raw_request(_exchange())


def test_collect_spares_an_orphan_inside_the_grace_window(tmp_path):
    """A report generated moments after a re-bind must still find its evidence."""
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    evidence.pin(traffic, record.request_id, pinned_at=100.0)

    # Forge an unreferenced blob, as a re-bind would leave behind.
    orphan = hashlib.sha256(b"orphan body").hexdigest()
    evidence._write_blob(b"orphan body")
    _age_blob(evidence, orphan, mtime=100.0 + 60)

    assert evidence.collect(now=100.0 + 120, grace_seconds=3600) == []
    assert evidence._blob_path(orphan).exists()


def test_collect_removes_an_orphan_past_the_grace_window(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id, pinned_at=100.0)

    orphan = hashlib.sha256(b"orphan body").hexdigest()
    evidence._write_blob(b"orphan body")
    _age_blob(evidence, orphan, mtime=100.0)

    removed = evidence.collect(now=100.0 + 10**6, grace_seconds=3600)

    assert removed == [orphan]
    assert not evidence._blob_path(orphan).exists()
    # the referenced evidence is untouched
    assert evidence.response_body(snapshot.snapshot_id) == _raw_response(_exchange())


# ── export ──────────────────────────────────────────────────────────────────


def test_export_writes_a_self_contained_bundle(tmp_path):
    import json

    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)
    traffic_dir = traffic.base_dir

    # Pin first, then lose the capture log: the bundle must still be complete.
    shutil.rmtree(traffic_dir)
    dest = evidence.export(snapshot.snapshot_id, tmp_path / "bundle")

    assert {p.name for p in dest.iterdir()} == {
        "manifest.json",
        "request.http",
        "request.bin",
        "response.http",
        "response.bin",
    }
    assert (dest / "request.bin").read_bytes() == _raw_request(_exchange())
    assert (dest / "response.bin").read_bytes() == _raw_response(_exchange())
    assert "POST /login HTTP/1.1" in (dest / "request.http").read_text(encoding="utf-8")
    assert ERROR_BODY.decode() in (dest / "response.http").read_text(encoding="utf-8")

    manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["snapshot_id"] == snapshot.snapshot_id
    assert manifest["request_sha256"] == snapshot.request_sha256
    assert manifest["url"] == "https://app.test/login"


def test_export_http_mirrors_the_stored_bytes_exactly(tmp_path):
    """``.http`` is the same message, not a lossy re-rendering.

    Round-2 (2026-10-09) regression: the writer rebuilt the message from
    head + body, which duplicated the head (the whole message was handed over as
    the body) and let the Windows newline translation turn every CRLF the head
    already contained into CRCRLF -- two ways for a bundle's readable copy to
    disagree with its own bytes.
    """
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)

    dest = evidence.export(snapshot.snapshot_id, tmp_path / "bundle")

    assert (dest / "request.http").read_bytes() == (dest / "request.bin").read_bytes()
    assert (dest / "response.http").read_bytes() == (dest / "response.bin").read_bytes()
    # the message is written once, and it is the verified blob
    assert (dest / "request.bin").read_bytes() == _raw_request(_exchange())
    assert (dest / "request.http").read_bytes().count(b"HTTP/1.1") == 1
    assert b"\r\r\n" not in (dest / "request.http").read_bytes()


def test_export_refuses_corrupted_evidence(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)
    evidence._blob_path(snapshot.response_sha256).write_bytes(b"tampered")

    with pytest.raises(EvidenceIntegrityError):
        evidence.export(snapshot.snapshot_id, tmp_path / "bundle")


def test_export_of_request_only_snapshot_omits_the_response_files(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(response_body=None), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)

    dest = evidence.export(snapshot.snapshot_id, tmp_path / "bundle")
    names = {p.name for p in dest.iterdir()}
    assert "response.bin" not in names
    assert "request.bin" in names


# ── index robustness (audit 2026-10-08: items 2 and 5) ──────────────────────


def test_a_row_appended_twice_is_read_once(tmp_path):
    """Two interleaved pins can land the same content-derived row twice."""
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)

    # Simulate the racing writer: the same row appended a second time.
    row = evidence.index_path.read_text(encoding="utf-8").strip()
    with evidence.index_path.open("a", encoding="utf-8") as handle:
        handle.write(row + "\n")

    assert [r["snapshot_id"] for r in evidence.entries()] == [snapshot.snapshot_id]
    assert len(evidence.snapshots()) == 1


def test_index_problems_names_the_lines_that_were_dropped(tmp_path):
    """A silently dropped row looks exactly like one that was never written."""
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    evidence.pin(traffic, record.request_id)

    with evidence.index_path.open("a", encoding="utf-8") as handle:
        handle.write("{not json\n")
        handle.write("\n")  # a blank line is not a problem

    problems = evidence.index_problems()
    assert len(problems) == 1
    assert problems[0]["line"] == 2
    assert "{not json" in problems[0]["snippet"]
    # entries() still yields the good row -- corruption must not hide it
    assert len(evidence.entries()) == 1


def test_index_problems_is_empty_for_a_healthy_store(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    evidence.pin(traffic, record.request_id)

    assert evidence.index_problems() == []


# ── retention tolerates foreign files (audit item 4) ────────────────────────


def test_blob_digests_ignores_names_the_store_never_wrote(tmp_path):
    """A stray ``*.bin`` used to make collect() raise on an unrelated file."""
    traffic, evidence, _ = _stores(tmp_path)
    record = traffic.record(_exchange(), source="proxy")
    snapshot = evidence.pin(traffic, record.request_id)

    prefix_dir = next(p for p in evidence.blobs_dir.iterdir() if p.is_dir())
    nested = prefix_dir / "not.a.digest.bin"  # stem is "not.a.digest"
    upper = prefix_dir / "ABCDEF.bin"
    nested.write_bytes(b"foreign")
    upper.write_bytes(b"foreign")

    digests = evidence.blob_digests()
    assert "not.a.digest" not in digests
    assert "ABCDEF" not in digests
    assert snapshot.request_sha256 in digests

    removed = evidence.collect(now=10**12, grace_seconds=0)

    assert removed == []
    # the foreign files are not ours to delete
    assert nested.exists()
    assert upper.exists()
    # and the referenced evidence survived
    assert evidence.response_body(snapshot.snapshot_id) == _raw_response(_exchange())
