"""Bind captured traffic to findings as durable, ordered, role-tagged evidence.

This is the writer that was missing. ``EvidenceRef`` / ``http_capture`` was
modelled, exported to SARIF and rendered by the report generator from the start,
but no code path ever *created* one -- so the model could see a ``request_id``
from ``traffic_list`` (the tool description even promises it can "cite a capture
in a finding") and had no way to do it. The loop closes here.

Two invariants make a binding trustworthy enough to build a report on:

**All-or-nothing.** Every spec is resolved and pinned *before* the finding is
touched. One bad ``request_id`` fails the whole call and leaves the finding
exactly as it was, because a partially-applied evidence list is worse than none:
the report would render some of the proof and silently present it as all of it.
Pins that succeeded before the failure stay in the snapshot index -- they are
immutable blobs that another finding may legitimately cite, not partial business
state -- but the finding never gains a partial list.

**Append, never overwrite.** Re-binding a capture that is already bound is a
no-op that reports a duplicate rather than replacing the role or note a human
may have written. Reordering is a separate, explicit operation that must name
the complete list, so a partial list cannot silently drop evidence off the end.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from vulnclaw.config.domain_models import (
    DEFAULT_EVIDENCE_ROLE,
    EVIDENCE_ROLES,
    EvidenceRef,
    VulnerabilityFinding,
    evidence_binding_signature,
)
from vulnclaw.traffic.evidence import EvidenceError, EvidenceStore


class EvidenceBindError(EvidenceError):
    """A binding operation was rejected; the finding is unchanged."""


@dataclass(frozen=True)
class BindOutcome:
    """What a bind/unbind/reorder did, in a shape both logs and the agent can read."""

    title: str
    version: int
    added: tuple[str, ...]
    duplicates: tuple[str, ...]
    bindings: int
    signature: str

    def describe(self) -> str:
        parts = [f"evidence v{self.version} ({self.bindings} bound)"]
        if self.added:
            parts.append("added: " + ", ".join(self.added))
        if self.duplicates:
            parts.append("already bound: " + ", ".join(self.duplicates))
        return f"{self.title}: " + " | ".join(parts)


def _validate_role(role: str) -> str:
    value = str(role or DEFAULT_EVIDENCE_ROLE).strip().lower()
    if value not in EVIDENCE_ROLES:
        raise EvidenceBindError(
            f"unknown evidence role {role!r}; expected one of {', '.join(EVIDENCE_ROLES)}"
        )
    return value


def _ref_handles(ref: EvidenceRef) -> set[str]:
    """Every identifier a ref can be matched by (new and legacy shapes)."""
    handles: set[str] = set()
    if ref.snapshot_id:
        handles.add(str(ref.snapshot_id))
    if ref.request_id:
        handles.add(str(ref.request_id))
    return handles


def _bound_handles(finding: VulnerabilityFinding) -> set[str]:
    handles: set[str] = set()
    for ref in getattr(finding, "evidence_refs", None) or []:
        handles |= _ref_handles(ref)
    return handles


def bind_finding_evidence(
    finding: VulnerabilityFinding,
    *,
    traffic_store: Any,
    evidence_store: EvidenceStore,
    specs: Iterable[dict[str, Any]],
) -> BindOutcome:
    """Pin each spec's capture and append it to ``finding.evidence_refs``.

    ``specs`` is an ordered list of ``{"request_id", "role"?, "note"?}``; the
    order becomes the report's reading order and therefore part of the binding
    identity.
    """
    spec_list = list(specs or [])
    if not spec_list:
        raise EvidenceBindError("no evidence specs supplied")

    # ── resolve everything first; the finding is not touched until all pass ──
    resolved: list[tuple[Any, str, str]] = []
    failures: list[str] = []
    for spec in spec_list:
        if not isinstance(spec, dict):
            failures.append(f"malformed spec (expected object): {spec!r}")
            continue
        request_id = str(spec.get("request_id") or "").strip()
        if not request_id:
            failures.append("spec is missing request_id")
            continue
        try:
            role = _validate_role(str(spec.get("role") or DEFAULT_EVIDENCE_ROLE))
        except EvidenceBindError as exc:
            failures.append(f"{request_id}: {exc}")
            continue
        try:
            snapshot = evidence_store.pin(traffic_store, request_id)
        except EvidenceError as exc:
            failures.append(f"{request_id}: {exc}")
            continue
        resolved.append((snapshot, role, str(spec.get("note") or "").strip()))

    if failures:
        raise EvidenceBindError(
            "evidence binding rejected; the finding is unchanged. " + "; ".join(failures)
        )

    # ── apply ───────────────────────────────────────────────────────────────
    existing = list(getattr(finding, "evidence_refs", None) or [])
    bound = _bound_handles(finding)
    added_refs: list[EvidenceRef] = []
    added_ids: list[str] = []
    duplicates: list[str] = []

    for snapshot, role, note in resolved:
        if snapshot.snapshot_id in bound or snapshot.source_request_id in bound:
            duplicates.append(snapshot.snapshot_id)
            continue
        ref = EvidenceRef(
            kind="http_capture",
            request_id=snapshot.source_request_id,
            snapshot_id=snapshot.snapshot_id,
            sha256=(
                snapshot.response_sha256 if snapshot.response_present else snapshot.request_sha256
            ),
            captured_at=snapshot.captured_at or None,
            role=role,
            note=note,
        )
        added_refs.append(ref)
        added_ids.append(snapshot.snapshot_id)
        bound |= _ref_handles(ref)

    if added_refs:
        finding.evidence_refs = existing + added_refs
        finding.evidence_version = int(getattr(finding, "evidence_version", 0) or 0) + 1

    return BindOutcome(
        title=finding.title,
        version=int(getattr(finding, "evidence_version", 0) or 0),
        added=tuple(added_ids),
        duplicates=tuple(duplicates),
        bindings=len(finding.evidence_refs),
        signature=evidence_binding_signature(finding.evidence_refs),
    )


def unbind_finding_evidence(
    finding: VulnerabilityFinding,
    *,
    snapshot_id: str | None = None,
    request_id: str | None = None,
) -> BindOutcome:
    """Remove one binding by snapshot id or (legacy) request id.

    Removing a binding is destructive to the report's proof, so it requires an
    explicit identifier and bumps the version even when nothing matched -- a
    caller that asked for a change must be able to see that it was considered.
    """
    target = str(snapshot_id or request_id or "").strip()
    if not target:
        raise EvidenceBindError("unbind needs a snapshot_id or request_id")

    existing = list(getattr(finding, "evidence_refs", None) or [])
    kept = [ref for ref in existing if target not in _ref_handles(ref)]
    removed = len(existing) - len(kept)

    if removed:
        finding.evidence_refs = kept
        finding.evidence_version = int(getattr(finding, "evidence_version", 0) or 0) + 1

    return BindOutcome(
        title=finding.title,
        version=int(getattr(finding, "evidence_version", 0) or 0),
        added=(),
        duplicates=(target,) if not removed else (),
        bindings=len(kept),
        signature=evidence_binding_signature(kept),
    )


def reorder_finding_evidence(
    finding: VulnerabilityFinding,
    *,
    handles: Iterable[str],
) -> BindOutcome:
    """Reorder bindings to match ``handles``, which must name the COMPLETE list.

    A complete list is required (rather than "move X before Y") so an
    out-of-date caller fails loudly instead of silently dropping the bindings it
    did not know about. Unknown or missing handles are rejected for the same
    reason.
    """
    order = [str(h) for h in handles]
    existing = list(getattr(finding, "evidence_refs", None) or [])
    if len(order) != len(existing):
        raise EvidenceBindError(
            f"reorder must name every binding: got {len(order)}, finding has {len(existing)}"
        )

    by_handle: dict[str, EvidenceRef] = {}
    for ref in existing:
        for handle in _ref_handles(ref):
            by_handle[handle] = ref

    seen: set[int] = set()
    reordered: list[EvidenceRef] = []
    for handle in order:
        ref = by_handle.get(handle)
        if ref is None:
            raise EvidenceBindError(f"reorder names an unknown binding: {handle!r}")
        if id(ref) in seen:
            raise EvidenceBindError(f"reorder names the same binding twice: {handle!r}")
        seen.add(id(ref))
        reordered.append(ref)

    if [id(r) for r in reordered] != [id(r) for r in existing]:
        finding.evidence_refs = reordered
        finding.evidence_version = int(getattr(finding, "evidence_version", 0) or 0) + 1

    return BindOutcome(
        title=finding.title,
        version=int(getattr(finding, "evidence_version", 0) or 0),
        added=(),
        duplicates=(),
        bindings=len(reordered),
        signature=evidence_binding_signature(reordered),
    )


def parse_binding_specs(raw: Any) -> list[dict[str, Any]]:
    """Coerce an agent-supplied argument into binding specs.

    Accepts the documented ``[{"request_id", "role"?, "note"?}, ...]`` shape, and
    tolerates a bare list of id strings, because a model that has just been told
    "cite the request_id" will reach for the simplest form. Rejecting it there
    would waste a turn on a formatting detail rather than on the finding.
    """
    if raw is None:
        return []
    if isinstance(raw, (str, bytes)):
        raise EvidenceBindError("evidence specs must be a list, not a string")
    specs: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, str):
            specs.append({"request_id": item})
        elif isinstance(item, dict):
            specs.append(dict(item))
        else:
            raise EvidenceBindError(f"malformed evidence spec: {item!r}")
    return specs
