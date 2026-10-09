"""VulnClaw-owned, sandbox-native HTTP traffic evidence store.

A single capture layer (mitmproxy addon + headless Playwright, plus optional
Burp / chrome-devtools overlays) writes every in-scope request/response to an
append-only JSONL index plus raw blob files under ``evidence/traffic/``.

That capture log is per-run and reclaimable, so it is *not* where a finding's
proof may live. Findings cite a capture through a **pinned snapshot**
(:class:`EvidenceStore`): an immutable, content-addressed copy under
``evidence/blobs/`` plus a metadata row in ``evidence/snapshots.jsonl``, with the
role that says whether the reader is looking at the control request or the one
that proved the bug. ``request_id`` keeps working for refs bound before pinning
existed, and the report generator resolves pinned first, capture log second --
reporting an unresolvable binding explicitly instead of dropping it.
"""

from __future__ import annotations

from vulnclaw.traffic.binding import (
    BindOutcome,
    EvidenceBindError,
    bind_finding_evidence,
    parse_binding_specs,
    reorder_finding_evidence,
    unbind_finding_evidence,
)
from vulnclaw.traffic.capture import TrafficCapture
from vulnclaw.traffic.evidence import (
    EvidenceIntegrityError,
    EvidenceNotFound,
    EvidencePinError,
    EvidenceSnapshot,
    EvidenceStore,
    compute_snapshot_id,
)
from vulnclaw.traffic.models import (
    SOURCE_BROWSER,
    SOURCE_MANUAL_REPLAY,
    SOURCE_PROXY,
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
    ScopeMode,
    Target,
    TrafficRecord,
)
from vulnclaw.traffic.scope import ScopeChecker
from vulnclaw.traffic.store import TrafficStore, compute_request_id

__all__ = [
    "TrafficCapture",
    "TrafficStore",
    "ScopeChecker",
    "ScopeMode",
    "Target",
    "CapturedExchange",
    "CapturedRequest",
    "CapturedResponse",
    "TrafficRecord",
    "compute_request_id",
    "SOURCE_PROXY",
    "SOURCE_BROWSER",
    "SOURCE_MANUAL_REPLAY",
    # ── pinned evidence ──────────────────────────────────────────────────
    "EvidenceStore",
    "EvidenceSnapshot",
    "compute_snapshot_id",
    "EvidenceBindError",
    "EvidenceIntegrityError",
    "EvidenceNotFound",
    "EvidencePinError",
    # ── binding ──────────────────────────────────────────────────────────
    "BindOutcome",
    "bind_finding_evidence",
    "unbind_finding_evidence",
    "reorder_finding_evidence",
    "parse_binding_specs",
]
