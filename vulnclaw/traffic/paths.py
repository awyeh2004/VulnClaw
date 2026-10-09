"""Resolve where the traffic evidence store lives.

Evidence is per-run: each run owns ``<run_dir>/evidence/`` -- the capture log at
``evidence/traffic`` and the pinned snapshots/blobs beside it. Resolution takes an
explicit ``run_dir`` and is deterministic: it never falls back to another run's
tree. Only when there is no run context (``run_dir is None``) does a
config-scoped default apply (overridable via ``VULNCLAW_EVIDENCE_DIR``), so
headless/CI runs still get a durable, addressable store.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vulnclaw.traffic.evidence import EvidenceStore
    from vulnclaw.traffic.store import TrafficStore

TRAFFIC_SUBDIR = "traffic"


def evidence_root() -> Path:
    override = os.environ.get("VULNCLAW_EVIDENCE_DIR")
    if override:
        return Path(override)
    from vulnclaw.config.settings import CONFIG_DIR

    return CONFIG_DIR / "evidence"


def traffic_dir(base: str | Path | None = None) -> Path:
    """Return the ``evidence/traffic`` directory for ``base`` (or the default)."""
    if base is not None:
        root = Path(base)
        # Accept either a run/evidence root or a direct traffic dir.
        if root.name == TRAFFIC_SUBDIR:
            return root
        if root.name == "evidence":
            return root / TRAFFIC_SUBDIR
        return root / "evidence" / TRAFFIC_SUBDIR
    return evidence_root() / TRAFFIC_SUBDIR


def evidence_dir(base: str | Path | None = None) -> Path:
    """Return the ``evidence/`` root that owns both the capture log and pinned evidence.

    Derived from :func:`traffic_dir` rather than duplicated, so the two can never
    disagree about where a run's evidence tree lives -- ``<evidence>/traffic`` is
    the capture log and ``<evidence>`` holds the pinned snapshots and blobs.
    """
    return traffic_dir(base).parent


def resolve_traffic_store(run_dir: str | Path | None = None) -> "TrafficStore":
    """Resolve the store the agent *writes* captures to.

    Deterministic: a given ``run_dir`` always maps to its own
    ``evidence/traffic`` (config default when ``run_dir`` is None). It never
    falls back to another run's store — a fresh run's first capture must land in
    that run's directory, not get appended to stale global evidence.
    """
    from vulnclaw.traffic.store import TrafficStore

    return TrafficStore(traffic_dir(run_dir))


def resolve_report_traffic_store(run_dir: str | Path | None = None) -> "TrafficStore":
    """Resolve the store the report generator *reads* from.

    An explicit ``run_dir`` is authoritative -- it returns that run's own store
    even when it holds no captures yet, so a report can never read another run's
    traffic (the defect this replaces: an empty run silently fell back to the
    config-scoped root and picked up a previous run's captures). Only when no run
    context exists (``run_dir is None``) is the config-scoped default used;
    ``VULNCLAW_EVIDENCE_DIR`` still overrides that default for headless/CI.
    Read-only: never affects where captures are written.
    """
    from vulnclaw.traffic.store import TrafficStore

    return TrafficStore(traffic_dir(run_dir))


def resolve_evidence_store(run_dir: str | Path | None = None) -> "EvidenceStore":
    """Resolve the pinned-evidence store the agent *writes* to.

    Deterministic, exactly like :func:`resolve_traffic_store`: a given ``run_dir``
    always maps to its own ``evidence/`` root, so a fresh run's pins never land in
    a stale global store.
    """
    from vulnclaw.traffic.evidence import EvidenceStore

    return EvidenceStore(evidence_dir(run_dir))


def resolve_report_evidence_store(run_dir: str | Path | None = None) -> "EvidenceStore":
    """Resolve the pinned-evidence store the report generator *reads* from.

    Mirrors :func:`resolve_report_traffic_store`: an explicit ``run_dir`` is
    authoritative and never falls back to the config-scoped root, so a run's
    report cannot surface another run's pinned proof. With no run context the
    config-scoped default applies (``VULNCLAW_EVIDENCE_DIR`` overridable).
    Read-only: never affects where pins are written.
    """
    from vulnclaw.traffic.evidence import EvidenceStore

    return EvidenceStore(evidence_dir(run_dir))
