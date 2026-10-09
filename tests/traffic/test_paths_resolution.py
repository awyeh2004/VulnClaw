"""The reader's resolution order: an explicit run dir is authoritative.

The defect these guard (D2): ``resolve_report_*_store`` used to *fall back* to
the config-scoped evidence root whenever the run's own store looked empty. A run
that captured nothing therefore silently read the previous run's captures and
attributed them to its own findings. The writer side never had that fallback
(``resolve_traffic_store``/``resolve_evidence_store`` are deterministic); the
reader must not either. ``VULNCLAW_EVIDENCE_DIR`` stays as the level-2 override
for callers that genuinely have no run context (headless/CI, and the traffic
tool tests).
"""

from __future__ import annotations

from vulnclaw.traffic.evidence import SNAPSHOTS_FILENAME
from vulnclaw.traffic.paths import (
    evidence_dir,
    resolve_report_evidence_store,
    resolve_report_traffic_store,
    traffic_dir,
)
from vulnclaw.traffic.store import INDEX_FILENAME


def _seed(path, filename: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / filename).write_text("[]", encoding="utf-8")


def test_report_traffic_store_with_explicit_run_dir_does_not_leak_global(
    tmp_path, monkeypatch
) -> None:
    """A run with an empty store must NOT read another run's captures."""
    global_root = tmp_path / "cfg" / "evidence"
    _seed(global_root / "traffic", INDEX_FILENAME)  # a *previous* run's captures
    monkeypatch.setenv("VULNCLAW_EVIDENCE_DIR", str(global_root))

    run_dir = tmp_path / "runs" / "2026-10-09-scan-x"
    store = resolve_report_traffic_store(run_dir)

    assert store.base_dir == traffic_dir(run_dir)
    assert store.base_dir != global_root / "traffic"


def test_report_evidence_store_with_explicit_run_dir_does_not_leak_global(
    tmp_path, monkeypatch
) -> None:
    global_root = tmp_path / "cfg" / "evidence"
    _seed(global_root, SNAPSHOTS_FILENAME)
    monkeypatch.setenv("VULNCLAW_EVIDENCE_DIR", str(global_root))

    run_dir = tmp_path / "runs" / "2026-10-09-scan-x"
    store = resolve_report_evidence_store(run_dir)

    assert store.base_dir == evidence_dir(run_dir)
    assert store.base_dir != global_root


def test_report_store_without_run_dir_still_honors_the_env_override(
    tmp_path, monkeypatch
) -> None:
    """No run context (headless/CI) keeps the level-2 override behaviour."""
    global_root = tmp_path / "cfg" / "evidence"
    _seed(global_root / "traffic", INDEX_FILENAME)
    _seed(global_root, SNAPSHOTS_FILENAME)
    monkeypatch.setenv("VULNCLAW_EVIDENCE_DIR", str(global_root))

    assert resolve_report_traffic_store(None).base_dir == global_root / "traffic"
    assert resolve_report_evidence_store(None).base_dir == global_root


def test_explicit_run_dir_reads_the_runs_own_captures(tmp_path) -> None:
    """The happy path still finds the run's own store when it *has* content."""
    run_dir = tmp_path / "runs" / "2026-10-09-scan-y"
    _seed(traffic_dir(run_dir), INDEX_FILENAME)
    _seed(evidence_dir(run_dir), SNAPSHOTS_FILENAME)

    assert resolve_report_traffic_store(run_dir).base_dir == traffic_dir(run_dir)
    assert resolve_report_evidence_store(run_dir).base_dir == evidence_dir(run_dir)
