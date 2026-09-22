"""conftest .test-tmp pruning: stale sandbox entries die, fresh ones survive."""

from __future__ import annotations

import os
import time
from pathlib import Path

import conftest


def _touch(path: Path, age_hours: float):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x", encoding="utf-8")
    stamp = time.time() - age_hours * 3600
    os.utime(path, (stamp, stamp))
    os.utime(path.parent, (stamp, stamp))


def test_stale_entries_pruned_fresh_kept(tmp_path, monkeypatch):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    _touch(sandbox / "old-dir" / "f", age_hours=conftest.STALE_TEST_ROOT_HOURS + 2)
    _touch(sandbox / "old-file", age_hours=conftest.STALE_TEST_ROOT_HOURS + 2)
    _touch(sandbox / "fresh-dir" / "f", age_hours=0)
    _touch(sandbox / "fresh-file", age_hours=0)

    monkeypatch.setattr(conftest, "TEST_ROOT", sandbox)
    removed = conftest._prune_stale_test_root()

    assert removed == 2
    assert not (sandbox / "old-dir").exists()
    assert not (sandbox / "old-file").exists()
    assert (sandbox / "fresh-dir" / "f").exists()
    assert (sandbox / "fresh-file").exists()


def test_boundary_age_is_kept(tmp_path, monkeypatch):
    """Exactly-at-the-cutoff entries stay — the window must not eat borderline files."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    _touch(sandbox / "edge-file", age_hours=conftest.STALE_TEST_ROOT_HOURS - 1)

    monkeypatch.setattr(conftest, "TEST_ROOT", sandbox)
    assert conftest._prune_stale_test_root() == 0
    assert (sandbox / "edge-file").exists()
