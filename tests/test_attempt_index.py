"""The attempt index answers "has this machine already tried this challenge?".

Motivation, measured 2026-10-31: four challenges were never started because the
platform view only shows *solved*, and nothing on screen distinguished "never
opened" from "opened, burned 300 tool calls, gave up". ``solve-all`` could only
skip solved challenges, so an abandoned attempt got re-run from scratch.

Two things make this harder than it looks and both are pinned here:

* ``run.json`` records the *actual* target (an IP, a host, a local path), never
  the platform ref — so matching a challenge to history has to fall back to names
  recovered from each run's goal;
* most ``run.json`` files still say ``"status": "running"`` because the process
  was killed. Presence of the directory is the honest signal; the recorded
  status is reported but never used to decide "attempted".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnclaw.attempt_index import (
    AttemptIndex,
    build_index,
    partition_targets,
    summarize,
)


def _make_run(
    root: Path,
    run_name: str,
    *,
    canonical: str,
    goal: str = "",
    calls: int = 0,
    status: str = "running",
    state_key: str | None = None,
) -> Path:
    run_dir = root / run_name
    (run_dir / "targets").mkdir(parents=True, exist_ok=True)
    key = state_key or "abc1234567890abc"
    payload = {
        "schema_version": 1,
        "run_name": run_name,
        "status": status,
        "command": "solve",
        "created_at": "2026-10-31T10:00:00Z",
        "targets": [
            {
                "target_id": key,
                "state_key": key,
                "input": canonical,
                "type": "domain",
                "canonical": canonical,
            }
        ],
    }
    (run_dir / "run.json").write_text(json.dumps(payload), encoding="utf-8")
    state_dir = run_dir / "targets" / key / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "agent_state": {
            "goal": goal,
            "tool_calls": [{"tool": "fetch"}] * calls,
            "evidence": [{"id": f"e{i}"} for i in range(max(0, calls // 2))],
        }
    }
    (state_dir / "current.json").write_text(json.dumps(state), encoding="utf-8")
    return run_dir


def test_finds_a_target_by_canonical_host(tmp_path):
    _make_run(tmp_path, "run1", canonical="https://target.example.com:443/", calls=12)

    index = build_index(tmp_path)

    assert index.was_attempted("target.example.com")
    assert index.effort_for("target.example.com") == 12


def test_matches_across_scheme_and_port_spellings(tmp_path):
    """``https://h:443`` and bare ``h`` hash differently; the host pass covers it."""
    _make_run(tmp_path, "run1", canonical="https://t.example.com:443/", calls=5)

    index = build_index(tmp_path)

    assert index.was_attempted("http://t.example.com")
    assert index.was_attempted("t.example.com")


def test_finds_a_challenge_by_name_recovered_from_the_goal(tmp_path):
    """A platform ref never appears in run.json, so the name is the only link."""
    _make_run(
        tmp_path,
        "run1",
        canonical="47.105.126.181:1883",
        goal="拿下 oldsvr（MIPS64 pwn）拿到 flag。",
        calls=235,
    )

    index = build_index(tmp_path)

    assert index.was_attempted("oldsvr")
    assert index.effort_for("oldsvr") == 235


def test_name_matching_runs_both_directions(tmp_path):
    """A longer query must find a shorter recorded name, and vice versa."""
    _make_run(
        tmp_path,
        "run1",
        canonical="1.2.3.4:80",
        goal="解出 NeuronShuffle，得到 flag（由 check.py 验证通过）。",
        calls=232,
    )

    index = build_index(tmp_path)

    assert index.was_attempted("NeuronShuffle")
    assert index.was_attempted("neuronshuffle check")


def test_status_running_does_not_mean_not_attempted(tmp_path):
    """Killed runs keep ``status: running``; presence still counts as attempted."""
    _make_run(
        tmp_path, "run1", canonical="h.example.com", calls=3, status="running"
    )

    index = build_index(tmp_path)

    assert index.was_attempted("h.example.com")


def test_effort_is_zero_when_state_is_missing(tmp_path):
    """A run that wrote run.json but no state is "started", not "cheap"."""
    run_dir = tmp_path / "run1"
    (run_dir / "targets").mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_name": "run1",
                "status": "running",
                "targets": [{"canonical": "bare.example.com", "state_key": "k1"}],
            }
        ),
        encoding="utf-8",
    )

    index = build_index(tmp_path)

    assert index.was_attempted("bare.example.com")
    assert index.effort_for("bare.example.com") == 0


def test_unknown_target_is_not_attempted(tmp_path):
    _make_run(tmp_path, "run1", canonical="known.example.com", calls=1)

    index = build_index(tmp_path)

    assert not index.was_attempted("other.example.com")
    assert index.for_target("") == []


def test_broken_run_json_is_skipped_not_fatal(tmp_path):
    good = _make_run(tmp_path, "run1", canonical="good.example.com", calls=2)
    bad = tmp_path / "run2"
    bad.mkdir()
    (bad / "run.json").write_text("{not json", encoding="utf-8")

    index = build_index(tmp_path)

    assert index.was_attempted("good.example.com")
    assert len(index.attempts) == 1


def test_limit_runs_reads_newest_first(tmp_path):
    _make_run(tmp_path, "20260101T000000Z-old", canonical="old.example.com", calls=1)
    _make_run(tmp_path, "20260102T000000Z-new", canonical="new.example.com", calls=1)

    index = build_index(tmp_path, limit_runs=1)

    assert len(index.attempts) == 1
    assert index.was_attempted("new.example.com")


def test_missing_runs_dir_yields_empty_index(tmp_path):
    index = build_index(tmp_path / "does-not-exist")

    assert index.attempts == []
    assert summarize(index) == {"runs": 0, "attempts": 0, "distinct_targets": 0}


def test_partition_splits_and_reports_effort(tmp_path):
    _make_run(tmp_path, "run1", canonical="tried.example.com", calls=300)
    index = build_index(tmp_path)

    untouched, attempted, effort = partition_targets(
        ["tried.example.com", "fresh.example.com"], index
    )

    assert untouched == ["fresh.example.com"]
    assert attempted == ["tried.example.com"]
    assert effort == {"tried.example.com": 300}


def test_summary_counts_distinct_targets_not_attempts(tmp_path):
    _make_run(tmp_path, "run1", canonical="same.example.com", calls=1)
    _make_run(tmp_path, "run2", canonical="same.example.com", calls=1)

    counts = summarize(build_index(tmp_path))

    assert counts == {"runs": 2, "attempts": 2, "distinct_targets": 1}


def test_empty_index_is_safe_to_query():
    index = AttemptIndex()

    assert not index.was_attempted("anything")
    assert index.effort_for("anything") == 0