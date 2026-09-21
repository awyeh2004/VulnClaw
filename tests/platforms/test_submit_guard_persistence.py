"""Submit-guard state must survive crashes and concurrent writers.

Round-5 review N8: the state file was written with a plain ``write_text``. A crash
mid-write truncated it, and ``_load`` treats a corrupt file as empty — which
silently *raises* the effective auto-submit budget, since the attempt counter is
what the cap is enforced against. Two processes submitting for the same key also
overwrote each other's counters.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from vulnclaw.platforms.submit_guard import SubmitGuard, _merge_entries

KEY = "gcs:exercise:10662"


def _guard(tmp_path) -> SubmitGuard:
    return SubmitGuard(state_path=tmp_path / "state.json")


def test_record_persists_and_reloads(tmp_path):
    guard = _guard(tmp_path)
    guard.record(KEY, accepted=False, flag="flag{a}")
    assert guard.attempts(KEY) == 1

    reloaded = _guard(tmp_path)
    assert reloaded.attempts(KEY) == 1
    assert reloaded.snapshot()[KEY]["last_flag"] == "flag{a}"


def test_state_file_is_valid_json_and_has_no_temp_leftovers(tmp_path):
    guard = _guard(tmp_path)
    guard.record(KEY, accepted=True, flag="flag{a}")
    raw = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert raw["entries"][KEY]["accepted"] is True
    assert list(tmp_path.glob(".submit-state-*")) == []


def test_a_truncated_state_file_is_not_produced_by_a_failed_write(tmp_path, monkeypatch):
    """The atomic path must leave the previous file intact on failure."""
    guard = _guard(tmp_path)
    guard.record(KEY, accepted=False, flag="flag{a}")
    before = (tmp_path / "state.json").read_text(encoding="utf-8")

    import os as _os

    def _boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(_os, "replace", _boom)
    guard.record(KEY, accepted=False, flag="flag{b}")
    after = (tmp_path / "state.json").read_text(encoding="utf-8")
    assert after == before, "the old state must survive a failed replace"
    assert list(tmp_path.glob(".submit-state-*")) == []


def test_merge_never_lowers_a_counter():
    disk = {KEY: {"attempts": 5, "accepted": False, "last_flag": "a"}}
    memory = {KEY: {"attempts": 2, "accepted": False, "last_flag": "b"}}
    merged = _merge_entries(disk, memory)
    assert merged[KEY]["attempts"] == 5


def test_merge_keeps_acceptance_sticky():
    disk = {KEY: {"attempts": 1, "accepted": True, "last_flag": "a"}}
    memory = {KEY: {"attempts": 1, "accepted": False, "last_flag": None}}
    assert _merge_entries(disk, memory)[KEY]["accepted"] is True


def test_merge_unions_unknown_keys():
    disk = {"ctf2:practice:1:2": {"attempts": 1, "accepted": False}}
    memory = {KEY: {"attempts": 3, "accepted": False}}
    merged = _merge_entries(disk, memory)
    assert set(merged) == {"ctf2:practice:1:2", KEY}
    assert merged[KEY]["attempts"] == 3


def test_concurrent_writers_do_not_lose_attempts(tmp_path):
    """Two guards on one file: the persisted count must not go backwards."""
    path = tmp_path / "state.json"
    first = SubmitGuard(state_path=path)
    second = SubmitGuard(state_path=path)
    first.record(KEY, accepted=False, flag="a")  # disk: 1
    second.record(KEY, accepted=False, flag="b")  # disk: 1 (local view) -> merge -> 2
    persisted = json.loads(path.read_text(encoding="utf-8"))["entries"][KEY]["attempts"]
    assert persisted == 2
    assert first.attempts(KEY) == 2 or second.attempts(KEY) == 2


_RACE_WORKER = r"""
import sys, time
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from vulnclaw.platforms.submit_guard import SubmitGuard
key = sys.argv[3]
barrier = Path(sys.argv[4])
guard = SubmitGuard(state_path=Path(sys.argv[2]))
while not barrier.exists():
    time.sleep(0.005)
for _ in range(5):
    guard.record(key, accepted=False, flag="f")
"""


def test_real_processes_serialize_their_counters(tmp_path):
    """Five processes x five attempts each must land as 25, not as one writer's 5."""
    path = tmp_path / "state.json"
    barrier = tmp_path / "go"
    root = Path(__file__).resolve().parents[2]
    workers = 5
    procs = [
        subprocess.Popen(  # noqa: S603 - fixed argv, no shell, no pipes
            [sys.executable, "-c", _RACE_WORKER, str(root), str(path), KEY, str(barrier)],
            cwd=str(root),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(workers)
    ]
    barrier.write_text("go", encoding="utf-8")
    for proc in procs:
        proc.wait(timeout=120)

    persisted = json.loads(path.read_text(encoding="utf-8"))["entries"][KEY]["attempts"]
    assert persisted == workers * 5, f"lost attempts: persisted {persisted}"


def test_guard_file_is_not_the_state_file(tmp_path):
    guard = _guard(tmp_path)
    guard.record(KEY, accepted=False, flag="a")
    assert (tmp_path / "state.json.guard").exists()


def test_guard_without_a_state_path_is_a_noop():
    guard = SubmitGuard(state_path=None)
    guard.record(KEY, accepted=False, flag="a")
    assert guard.attempts(KEY) == 1


def test_threads_do_not_corrupt_the_file(tmp_path):
    path = tmp_path / "state.json"
    guard = SubmitGuard(state_path=path)

    def worker(n: int) -> None:
        for _ in range(3):
            guard.record(f"{KEY}:{n}", accepted=False, flag="f")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert len(raw["entries"]) == 4
    _ = pytest  # keep the import explicit for clarity
