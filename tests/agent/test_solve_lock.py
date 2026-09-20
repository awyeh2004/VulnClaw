"""Single-instance solve lock: staleness, PID reuse and atomic acquisition.

The lock is a "read JSON → check pid → overwrite" file, which has three classic
failure modes: a recycled PID pins the lock forever, two processes can both pass
the staleness check (TOCTOU), and on Windows an elevated holder looks dead
because OpenProcess returns ACCESS_DENIED rather than a handle.
"""

from __future__ import annotations

import json
import os

import pytest

from vulnclaw.agent import solver


@pytest.fixture()
def lock_dir(tmp_path, monkeypatch):
    """Redirect the lock file into tmp_path (CONFIG_DIR is outside the repo)."""
    monkeypatch.setattr(
        solver,
        "_solve_lock_path",
        lambda target: tmp_path / (solver.hashlib.sha1(
            (target or "").encode("utf-8")).hexdigest()[:16] + ".lock"),
    )
    return tmp_path


TARGET = "http://lock-test.invalid"

# Beyond any reachable pid_max (Linux caps at 4194304, Windows pids are far
# lower), so "no such process" is guaranteed on every platform.
DEAD_PID = 2**31 - 2


def _write(path, payload):
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload),
                    encoding="utf-8")


def test_free_lock_is_acquired_and_released(lock_dir):
    path = solver._solve_lock_path(TARGET)
    assert solver._acquire_solve_lock(TARGET) is None
    assert path.exists()
    info = json.loads(path.read_text(encoding="utf-8"))
    assert info["pid"] == os.getpid()
    assert info["target"] == TARGET
    solver._release_solve_lock(TARGET)
    assert not path.exists()


def test_release_does_not_remove_someone_elses_lock(lock_dir):
    path = solver._solve_lock_path(TARGET)
    _write(path, {"pid": os.getpid() + 1, "target": TARGET})
    solver._release_solve_lock(TARGET)
    assert path.exists()


def test_live_foreign_holder_blocks_acquisition(lock_dir):
    path = solver._solve_lock_path(TARGET)
    ppid = os.getppid()
    if ppid <= 0:
        pytest.skip("no parent pid available")
    _write(path, {"pid": ppid, "start": solver._process_start_token(ppid) or "",
                  "target": TARGET, "started": "12:00:00"})
    holder = solver._acquire_solve_lock(TARGET)
    assert holder is not None
    assert holder["pid"] == ppid
    assert holder["started"] == "12:00:00"


def test_dead_holder_is_replaced(lock_dir):
    path = solver._solve_lock_path(TARGET)
    _write(path, {"pid": DEAD_PID, "start": "", "target": TARGET})
    assert solver._acquire_solve_lock(TARGET) is None
    assert json.loads(path.read_text(encoding="utf-8"))["pid"] == os.getpid()


def test_recycled_pid_is_treated_as_stale(lock_dir):
    """Same live pid, different creation time ⇒ the recorded holder is gone."""
    assert solver._lock_is_stale({"pid": os.getpid(), "start": "1"}) is True


def test_matching_start_token_is_not_stale():
    token = solver._process_start_token(os.getpid())
    if not token:
        pytest.skip("no process start token on this platform")
    assert solver._lock_is_stale({"pid": os.getpid(), "start": token}) is False


def test_legacy_lock_without_start_token_falls_back_to_liveness():
    """Locks written before the start token existed must stay respected."""
    assert solver._lock_is_stale({"pid": os.getpid()}) is False


def test_corrupt_lock_is_self_healed(lock_dir):
    path = solver._solve_lock_path(TARGET)
    _write(path, "not json at all")
    assert solver._acquire_solve_lock(TARGET) is None
    assert json.loads(path.read_text(encoding="utf-8"))["pid"] == os.getpid()


def test_malformed_pid_is_stale():
    assert solver._lock_is_stale({"pid": 0}) is True
    assert solver._lock_is_stale({}) is True


def test_own_lock_is_reacquirable(lock_dir):
    """A second solve in the same process must not deadlock on its own lock."""
    assert solver._acquire_solve_lock(TARGET) is None
    assert solver._acquire_solve_lock(TARGET) is None


def test_pid_alive_basics():
    assert solver._pid_alive(0) is False
    assert solver._pid_alive(-1) is False
    assert solver._pid_alive(os.getpid()) is True
    assert solver._pid_alive(DEAD_PID) is False


def test_process_start_token_is_stable_for_self():
    first = solver._process_start_token(os.getpid())
    second = solver._process_start_token(os.getpid())
    assert first == second
    assert solver._process_start_token(0) is None
