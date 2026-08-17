import pytest

from vulnclaw.ctf_platform.submit_guard import (
    SubmitGuard,
    guard_reason_to_message,
)


def test_guard_allows_first_auto_submits():
    guard = SubmitGuard()
    assert guard.allow("p1", "c1", "flag{one}")[0] is True
    guard.record("p1", "c1", accepted=False, flag="flag{one}")
    assert guard.allow("p1", "c1", "flag{two}")[0] is True
    guard.record("p1", "c1", accepted=False, flag="flag{two}")
    assert guard.allow("p1", "c1", "flag{three}")[0] is True


def test_guard_escalates_after_auto_limit(monkeypatch):
    monkeypatch.setenv("VULNCLAW_CTF_AUTO_SUBMIT_LIMIT", "3")
    guard = SubmitGuard()
    for _ in range(3):
        guard.record("p1", "c1", accepted=False, flag="flag{wrong}")
    allowed, reason = guard.allow("p1", "c1", "flag{next}")
    assert allowed is False
    assert "human confirmation" in reason


def test_guard_hard_limit_blocks(monkeypatch):
    monkeypatch.setenv("VULNCLAW_CTF_MAX_SUBMIT_LIMIT", "50")
    guard = SubmitGuard()
    for i in range(50):
        guard.record("p1", "c1", accepted=False, flag=f"flag{i}")
    allowed, reason = guard.allow("p1", "c1", "flag{new}")
    assert allowed is False
    assert "limit reached" in reason


def test_guard_blocks_duplicate_failed_flag():
    guard = SubmitGuard()
    guard.record("p1", "c1", accepted=False, flag="flag{same}")
    allowed, reason = guard.allow("p1", "c1", "flag{same}")
    assert allowed is False
    assert "dedup" in reason


def test_guard_stops_after_accepted():
    guard = SubmitGuard()
    guard.record("p1", "c1", accepted=True, flag="flag{good}")
    allowed, reason = guard.allow("p1", "c1", "flag{other}")
    assert allowed is False
    assert "already solved" in reason


def test_guard_counts_attempts():
    guard = SubmitGuard()
    assert guard.attempts("p1", "c1") == 0
    guard.record("p1", "c1", accepted=False, flag="flag{a}")
    guard.record("p1", "c1", accepted=False, flag="flag{b}")
    assert guard.attempts("p1", "c1") == 2
    assert guard.is_accepted("p1", "c1") is False


def test_guard_persists_state(tmp_path):
    state = tmp_path / "submit_state.json"
    guard = SubmitGuard(state_path=state)
    guard.record("p1", "c1", accepted=True, flag="flag{good}")
    reloaded = SubmitGuard(state_path=state)
    assert reloaded.attempts("p1", "c1") == 1
    assert reloaded.is_accepted("p1", "c1") is True


def test_guard_tolerates_corrupt_state(tmp_path):
    state = tmp_path / "submit_state.json"
    state.write_text("{{{ not json", encoding="utf-8")
    guard = SubmitGuard(state_path=state)
    assert guard.attempts("p1", "c1") == 0
    assert guard.allow("p1", "c1", "flag{ok}")[0] is True


def test_guard_message_is_escalation_hint():
    msg = guard_reason_to_message("p1", "c1", "needs human confirmation")
    assert "[ctf2_confirm]" in msg
    assert "Ask the user" in msg
