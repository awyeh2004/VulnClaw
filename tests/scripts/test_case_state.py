"""case_state.json is how one review round hands a direction to the next.

Measured 2026-11-17 on oldsvr: the reviewer's entire contribution was one
direction change — "the md5 compare stops at the shared NUL, so this is a 24-bit
prefix constraint, not a wordlist lookup". The next round went from 162 tool calls
with 0 conclusions to ~90 calls with 7. That instruction travelled through a chat
message, which means a different process or a different day would have lost it.

Two properties matter, and both are about refusing to guess:

* a verdict recorded against target A is never handed to target B;
* an unreadable or newer-schema file is an error at the CLI, not silence.

The runner deliberately *does* fail quiet (see ``_case_state_hints``): a broken
file must not stop a solve. The CLI is where the operator gets told.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "case_state.py"


@pytest.fixture(scope="module")
def cs():
    spec = importlib.util.spec_from_file_location("case_state_mod", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def test_missing_file_is_an_empty_state(cs, tmp_path):
    state = cs.load(tmp_path)

    assert state.rounds == []
    assert state.hints_for("anything") == []


def test_add_round_persists_and_is_readable(cs, tmp_path):
    cs.add_round(
        tmp_path,
        run_name="run-1",
        verdict=cs.VERDICT_STALLED,
        blocked_at="auth",
        ruled_out=["dictionary attack"],
        next_hint="enumerate the prefix constraint",
        target="t.example",
    )

    reloaded = cs.load(tmp_path)

    assert len(reloaded.rounds) == 1
    assert reloaded.rounds[0].blocked_at == "auth"
    assert reloaded.target == "t.example"


def test_hints_carry_blocked_ruled_out_and_next(cs, tmp_path):
    cs.add_round(
        tmp_path,
        verdict=cs.VERDICT_STALLED,
        blocked_at="CONNECT auth",
        ruled_out=["rockyou wordlist"],
        next_hint="24-bit prefix enumeration",
        target="t",
    )

    hints = cs.load(tmp_path).hints_for("t")

    assert any("blocked at" in h and "CONNECT auth" in h for h in hints)
    assert any("ruled out" in h and "rockyou" in h for h in hints)
    assert any("24-bit prefix" in h for h in hints)


def test_verdict_for_another_target_yields_no_hints(cs, tmp_path):
    """A conclusion about challenge A is not a hint about challenge B."""
    cs.add_round(tmp_path, next_hint="do X", target="challenge-a")

    assert cs.load(tmp_path).hints_for("challenge-b") == []


def test_solved_verdict_yields_no_hints(cs, tmp_path):
    cs.add_round(tmp_path, verdict=cs.VERDICT_SOLVED, next_hint="ignore me", target="t")

    assert cs.load(tmp_path).hints_for("t") == []


def test_unknown_verdict_is_rejected_at_write_time(cs, tmp_path):
    """Closed vocabulary: an unknown verdict must not be carried forward silently."""
    with pytest.raises(cs.CaseStateError):
        cs.add_round(tmp_path, verdict="probably-fine", target="t")


def test_unknown_verdict_in_a_file_is_rejected_on_load(cs, tmp_path):
    (tmp_path / "case_state.json").write_text(
        json.dumps({"schema_version": 1, "target": "t",
                    "rounds": [{"round": 1, "verdict": "made-up"}]}),
        encoding="utf-8",
    )

    with pytest.raises(cs.CaseStateError):
        cs.load(tmp_path)


def test_newer_schema_is_refused_not_guessed(cs, tmp_path):
    (tmp_path / "case_state.json").write_text(
        json.dumps({"schema_version": cs.SCHEMA_VERSION + 1, "target": "t", "rounds": []}),
        encoding="utf-8",
    )

    with pytest.raises(cs.CaseStateError) as exc:
        cs.load(tmp_path)

    assert "refusing" in str(exc.value)


def test_corrupt_file_raises_rather_than_silently_resetting(cs, tmp_path):
    """Silently starting over would erase a verdict the operator may still need."""
    (tmp_path / "case_state.json").write_text("{not json", encoding="utf-8")

    with pytest.raises(cs.CaseStateError):
        cs.load(tmp_path)


def test_rounds_are_numbered_sequentially(cs, tmp_path):
    for _ in range(3):
        cs.add_round(tmp_path, verdict=cs.VERDICT_STALLED, target="t")

    rounds = cs.load(tmp_path).rounds

    assert [r.round for r in rounds] == [1, 2, 3]


def test_round_history_is_capped(cs, tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "MAX_ROUNDS", 3)
    for i in range(6):
        cs.add_round(tmp_path, next_hint=f"hint {i}", target="t")

    state = cs.load(tmp_path)

    assert len(state.rounds) == 3
    # The newest survives; the oldest are dropped.
    assert state.rounds[-1].next_hint == "hint 5"


def test_only_the_latest_round_supplies_hints(cs, tmp_path):
    cs.add_round(tmp_path, next_hint="first advice", target="t")
    cs.add_round(tmp_path, next_hint="second advice", target="t")

    hints = cs.load(tmp_path).hints_for("t")

    assert any("second advice" in h for h in hints)
    assert not any("first advice" in h for h in hints)


def test_save_is_atomic(cs, tmp_path):
    """A half-written file must never be visible to the next round."""
    cs.add_round(tmp_path, next_hint="x", target="t")

    # No leftover temp file from the atomic write.
    assert not list(tmp_path.glob("*.tmp"))


def test_target_is_explicitly_saved(cs, tmp_path):
    cs.add_round(tmp_path, target="E:\\work\\lab")

    assert json.loads((tmp_path / "case_state.json").read_text(encoding="utf-8"))["target"]


def test_cli_add_and_hints_round_trip(cs, tmp_path, capsys):
    assert cs.main([
        "add-round", str(tmp_path),
        "--verdict", "stalled", "--blocked-at", "auth",
        "--ruled-out", "wordlist", "--next-hint", "enumerate", "--target", "t",
    ]) == 0

    assert cs.main(["hints", str(tmp_path), "--target", "t"]) == 0
    out = capsys.readouterr().out
    assert "enumerate" in out
    assert "wordlist" in out


def test_cli_reports_a_bad_file(cs, tmp_path, capsys):
    (tmp_path / "case_state.json").write_text("{bad", encoding="utf-8")

    code = cs.main(["show", str(tmp_path)])

    assert code == 2
    assert "cannot read" in capsys.readouterr().err