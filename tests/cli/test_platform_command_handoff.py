"""`vulnclaw ctf2` / `vulnclaw gcs` must hand plain values to `solve()`.

Both commands are Typer command functions that call another Typer command
function (`solve`) directly from Python. Typer only substitutes real values when
it invokes a command itself, so a parameter the caller does not pass stays an
``OptionInfo`` object -- and those sentinels are **truthy** and stringify into
nonsense.

That was not hypothetical: `vulnclaw ctf2` failed before the agent even started,

    TypeError: Value after * must be an iterable, not OptionInfo
      vulnclaw/targets.py:82 in build_targets

because `additional_targets` was a sentinel. `gcs` had been patched to pass
everything explicitly; `ctf2` had not, and `gcs` still missed `model`.

These tests call the commands directly (exactly the failing call convention) with
`solve` stubbed, and assert every forwarded value is a plain value.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.cli import main

SENTINELS = {"OptionInfo", "ArgumentInfo"}


def _assert_no_sentinels(captured: dict) -> None:
    offenders = {
        name: type(value).__name__
        for name, value in captured.items()
        if type(value).__name__ in SENTINELS
    }
    assert offenders == {}, f"typer sentinels leaked into solve(): {offenders}"


@pytest.fixture
def captured_solve(monkeypatch):
    captured: dict = {}

    def fake_solve(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(main, "solve", fake_solve)
    monkeypatch.setattr(main, "has_llm_credentials", lambda llm: True)
    monkeypatch.setattr(main, "load_config", lambda: SimpleNamespace(llm=SimpleNamespace()))
    monkeypatch.setattr(main, "ctf2_is_configured", lambda: True)
    monkeypatch.setattr(main, "gcs_is_configured", lambda: True)
    monkeypatch.setattr(main, "_gcs_rank", lambda *a, **k: ("", ""), raising=False)
    return captured


def test_ctf2_forwards_plain_values(captured_solve, monkeypatch):
    async def fake_read(practice_id, challenge_id):
        return {"data": {"name": "stack", "category": "pwn", "difficulty": "Easy"}}

    monkeypatch.setattr(main, "ctf2_read_challenge", fake_read)

    # Called the way a Python caller (or the failing reproduction) calls it:
    # optional parameters omitted, so they are still typer sentinels.
    main.ctf2("challenge-id", "practice-id")

    _assert_no_sentinels(captured_solve)
    assert captured_solve["target"] == "practice-id"
    assert captured_solve["resume"] is False
    assert captured_solve["stream"] is False
    assert captured_solve["model"] == "auto"
    assert captured_solve["additional_targets"] is None
    assert isinstance(captured_solve["max_steps"], int)


def test_ctf2_max_steps_override_survives(captured_solve, monkeypatch):
    async def fake_read(practice_id, challenge_id):
        return {"data": {"name": "stack"}}

    monkeypatch.setattr(main, "ctf2_read_challenge", fake_read)
    main.ctf2("challenge-id", "practice-id", max_steps=42)
    assert captured_solve["max_steps"] == 42


def test_gcs_forwards_plain_values(captured_solve, monkeypatch):
    async def fake_exercise(exercise_id):
        return {"data": {"name": "some exercise", "isNeedInit": True}}

    monkeypatch.setattr(main, "gcs_exercise", fake_exercise)
    main.gcs(1234)

    _assert_no_sentinels(captured_solve)
    assert captured_solve["target"] == "1234"
    assert captured_solve["model"] == "auto"


def test_the_helper_unwraps_and_passes_through():
    from typer.models import OptionInfo

    assert main._cli_value(OptionInfo(default=7), 99) == 7
    assert main._cli_value(OptionInfo(default=None), 99) is None
    assert main._cli_value(5, 99) == 5
    assert main._cli_value("x", 99) == "x"
    assert main._cli_value(None, 99) is None
