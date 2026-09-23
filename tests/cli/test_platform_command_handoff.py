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


# ── the goal text must name its ref exactly once ──────────────────────────
#
# Every entry point writes the ref into the goal it hands the agent. A ref is long
# (an 87-char CTF2 token, say) and the agent only has to *echo* it, so writing it
# into each `platform_*(ref=...)` example as well was pure repeated cost -- and two
# spellings of one ref is how a model starts inventing a third. Commit 897ff65
# deduplicated `ctf2`/`gcs`; `competition solve` still repeated it 2-4x until
# tests/cli/test_competition_solve_ref.py caught it. These guard the other two.


def test_ctf2_goal_names_the_ref_exactly_once(captured_solve, monkeypatch):
    async def fake_read(practice_id, challenge_id):
        return {"data": {"name": "stack", "category": "pwn", "has_container": True}}

    monkeypatch.setattr(main, "ctf2_read_challenge", fake_read)
    main.ctf2("challenge-id", "practice-id")

    token = "ctf2:practice:practice-id:challenge-id"
    goal = captured_solve["goal"]
    assert goal.count(token) == 1
    assert f"REF: {token}" in goal
    assert f'ref="{token}"' not in goal


def test_gcs_goal_names_the_ref_exactly_once(captured_solve, monkeypatch):
    async def fake_exercise(exercise_id):
        return {"data": {"name": "some exercise", "isNeedInit": True}}

    monkeypatch.setattr(main, "gcs_exercise", fake_exercise)
    main.gcs(10662)

    goal = captured_solve["goal"]
    assert goal.count("gcs:exercise:10662") == 1
    assert "REF: gcs:exercise:10662" in goal
    assert 'ref="gcs:exercise:10662"' not in goal


# ── a RE challenge's attachment must not be forbidden ─────────────────────
#
# The CTF2 goal used to say "Do not attempt to fetch files from or attack
# ctf2*.dasctf.com hosts". For a reverse-engineering challenge the attachment IS
# the challenge, and the platform publishes it on ctf2-files.dasctf.com -- so the
# blanket ban told the agent not to obtain the challenge at all. Measured on
# "不一样的flag" (Easy RE, 9 KB zip): the agent had to fetch that URL.

FORBIDDEN_BLANKET_BAN = "Do not attempt to fetch files from or attack"


def test_ctf2_goal_permits_downloading_the_challenge_attachment(captured_solve, monkeypatch):
    async def fake_read(practice_id, challenge_id):
        return {"data": {"name": "不一样的flag", "category": "REVERSE"}}

    monkeypatch.setattr(main, "ctf2_read_challenge", fake_read)
    main.ctf2("challenge-id", "practice-id")

    goal = captured_solve["goal"]
    assert "attachments" in goal.lower()
    assert "IS expected" in goal


def test_ctf2_goal_still_forbids_attacking_the_platform(captured_solve, monkeypatch):
    """Lifting the file ban must not lift the 'do not attack the platform' rule."""

    async def fake_read(practice_id, challenge_id):
        return {"data": {"name": "x"}}

    monkeypatch.setattr(main, "ctf2_read_challenge", fake_read)
    main.ctf2("challenge-id", "practice-id")

    goal = captured_solve["goal"]
    assert FORBIDDEN_BLANKET_BAN not in goal
    assert "out of bounds" in goal
    assert "no scanning or" in goal
