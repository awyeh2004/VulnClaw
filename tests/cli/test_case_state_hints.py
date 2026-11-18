"""`solve --case-state` must actually carry the previous verdict forward.

The runner loads ``scripts/case_state.py`` by path, and the first version of that
loader failed silently: a module executed without being registered in
``sys.modules`` breaks ``@dataclass`` (annotations resolve through
``sys.modules[cls.__module__]``), the surrounding ``except Exception`` swallowed
the AttributeError, and the feature reported "no hints" for a file that plainly
had them. Silent failure on the feature whose whole job is not to lose
information is the worst possible shape, hence these tests exercise the real
script rather than a stub.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from vulnclaw.cli import commands_run

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "case_state.py"


def _write_case_state(directory: Path, *, target: str, hint: str, verdict: str = "stalled") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "case_state.json").write_text(
        __import__("json").dumps(
            {
                "schema_version": 1,
                "target": target,
                "rounds": [
                    {
                        "round": 1,
                        "run_name": "run-1",
                        "verdict": verdict,
                        "blocked_at": "auth",
                        "ruled_out": ["wordlist"],
                        "next_hint": hint,
                        "target": target,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_hints_are_loaded_from_the_real_script(tmp_path):
    """Regression: the dataclass-in-unregistered-module failure returned [] here."""
    _write_case_state(tmp_path, target="t", hint="enumerate the prefix constraint")

    hints = commands_run._case_state_hints(str(tmp_path), "t")

    assert any("enumerate the prefix constraint" in h for h in hints)
    assert any("wordlist" in h for h in hints)


def test_hints_are_empty_for_a_different_target(tmp_path):
    _write_case_state(tmp_path, target="challenge-a", hint="do X")

    assert commands_run._case_state_hints(str(tmp_path), "challenge-b") == []


def test_missing_directory_is_not_an_error(tmp_path):
    assert commands_run._case_state_hints(str(tmp_path / "nope"), "t") == []


def test_corrupt_file_does_not_break_the_solve(tmp_path):
    """The CLI reports corruption; the runner keeps going without hints."""
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "case_state.json").write_text("{bad", encoding="utf-8")

    assert commands_run._case_state_hints(str(tmp_path), "t") == []


def test_loader_does_not_leak_the_module_into_sys_modules(tmp_path):
    """Registering for dataclass resolution must be undone afterwards."""
    _write_case_state(tmp_path, target="t", hint="h")

    commands_run._case_state_hints(str(tmp_path), "t")

    assert "_vulnclaw_case_state" not in sys.modules


def test_script_path_is_resolvable_from_the_cli_package():
    """The loader walks up from commands_run.py; that must land on scripts/."""
    expected = Path(commands_run.__file__).resolve().parents[2] / "scripts" / "case_state.py"
    assert expected.is_file()
