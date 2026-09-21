"""The hand-off from ``ctf2``/``gcs``/``go`` into ``solve`` must not drift.

``solve`` is a Typer command: calling it from Python leaves un-passed parameters
as truthy ``OptionInfo`` sentinels, so every optional flag has to be passed. Those
values used to be copied by hand at three call sites, which meant changing a
default in ``solve`` silently left the old value behind. They are now read from
the command's signature; this test pins that they still equal what the call sites
used to spell out.
"""

from __future__ import annotations

from vulnclaw.cli.main import _solve_defaults

# The values the three call sites hand-wrote before the refactor.
_HAND_WRITTEN = {
    "prompt": None,
    "max_steps": 240,
    "max_directions": 3,
    "max_tool_rounds": 6,
    "resume": True,
    "snapshot": None,
    "run_name": None,
    "resume_run": None,
    "runs_dir": None,
    "additional_targets": None,
    "target_type": None,
    "mount": False,
    "repair": False,
    "force_fresh": False,
    "no_import": False,
    "stream": False,
    "writeup_dir": None,
    "model": "auto",
}


def test_derived_defaults_match_the_hand_written_values():
    got = _solve_defaults(target="t", goal="g")
    missing = set(_HAND_WRITTEN) - set(got)
    assert not missing, f"parameters vanished from solve(): {sorted(missing)}"
    for name, expected in _HAND_WRITTEN.items():
        assert got[name] == expected, f"{name}: {got[name]!r} != {expected!r}"


def test_overrides_win():
    got = _solve_defaults(target="t", goal="g", max_steps=5, resume=False, model="x")
    assert got["max_steps"] == 5
    assert got["resume"] is False
    assert got["model"] == "x"
    assert got["target"] == "t" and got["goal"] == "g"


def test_required_arguments_are_not_invented():
    """``target`` is a required Typer argument (Ellipsis); it must come from the
    caller, never from a fabricated default."""
    import inspect

    from vulnclaw.cli.main import solve

    assert inspect.signature(solve).parameters["target"].default is not inspect.Parameter.empty
    assert "target" not in _solve_defaults()
    assert "goal" in _solve_defaults()  # optional, so it does carry a default


def test_no_truthy_typer_sentinels_leak_through():
    """The bug the explicit-passing rule exists for: sentinels read as truthy."""
    for name, value in _solve_defaults(target="t", goal="g").items():
        assert type(value).__name__ not in {"OptionInfo", "ArgumentInfo"}, name
        assert not hasattr(value, "__rich_console__"), name


# ── sentinel detection must not depend on the typer class NAME ──────────


def test_cli_value_unwraps_a_real_typer_option():
    import typer

    from vulnclaw.cli.main import _cli_value

    option = typer.Option(7, "--n")
    assert _cli_value(option, 1) == 7
    assert _cli_value(typer.Argument(...), 99) == 99  # required -> fallback


def test_cli_value_uses_the_real_classes_not_their_names():
    """A renamed-but-real sentinel must still be unwrapped (and vice versa)."""
    from vulnclaw.cli.main import _is_typer_sentinel

    class RenamedOption:
        """Stand-in with the same shape but a different class name."""

        default = 5

    assert _is_typer_sentinel(RenamedOption()) is False  # not a typer type
    assert _is_typer_sentinel(5) is False
    assert _is_typer_sentinel(None) is False

    sentinels = _typer_sentinel_types_or_skip()
    if sentinels:
        assert _is_typer_sentinel(sentinels[0]()) is True


def _typer_sentinel_types_or_skip():
    from vulnclaw.cli.main import _typer_sentinel_types

    return _typer_sentinel_types()


def test_a_lookalike_class_name_is_still_caught():
    """Fallback path: the name check keeps working when typer is unavailable."""
    from vulnclaw.cli.main import _cli_value

    class OptionInfo:  # noqa: N801 - deliberately mimics typer's name
        default = 3

    assert _cli_value(OptionInfo(), 1) == 3
