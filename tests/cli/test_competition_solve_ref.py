"""`competition solve` must be ref-driven, on every platform, or fail loudly.

`_competition_solve` used to be hardcoded to the GCS command and a numeric
exercise id, which made "competition solve" the one CLI path that only worked for
one platform -- and it was the last place still reading a challenge through a
platform-specific client instead of the adapter layer.

Commit 04d1033 shipped the ref rewrite with no test of its own; this file is that
gap. What it pins:

* a bare numeric id still means `gcs:exercise:<id>` (the old CLI form), so the
  rewrite stays backward compatible;
* the ref the agent is handed is the *same* string the goal names, exactly once
  (commit 897ff65 -- repeating it burned ~60-90 tokens per challenge, and two
  spellings of one ref is how a model starts inventing a third);
* an unusable ref exits 1 *before* any agent starts, rather than starting a run
  against a target it cannot address;
* the stall guard's threshold actually reaches `solve()` (`max_steps` scales with
  `competition.stall_turns`, never below 60).

The adapters are stubbed: this is a CLI contract test, not a platform test. The
real ref parsing is covered by tests/platforms/test_refs.py.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import typer

from vulnclaw.cli import main
from vulnclaw.platforms import registry
from vulnclaw.platforms.base import Challenge
from vulnclaw.platforms.refs import ChallengeRef, parse_fields

SENTINELS = {"OptionInfo", "ArgumentInfo"}


class _StubAdapter:
    """The minimum `adapter_for` + `_competition_solve` touch.

    `parse_ref` returns a real `ChallengeRef` built from real field validation, so
    the ref shapes under test are the ones the adapters actually produce.
    """

    enabled_by_default = True

    def __init__(
        self, name: str, challenge: Challenge | None = None, error: Exception | None = None
    ):
        self.name = name
        self._challenge = challenge
        self._error = error
        self.seen_refs: list[ChallengeRef] = []

    def is_configured(self) -> bool:
        return True

    def parse_ref(self, tail: str) -> ChallengeRef:
        fields = parse_fields(tail)
        if self.name == "gcs":
            # gcs:exercise[:<eid>]
            if fields[0] != "exercise":
                raise ValueError(f"gcs ref must be exercise[:<id>], got {tail!r}")
            return ChallengeRef("gcs", "exercise", id=fields[1] if len(fields) > 1 else "")
        # ctf2:practice:<pid>:<cid> / ctf2:stage:<sid>:<cid> / ctf2:daily[:<cid>]
        if fields[0] not in {"practice", "stage", "daily"}:
            raise ValueError(f"unknown ctf2 kind {fields[0]!r}")
        if len(fields) > 2:
            return ChallengeRef("ctf2", fields[0], group=fields[1], id=fields[2])
        return ChallengeRef("ctf2", fields[0], id=fields[1] if len(fields) > 1 else "")

    async def read_challenge(self, ref: ChallengeRef) -> Challenge:
        self.seen_refs.append(ref)
        if self._error is not None:
            raise self._error
        if self._challenge is not None:
            return self._challenge
        return Challenge(ref=ref, name="stub challenge")


@pytest.fixture
def stub_platforms(monkeypatch):
    """Isolate the registry and stub both platforms."""
    gcs = _StubAdapter("gcs")
    ctf2 = _StubAdapter("ctf2")

    monkeypatch.setattr(registry, "_ADAPTERS", {}, raising=False)
    monkeypatch.setattr(registry, "is_enabled", lambda adapter: True)
    registry.register_adapter(gcs)
    registry.register_adapter(ctf2)
    monkeypatch.setattr("vulnclaw.platforms.bootstrap.ensure_adapters", lambda *a, **k: None)
    yield SimpleNamespace(gcs=gcs, ctf2=ctf2)
    registry.clear_adapters()


@pytest.fixture
def captured_solve(monkeypatch):
    captured: dict = {}

    def fake_solve(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(main, "solve", fake_solve)
    return captured


def _cfg(stall_turns: int = 8):
    return SimpleNamespace(competition=SimpleNamespace(stall_turns=stall_turns))


def _challenge(name: str, **kwargs) -> Challenge:
    ref = ChallengeRef("ctf2", "practice", group="pid-1", id="cid-2")
    return Challenge(ref=ref, name=name, **kwargs)


# A full-length CTF2 token: the length is the point in the dedup tests below.
LONG_TOKEN = (
    "ctf2:practice:b9bbb32f-f186-458f-b90b-12440c0f6aea:"
    "30c90c3e-2227-4263-8218-9494728f4c38"
)


def test_bare_numeric_id_normalizes_to_the_gcs_exercise_ref(
    stub_platforms, captured_solve, monkeypatch
):
    monkeypatch.setattr(main, "load_config", lambda: _cfg())

    main._competition_solve(_cfg(), "10662")

    assert captured_solve["target"] == "gcs:exercise:10662"
    ref = stub_platforms.gcs.seen_refs[-1]
    assert (ref.platform, ref.kind, ref.id) == ("gcs", "exercise", "10662")


def test_explicit_ctf2_ref_reaches_the_ctf2_adapter(stub_platforms, captured_solve, monkeypatch):
    monkeypatch.setattr(main, "load_config", lambda: _cfg())
    token = "ctf2:practice:pid-1:cid-2"

    main._competition_solve(_cfg(), token)

    assert captured_solve["target"] == token
    ref = stub_platforms.ctf2.seen_refs[-1]
    assert (ref.platform, ref.kind, ref.group, ref.id) == ("ctf2", "practice", "pid-1", "cid-2")
    assert stub_platforms.gcs.seen_refs == [], "a ctf2 ref must not touch the gcs adapter"


def test_unknown_platform_exits_before_starting_an_agent(
    stub_platforms, captured_solve, monkeypatch
):
    monkeypatch.setattr(main, "load_config", lambda: _cfg())

    with pytest.raises(typer.Exit) as excinfo:
        main._competition_solve(_cfg(), "nope:exercise:1")

    assert excinfo.value.exit_code == 1
    assert captured_solve == {}, "solve() must not run for an unusable ref"


def test_malformed_ref_exits_before_starting_an_agent(stub_platforms, captured_solve, monkeypatch):
    monkeypatch.setattr(main, "load_config", lambda: _cfg())

    with pytest.raises(typer.Exit) as excinfo:
        main._competition_solve(_cfg(), "not-a-ref")

    assert excinfo.value.exit_code == 1
    assert captured_solve == {}


def test_read_failure_exits_instead_of_starting_a_blind_run(
    stub_platforms, captured_solve, monkeypatch
):
    monkeypatch.setattr(main, "load_config", lambda: _cfg())
    stub_platforms.gcs._error = RuntimeError("502 Bad Gateway")

    with pytest.raises(typer.Exit) as excinfo:
        main._competition_solve(_cfg(), "10662")

    assert excinfo.value.exit_code == 1
    assert captured_solve == {}


def test_goal_names_the_ref_exactly_once(stub_platforms, captured_solve, monkeypatch):
    """The ref is long; repeating it in the goal is pure waste (commit 897ff65).

    This first failed against the shipped `_competition_solve`, which wrote the
    token into `platform_submit(ref=...)`, `platform_start_env(ref=...)` and
    `platform_stop_env(ref=...)` as well as the preamble: 2 occurrences without an
    environment, 4 with one (~260 wasted chars on an 87-char ref).
    """
    monkeypatch.setattr(main, "load_config", lambda: _cfg())

    main._competition_solve(_cfg(), LONG_TOKEN)

    assert captured_solve["goal"].count(LONG_TOKEN) == 1
    # ... and that single occurrence is the one the tools take, not prose.
    assert f'ref="{LONG_TOKEN}"' not in captured_solve["goal"]
    assert "REF: " in captured_solve["goal"]


def test_env_goal_also_names_the_ref_once(stub_platforms, captured_solve, monkeypatch):
    """The env branch is where the token used to be repeated most."""
    monkeypatch.setattr(main, "load_config", lambda: _cfg())
    stub_platforms.ctf2._challenge = _challenge("BabySQL", needs_env=True)

    main._competition_solve(_cfg(), LONG_TOKEN)

    assert captured_solve["goal"].count(LONG_TOKEN) == 1


def test_goal_points_at_the_neutral_platform_tools(stub_platforms, captured_solve, monkeypatch):
    monkeypatch.setattr(main, "load_config", lambda: _cfg())
    stub_platforms.ctf2._challenge = _challenge(
        "BabySQL", category="WEB", difficulty="Easy", needs_env=True
    )

    main._competition_solve(_cfg(), "ctf2:practice:pid-1:cid-2")

    goal = captured_solve["goal"]
    assert "platform_submit" in goal
    assert "platform_start_env" in goal
    assert "platform_read_env" in goal
    assert "platform_stop_env" in goal
    # The legacy, platform-named tools must not be advertised anywhere: they are
    # hidden from the schema by default, so naming them would send the model to a
    # tool that does not exist.
    for legacy in ("ctf2_submit_flag", "ctf2_start_environment", "gcs_submit_flag"):
        assert legacy not in goal


def test_env_less_challenge_does_not_tell_the_agent_to_start_anything(
    stub_platforms, captured_solve, monkeypatch
):
    monkeypatch.setattr(main, "load_config", lambda: _cfg())
    stub_platforms.ctf2._challenge = _challenge("RSA", category="crypto", needs_env=False)

    main._competition_solve(_cfg(), "ctf2:practice:pid-1:cid-2")

    goal = captured_solve["goal"]
    assert "no running environment" in goal
    assert "platform_start_env" not in goal


def test_solve_is_called_with_plain_values_and_a_stall_aware_budget(
    stub_platforms, captured_solve, monkeypatch
):
    monkeypatch.setattr(main, "load_config", lambda: _cfg(stall_turns=30))

    main._competition_solve(_cfg(stall_turns=30), "10662")

    offenders = {
        name: type(value).__name__
        for name, value in captured_solve.items()
        if type(value).__name__ in SENTINELS
    }
    assert offenders == {}, f"typer sentinels leaked into solve(): {offenders}"
    # stall_turns * 4 = 120 > the 60 floor, so the guard's threshold drives the cap.
    assert captured_solve["max_steps"] == 120
    assert captured_solve["model"] == "auto"
    assert captured_solve["resume"] is False


def test_small_stall_setting_still_gets_a_usable_budget(
    stub_platforms, captured_solve, monkeypatch
):
    monkeypatch.setattr(main, "load_config", lambda: _cfg(stall_turns=2))

    main._competition_solve(_cfg(stall_turns=2), "10662")

    assert captured_solve["max_steps"] == 60


def test_default_stall_threshold_when_config_says_nothing(
    stub_platforms, captured_solve, monkeypatch
):
    """A config object without `stall_turns` must not crash the command."""
    bare = SimpleNamespace(competition=SimpleNamespace())
    monkeypatch.setattr(main, "load_config", lambda: bare)

    main._competition_solve(bare, "10662")

    assert captured_solve["max_steps"] == 60
