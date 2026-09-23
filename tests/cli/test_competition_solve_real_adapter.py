"""`competition solve` driven through the REAL adapter and the REAL registry.

The sibling file (`test_competition_solve_ref.py`) tests the CLI contract with a
*stub* adapter, which is the right shape for asserting "what does this command hand to
solve()". This file covers the seam that a stub cannot: the token a user types going
through `registry.adapter_for` → the real `CTF2Adapter.parse_ref` → the real
`_pair()` mapping → the real `read_challenge` and attachment extraction.

Why that seam is worth its own file: a stub's `parse_ref` returns whatever the test
author imagined, so a mismatch between what the real parser produces and what
`_pair`/the CLI expect is invisible. The clearest example is `ctf2:daily`, which the
real adapter refuses (`CTF2 needs both a daily id and a challenge id`) -- a stub would
have happily produced a ref and the run would have started against an unaddressable
challenge.

Everything is offline: the real adapter is constructed with a fake client returning
payloads recorded from the live platform.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import typer

from tests.platforms import ctf2_payloads as fx
from tests.platforms.ctf2_fakes import FakeClient
from vulnclaw.cli import main
from vulnclaw.platforms import registry
from vulnclaw.platforms.ctf2 import CTF2Adapter

PRACTICE_TOKEN = f"ctf2:practice:{fx.PRACTICE_ID}:{fx.CHALLENGE_ID}"
STAGE_TOKEN = "ctf2:stage:stage-777:challenge-999"

# From the recorded payload: one nested file row, `files[].file.original_name`.
RECORDED_ATTACHMENT_NAME = "libc-2.27.so"
RECORDED_ATTACHMENT_SIZE = 2030544


def _cfg(stall_turns: int = 8):
    return SimpleNamespace(competition=SimpleNamespace(stall_turns=stall_turns))


@pytest.fixture
def real_ctf2(monkeypatch):
    """The real CTF2Adapter, registered in the real registry, backed by fixtures."""
    client = FakeClient(read_challenge=fx.CHALLENGE_DETAIL_PAYLOAD)
    adapter = CTF2Adapter(client)

    monkeypatch.setattr(registry, "_ADAPTERS", {}, raising=False)
    monkeypatch.setattr(registry, "is_enabled", lambda adapter: True)
    registry.register_adapter(adapter)
    # Otherwise bootstrap would re-register the default adapters over this one.
    monkeypatch.setattr("vulnclaw.platforms.bootstrap.ensure_adapters", lambda *a, **k: None)
    yield SimpleNamespace(adapter=adapter, client=client)
    registry.clear_adapters()


@pytest.fixture
def captured_solve(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(main, "solve", lambda **kwargs: captured.update(kwargs))
    return captured


@pytest.fixture
def captured_attachments(monkeypatch):
    """Capture what the pre-download is handed, without downloading anything."""
    seen: list[tuple] = []

    def fake_predownload(cfg, challenge_name, attachments, adapter):
        seen.append((challenge_name, tuple(attachments)))
        return []

    monkeypatch.setattr(main, "_predownload_challenge_attachments", fake_predownload)
    return seen


class TestTheRealAdapterIsReachedThroughTheRegistry:
    def test_the_token_resolves_and_the_api_gets_the_pair_from_it(
        self, real_ctf2, captured_solve, captured_attachments
    ):
        main._competition_solve(_cfg(), PRACTICE_TOKEN)

        # The real _pair() maps group -> practice id and id -> challenge id.
        assert ("read_challenge", (fx.PRACTICE_ID, fx.CHALLENGE_ID)) in real_ctf2.client.calls
        assert captured_solve["target"] == PRACTICE_TOKEN

    def test_a_stage_ref_addresses_the_stage_id_in_the_practice_slot(
        self, real_ctf2, captured_solve, captured_attachments
    ):
        """`_pair`'s documented quirk: CTF2 stage routes take the stage id as the pid."""
        main._competition_solve(_cfg(), STAGE_TOKEN)

        assert ("read_challenge", ("stage-777", "challenge-999")) in real_ctf2.client.calls

    def test_the_goal_carries_the_recorded_challenge_metadata(
        self, real_ctf2, captured_solve, captured_attachments
    ):
        main._competition_solve(_cfg(), PRACTICE_TOKEN)

        goal = captured_solve["goal"]
        assert "stack" in goal
        assert "第06章 CTF之PWN篇" in goal  # category, verbatim from the payload
        assert "Easy" in goal
        # has_container: true in the recorded payload -> the env lifecycle wording.
        assert "platform_start_env" in goal
        assert "platform_stop_env" in goal
        assert PRACTICE_TOKEN in goal

    def test_the_real_attachment_extraction_reaches_the_predownload(
        self, real_ctf2, captured_solve, captured_attachments
    ):
        """The nested `files[].file.original_name` shape is what makes this work."""
        main._competition_solve(_cfg(), PRACTICE_TOKEN)

        name, attachments = captured_attachments[0]
        assert name == "stack"
        assert [a.name for a in attachments] == [RECORDED_ATTACHMENT_NAME]
        assert attachments[0].size == RECORDED_ATTACHMENT_SIZE


class TestWhatAStubAdapterCannotShow:
    def test_a_ref_the_real_adapter_cannot_address_exits_before_the_agent(
        self, real_ctf2, captured_solve, captured_attachments
    ):
        """`ctf2:daily` has no challenge id, so the real `_pair` refuses it.

        The stub-based tests produce a ref for anything, so this path -- exit before
        starting a run against a challenge that cannot be addressed -- is invisible
        there.
        """
        with pytest.raises(typer.Exit) as excinfo:
            main._competition_solve(_cfg(), "ctf2:daily")

        assert excinfo.value.exit_code == 1
        assert captured_solve == {}, "no agent may start for an unaddressable ref"

    def test_an_unknown_platform_never_reaches_the_adapter(
        self, real_ctf2, captured_solve, captured_attachments
    ):
        with pytest.raises(typer.Exit) as excinfo:
            main._competition_solve(_cfg(), "nope:practice:1:2")

        assert excinfo.value.exit_code == 1
        assert captured_solve == {}
        assert real_ctf2.client.calls == []
