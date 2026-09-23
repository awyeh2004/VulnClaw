"""The submit path, driven by the payloads the platform actually served.

The one IRREVERSIBLE action had the weakest recorded evidence: its request body was
*inferred*, and the four responses below were captured only on 2026-09-23 -- until
then they existed as hand-copied dictionaries inside two test files. Hand-copied
samples are exactly how four CTF2 field names once came out wrong
(`hasSolved`/`is_solved`, `score`/`points`, `files[].name`, `files[].size`), so the
shapes now live in `ctf2_payloads` and every test reads them from there.

Two layers are pinned:

* the ADAPTER's reading of a payload (accepted vs not, without crashing);
* the POLICY's accounting in `submit_flag_via` -- which is what decides whether a
  failed submit burns one of the limited, irreversible attempts.
"""

from __future__ import annotations

import httpx
import pytest

from tests.platforms import ctf2_payloads as fx
from vulnclaw.ctf_platform import client as ctf2_client
from vulnclaw.platforms import base
from vulnclaw.platforms import tools as platform_tools
from vulnclaw.platforms.ctf2 import CTF2Adapter
from vulnclaw.platforms.refs import ChallengeRef
from vulnclaw.platforms.submit_guard import SubmitGuard

REF = ChallengeRef("ctf2", "practice", fx.PRACTICE_ID, fx.CHALLENGE_ID)
FLAG = "flag{222441144222}"


class _SubmitClient:
    """Minimal client: only `submit_flag` is reachable for these tests."""

    def __init__(self, payload=None, error: Exception | None = None) -> None:
        self._payload = payload
        self._error = error
        self.calls: list[tuple] = []

    def is_configured(self) -> bool:
        return True

    async def submit_flag(self, practice_id, challenge_id, flag):
        self.calls.append((practice_id, challenge_id, flag))
        if self._error is not None:
            raise self._error
        return self._payload


def _client_error(status: int, payload) -> RuntimeError:
    """The real error the client raises for a recorded status+body.

    Built through `_raise_for_status` rather than hand-written, so the recorded body
    is what produces the message the policy has to handle.
    """
    response = httpx.Response(
        status, json=payload, request=httpx.Request("POST", "https://ctf2.dasctf.com/x")
    )
    with pytest.raises(RuntimeError) as excinfo:
        ctf2_client._raise_for_status(response)
    return excinfo.value


# ── layer 1: the adapter's reading of the recorded payloads ───────────────


class TestAdapterReadsTheRecordedSubmitPayloads:
    async def test_the_accepted_payload_reads_as_accepted(self):
        adapter = CTF2Adapter(_SubmitClient(fx.SUBMIT_ACCEPTED_PAYLOAD))

        result = await adapter.submit_flag(REF, FLAG)

        assert isinstance(result, base.SubmitResult)
        assert result.accepted is True
        assert result.judged is True
        # The raw payload must survive for the operator/report.
        assert result.raw == fx.SUBMIT_ACCEPTED_PAYLOAD

    async def test_the_accepted_payload_sends_the_pair_the_api_takes(self):
        client = _SubmitClient(fx.SUBMIT_ACCEPTED_PAYLOAD)
        await CTF2Adapter(client).submit_flag(REF, FLAG)

        assert client.calls == [(fx.PRACTICE_ID, fx.CHALLENGE_ID, FLAG)]

    @pytest.mark.parametrize(
        ("label", "payload"),
        [
            ("invalid_request", fx.SUBMIT_INVALID_REQUEST_PAYLOAD),
            ("invalid_request_hint", fx.SUBMIT_INVALID_REQUEST_HINT_PAYLOAD),
            ("route_not_found", fx.SUBMIT_ROUTE_NOT_FOUND_PAYLOAD),
        ],
    )
    async def test_a_rejection_body_is_not_accepted(self, label, payload):
        """`success: false` must never read as accepted, whatever else it carries.

        In production these never reach the adapter (the client raises first), but a
        tolerant reader that reported `accepted` here would mark a challenge solved on
        a rejected request -- the worst possible failure for this path.
        """
        adapter = CTF2Adapter(_SubmitClient(payload))

        result = await adapter.submit_flag(REF, FLAG)

        assert result.accepted is False, label

    def test_the_risk_control_body_is_not_accepted_either(self):
        """No `success` key at all -- so it must default to not-accepted."""
        from vulnclaw.platforms.ctf2 import submit_accepted

        assert submit_accepted(fx.SUBMIT_RISK_CONTROL_PAYLOAD) is False


# ── layer 2: what the policy charges for each outcome ─────────────────────


@pytest.fixture
def guard(monkeypatch, tmp_path):
    """A fresh, isolated guard, wired into the policy."""
    fresh = SubmitGuard(state_path=tmp_path / "submit_guard.json")
    monkeypatch.setattr(platform_tools, "get_guard", lambda: fresh)
    monkeypatch.setattr(platform_tools, "_flag_submission_enabled", lambda: True)
    return fresh


class TestSubmitAccounting:
    async def test_an_accepted_flag_consumes_an_attempt_and_closes_the_challenge(self, guard):
        adapter = CTF2Adapter(_SubmitClient(fx.SUBMIT_ACCEPTED_PAYLOAD))

        message = await platform_tools.submit_flag_via(adapter, REF, FLAG)

        assert "ACCEPTED" in message
        assert guard.attempts(REF.key) == 1
        assert guard.is_accepted(REF.key) is True

    @pytest.mark.parametrize(
        ("status", "payload"),
        [
            (400, fx.SUBMIT_INVALID_REQUEST_PAYLOAD),
            (400, fx.SUBMIT_INVALID_REQUEST_HINT_PAYLOAD),
            (404, fx.SUBMIT_ROUTE_NOT_FOUND_PAYLOAD),
        ],
    )
    async def test_a_rejected_request_consumes_NOTHING(self, guard, status, payload):
        """The platform never judged the flag, so it must not cost an attempt.

        This is the behaviour the BabySQL investigation depended on: the request was
        rejected at validation, the guard recorded an *error*, and the flag could
        still be submitted later without having burnt the cap.
        """
        adapter = CTF2Adapter(_SubmitClient(error=_client_error(status, payload)))

        message = await platform_tools.submit_flag_via(adapter, REF, FLAG)

        assert "failed" in message
        assert guard.attempts(REF.key) == 0
        assert guard.is_accepted(REF.key) is False

    async def test_the_risk_control_gate_also_consumes_nothing(self, guard):
        """A CAPTCHA is not a wrong answer -- and the message must say so."""
        adapter = CTF2Adapter(
            _SubmitClient(error=_client_error(429, fx.SUBMIT_RISK_CONTROL_PAYLOAD))
        )

        message = await platform_tools.submit_flag_via(adapter, REF, FLAG)

        assert guard.attempts(REF.key) == 0
        assert "HUMAN-VERIFICATION" in message
        assert "DO NOT retry" in message

    async def test_the_same_flag_can_be_retried_after_a_rejected_request(self, guard):
        """An error must not dedup-block the retry it did not charge for."""
        failing = CTF2Adapter(
            _SubmitClient(error=_client_error(400, fx.SUBMIT_INVALID_REQUEST_PAYLOAD))
        )
        await platform_tools.submit_flag_via(failing, REF, FLAG)

        working = CTF2Adapter(_SubmitClient(fx.SUBMIT_ACCEPTED_PAYLOAD))
        message = await platform_tools.submit_flag_via(working, REF, FLAG)

        assert "ACCEPTED" in message
        assert guard.is_accepted(REF.key) is True
