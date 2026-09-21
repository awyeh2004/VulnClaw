"""Client and GCS adapter must agree on WHO unwraps the envelope.

Round-5 review N1: ``gcs_platform.client._request`` returns ``_unwrap(payload)``
— the ``data`` member of the ``{code, message, data}`` envelope — while every
helper in the adapter indexed ``payload["data"]`` a second time. On the real
platform that made ``read_challenge`` yield an empty description/attachment list
and ``read_env``/``start_env`` collapse a live environment to ``STATE_NONE``.

The unit tests never caught it because their FakeClient returned the *envelope*
shape the real client never returns. These tests drive the REAL client through a
mocked HTTP transport into the adapter, so the two sides are pinned to each
other: whichever side changes its unwrapping, this fails.

(For contrast, ``ctf_platform.client._request`` returns the whole envelope, so
the CTF2 adapter must unwrap. The asymmetry is deliberate; it is what makes a
shape assumption here so easy to get wrong.)
"""

from __future__ import annotations

import httpx
import pytest

from vulnclaw.gcs_platform import client as gcs_client
from vulnclaw.platforms import base
from vulnclaw.platforms.base import ChallengeRef
from vulnclaw.platforms.gcs import (
    GCSAdapter,
    normalize_exercise_env,
    payload_body,
    row_of,
)

REF = ChallengeRef("gcs", "exercise", "", "10662")


def _envelope(data):
    """The unified reply the platform actually sends over the wire."""
    return {"code": "00000", "message": "", "data": data}


@pytest.fixture()
async def http_client(monkeypatch):
    """A real client whose HTTP layer is mocked, isolated per test."""
    state: dict = {"responses": [], "requests": []}

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        if not state["responses"]:
            return httpx.Response(404, json=_envelope(None))
        return httpx.Response(200, json=state["responses"].pop(0))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(gcs_client, "access_key", lambda: "test-key")
    monkeypatch.setattr(gcs_client, "get_client", lambda timeout=30.0: client)
    yield state
    await client.aclose()


async def test_read_env_sees_a_running_target(http_client):
    http_client["responses"].append(
        _envelope(
            {"name": "p1", "isNeedCheck": False, "exposeIps": ["10.0.0.1:1337"]}
        )
    )
    info = await GCSAdapter(gcs_client).read_env(REF)
    assert info.state == base.STATE_RUNNING, (
        "a live environment was normalized to "
        f"{info.state!r}: the adapter is unwrapping an already-unwrapped payload"
    )
    assert [ep.port for ep in info.endpoints] == [1337]


async def test_read_challenge_keeps_name_and_attachments(http_client):
    http_client["responses"].append(
        _envelope(
            {
                "name": "web-1",
                "description": "find the flag",
                "difficulty": "Easy",
                "isNeedInit": True,
                "fileList": [{"name": "a.zip", "url": "http://h/a.zip"}],
            }
        )
    )
    challenge = await GCSAdapter(gcs_client).read_challenge(REF)
    assert challenge.name == "web-1"
    assert challenge.needs_env is True
    assert [a.name for a in challenge.attachments] == ["a.zip"]


async def test_environment_ack_is_not_read_as_a_live_target(http_client):
    """The async-start path must poll, not report a target it never saw."""
    http_client["responses"].append(_envelope({"name": "p1"}))
    info = await GCSAdapter(gcs_client).start_env(REF)
    assert info.state == base.STATE_STARTING
    assert info.complete is False


async def test_event_info_is_populated(http_client):
    http_client["responses"].append(_envelope({"note": "N", "rule": "R"}))
    assert await GCSAdapter(gcs_client).event_info() == "N\nR"


async def test_notices_list_survives_the_round_trip(http_client):
    http_client["responses"].append(_envelope([{"id": 1, "title": "t"}]))
    assert await GCSAdapter(gcs_client).notices() == [{"id": 1, "title": "t"}]


async def test_submit_reports_a_correct_flag(http_client):
    http_client["responses"].append(_envelope({"isCorrect": True}))
    result = await GCSAdapter(gcs_client).submit_flag(REF, "flag{x}")
    assert result.judged is True
    assert result.accepted is True


async def test_a_bad_code_is_reported_not_silently_empty(http_client):
    http_client["responses"].append(
        {"code": "10001", "message": "no such exercise", "data": None}
    )
    with pytest.raises(gcs_client.GCSError):
        await GCSAdapter(gcs_client).read_env(REF)


# ── the accessor contract itself ────────────────────────────────────────


def test_client_unwraps_the_envelope():
    """Pin the client side: ``_request`` returns ``data``, not the envelope."""
    assert gcs_client._unwrap({"code": "00000", "message": "", "data": {"a": 1}}) == {"a": 1}


def test_adapter_accessors_treat_the_payload_as_the_body():
    body = {"name": "x", "isNeedCheck": False}
    assert payload_body(body) is body
    assert row_of(body) == body
    # A body carrying a "data" member must not be replaced by it.
    sneaky = {"name": "x", "data": {"name": "WRONG"}}
    assert row_of(sneaky) == sneaky
