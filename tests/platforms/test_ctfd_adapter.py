"""CTFd adapter: the platform most public CTFs actually use.

Field names come from CTFd's own source (`CTFd/api/v1/challenges.py`, read
2026-11-21), because the published docs show only "200 Success" for the attempt
endpoint — not enough to normalize against. The live instance could not be probed
either: before a competition opens, CTFd 302s `/api/v1/challenges` to the login
page, so every unauthenticated probe returns HTML.

Two things are worth testing harder than the plumbing:

* **`judged` vs `accepted`.** CTFd answers ``correct`` / ``partial`` /
  ``incorrect`` / ``already_solved`` / ``ratelimited`` / ``authentication_required``.
  The last two are *not* judgements of the flag. Collapsing them into "rejected"
  would burn attempts and tell the run its answer was wrong when the platform
  never looked at it.
* **No environment.** CTFd has no per-challenge environment; ``read_env`` returns
  ``None`` (the protocol's documented "not applicable"), and ``start_env`` reports
  ``not_required``. Pretending otherwise would send a run hunting for a target
  that does not exist.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from vulnclaw.platforms import base
from vulnclaw.platforms.ctfd import (
    CTFdAdapter,
    CTFdError,
    build_adapter,
    _basename,
)
from vulnclaw.platforms.refs import RefError


def _adapter(**kwargs: Any) -> CTFdAdapter:
    return CTFdAdapter(base_url="https://ctf.example", token="tok", **kwargs)


class _FakeResponse:
    def __init__(self, body: dict | None) -> None:
        self._body = json.dumps(body).encode() if body is not None else b""

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _patch_urlopen(monkeypatch, *, body: dict | None = None, seen: list | None = None):
    def fake_urlopen(request, timeout=None):  # noqa: ARG001
        if seen is not None:
            seen.append(request)
        return _FakeResponse(body)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)


# ── config ──────────────────────────────────────────────────────────────


def test_unconfigured_adapter_reports_itself():
    assert CTFdAdapter().is_configured() is False
    assert CTFdAdapter(base_url="https://x", token="").is_configured() is False
    assert CTFdAdapter(base_url="", token="t").is_configured() is False
    assert _adapter().is_configured() is True


def test_requests_fail_loud_when_unconfigured():
    import asyncio

    with pytest.raises(CTFdError) as exc:
        asyncio.run(CTFdAdapter().list_challenges(None))

    assert "not configured" in str(exc.value)


def test_build_adapter_reads_the_config_section():
    class _Section:
        url = "https://ctf.example"
        token = "abc"

    class _Platforms:
        ctfd = _Section()

    class _Config:
        platforms = _Platforms()

    adapter = build_adapter(_Config())

    assert adapter.is_configured() is True


def test_build_adapter_tolerates_no_config():
    assert build_adapter(None).is_configured() is False
    assert build_adapter(object()).is_configured() is False


# ── refs ────────────────────────────────────────────────────────────────


def test_challenge_ref_round_trips():
    adapter = _adapter()

    ref = adapter.parse_ref("challenge:42")

    assert ref.token() == "ctfd:challenge:42"
    assert adapter.make_ref(kind="challenge", id="42").token() == "ctfd:challenge:42"


def test_unknown_kind_is_rejected():
    with pytest.raises(RefError):
        _adapter().parse_ref("environment:1")


def test_category_ref_keeps_its_name():
    ref = _adapter().parse_ref("category:web")

    assert ref.token() == "ctfd:category:web"


# ── challenges ──────────────────────────────────────────────────────────


def test_list_maps_the_documented_fields(monkeypatch):
    import asyncio

    payload = {
        "success": True,
        "data": [
            {
                "id": 1,
                "name": "Warmup",
                "category": "misc",
                "value": 100,
                "description": "easy one",
                "solved_by_me": False,
                "connection_info": "",
                "files": ["https://ctf.example/files/x/chal.zip"],
            },
            {
                "id": 2,
                "name": "Pwn1",
                "category": "pwn",
                "value": 500,
                "description": "",
                "solved_by_me": True,
                "connection_info": "nc ctf.example 1337",
                "files": [],
            },
        ],
    }
    _patch_urlopen(monkeypatch, body=payload)

    challenges = asyncio.run(_adapter().list_challenges(None))

    assert [c.name for c in challenges] == ["Warmup", "Pwn1"]
    assert challenges[0].attachments[0].name == "chal.zip"
    assert challenges[0].needs_env is False
    assert challenges[1].needs_env is True
    assert challenges[1].solved is True
    assert challenges[1].score == "500"


def test_list_filters_by_category(monkeypatch):
    import asyncio

    from vulnclaw.platforms.refs import CorpusRef

    payload = {
        "success": True,
        "data": [
            {"id": 1, "name": "A", "category": "web"},
            {"id": 2, "name": "B", "category": "pwn"},
        ],
    }
    _patch_urlopen(monkeypatch, body=payload)
    adapter = _adapter()

    # list_challenges takes a CorpusRef, not a ChallengeRef — the corpus id is the
    # category name here.
    corpus = CorpusRef(adapter.name, "category", "web")
    web = asyncio.run(adapter.list_challenges(corpus))

    assert [c.name for c in web] == ["A"]


def test_attachment_mapping_handles_both_shapes(monkeypatch):
    """CTFd has returned plain URLs and {url,name} objects across versions."""
    import asyncio

    payload = {
        "success": True,
        "data": [
            {
                "id": 1,
                "name": "x",
                "category": "misc",
                "files": [
                    "https://ctf.example/files/a/one.bin",
                    {"url": "https://ctf.example/files/b/two.bin", "name": "two.bin"},
                ],
            }
        ],
    }
    _patch_urlopen(monkeypatch, body=payload)

    challenge = asyncio.run(_adapter().list_challenges(None))[0]

    names = [a.name for a in challenge.attachments]
    assert names == ["one.bin", "two.bin"]


def test_read_challenge_unwraps_data(monkeypatch):
    import asyncio

    payload = {"success": True, "data": {"id": 7, "name": "Solo", "category": "crypto", "value": 300}}
    _patch_urlopen(monkeypatch, body=payload)
    adapter = _adapter()

    challenge = asyncio.run(adapter.read_challenge(adapter.parse_ref("challenge:7")))

    assert challenge.name == "Solo"
    assert challenge.ref.token() == "ctfd:challenge:7"


# ── no environment concept ──────────────────────────────────────────────


def test_read_env_returns_none_because_ctfd_has_none():
    """None is the protocol's "not applicable", not an error."""
    import asyncio

    adapter = _adapter()
    ref = adapter.parse_ref("challenge:1")

    assert asyncio.run(adapter.read_env(ref)) is None


def test_start_env_reports_not_required():
    import asyncio

    adapter = _adapter()
    ref = adapter.parse_ref("challenge:1")

    info = asyncio.run(adapter.start_env(ref))

    assert info.state == base.STATE_NOT_REQUIRED
    assert info.complete is True
    assert info.usable is True


def test_stop_env_is_a_noop():
    import asyncio

    adapter = _adapter()
    assert asyncio.run(adapter.stop_env(adapter.parse_ref("challenge:1"))) is None


# ── submission ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "status,accepted,judged",
    [
        ("correct", True, True),
        ("already_solved", True, True),
        ("incorrect", False, True),
        ("partial", False, True),
        ("ratelimited", False, False),
        ("authentication_required", False, False),
    ],
)
def test_submission_outcomes_map_to_judged(monkeypatch, status, accepted, judged):
    """Only *judged* outcomes consume an attempt.

    ``ratelimited`` and ``authentication_required`` mean the platform never looked
    at the flag. Reporting them as rejected would burn a submission and tell the
    run its answer was wrong.
    """
    import asyncio

    _patch_urlopen(monkeypatch, body={"success": True, "data": {"status": status, "message": "m"}})
    adapter = _adapter()

    result = asyncio.run(adapter.submit_flag(adapter.parse_ref("challenge:3"), "flag{x}"))

    assert result.accepted is accepted
    assert result.judged is judged


def test_submission_sends_numeric_challenge_id(monkeypatch):
    """CTFd type-checks the id; a numeric string is not always accepted."""
    import asyncio

    seen: list = []
    _patch_urlopen(monkeypatch, body={"success": True, "data": {"status": "correct"}}, seen=seen)
    adapter = _adapter()

    asyncio.run(adapter.submit_flag(adapter.parse_ref("challenge:3"), "flag{x}"))

    body = json.loads(seen[0].data.decode())
    assert body["challenge_id"] == 3
    assert isinstance(body["challenge_id"], int)
    assert body["submission"] == "flag{x}"


def test_submission_without_data_is_not_judged(monkeypatch):
    import asyncio

    _patch_urlopen(monkeypatch, body={"success": False})
    adapter = _adapter()

    result = asyncio.run(adapter.submit_flag(adapter.parse_ref("challenge:3"), "flag{x}"))

    assert result.judged is False
    assert result.accepted is False


# ── auth hygiene ────────────────────────────────────────────────────────


def test_token_is_sent_as_authorization_header(monkeypatch):
    import asyncio

    seen: list = []
    _patch_urlopen(monkeypatch, body={"success": True, "data": []}, seen=seen)

    asyncio.run(_adapter().list_challenges(None))

    headers = {k.lower(): v for k, v in seen[0].headers.items()}
    assert headers.get("authorization") == "Token tok"


def test_auth_failure_message_never_contains_the_token(monkeypatch):
    """An error path that echoes the header would leak the credential into logs."""
    import asyncio
    import urllib.error

    def boom(request, timeout=None):  # noqa: ARG001
        raise urllib.error.HTTPError("u", 401, "Unauthorized", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", boom)
    # A distinctive token: "tok" would match inside "platforms.ctfd.token" and the
    # assertion below would pass for the wrong reason.
    adapter = CTFdAdapter(base_url="https://ctf.example", token="SECRET-VALUE-9f3a")

    with pytest.raises(CTFdError) as exc:
        asyncio.run(adapter.list_challenges(None))

    assert "SECRET-VALUE-9f3a" not in str(exc.value)
    assert "token" in str(exc.value).lower()


def test_non_json_response_is_reported_as_a_likely_login_redirect(monkeypatch):
    """Before a competition opens, CTFd 302s the API to the login page."""
    import asyncio

    class _Html(_FakeResponse):
        def __init__(self):
            self._body = b"<!doctype html><html>login</html>"

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: _Html())

    with pytest.raises(CTFdError) as exc:
        asyncio.run(_adapter().list_challenges(None))

    assert "login redirect" in str(exc.value) or "non-JSON" in str(exc.value)


def test_basename_strips_query_and_decodes():
    assert _basename("https://h/files/abc/a%20b.zip?x=1") == "a b.zip"

def test_token_can_come_from_the_environment(monkeypatch):
    """Config files get pasted into bug reports; the environment does not."""
    monkeypatch.setenv("CTFD_TOKEN", "env-token")
    monkeypatch.setenv("CTFD_URL", "https://env.example")

    adapter = build_adapter(None)

    assert adapter.is_configured() is True


def test_config_token_wins_over_the_environment(monkeypatch):
    monkeypatch.setenv("CTFD_TOKEN", "env-token")

    class _Section:
        url = "https://cfg.example"
        token = "cfg-token"

    class _Platforms:
        ctfd = _Section()

    class _Config:
        platforms = _Platforms()

    adapter = build_adapter(_Config())

    assert adapter.is_configured() is True
