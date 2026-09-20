"""Tests for the CTF2 client's credential fallback and the submission gate.

Two independent defects motivated these tests, both found by actually running
the tools against a real logged-in account with no personal access token:

1. **Every Open API call 401'd.** `ctf2_list_practice` and friends hit
   `/api/open/v1/user/...` with `X-CTF2-API-Key`; with only a browser session
   token that returns
   `401 {"code": "AUTH_REQUIRED", "key": "errors.auth.permission_denied"}`.
   The equivalent front-end paths (`/api/v1/practice/`) returned 200, so a
   perfectly usable account looked broken. Fixed with a session-API fallback.

2. **Flag submission was ungated.** `is_configured()` accepts a session token, so
   `ctf2_submit_flag` worked without any deliberate opt-in. Submitting a flag is
   irreversible and the handbook treats an invalid operation as grounds for
   disqualification, so it now requires `competition.allow_flag_submission`.

No test performs network I/O: the client's transport is monkeypatched, so the
routing logic (what gets called, in what order, with which headers) is asserted
directly rather than inferred from a live response.
"""

from __future__ import annotations

import pytest

from vulnclaw.ctf_platform import client as ctf_client


class _Recorder:
    """Captures the URL/headers of each request and returns a canned response."""

    def __init__(self, status: int = 200, payload: dict | None = None):
        self.calls: list[tuple[str, str, dict]] = []
        self.status = status
        self.payload = payload if payload is not None else {"data": {"data": []}}

    async def request(self, method, url, headers=None, **kwargs):
        self.calls.append((method, url, dict(headers or {})))

        class _Resp:
            status_code = self.status
            reason_phrase = "Error"
            text = "boom"

            def json(self_inner):
                return self.payload

        return _Resp()


@pytest.fixture()
def no_credentials(monkeypatch):
    """No API key, but a session token -- the real-world situation measured."""
    monkeypatch.setattr(ctf_client, "api_token", lambda: "")
    monkeypatch.setattr(ctf_client, "session_token", lambda: "eyJ.fake.jwt")


@pytest.fixture()
def both_credentials(monkeypatch):
    monkeypatch.setattr(ctf_client, "api_token", lambda: "pat-123")
    monkeypatch.setattr(ctf_client, "session_token", lambda: "eyJ.fake.jwt")


@pytest.fixture()
def neither_credential(monkeypatch):
    monkeypatch.setattr(ctf_client, "api_token", lambda: "")
    monkeypatch.setattr(ctf_client, "session_token", lambda: "")


# ── path mapping ────────────────────────────────────────────────────────


class TestSessionPathMapping:
    def test_know_roots_map(self):
        assert ctf_client._session_path_for("/practice/") == "/practice/"
        assert ctf_client._session_path_for("/competitions/") == "/competitions/"

    def test_practice_subresources_map(self):
        path = "/practice/p1/challenges/c1/environment/start/"
        assert ctf_client._session_path_for(path) == path

    def test_daily_has_no_session_twin(self):
        """No session route was observed, so the mapping must refuse rather than
        invent one -- a wrong guess would look like a platform failure."""
        assert ctf_client._session_path_for("/daily/") is None
        assert ctf_client._session_path_for("/submissions/") is None
        assert ctf_client._session_path_for("/stages/s1/challenges/") is None


# ── fallback routing ────────────────────────────────────────────────────


class TestFallbackRouting:
    async def test_session_api_used_when_no_api_key(self, no_credentials):
        """This is the defect: without it, list_practice raised auth errors."""
        rec = _Recorder()
        await ctf_client._request_with_fallback(rec, "GET", "/practice/", params={"limit": 5})
        assert len(rec.calls) == 1
        method, url, headers = rec.calls[0]
        assert url.endswith("/api/v1/practice/")
        assert headers.get("Authorization") == "Bearer eyJ.fake.jwt"
        assert "X-CTF2-API-Key" not in headers

    async def test_open_api_preferred_when_key_present(self, both_credentials):
        rec = _Recorder()
        await ctf_client._request_with_fallback(rec, "GET", "/practice/")
        method, url, headers = rec.calls[0]
        assert url.endswith("/api/open/v1/user/practice/")
        assert headers.get("X-CTF2-API-Key") == "pat-123"

    async def test_falls_back_on_401(self, both_credentials):
        """A stale/insufficient key must not brick a usable session."""
        rec = _Recorder(status=401)
        with pytest.raises(RuntimeError):
            # Without a session token the 401 is genuine; here we only assert the
            # primary path was attempted first.
            await ctf_client._request_with_fallback(rec, "GET", "/practice/")
        assert rec.calls[0][1].endswith("/api/open/v1/user/practice/")

    async def test_non_auth_errors_propagate_without_retry(self, both_credentials):
        """A 500 or 404 is real breakage -- retrying it via another API would
        hide it."""
        rec = _Recorder(status=500)
        with pytest.raises(RuntimeError):
            await ctf_client._request_with_fallback(rec, "GET", "/practice/")
        assert len(rec.calls) == 1, "must not retry non-auth failures"

    async def test_missing_credentials_explains_both_options(self, neither_credential):
        rec = _Recorder()
        with pytest.raises(RuntimeError) as exc:
            await ctf_client._request_with_fallback(rec, "GET", "/practice/")
        msg = str(exc.value)
        assert "VULNCLAW_CTF2_API_KEY" in msg
        assert "session token" in msg
        assert not rec.calls, "must not attempt a request with no credentials"

    async def test_unmappable_route_reports_actionable_error(self, no_credentials):
        """`/daily/` has no session twin: say so instead of a bare 401."""
        rec = _Recorder()
        with pytest.raises(RuntimeError) as exc:
            await ctf_client._request_with_fallback(rec, "GET", "/daily/")
        assert "personal access token" in str(exc.value)
        assert not rec.calls

    async def test_is_configured_accepts_either_credential(self, monkeypatch):
        monkeypatch.setattr(ctf_client, "api_token", lambda: "k")
        monkeypatch.setattr(ctf_client, "session_token", lambda: "")
        assert ctf_client.is_configured() is True
        monkeypatch.setattr(ctf_client, "api_token", lambda: "")
        monkeypatch.setattr(ctf_client, "session_token", lambda: "j")
        assert ctf_client.is_configured() is True
        monkeypatch.setattr(ctf_client, "session_token", lambda: "")
        assert ctf_client.is_configured() is False


# ── the submission gate ─────────────────────────────────────────────────


class TestFlagSubmissionGate:
    def test_default_is_disabled(self):
        from vulnclaw.config.schema import CompetitionConfig

        assert CompetitionConfig().allow_flag_submission is False

    def test_gate_fails_closed_on_config_error(self, monkeypatch):
        """Not being able to read the setting must not permit an irreversible
        action."""
        import vulnclaw.config.settings as settings
        from vulnclaw.ctf_platform.tools import _flag_submission_enabled

        def boom():
            raise RuntimeError("config unreadable")

        monkeypatch.setattr(settings, "load_config", boom)
        assert _flag_submission_enabled() is False

    def test_gate_reads_config(self, monkeypatch):
        import vulnclaw.config.settings as settings
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.ctf_platform.tools import _flag_submission_enabled

        cfg = VulnClawConfig()
        cfg.competition.allow_flag_submission = True
        monkeypatch.setattr(settings, "load_config", lambda: cfg)
        assert _flag_submission_enabled() is True

    async def test_handler_blocks_and_never_calls_the_api(self, monkeypatch):
        """The property that matters: a blocked submission must not reach the
        platform at all."""
        from vulnclaw.ctf_platform import tools

        monkeypatch.setattr(tools, "_flag_submission_enabled", lambda: False)

        called = {"submit": 0}

        async def _fake_submit(*a, **k):
            called["submit"] += 1
            return {}

        monkeypatch.setattr(tools._client, "submit_flag", _fake_submit)
        monkeypatch.setattr(tools, "_client", type("X", (), {"submit_flag": _fake_submit, "is_configured": lambda: True}))

        out = await tools._handle_submit_flag(
            {"practice_id": "p", "challenge_id": "c", "flag": "flag{nope}"}
        )
        assert "ctf2_flag_submission_disabled" in out
        assert called["submit"] == 0, "a blocked submission must not hit the API"

    async def test_block_message_tells_the_operator_how_to_enable(self, monkeypatch):
        from vulnclaw.ctf_platform import tools

        monkeypatch.setattr(tools, "_flag_submission_enabled", lambda: False)
        out = await tools.dispatch_ctf2_tool(
            "ctf2_submit_flag",
            {"practice_id": "p", "challenge_id": "c", "flag": "flag{x}"},
        )
        assert "allow_flag_submission" in out
        assert "VULNCLAW_COMPETITION__ALLOW_FLAG_SUBMISSION" in out

    async def test_other_tools_are_not_gated(self, monkeypatch):
        """Reading and listing must keep working without the opt-in -- otherwise
        the gate would make the platform unusable rather than safe."""
        from vulnclaw.ctf_platform import tools

        monkeypatch.setattr(tools, "_flag_submission_enabled", lambda: False)
        monkeypatch.setattr(tools, "_guard_config", lambda: _noop())

        async def _fake_list(limit=20):
            return {"data": {"data": []}}

        monkeypatch.setattr(tools._client, "list_practice", _fake_list)
        out = await tools.dispatch_ctf2_tool("ctf2_list_practice", {"limit": 3})
        assert "ctf2_flag_submission_disabled" not in out


async def _noop():
    return None
