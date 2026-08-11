"""Tests for the Web UI bearer-token file logic (vulnclaw.web.auth).

The loopback-vs-remote middleware gate is covered in test_web.py
(TestWebAuthLoopback); this file covers token generation/verification, kept off
the real home directory via monkeypatch.
"""

from __future__ import annotations

import vulnclaw.web.auth as auth


def _redirect_token_dir(monkeypatch, tmp_path):
    token_dir = tmp_path / ".vulnclaw"
    monkeypatch.setattr(auth, "TOKEN_DIR", token_dir)
    monkeypatch.setattr(auth, "TOKEN_FILE", token_dir / "web_token")
    return token_dir / "web_token"


class TestTokenFile:
    def test_generate_persists_and_is_reused(self, monkeypatch, tmp_path):
        token_file = _redirect_token_dir(monkeypatch, tmp_path)
        first = auth.generate_token()
        assert first and token_file.is_file()
        assert token_file.read_text(encoding="utf-8").strip() == first
        # A second call reuses the persisted token rather than minting a new one.
        assert auth.generate_token() == first

    def test_verify_token_matches_and_rejects(self, monkeypatch, tmp_path):
        _redirect_token_dir(monkeypatch, tmp_path)
        token = auth.generate_token()
        assert auth.verify_token(token) is True
        assert auth.verify_token("not-the-token") is False

    def test_verify_token_false_when_no_file(self, monkeypatch, tmp_path):
        token_file = _redirect_token_dir(monkeypatch, tmp_path)
        assert not token_file.exists()
        assert auth.verify_token("anything") is False

    def test_client_is_loopback_variants(self):
        assert auth._client_is_loopback("127.0.0.1")
        assert auth._client_is_loopback("::1")
        assert auth._client_is_loopback("localhost")
        assert not auth._client_is_loopback("8.8.8.8")
        assert not auth._client_is_loopback(None)


class _FakeRequest:
    """Minimal stand-in for the Starlette Request surface the auth gate reads."""

    class _URL:
        def __init__(self, path):
            self.path = path

    class _Client:
        def __init__(self, host):
            self.host = host

    def __init__(self, path="/api/tasks", host="192.168.181.1", headers=None, cookies=None):
        self.url = self._URL(path)
        self.client = self._Client(host) if host else None
        self.headers = headers or {}
        self.cookies = cookies or {}


class TestSessionCookie:
    """A browser behind Docker's port NAT is never a loopback client, and the
    shipped UI can send no bearer header — the session cookie is what lets it
    authenticate at all. See the module docstring in vulnclaw.web.auth."""

    def test_valid_cookie_is_accepted(self, monkeypatch, tmp_path):
        _redirect_token_dir(monkeypatch, tmp_path)
        token = auth.generate_token()
        request = _FakeRequest(cookies={auth.SESSION_COOKIE: token})
        assert auth.request_has_valid_session(request) is True

    def test_wrong_or_absent_cookie_is_rejected(self, monkeypatch, tmp_path):
        _redirect_token_dir(monkeypatch, tmp_path)
        auth.generate_token()
        assert auth.request_has_valid_session(_FakeRequest()) is False
        assert (
            auth.request_has_valid_session(
                _FakeRequest(cookies={auth.SESSION_COOKIE: "forged"})
            )
            is False
        )

    async def test_middleware_lets_a_docker_browser_through_with_cookie(
        self, monkeypatch, tmp_path
    ):
        """The reported bug: GET /api/config from 192.168.181.1 returned 401."""
        import vulnclaw.web.app as web_app

        if not web_app.FASTAPI_AVAILABLE:
            import pytest

            pytest.skip("FastAPI is not installed in this environment")

        _redirect_token_dir(monkeypatch, tmp_path)
        token = auth.generate_token()
        mw = auth.AuthMiddleware(None)

        async def call_next(_req):
            return "PASSED"

        # Docker bridge gateway address, exactly as seen in the uvicorn log.
        no_cookie = await mw.dispatch(_FakeRequest(path="/api/config"), call_next)
        assert getattr(no_cookie, "status_code", None) == 401

        with_cookie = _FakeRequest(
            path="/api/config", cookies={auth.SESSION_COOKIE: token}
        )
        assert await mw.dispatch(with_cookie, call_next) == "PASSED"

    def test_attach_session_cookie_is_httponly_and_strict(self, monkeypatch, tmp_path):
        import vulnclaw.web.app as web_app

        if not web_app.FASTAPI_AVAILABLE:
            import pytest

            pytest.skip("FastAPI is not installed in this environment")

        from starlette.responses import Response

        _redirect_token_dir(monkeypatch, tmp_path)
        token = auth.generate_token()
        response = Response()
        auth.attach_session_cookie(response, token)

        header = response.headers["set-cookie"]
        assert f"{auth.SESSION_COOKIE}={token}" in header
        assert "HttpOnly" in header
        assert "samesite=strict" in header.lower()
