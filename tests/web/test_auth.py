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


class TestDnsRebindingCannotBorrowTheLocalExemption:
    """C3 (open since round5): the loopback exemption trusted the peer address alone.

    A page on an attacker-controlled domain whose DNS is re-pointed at 127.0.0.1 reaches
    the server from a loopback peer. On that field the request is indistinguishable from
    the operator's own browser, so the whole `/api` surface used to be reachable with no
    credentials at all. The Host header is the field the attacker cannot make loopback
    while still talking to their own domain, and it is now required.
    """

    def test_host_is_loopback_variants(self):
        assert auth._host_is_loopback("127.0.0.1")
        assert auth._host_is_loopback("127.0.0.1:3080")
        assert auth._host_is_loopback("127.0.0.5")          # the whole /8 is loopback
        assert auth._host_is_loopback("localhost")
        assert auth._host_is_loopback("LOCALHOST:3080")
        assert auth._host_is_loopback("localhost.")          # FQDN spelling
        assert auth._host_is_loopback("::1")
        assert auth._host_is_loopback("[::1]:3080")

    def test_a_foreign_or_missing_host_is_not_loopback(self):
        for host in (
            None,
            "",
            "evil.com",
            "evil.com:3080",
            "localhost.evil.com",       # suffix lookalike
            "127.0.0.1.evil.com",
            "10.0.0.5",
            "8.8.8.8",
            "0.0.0.0",
        ):
            assert not auth._host_is_loopback(host), host

    async def test_a_rebound_request_is_rejected(self, monkeypatch, tmp_path):
        """The finding itself: loopback peer + attacker Host + no token => 401."""
        _redirect_token_dir(monkeypatch, tmp_path)
        auth.generate_token()
        mw = auth.AuthMiddleware(None)

        async def call_next(_req):
            return "PASSED"

        rebound = _FakeRequest(
            path="/api/config",
            host="127.0.0.1",
            headers={"Host": "attacker.example"},
        )
        response = await mw.dispatch(rebound, call_next)
        assert getattr(response, "status_code", None) == 401

    async def test_the_refusal_names_the_reverse_proxy_escape_hatch(self, monkeypatch, tmp_path):
        """A working setup (local reverse proxy) must not be left guessing."""
        _redirect_token_dir(monkeypatch, tmp_path)
        auth.generate_token()
        mw = auth.AuthMiddleware(None)

        async def call_next(_req):
            return "PASSED"

        response = await mw.dispatch(
            _FakeRequest(path="/api/config", host="127.0.0.1", headers={"Host": "ui.internal"}),
            call_next,
        )
        detail = response.body.decode()
        assert auth.TRUSTED_HOSTS_ENV in detail

    async def test_the_local_ui_still_works_without_any_token(self, monkeypatch, tmp_path):
        _redirect_token_dir(monkeypatch, tmp_path)
        auth.generate_token()
        mw = auth.AuthMiddleware(None)

        async def call_next(_req):
            return "PASSED"

        for host_header in ("127.0.0.1:3080", "localhost:3080", "[::1]:3080"):
            assert (
                await mw.dispatch(
                    _FakeRequest(path="/api/config", host="127.0.0.1", headers={"Host": host_header}),
                    call_next,
                )
                == "PASSED"
            ), host_header

    async def test_the_host_requirement_never_helps_a_remote_client(self, monkeypatch, tmp_path):
        """A loopback Host from a remote peer must not be exempted either."""
        _redirect_token_dir(monkeypatch, tmp_path)
        auth.generate_token()
        mw = auth.AuthMiddleware(None)

        async def call_next(_req):
            return "PASSED"

        remote = _FakeRequest(
            path="/api/config", host="203.0.113.7", headers={"Host": "127.0.0.1:3080"}
        )
        assert getattr(await mw.dispatch(remote, call_next), "status_code", None) == 401

    async def test_an_operator_trusted_host_is_honoured_for_loopback_peers(
        self, monkeypatch, tmp_path
    ):
        """The escape hatch: a local reverse proxy, declared explicitly."""
        _redirect_token_dir(monkeypatch, tmp_path)
        auth.generate_token()
        monkeypatch.setenv(auth.TRUSTED_HOSTS_ENV, "ui.internal, 10.0.0.5:3080")
        mw = auth.AuthMiddleware(None)

        async def call_next(_req):
            return "PASSED"

        for host_header in ("ui.internal", "ui.internal:443", "10.0.0.5:3080"):
            assert (
                await mw.dispatch(
                    _FakeRequest(path="/api/config", host="127.0.0.1", headers={"Host": host_header}),
                    call_next,
                )
                == "PASSED"
            ), host_header

    async def test_the_trusted_host_list_does_not_exempt_remote_peers(
        self, monkeypatch, tmp_path
    ):
        """Declaring a host local must not become a way to skip auth from outside."""
        _redirect_token_dir(monkeypatch, tmp_path)
        auth.generate_token()
        monkeypatch.setenv(auth.TRUSTED_HOSTS_ENV, "ui.internal")
        mw = auth.AuthMiddleware(None)

        async def call_next(_req):
            return "PASSED"

        remote = _FakeRequest(
            path="/api/config", host="203.0.113.7", headers={"Host": "ui.internal"}
        )
        assert getattr(await mw.dispatch(remote, call_next), "status_code", None) == 401


class TestTheRealAppRefusesAReboundRequest:
    """The same finding, on the wired app rather than a stand-in request.

    The middleware tests above use a minimal fake; this one goes through FastAPI's own
    stack with a loopback client address, which is what a rebound browser actually is.
    """

    def _client(self, monkeypatch, tmp_path):
        import pytest

        import vulnclaw.web.app as web_app

        if not web_app.FASTAPI_AVAILABLE:
            pytest.skip("FastAPI is not installed in this environment")

        TestClient = pytest.importorskip("fastapi.testclient").TestClient
        _redirect_token_dir(monkeypatch, tmp_path)
        token = auth.generate_token()
        return TestClient(web_app.create_app(), client=("127.0.0.1", 51234)), token

    def test_loopback_host_is_served_and_a_foreign_host_is_refused(self, monkeypatch, tmp_path):
        client, token = self._client(monkeypatch, tmp_path)

        assert (
            client.get("/api/config", headers={"Host": "127.0.0.1:3080"}).status_code == 200
        ), "the shipped local UI must keep working with no credentials"
        rebound = client.get("/api/config", headers={"Host": "attacker.example"})
        assert rebound.status_code == 401, "a DNS-rebound request must not inherit the exemption"

        # The exemption is not the only way in: a real credential still works from any Host.
        assert (
            client.get(
                "/api/config",
                headers={"Host": "attacker.example", "Authorization": f"Bearer {token}"},
            ).status_code
            == 200
        )
        # /api/health stays exempt so uptime probes keep working.
        assert client.get("/api/health", headers={"Host": "attacker.example"}).status_code == 200


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
