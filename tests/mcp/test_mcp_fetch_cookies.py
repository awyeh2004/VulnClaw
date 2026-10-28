"""Regression tests for the fetch tool's shared cookie-jar handling.

Covers the bug where brute_force_login synced session cookies into
MCPLifecycleManager._fetch_cookies, but _call_fetch created a fresh,
cookie-less httpx.AsyncClient per call and never read or wrote that jar.
"""

from __future__ import annotations

import json

import httpx
import pytest

from vulnclaw.config.domain_models import TaskConstraints
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.mcp.lifecycle import MCPLifecycleManager


def _manager() -> MCPLifecycleManager:
    return MCPLifecycleManager(VulnClawConfig())


def _patch_fetch_transport(monkeypatch, handler, seen_client_kwargs=None):
    class _RecordingAsyncClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            if seen_client_kwargs is not None:
                seen_client_kwargs.append(dict(kwargs))
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _RecordingAsyncClient)


@pytest.mark.asyncio
async def test_call_fetch_defaults_to_get_and_supports_https_without_tls_verification(
    monkeypatch,
):
    seen_client_kwargs: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == "https://example.com/"
        return httpx.Response(200, text="ok")

    _patch_fetch_transport(monkeypatch, handler, seen_client_kwargs)

    manager = _manager()
    result = await manager._call_fetch({"url": "https://example.com/"})

    assert "Request: GET https://example.com/" in result
    assert "Status: 200" in result
    assert seen_client_kwargs[0]["verify"] is False
    # Redirects are followed by the scoped redirect guard, not by httpx. The
    # client must stay ``follow_redirects=False`` so every destination host can
    # be checked before it is requested (measured 2026-10-21).
    assert seen_client_kwargs[0]["follow_redirects"] is False


@pytest.mark.asyncio
async def test_call_fetch_rejects_a_redirect_from_a_research_host_to_an_out_of_scope_host(
    monkeypatch,
):
    """The research-host exemption must not become a redirect pivot.

    Measured 2026-10-21: ``follow_redirects`` defaulted True while constraints
    were checked only for the initial URL, so a 302 from a research host could
    send the request to any internal/blocked host. Each hop is now checked with
    the research exemption disabled.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://duckduckgo.com/":
            return httpx.Response(302, headers={"location": "https://internal.test/secret"})
        raise AssertionError(f"unexpected request {request.url}")

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    manager.set_task_constraints(
        TaskConstraints(allowed_hosts=["example.com"], strict_mode=True)
    )
    result = await manager._call_fetch({"url": "https://duckduckgo.com/"})

    assert "任务范围拦截" in result, result
    assert "internal.test" in result, result


@pytest.mark.asyncio
async def test_call_fetch_follows_a_redirect_to_an_in_scope_host(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://example.com/old":
            return httpx.Response(301, headers={"location": "https://example.com/new"})
        assert str(request.url) == "https://example.com/new"
        return httpx.Response(200, text="landed")

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    manager.set_task_constraints(
        TaskConstraints(allowed_hosts=["example.com"], strict_mode=True)
    )
    result = await manager._call_fetch({"url": "https://example.com/old"})

    assert "Final URL: https://example.com/new" in result
    assert "landed" in result


@pytest.mark.asyncio
async def test_call_fetch_follows_a_redirect_between_research_hosts(monkeypatch):
    """Research -> research hops must survive the scope guard.

    Measured 2026-10-28 (DASBOOK 7.5.2 pdf隐写): the run fetched
    ``https://www.bing.com/search?q=...`` (allowed as a research host), bing
    answered 302 to ``cn.bing.com``, and the hop guard -- which disabled the
    research exemption unconditionally -- rejected it with
    ``Host cn.bing.com is outside allowed scope [...]``. Every search engine
    redirects like this (google -> www.google.com, duckduckgo ->
    html.duckduckgo.com), so a scoped CTF run could not search the web at all,
    which is exactly what the writeup policy says it may do read-only.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://www.bing.com/search":
            return httpx.Response(302, headers={"location": "https://cn.bing.com/search"})
        assert str(request.url) == "https://cn.bing.com/search"
        return httpx.Response(200, text="results")

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    manager.set_task_constraints(
        TaskConstraints(allowed_hosts=["example.com"], strict_mode=True)
    )
    result = await manager._call_fetch({"url": "https://www.bing.com/search"})

    assert "任务范围拦截" not in result, result
    assert "results" in result


@pytest.mark.asyncio
async def test_a_research_redirect_still_cannot_reach_a_blocked_host(monkeypatch):
    """The per-hop exemption must not launder a blocked destination."""
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://www.bing.com/search":
            return httpx.Response(302, headers={"location": "https://evil.example/x"})
        raise AssertionError(f"unexpected request {request.url}")

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    manager.set_task_constraints(
        TaskConstraints(
            allowed_hosts=["example.com"],
            blocked_hosts=["evil.example"],
            strict_mode=True,
        )
    )
    result = await manager._call_fetch({"url": "https://www.bing.com/search"})

    assert "任务范围拦截" in result, result
    assert "evil.example" in result, result


@pytest.mark.asyncio
async def test_call_fetch_stops_after_a_bounded_number_of_redirects(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://example.com/loop"})

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    result = await manager._call_fetch({"url": "https://example.com/loop"})

    assert "redirect limit" in result, result


@pytest.mark.asyncio
async def test_call_fetch_stops_when_redirect_chain_budget_is_exhausted(monkeypatch):
    import vulnclaw.mcp.lifecycle as lifecycle

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("budget should prevent the first request")

    monkeypatch.setattr(lifecycle, "_FETCH_CHAIN_BUDGET", 0.0)
    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    result = await manager._call_fetch({"url": "https://example.com/loop"})

    assert "redirect chain budget exceeded" in result, result


@pytest.mark.asyncio
async def test_call_fetch_retries_once_without_tls_after_certificate_failure(monkeypatch):
    seen_verify: list[bool] = []

    class RetryAsyncClient:
        def __init__(self, *args, **kwargs):
            self.verify = kwargs.get("verify")
            seen_verify.append(self.verify)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def request(self, **kwargs):
            request = httpx.Request(kwargs["method"], kwargs["url"])
            if self.verify:
                raise httpx.ConnectError(
                    "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed",
                    request=request,
                )
            return httpx.Response(200, request=request, text="ok-after-retry")

    monkeypatch.setattr(httpx, "AsyncClient", RetryAsyncClient)

    manager = _manager()
    result = await manager._call_fetch(
        {"url": "https://example.com/", "verify_tls": True}
    )

    assert seen_verify == [True, False]
    assert "TLS verification failed; retried once with verify_tls=false" in result
    assert "ok-after-retry" in result


@pytest.mark.asyncio
async def test_call_fetch_sends_json_body_headers_params_and_method(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "PUT"
        assert request.headers["x-test"] == "yes"
        assert request.url.params["a"] == "1"
        assert json.loads(request.content.decode()) == {"id": 1}
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"ok": True},
        )

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    result = await manager._call_fetch(
        {
            "url": "https://example.com/api",
            "method": "PUT",
            "headers": {"X-Test": "yes"},
            "params": {"a": "1"},
            "json": {"id": 1},
        }
    )

    assert "Request: PUT https://example.com/api" in result
    assert "Request body mode: json" in result
    assert '"ok": true' in result


@pytest.mark.asyncio
async def test_call_fetch_sends_raw_body_for_post(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"
        assert request.content == b"a=1&b=2"
        return httpx.Response(201, text="created")

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    result = await manager._call_fetch(
        {
            "url": "http://example.com/submit",
            "method": "POST",
            "headers": {"content-type": "application/x-www-form-urlencoded"},
            "body": "a=1&b=2",
        }
    )

    assert "Status: 201" in result
    assert "Request body mode: body" in result


@pytest.mark.asyncio
async def test_call_fetch_returns_full_body_by_default(monkeypatch):
    marker = "select-waf.php"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="A" * 3000 + marker)

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    result = await manager._call_fetch({"url": "https://example.com/"})

    assert marker in result
    assert "truncated from" not in result
    assert "Body (length" in result


@pytest.mark.asyncio
async def test_call_fetch_renders_highlighted_source_before_raw_body(monkeypatch):
    highlighted = """
    <code><span style="color:#0000BB">&lt;?php<br /></span>
    <span style="color:#007700">highlight_file(</span><span style="color:#0000BB">__FILE__</span><span style="color:#007700">);<br />
    if(!preg_match('/[oc]:\\d+:/i', $_COOKIE['user'])){<br />
        $user = unserialize($_COOKIE['user']);<br />
    }<br />
    class&nbsp;</span><span style="color:#0000BB">backDoor</span><span style="color:#007700">{ public function getInfo(){ eval($this->code); } }<br />
    </span></code>
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text=highlighted)

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    result = await manager._call_fetch({"url": "https://example.com/source.php"})

    assert "# Decoded highlighted source (auto)" in result
    assert "highlight_file(__FILE__);" in result
    assert "if(!preg_match('/[oc]:\\d+:/i', $_COOKIE['user'])){" in result
    assert "$user = unserialize($_COOKIE['user']);" in result
    assert "class backDoor{ public function getInfo(){ eval($this->code); } }" in result
    assert result.index("# Decoded highlighted source (auto)") < result.index("Body (length")


@pytest.mark.asyncio
async def test_call_fetch_can_opt_into_body_limit(monkeypatch):
    marker = "select-waf.php"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="A" * 3000 + marker)

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    result = await manager._call_fetch(
        {"url": "https://example.com/", "max_body_chars": 100}
    )

    assert marker not in result
    assert "Body (first 100 chars, truncated from" in result


@pytest.mark.asyncio
async def test_call_fetch_rejects_non_http_url():
    manager = _manager()

    result = await manager._call_fetch({"url": "file:///etc/passwd"})

    assert "fetch only supports absolute http/https URLs" in result


@pytest.mark.asyncio
async def test_call_fetch_persists_response_cookies_into_shared_jar(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"set-cookie": "session=abc123; Path=/"},
            text="ok",
        )

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    await manager._call_fetch({"url": "https://example.com/login", "method": "GET"})

    jar = manager._fetch_cookies
    assert jar is not None
    assert jar.get("session") == "abc123"


@pytest.mark.asyncio
async def test_call_fetch_sends_previously_stored_cookies(monkeypatch):
    seen_cookie_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookie_headers.append(request.headers.get("cookie"))
        return httpx.Response(200, text="post-login content")

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    manager._fetch_cookies = httpx.Cookies()
    manager._fetch_cookies.set("session", "abc123", domain="example.com", path="/")

    await manager._call_fetch({"url": "https://example.com/dashboard", "method": "GET"})

    assert seen_cookie_headers == ["session=abc123"]


@pytest.mark.asyncio
async def test_call_fetch_with_no_prior_session_sends_no_cookie_header(monkeypatch):
    seen_cookie_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookie_headers.append(request.headers.get("cookie"))
        return httpx.Response(200, text="ok")

    _patch_fetch_transport(monkeypatch, handler)

    manager = _manager()
    await manager._call_fetch({"url": "https://example.com/", "method": "GET"})

    assert seen_cookie_headers == [None]
