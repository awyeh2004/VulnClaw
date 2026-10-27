from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest

from vulnclaw.agent.tools.http_probe import _request_with_scoped_redirects
from vulnclaw.config.domain_models import TaskConstraints
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.mcp.lifecycle import MCPLifecycleManager


class _Agent:
    config = SimpleNamespace()


def _probe_item(url: str, **extra):
    item = {
        "method": "GET",
        "url": url,
        "headers": {"Authorization": "Bearer secret", "X-Keep": "yes"},
        "cookies": {"session": "explicit-secret"},
        "params": {"from": "original"},
        "data": None,
        "json": None,
    }
    item.update(extra)
    return item


def test_probe_real_mock_transport_strips_explicit_credentials_and_query_on_cross_origin():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(
                302,
                headers={"location": "https://other.test/next?to=target"},
                request=request,
            )
        return httpx.Response(200, text="landed", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    try:
        response, error = _request_with_scoped_redirects(
            client,
            _probe_item("https://example.test/start"),
            agent=_Agent(),
            follow_redirects=True,
        )
    finally:
        client.close()

    assert error is None
    assert response.status_code == 200
    assert len(seen) == 2
    assert seen[0].headers["authorization"] == "Bearer secret"
    assert seen[0].headers["cookie"] == "session=explicit-secret"
    assert seen[1].headers.get("authorization") is None
    assert seen[1].headers.get("cookie") is None
    assert str(seen[1].url) == "https://other.test/next?to=target"
    assert "from=original" not in str(seen[1].url)


def test_probe_real_mock_transport_default_port_is_same_origin_but_scheme_switch_is_not():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(302, headers={"location": "https://example.test:443/next"}, request=request)
        return httpx.Response(200, text="ok", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    try:
        response, error = _request_with_scoped_redirects(
            client,
            _probe_item("https://example.test/start"),
            agent=_Agent(),
            follow_redirects=True,
        )
    finally:
        client.close()
    assert error is None
    assert seen[1].headers["authorization"] == "Bearer secret"

    seen.clear()
    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    try:
        response, error = _request_with_scoped_redirects(
            client,
            _probe_item("http://example.test/start"),
            agent=_Agent(),
            follow_redirects=True,
        )
    finally:
        client.close()
    assert error is None
    assert seen[1].headers.get("authorization") is None


@pytest.mark.asyncio
async def test_fetch_real_mock_transport_strips_explicit_cookies_and_does_not_reapply_params(monkeypatch):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(
                302,
                headers={"location": "https://other.test/next?to=target"},
                request=request,
            )
        return httpx.Response(200, text="landed", request=request)

    def factory(**kwargs):
        assert kwargs["follow_redirects"] is False
        kwargs.pop("targets", None)
        kwargs.pop("proxy", None)
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr("vulnclaw.utils.http_client.async_http_client", factory)
    manager = MCPLifecycleManager(VulnClawConfig())
    result = await manager._call_fetch(
        {
            "url": "https://example.test/start",
            "headers": {"Authorization": "Bearer secret"},
            "cookies": {"session": "explicit-secret"},
            "params": {"from": "original"},
        }
    )

    assert "landed" in result
    assert seen[0].headers["cookie"] == "session=explicit-secret"
    assert seen[1].headers.get("authorization") is None
    assert seen[1].headers.get("cookie") is None
    assert str(seen[1].url) == "https://other.test/next?to=target"
    assert "from=original" not in str(seen[1].url)


@pytest.mark.asyncio
async def test_fetch_real_mock_transport_does_not_carry_cookie_jar_across_origin(monkeypatch):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(
                302,
                headers={
                    "location": "https://other.test/next",
                    "set-cookie": "session=from-first; Domain=example.test; Path=/",
                },
                request=request,
            )
        return httpx.Response(200, text="ok", request=request)

    def factory(**kwargs):
        kwargs.pop("targets", None)
        kwargs.pop("proxy", None)
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr("vulnclaw.utils.http_client.async_http_client", factory)
    manager = MCPLifecycleManager(VulnClawConfig())
    result = await manager._call_fetch({"url": "https://example.test/start"})

    assert "Status: 200" in result
    assert seen[1].headers.get("cookie") is None


@pytest.mark.asyncio
async def test_fetch_redirect_constraint_is_checked_before_second_real_request(monkeypatch):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "https://blocked.test/secret"}, request=request)

    def factory(**kwargs):
        kwargs.pop("targets", None)
        kwargs.pop("proxy", None)
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr("vulnclaw.utils.http_client.async_http_client", factory)
    manager = MCPLifecycleManager(VulnClawConfig())
    manager.set_task_constraints(TaskConstraints(allowed_hosts=["example.test"], strict_mode=True))
    result = await manager._call_fetch({"url": "https://example.test/start"})

    assert "任务范围拦截" in result
    assert len(seen) == 1
    assert "blocked.test" in result


class TestWafInterceptionIsMarked:
    """Measured 2026-10-27 (dg.lszyxy.edu.cn): real-vs-false boolean probes both
    came back as the same 4646-byte NWAF page, but the two payloads were echoed
    into the page, so the bytes differed and the run reported "bool_diff=True".
    A response that never reached the app must be labelled as such.
    """

    def test_field_samples_are_recognized(self):
        from vulnclaw.agent.tools.http_probe import _detect_waf_block

        assert _detect_waf_block(403, {}, "<h1>NWAF页面</h1>") == "nwaf"
        assert (
            _detect_waf_block(403, {}, "<img src='/wengine-auth-failed.png'>") == "wengine"
        )
        assert (
            _detect_waf_block(405, {}, "https://errors.aliyun.com/images/x.png") == "aliyun"
        )
        assert (
            _detect_waf_block(403, {}, "当前访问疑似攻击行为，已被网站管理员设置为拦截")
            == "generic"
        )

    def test_cookie_only_waf_is_recognized(self):
        from vulnclaw.agent.tools.http_probe import _detect_waf_block

        headers = {"set-cookie": "HWWAFSESID=abc; HWWAFSESTIME=1"}
        assert _detect_waf_block(200, headers, "ok") == "huawei"

    def test_normal_pages_are_not_flagged(self):
        from vulnclaw.agent.tools.http_probe import _detect_waf_block

        assert _detect_waf_block(200, {}, "<html>廊坊师范学院 首页 安全培训</html>") == ""
        assert _detect_waf_block(200, {"server": "Tengine"}, "正常页面") == ""
        assert _detect_waf_block(401, {}, '{"code":"401","msg":"登录"') == ""
