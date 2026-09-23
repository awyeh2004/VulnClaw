"""Platform HTTP clients: per-request timeouts and explicit shutdown.

Round-5 review N3/N4:
  * a longer ``timeout`` asked for AFTER the cached client existed was silently
    dropped (httpx fixes the default at construction), so ``start_environment``
    (120s) and ``get_target`` (60s) actually ran with the 30s default;
  * neither module-level client was ever closed, and a client whose event loop
    had gone was simply abandoned;
  * ``ensure_gateway_proxy_running`` built a second server on an upstream change
    and never shut the first one down, leaking a listener and a thread.
"""

from __future__ import annotations

import asyncio
import socket

import httpx
import pytest

from vulnclaw.ctf_platform import client as ctf2_client
from vulnclaw.gcs_platform import client as gcs_client
from vulnclaw.utils import gateway_proxy


def _recorder(module, payload, monkeypatch):
    """Patch a client module's transport, returning the list of seen requests."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=payload(request))

    original = module.get_client

    def _client(timeout: float = module.DEFAULT_TIMEOUT) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), timeout=timeout
        )

    monkeypatch.setattr(module, "get_client", _client)
    monkeypatch.setattr(module, "_client", None, raising=False)
    monkeypatch.setattr(module, "_client_loop", None, raising=False)
    return seen, original


def _read_timeout(request: httpx.Request) -> float:
    return float(request.extensions["timeout"]["read"])  # type: ignore[index]


# ── GCS ─────────────────────────────────────────────────────────────────


def test_gcs_slow_calls_carry_their_own_timeout(monkeypatch):
    seen, _ = _recorder(gcs_client, lambda r: {"code": "00000", "data": {}}, monkeypatch)
    monkeypatch.setattr(gcs_client, "access_key", lambda: "k")

    async def run():
        await gcs_client.build_environment(7)
        await gcs_client.recover_environment(7)
        await gcs_client.overview()

    asyncio.run(run())
    assert _read_timeout(seen[0]) == gcs_client.SLOW_TIMEOUT
    assert _read_timeout(seen[1]) == gcs_client.MEDIUM_TIMEOUT
    # A quick read keeps the small budget: the long ones must not raise it for
    # everything else.
    assert _read_timeout(seen[2]) == gcs_client.DEFAULT_TIMEOUT


def test_gcs_cached_client_does_not_swallow_the_long_timeout(monkeypatch):
    """The regression: a cached client used to ignore the longer request."""
    monkeypatch.setattr(gcs_client, "access_key", lambda: "k")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"code": "00000", "data": {}})

    monkeypatch.setattr(
        gcs_client,
        "get_client",
        lambda timeout=gcs_client.DEFAULT_TIMEOUT: httpx.AsyncClient(
            transport=httpx.MockTransport(handler), timeout=gcs_client.DEFAULT_TIMEOUT
        ),
    )

    async def run():
        await gcs_client.overview()  # creates the "cached" default client
        await gcs_client.build_environment(7)  # needs 120s

    asyncio.run(run())
    assert _read_timeout(seen[0]) == gcs_client.DEFAULT_TIMEOUT
    assert _read_timeout(seen[1]) == gcs_client.SLOW_TIMEOUT


def test_gcs_aclose_client_closes_and_resets(monkeypatch):
    monkeypatch.setattr(gcs_client, "_client", None, raising=False)
    monkeypatch.setattr(gcs_client, "_client_loop", None, raising=False)

    async def run():
        first = gcs_client.get_client()
        assert not first.is_closed
        await gcs_client.aclose_client()
        assert first.is_closed
        assert gcs_client._client is None
        second = gcs_client.get_client()
        assert second is not first and not second.is_closed
        await gcs_client.aclose_client()

    asyncio.run(run())


def test_gcs_loop_change_discards_the_stale_client(monkeypatch):
    """A client from a dead loop must not be handed to the next loop."""
    monkeypatch.setattr(gcs_client, "_client", None, raising=False)
    monkeypatch.setattr(gcs_client, "_client_loop", None, raising=False)
    real_get = gcs_client.get_client

    async def first_loop():
        return real_get()

    one = asyncio.run(first_loop())

    async def second_loop():
        two = real_get()
        await gcs_client.aclose_client()
        return two

    two = asyncio.run(second_loop())
    assert two is not one


# ── CTF2 ────────────────────────────────────────────────────────────────


def test_ctf2_slow_calls_carry_their_own_timeout(monkeypatch):
    monkeypatch.setenv("VULNCLAW_CTF2_API_KEY", "token")
    monkeypatch.setenv("VULNCLAW_CTF2_SESSION_TOKEN", "jwt")
    seen, _ = _recorder(ctf2_client, lambda r: {"code": 0, "data": {}}, monkeypatch)

    async def run():
        await ctf2_client.start_environment("p1", "c1")
        await ctf2_client.get_target("p1", "c1")
        await ctf2_client.create_target("p1", "c1")

    asyncio.run(run())
    assert _read_timeout(seen[0]) == ctf2_client.SLOW_TIMEOUT
    assert _read_timeout(seen[1]) == ctf2_client.MEDIUM_TIMEOUT
    assert _read_timeout(seen[2]) == ctf2_client.SLOW_TIMEOUT


def test_ctf2_aclose_client(monkeypatch):
    monkeypatch.setattr(ctf2_client, "_client", None, raising=False)
    monkeypatch.setattr(ctf2_client, "_client_loop", None, raising=False)
    real_get = ctf2_client.get_client

    async def run():
        client = real_get()
        assert not client.is_closed
        await ctf2_client.aclose_client()
        assert client.is_closed
        assert ctf2_client._client is None

    asyncio.run(run())


# ── gateway proxy: a changed upstream must not leak a listener ──────────


def _port_of(base_url: str) -> int:
    return int(base_url.rsplit(":", 1)[1])


def _accepts(port: int) -> bool:
    sock = socket.socket()
    sock.settimeout(0.5)
    try:
        return sock.connect_ex(("127.0.0.1", port)) == 0
    finally:
        sock.close()


def test_upstream_change_shuts_the_old_proxy_down():
    gateway_proxy.shutdown_gateway_proxy()
    first = gateway_proxy.ensure_gateway_proxy_running("https://gw.example/a")
    first_port = _port_of(first)
    try:
        assert _accepts(first_port)
        second = gateway_proxy.ensure_gateway_proxy_running("https://gw.example/b")
        second_port = _port_of(second)
        assert second_port != first_port
        assert _accepts(second_port)
        assert not _accepts(first_port), "the old proxy listener was leaked"
    finally:
        gateway_proxy.shutdown_gateway_proxy()
    assert not _accepts(_port_of(second))


def test_same_upstream_reuses_the_proxy():
    gateway_proxy.shutdown_gateway_proxy()
    try:
        assert gateway_proxy.ensure_gateway_proxy_running("https://gw.example/a") == (
            gateway_proxy.ensure_gateway_proxy_running("https://gw.example/a")
        )
    finally:
        gateway_proxy.shutdown_gateway_proxy()


def test_api_key_change_also_restarts():
    gateway_proxy.shutdown_gateway_proxy()
    first = gateway_proxy.ensure_gateway_proxy_running("https://gw.example/a", "k1")
    try:
        second = gateway_proxy.ensure_gateway_proxy_running(
            "https://gw.example/a", "k2"
        )
        assert second != first
        assert not _accepts(_port_of(first))
    finally:
        gateway_proxy.shutdown_gateway_proxy()
