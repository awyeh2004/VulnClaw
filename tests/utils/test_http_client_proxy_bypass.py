"""The system proxy must not capture loopback/private targets.

Regression context: httpx defaults to ``trust_env=True`` and reads the platform
proxy (Windows: WinINET). It does **not** honour the Windows ``ProxyOverride``
bypass list, so on any machine running a proxy tool, requests to ``127.0.0.1``
and to internal targets were sent to the proxy. Observed directly:

    connect_tcp.started host='127.0.0.1' port=12334   # destination was loopback
    httpcore._sync.http_proxy.py:207 handle_request(proxy_request)
    ReadError(ConnectionResetError(10054))

Consequences: every local-server test failed while a proxy was running, and a
pentest target would have been probed from the proxy's address (internal targets
simply unreachable, reported as down).
"""

from __future__ import annotations

import httpx
import pytest

from vulnclaw.utils.http_client import (
    async_http_client,
    http_client,
    targets_need_direct,
)


class TestDirectTargetDetection:
    @pytest.mark.parametrize(
        "target",
        [
            "http://127.0.0.1:8080/x",
            "http://localhost:3000",
            "127.0.0.1",
            "localhost:8080",
            "http://[::1]:80",
            "http://10.1.2.3/",
            "http://192.168.1.10:80",
            "http://172.16.0.9/",
            "http://169.254.1.1/",
            "http://0.0.0.0:80",
            "http://box.local/",
            "http://host.internal/",
        ],
    )
    def test_local_and_private_need_direct(self, target):
        assert targets_need_direct(target) is True

    @pytest.mark.parametrize(
        "target",
        [
            "https://ctf2.dasctf.com",
            "https://api.deepseek.com",
            "https://llm-gateway.dasctf.com/llm-gateway/proxy/e/tok",
            "http://8.8.8.8/",
            "example.com:443",
        ],
    )
    def test_public_keeps_environment_proxy(self, target):
        assert targets_need_direct(target) is False

    def test_mixed_targets_keep_the_proxy(self):
        """All, not any: one public target must not lose its proxy."""
        assert targets_need_direct(["https://a.example.com", "http://10.0.0.1"]) is False

    def test_unknown_targets_honour_the_environment(self):
        assert targets_need_direct(None) is False
        assert targets_need_direct([]) is False
        assert targets_need_direct("") is False

    def test_ipv6_and_bare_hosts(self):
        assert targets_need_direct("::1") is True
        assert targets_need_direct("[fe80::1]") is True


class TestClientFactory:
    def test_local_target_disables_trust_env(self):
        client = http_client(targets="http://127.0.0.1:1")
        try:
            assert client.trust_env is False
        finally:
            client.close()

    def test_public_target_keeps_trust_env(self):
        client = http_client(targets="https://example.com")
        try:
            assert client.trust_env is True
        finally:
            client.close()

    def test_explicit_trust_env_wins(self):
        client = http_client(targets="http://127.0.0.1:1", trust_env=True)
        try:
            assert client.trust_env is True
        finally:
            client.close()

    def test_no_targets_honours_environment(self):
        client = http_client()
        try:
            assert client.trust_env is True
        finally:
            client.close()

    @pytest.mark.asyncio
    async def test_async_client_matches(self):
        local = async_http_client(targets="http://localhost:9")
        public = async_http_client(targets="https://example.com")
        try:
            assert local.trust_env is False
            assert public.trust_env is True
        finally:
            await local.aclose()
            await public.aclose()

    def test_accepts_iterable_of_targets(self):
        client = http_client(targets=["http://10.0.0.5", "http://192.168.0.1"])
        try:
            assert client.trust_env is False
        finally:
            client.close()


class TestRealLoopbackRequest:
    """End-to-end: a request through the factory still works with a proxy set.

    The unit assertions above inspect ``trust_env``; this one proves the request
    actually reaches a local server even when the environment points at a proxy,
    which is what broke in the field.
    """

    def test_loopback_request_reaches_the_server(self, monkeypatch):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = b"pong"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        # Point the environment at a dead proxy: if trust_env were honoured for
        # this loopback target the request would fail instead of returning pong.
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/"
            with http_client(targets=url, timeout=5.0) as client:
                assert client.get(url).text == "pong"
        finally:
            server.shutdown()
