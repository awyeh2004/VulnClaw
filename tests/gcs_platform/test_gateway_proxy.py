import json
import threading

import httpx

from vulnclaw.gcs_platform.gateway_proxy import (
    ensure_gateway_proxy_running,
    is_gateway_url,
)


def _local_server():
    """Return a mock upstream (bare gateway) that echoes back a valid reply."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    received: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - http.server protocol
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            received["path"] = self.path
            received["body"] = json.loads(raw)
            received["auth"] = self.headers.get("Authorization", "")
            payload = json.dumps(
                {
                    "id": "mock",
                    "object": "chat.completion",
                    "model": "deepseek-v4-flash",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "pong"},
                        }
                    ],
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):  # noqa: N802 - http.server protocol
            # The proxy must forward *exactly* the bare URL, never the
            # SDK-suffixed path — so GET on the bare URL counts as a hit too.
            received["path"] = self.path
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1], received


def test_is_gateway_url_matcher():
    assert is_gateway_url(
        "https://llm-gateway.dasctf.com/llm-gateway/proxy/e/abc"
    )
    assert not is_gateway_url("https://api.deepseek.com")
    assert not is_gateway_url("https://gcsis.dasctf.com/slab-match")


def test_proxy_forwards_to_bare_url():
    server, port, received = _local_server()
    upstream = f"http://127.0.0.1:{port}"
    local = ensure_gateway_proxy_running(upstream=upstream, api_key="k1")
    try:
        resp = httpx.post(
            f"{local}/chat/completions",
            headers={"Authorization": "Bearer k1", "Content-Type": "application/json"},
            json={"model": "deepseek-chat", "messages": [{"role": "user", "content": "hi"}]},
            timeout=10,
        )
        assert resp.status_code == 200
        assert resp.json()["choices"][0]["message"]["content"] == "pong"
        assert received["path"] == "/", "must forward to bare URL, not a suffixed path"
        assert received["auth"] == "Bearer k1"
        assert received["body"]["model"] == "deepseek-chat"
    finally:
        server.shutdown()


def test_proxy_reuses_same_upstream():
    server, port, _ = _local_server()
    upstream = f"http://127.0.0.1:{port}"
    first = ensure_gateway_proxy_running(upstream=upstream, api_key="k")
    second = ensure_gateway_proxy_running(upstream=upstream, api_key="k")
    try:
        assert first == second
    finally:
        server.shutdown()


def test_proxy_restarts_on_new_upstream():
    server1, port1, _ = _local_server()
    server2, port2, _ = _local_server()
    try:
        first = ensure_gateway_proxy_running(
            upstream=f"http://127.0.0.1:{port1}", api_key="k"
        )
        second = ensure_gateway_proxy_running(
            upstream=f"http://127.0.0.1:{port2}", api_key="k"
        )
        assert first != second
        # The old mapping is replaced: both ports should route to their mocks.
        r = httpx.post(
            f"{second}/chat/completions",
            headers={"Authorization": "Bearer k", "Content-Type": "application/json"},
            json={"model": "m", "messages": [{"role": "user", "content": "x"}]},
            timeout=10,
        )
        assert r.status_code == 200
    finally:
        server1.shutdown()
        server2.shutdown()