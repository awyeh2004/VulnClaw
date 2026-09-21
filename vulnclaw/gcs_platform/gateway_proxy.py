"""Local forwarding proxy for the DASCTF LLM gateway.

The competition gateway URL (``https://llm-gateway.dasctf.com/llm-gateway/
proxy/e/<token>``) acts as a *complete endpoint*: it accepts the OpenAI
chat.completions payload directly and does **not** expect the standard
``/chat/completions`` (or ``/v1/...``) suffix the openai SDK appends to
``base_url``.  POSTing the bare URL returns 200 while ``.../chat/completions``
returns 404.

This module starts a tiny in-process HTTP server on ``127.0.0.1`` that:

- receives the SDK's ``POST 127.0.0.1:<port>/chat/completions`` request,
- forwards the exact same body/headers to the bare gateway URL,
- streams the gateway reply back verbatim.

The SDK is then pointed at ``http://127.0.0.1:<port>`` (which it equips with
``/chat/completions``) instead of the raw gateway URL, so the gateway is used
without any code-path changes elsewhere.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import httpx

_PROXY_LOCK = threading.Lock()
_PROXY_BASE_URL: str | None = None
_PROXY_SERVER: ThreadingHTTPServer | None = None
_PROXY_THREAD: threading.Thread | None = None


class _GatewayProxyHandler(BaseHTTPRequestHandler):
    """Echo any request to the bare gateway URL and return its response."""

    upstream: str = ""
    api_key: str = ""

    @staticmethod
    def _read_body_length(headers) -> int:
        raw = headers.get("Content-Length", "0")
        try:
            return max(int(raw), 0)
        except ValueError:
            return 0

    @staticmethod
    def _redact(text: object) -> str:
        """Strip the upstream URL / token / API key out of an error string.

        httpx puts the request URL into most of its exception messages, and this
        proxy's upstream carries the per-team gateway token in its path. The 502
        body is echoed back to the SDK, so an unredacted message can land in logs
        or in the model's context window.
        """
        out = str(text or "")
        upstream = _GatewayProxyHandler.upstream or ""
        if upstream:
            out = out.replace(upstream, "<upstream>")
            token = upstream.rstrip("/").rsplit("/", 1)[-1]
            if len(token) >= 8:
                out = out.replace(token, "<token>")
        key = _GatewayProxyHandler.api_key or ""
        if len(key) >= 8:
            out = out.replace(key, "<api-key>")
        return out

    def _forward(self) -> None:
        length = self._read_body_length(self.headers)
        body = self.rfile.read(length) if length else b""
        headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}
        headers.pop("Content-Length", None)
        try:
            with httpx.Client(timeout=600.0, follow_redirects=True) as client:
                resp = client.request(
                    self.command,
                    _GatewayProxyHandler.upstream,
                    content=body,
                    headers=headers,
                )
        except Exception as exc:  # noqa: BLE001 - surface anything as an API error
            self._send_error_json(502, f"gateway proxy error: {self._redact(exc)}")
            return
        self._send_raw(resp)

    def _send_raw(self, resp: httpx.Response) -> None:
        self.send_response(resp.status_code)
        for key, value in resp.headers.items():
            # The upstream body has already been decoded by httpx, so re-adding
            # content-encoding/content-length/transfer-encoding would corrupt
            # the response for the SDK (e.g. it would try to gunzip an already
            # decoded body). Strip them and let httpx recompute on our side.
            if key.lower() in (
                "transfer-encoding",
                "connection",
                "content-length",
                "content-encoding",
            ):
                continue
            try:
                self.send_header(key, value)
            except Exception:
                pass
        self.send_header("Content-Length", str(len(resp.content)))
        self.end_headers()
        self.wfile.write(resp.content)

    def _send_error_json(self, status: int, message: str) -> None:
        body = json.dumps(
            {"error": {"message": message, "type": "gateway_proxy_error"}}
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server protocol
        self._forward()

    def do_POST(self) -> None:  # noqa: N802 - http.server protocol
        self._forward()

    def do_OPTIONS(self) -> None:  # noqa: N802 - http.server protocol
        self._forward()

    def log_message(self, *args) -> None:  # silence default logging
        pass


def is_gateway_url(base_url: str) -> bool:
    """Whether a base_url looks like the DASCTF gateway (complete endpoint)."""
    host = urlparse(base_url).hostname or ""
    return "llm-gateway.dasctf.com" in host and "/proxy/e/" in base_url


def _stop_proxy_locked() -> None:
    """Shut the current proxy down and release its port.

    Must be called with ``_PROXY_LOCK`` held, from a thread that is NOT the
    server's own serve_forever thread (``shutdown()`` would deadlock there).
    Previously a changed upstream/api_key simply built a second server and
    abandoned the first, so every change leaked a listening socket and a thread
    for the life of the process.
    """
    global _PROXY_BASE_URL, _PROXY_SERVER, _PROXY_THREAD
    server, thread = _PROXY_SERVER, _PROXY_THREAD
    _PROXY_BASE_URL = None
    _PROXY_SERVER = None
    _PROXY_THREAD = None
    if server is not None:
        try:
            server.shutdown()
        except Exception:
            pass
        try:
            server.server_close()
        except Exception:
            pass
    if thread is not None and thread.is_alive():
        try:
            thread.join(timeout=2.0)
        except Exception:
            pass


def shutdown_gateway_proxy() -> None:
    """Stop the in-process proxy, if one is running (idempotent)."""
    with _PROXY_LOCK:
        _stop_proxy_locked()


def ensure_gateway_proxy_running(upstream: str, api_key: str = "") -> str:
    """Start the in-process gateway proxy (once) and return its local base_url.

    ``upstream`` is the bare gateway URL that accepts the payload directly.
    If the proxy already points at a different upstream, the previous server is
    shut down and a fresh one is started so the mapping is always correct (and
    no listener is leaked).
    """
    global _PROXY_BASE_URL, _PROXY_SERVER, _PROXY_THREAD
    with _PROXY_LOCK:
        if _PROXY_BASE_URL is not None and (
            _GatewayProxyHandler.upstream == upstream
            and _GatewayProxyHandler.api_key == api_key
        ):
            return _PROXY_BASE_URL
        _stop_proxy_locked()
        _GatewayProxyHandler.upstream = upstream
        _GatewayProxyHandler.api_key = api_key
        server = ThreadingHTTPServer(("127.0.0.1", 0), _GatewayProxyHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _PROXY_SERVER = server
        _PROXY_THREAD = thread
        _PROXY_BASE_URL = f"http://127.0.0.1:{port}"
        return _PROXY_BASE_URL