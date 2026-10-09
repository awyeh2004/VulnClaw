"""An explicit egress proxy must be honoured for *private* targets.

Background: ``test_http_client_proxy_bypass.py`` covers the opposite direction --
the *system* proxy must stay away from loopback/private targets. This file covers
the deliberate case where the operator builds a tunnel and wants target traffic
to leave through it, canonically::

    ssh -D 1080 jumpbox
    VULNCLAW_HTTP_PROXY=socks5://127.0.0.1:1080 vulnclaw solve ...

Two facts make that worth code rather than a note in the runbook:

* ``trust_env`` cannot express it. Private targets are forced ``trust_env=False``
  precisely so a corporate/TUN proxy cannot swallow them, and the target of a
  tunnel is private by definition.
* The scope gate (``--only-host`` / ``blocked_hosts``) keeps working, because the
  request still carries the real hostname. ``ssh -L`` does not: the agent can only
  address ``127.0.0.1:8080``, so the gate sees ``127.0.0.1`` and stops
  discriminating. That is why SOCKS is the supported shape.

Everything asserted here was measured against httpx 0.28.1 / httpcore 1.0.2 /
socksio 1.0.0 with a logging SOCKS5 server (2026-10-10), not assumed:

* ``socks5://`` sends SOCKS5 ``ATYP=3`` (domain name) -- DNS is resolved at the
  proxy end. httpcore has no local-DNS variant, so ``socks5://`` and
  ``socks5h://`` mean the same thing here, unlike curl -- and ``socks5h`` is a
  bare ``KeyError`` before httpcore 1.0.9. We rewrite it in
  ``normalise_proxy_url``; this file's first run found that by passing on
  httpcore 1.0.9 (a scratch venv) and crashing on the 1.0.2 installed here.
* An explicit ``proxy=`` wins over ``trust_env``, ``NO_PROXY`` and ``HTTP_PROXY``.
* Without ``socksio`` httpx raises on client construction with an actionable
  ImportError; our own check upgrades it to name the ``vulnclaw[socks]`` extra.
"""

from __future__ import annotations

import importlib.util
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vulnclaw import utils
from vulnclaw.utils import http_client as hc

# ``.invalid`` is reserved (RFC 2606) and never resolves -- which is the point:
# the request can only succeed if the *proxy* did the name resolution.
UNRESOLVABLE_HOST = "internal-target.invalid"


# ── A minimal, logging SOCKS5 server ─────────────────────────────────────


class Socks5Relay:
    """SOCKS5 ``CONNECT`` server that records the address form the client sent.

    It ignores the requested destination and always relays to ``relay_to``, so a
    hostname the client itself cannot resolve still completes the exchange. The
    log is therefore the evidence: ``ATYP=3`` means the client sent a *name*.
    """

    def __init__(self, relay_to: tuple[str, int]) -> None:
        self.relay_to = relay_to
        self.requests: list[tuple[str, str, int]] = []
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = int(self._sock.getsockname()[1])
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    # -- lifecycle --------------------------------------------------------
    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5)

    def __enter__(self) -> Socks5Relay:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def url(self) -> str:
        return f"socks5://127.0.0.1:{self.port}"

    # -- server -----------------------------------------------------------
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _recv_exactly(self, conn: socket.socket, count: int) -> bytes:
        buf = b""
        while len(buf) < count:
            chunk = conn.recv(count - len(buf))
            if not chunk:
                raise ConnectionError("client closed during handshake")
            buf += chunk
        return buf

    def _handle(self, conn: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            conn.settimeout(10)
            version, method_count = struct.unpack("!BB", self._recv_exactly(conn, 2))
            if version != 5:
                return
            self._recv_exactly(conn, method_count)
            conn.sendall(b"\x05\x00")  # no authentication

            version, command, _, atyp = struct.unpack("!BBBB", self._recv_exactly(conn, 4))
            if atyp == 1:
                address = socket.inet_ntoa(self._recv_exactly(conn, 4))
                kind = "ipv4"
            elif atyp == 3:
                (length,) = struct.unpack("!B", self._recv_exactly(conn, 1))
                address = self._recv_exactly(conn, length).decode("ascii", "replace")
                kind = "domain"
            elif atyp == 4:
                address = socket.inet_ntop(socket.AF_INET6, self._recv_exactly(conn, 16))
                kind = "ipv6"
            else:
                return
            (port,) = struct.unpack("!H", self._recv_exactly(conn, 2))
            self.requests.append((kind, address, port))

            if command != 1:  # CONNECT only
                conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return
            conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)  # succeeded

            upstream = socket.create_connection(self.relay_to, timeout=10)
            self._pump(conn, upstream)
        except (OSError, ConnectionError):
            pass
        finally:
            for sock in (conn, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    def _pump(self, client: socket.socket, upstream: socket.socket) -> None:
        done = threading.Event()

        def forward(src: socket.socket, dst: socket.socket) -> None:
            try:
                while not done.is_set():
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                done.set()

        thread = threading.Thread(target=forward, args=(upstream, client), daemon=True)
        thread.start()
        forward(client, upstream)
        thread.join(timeout=10)


class _PongHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"pong"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep pytest output clean
        pass


@pytest.fixture
def pong_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PongHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()


@pytest.fixture
def socks5_relay(pong_server):
    if importlib.util.find_spec("socksio") is None:
        pytest.skip("socksio not installed -- pip install 'vulnclaw[socks]'")
    host = pong_server.split("//", 1)[1].rstrip("/").rsplit(":", 1)
    with Socks5Relay((host[0], int(host[1]))) as relay:
        yield relay


# ── resolve_egress_proxy ─────────────────────────────────────────────────


class TestResolveEgressProxy:
    def test_empty_by_default(self, monkeypatch):
        monkeypatch.delenv(hc.EGRESS_PROXY_ENV, raising=False)
        assert hc.resolve_egress_proxy(None) == ""

    def test_env_is_the_fallback(self, monkeypatch):
        monkeypatch.setenv(hc.EGRESS_PROXY_ENV, "  socks5://127.0.0.1:1080  ")
        assert hc.resolve_egress_proxy(None) == "socks5://127.0.0.1:1080"

    def test_config_wins_over_env(self, monkeypatch):
        monkeypatch.setenv(hc.EGRESS_PROXY_ENV, "socks5://127.0.0.1:1080")
        config = type("Cfg", (), {"network": type("N", (), {"http_proxy": "http://10.0.0.9:3128"})()})()
        assert hc.resolve_egress_proxy(config) == "http://10.0.0.9:3128"

    def test_config_without_network_falls_back_to_env(self, monkeypatch):
        monkeypatch.setenv(hc.EGRESS_PROXY_ENV, "socks5://127.0.0.1:1080")
        assert hc.resolve_egress_proxy(type("Cfg", (), {})()) == "socks5://127.0.0.1:1080"

    def test_schema_defaults_to_off(self):
        from vulnclaw.config.schema import NetworkConfig, VulnClawConfig

        assert NetworkConfig().http_proxy == ""
        assert VulnClawConfig().network.http_proxy == ""


# ── egress_settings: the decision table ──────────────────────────────────


class TestEgressSettings:
    def test_no_proxy_keeps_the_legacy_bypass(self, monkeypatch):
        monkeypatch.delenv(hc.EGRESS_PROXY_ENV, raising=False)
        for target in ("http://10.1.2.3/", "http://127.0.0.1:9/", "https://example.com/"):
            assert hc.egress_settings(target, "") == (
                None,
                not hc.targets_need_direct(target),
            )

    def test_explicit_proxy_is_used_for_private_targets(self):
        """The whole point: a private target is what the tunnel exists to reach."""
        assert hc.egress_settings("http://10.1.2.3/", "socks5://127.0.0.1:1080") == (
            "socks5://127.0.0.1:1080",
            False,
        )

    def test_public_targets_also_use_it(self):
        url, trust_env = hc.egress_settings("https://example.com/", "http://10.0.0.9:3128")
        assert url == "http://10.0.0.9:3128"
        assert trust_env is False

    @pytest.mark.parametrize(
        "target",
        ["http://127.0.0.1:8080/", "http://localhost:8080/", "http://[::1]:8080/"],
    )
    def test_loopback_targets_stay_direct(self, target):
        """Through a tunnel the far end reads 127.0.0.1 as *itself*."""
        assert hc.egress_settings(target, "socks5://127.0.0.1:1080") == (None, False)

    def test_mixed_set_is_proxied(self):
        """A hostname that merely looks private is exactly what we want to proxy."""
        assert hc.egress_settings(
            ["http://box.internal/", "http://10.1.2.3/"], "socks5://127.0.0.1:1080"
        ) == ("socks5://127.0.0.1:1080", False)

    def test_socks4_is_rejected(self):
        """httpx only speaks http/https/socks5/socks5h; fail here, not inside httpx."""
        with pytest.raises(ValueError, match="unsupported proxy scheme"):
            hc.egress_settings("http://10.1.2.3/", "socks4://127.0.0.1:1080")

    def test_socks5h_is_normalised_to_socks5(self):
        """httpcore 1.0.2 raises ``KeyError: b'socks5h'``; 1.0.9 accepts it.

        Both send ATYP=3 (measured), so rewriting is behaviour-preserving on new
        httpcore and the difference between working and a mystery traceback on
        old. The operator's curl habit must not cost them the tunnel.
        """
        assert hc.normalise_proxy_url("socks5h://127.0.0.1:1080") == "socks5://127.0.0.1:1080"
        assert hc.normalise_proxy_url("SOCKS5H://127.0.0.1:1080") == "socks5://127.0.0.1:1080"
        assert hc.normalise_proxy_url("socks5://127.0.0.1:1080") == "socks5://127.0.0.1:1080"
        assert hc.normalise_proxy_url("http://10.0.0.9:3128") == "http://10.0.0.9:3128"
        assert hc.egress_settings("http://10.1.2.3/", "socks5h://127.0.0.1:1080") == (
            "socks5://127.0.0.1:1080",
            False,
        )

    def test_installed_httpcore_accepts_every_scheme_we_pass_through(self):
        """Guard the default-port table ``URL.origin`` indexes by scheme.

        An unknown scheme surfaces as a bare ``KeyError`` at request time with no
        mention of the proxy URL -- which is exactly how ``socks5h`` was found
        (httpcore 1.0.2 knows ``socks5`` but not ``socks5h``; 1.0.9 added it).
        We normalise ``socks5h`` away precisely so the schemes we hand httpcore
        are the ones it defines.
        """
        from httpcore import URL

        for scheme in ("http", "https", "socks5"):
            URL(f"{scheme}://127.0.0.1:1080").origin  # must not raise

    def test_unsupported_scheme_is_rejected(self):
        with pytest.raises(ValueError, match="unsupported proxy scheme"):
            hc.egress_settings("http://10.1.2.3/", "ftp://127.0.0.1:21")

    def test_bare_host_is_rejected(self):
        with pytest.raises(ValueError, match="unsupported proxy scheme"):
            hc.egress_settings("http://10.1.2.3/", "127.0.0.1:1080")

    def test_missing_socksio_is_reported_with_the_extra(self, monkeypatch):
        real_find_spec = importlib.util.find_spec

        def fake_find_spec(name, *args, **kwargs):
            if name == "socksio":
                return None
            return real_find_spec(name, *args, **kwargs)

        monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)
        with pytest.raises(RuntimeError, match=r"vulnclaw\[socks\]"):
            hc.egress_settings("http://10.1.2.3/", "socks5://127.0.0.1:1080")

    def test_http_proxy_needs_no_extra(self, monkeypatch):
        monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a, **k: None)
        assert hc.egress_settings("http://10.1.2.3/", "http://127.0.0.1:3128")[0] == (
            "http://127.0.0.1:3128"
        )

    def test_factory_wires_the_decision_in(self):
        with hc.http_client(targets="http://10.1.2.3/", proxy="socks5://127.0.0.1:1080") as c:
            assert c.trust_env is False
        with hc.http_client(targets="http://10.1.2.3/") as c:
            assert c.trust_env is False  # legacy private-target bypass
        with hc.http_client(targets="https://example.com/") as c:
            assert c.trust_env is True  # legacy environment proxy


# ── End to end through a real SOCKS5 server ──────────────────────────────


class TestSocksTunnelEndToEnd:
    """Proves the proxy is actually used, and that the hostname survives."""

    def test_private_host_name_is_resolved_by_the_proxy(self, socks5_relay, monkeypatch):
        # A hostile environment must not be able to redirect or disable it.
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("NO_PROXY", "*")
        monkeypatch.delenv(hc.EGRESS_PROXY_ENV, raising=False)

        url = f"http://{UNRESOLVABLE_HOST}/admin"
        with hc.http_client(targets=url, proxy=socks5_relay.url, timeout=10.0) as client:
            assert client.get(url).text == "pong"

        assert socks5_relay.requests == [("domain", UNRESOLVABLE_HOST, 80)], (
            "httpx must hand the proxy the hostname (ATYP=3); an IP here would mean "
            "the client resolved the name itself, which cannot work for a "
            "tunnel-only target"
        )

    def test_env_fallback_is_used_when_no_explicit_proxy_is_passed(self, socks5_relay, monkeypatch):
        monkeypatch.setenv(hc.EGRESS_PROXY_ENV, socks5_relay.url)
        url = f"http://{UNRESOLVABLE_HOST}/"
        config_without_proxy = type("Cfg", (), {"network": type("N", (), {"http_proxy": ""})()})()
        proxy = hc.resolve_egress_proxy(config_without_proxy)
        with hc.http_client(targets=url, proxy=proxy, timeout=10.0) as client:
            assert client.get(url).text == "pong"
        assert socks5_relay.requests and socks5_relay.requests[0][1] == UNRESOLVABLE_HOST

    def test_loopback_target_never_reaches_the_tunnel(self, socks5_relay, pong_server):
        with hc.http_client(targets=pong_server, proxy=socks5_relay.url, timeout=10.0) as client:
            assert client.get(pong_server).text == "pong"
        assert socks5_relay.requests == [], "a loopback target must not be tunnelled"

    @pytest.mark.asyncio
    async def test_async_factory_matches(self, socks5_relay):
        url = f"http://{UNRESOLVABLE_HOST}/"
        async with hc.async_http_client(
            targets=url, proxy=socks5_relay.url, timeout=10.0
        ) as client:
            response = await client.get(url)
        assert response.text == "pong"
        assert socks5_relay.requests[0][1] == UNRESOLVABLE_HOST

    def test_socks5h_proxy_url_still_works(self, socks5_relay):
        """A curl habit must not cost the tunnel: we rewrite it to socks5://.

        Left as written, httpcore 1.0.2 raises ``KeyError: b'socks5h'`` here --
        from inside URL.origin, naming neither the proxy nor the feature.
        """
        url = f"http://{UNRESOLVABLE_HOST}/"
        h_url = socks5_relay.url.replace("socks5://", "socks5h://")
        with hc.http_client(targets=url, proxy=h_url, timeout=10.0) as client:
            assert client.get(url).text == "pong"
        assert socks5_relay.requests[0] == ("domain", UNRESOLVABLE_HOST, 80)


def test_module_is_reachable_the_way_call_sites_import_it():
    """Call sites use ``from vulnclaw.utils.http_client import ...``."""
    assert utils.http_client.resolve_egress_proxy is hc.resolve_egress_proxy
