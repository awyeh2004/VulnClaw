"""Transport must come from an explicit flag when there is one, else the URL scheme.

The ordering is the whole point, and it is the measured lesson: a real CTF2 payload
carries ``access_type: "tcp"`` alongside ``nc_ssl: true``, so a flag always wins.
The scheme is only a fallback, and it exists because CTF2's HTTP targets publish
``http://host:80`` with no ``nc_ssl`` -- which used to render as

    endpoint: http://host:80  (transport: not reported)
       -> Try plain TCP first; if the handshake succeeds but the service never
          responds, try TLS.

i.e. a hedge about an endpoint the platform had plainly published as plain HTTP,
repeated on every poll.
"""

from __future__ import annotations

import pytest

from vulnclaw.platforms import base
from vulnclaw.platforms.base import EnvEndpoint
from vulnclaw.platforms.ctf2 import extract_endpoints, normalize_target_payload
from vulnclaw.platforms.gcs import extract_endpoints as gcs_endpoints
from vulnclaw.platforms.normalize import transport_from_url
from vulnclaw.platforms.refs import ChallengeRef
from vulnclaw.platforms.render import render_env_info

REF = ChallengeRef("ctf2", "practice", "p", "c")
HTTP_URL = "557dd51809de3ac70ebc09d8.http-ctf2.dasctf.com:80"


def _head(text: str) -> str:
    return text.split("\n{", 1)[0]


class TestTransportFromUrl:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("http://h:80", base.TRANSPORT_TCP),
            ("https://h:443", base.TRANSPORT_TLS),
            ("ws://h:80", base.TRANSPORT_TCP),
            ("wss://h:443", base.TRANSPORT_TLS),
            ("h:9999", base.TRANSPORT_UNKNOWN),          # no scheme -> no evidence
            ("", base.TRANSPORT_UNKNOWN),
            (None, base.TRANSPORT_UNKNOWN),
            ("tcp://h:1", base.TRANSPORT_TCP),
        ],
    )
    def test_scheme_mapping(self, url, expected):
        assert transport_from_url(url) == expected


class TestExplicitFlagStillWins:
    def test_nc_ssl_true_beats_a_plain_scheme(self):
        """The measured trap: never let anything override an explicit nc_ssl."""
        payload = {
            "data": {
                "status": "running",
                "nc_ssl": True,
                "access_url": "http://h:80",
                "access_urls": [{"nc_ssl": True, "url": "http://h:80"}],
            }
        }
        (endpoint,) = normalize_target_payload(payload, REF).endpoints
        assert endpoint.transport == base.TRANSPORT_TLS

    def test_nc_ssl_false_beats_an_https_scheme(self):
        payload = {
            "data": {"status": "running", "nc_ssl": False, "access_url": "https://h:443"}
        }
        (endpoint,) = normalize_target_payload(payload, REF).endpoints
        assert endpoint.transport == base.TRANSPORT_TCP

    def test_no_flag_falls_back_to_the_scheme(self):
        payload = {"data": {"status": "running", "access_type": "http",
                            "access_url": f"http://{HTTP_URL}"}}
        (endpoint,) = normalize_target_payload(payload, REF).endpoints
        assert endpoint.transport == base.TRANSPORT_TCP

    def test_bare_host_port_stays_unknown(self):
        """No flag and no scheme is genuinely unknown -- do not invent one."""
        payload = {"data": {"status": "running", "access_type": "tcp",
                            "access_url": "h:9999"}}
        (endpoint,) = normalize_target_payload(payload, REF).endpoints
        assert endpoint.transport == base.TRANSPORT_UNKNOWN

    def test_the_recorded_tls_payload_is_unchanged(self):
        """Regression on real data: bare host:port + nc_ssl:true is still TLS."""
        from tests.platforms import ctf2_payloads as fx

        info = normalize_target_payload(fx.RUNNING_PAYLOAD, REF)
        assert info.transports() == frozenset({base.TRANSPORT_TLS})


class TestHttpTargetIsNoLongerHedged:
    def test_render_says_plain_tcp_for_an_http_endpoint(self):
        payload = {"data": {"status": "running", "access_type": "http",
                            "access_url": f"http://{HTTP_URL}",
                            "access_urls": [{"type": "http",
                                             "url": f"http://{HTTP_URL}"}]}}
        head = _head(render_env_info(normalize_target_payload(payload, REF)))
        assert "plain TCP" in head
        assert "not reported" not in head
        assert "try TLS" not in head

    def test_gcs_endpoints_use_the_scheme_too(self):
        (endpoint,) = gcs_endpoints({"exposeIps": [f"http://{HTTP_URL}"]})
        assert endpoint.transport == base.TRANSPORT_TCP

    def test_gcs_bare_host_port_stays_unknown(self):
        (endpoint,) = gcs_endpoints({"exposeIps": ["10.0.0.1:8080"]})
        assert endpoint.transport == base.TRANSPORT_UNKNOWN


def test_endpoint_transport_is_a_closed_set():
    """Whatever the source, EnvEndpoint only accepts the three known values."""
    for transport in (base.TRANSPORT_TCP, base.TRANSPORT_TLS, base.TRANSPORT_UNKNOWN):
        EnvEndpoint(host="h", transport=transport)
