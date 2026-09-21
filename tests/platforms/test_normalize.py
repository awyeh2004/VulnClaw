"""Normalization: platform-native values -> the adapter vocabulary.

The accuracy rule under test is invariant I3: an unrecognized transport stays
`unknown`.  A wrong `tcp` costs 20+ minutes (a raw socket against a TLS service
looks exactly like a failed exploit); an honest `unknown` costs one probe.
"""

from __future__ import annotations

import pytest

from vulnclaw.platforms import base
from vulnclaw.platforms.normalize import (
    first_present,
    normalize_bool,
    normalize_status,
    normalize_transport,
    split_host_port,
    state_from_flags,
)


class TestTransport:
    @pytest.mark.parametrize("value", [True, 1, "1", "true", "yes", "on", "tls", "ssl", "starttls"])
    def test_truthy_flags_mean_tls(self, value):
        assert normalize_transport(value) == base.TRANSPORT_TLS

    @pytest.mark.parametrize("value", [False, 0, "0", "false", "no", "off", "tcp", "plain", "none"])
    def test_falsy_flags_mean_plain_tcp(self, value):
        assert normalize_transport(value) == base.TRANSPORT_TCP

    @pytest.mark.parametrize("value", [None, "", "   ", "garbage", 7, "maybe"])
    def test_unknown_stays_unknown(self, value):
        """Never default to tcp -- that is the whole point of the invariant."""
        assert normalize_transport(value) == base.TRANSPORT_UNKNOWN

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("https", base.TRANSPORT_TLS),
            ("wss", base.TRANSPORT_TLS),
            ("http", base.TRANSPORT_TCP),
            ("ws", base.TRANSPORT_TCP),
            ("tcp-ssl", base.TRANSPORT_TLS),
            ("ssl://host:1", base.TRANSPORT_TLS),
            ("plain-tcp", base.TRANSPORT_TCP),
        ],
    )
    def test_scheme_style_values(self, value, expected):
        assert normalize_transport(value) == expected

    @pytest.mark.parametrize("value", ["https", "wss", "HTTPS", "WSS"])
    def test_tls_markers_win_over_the_tcp_substring(self, value):
        """Regression guard: 'https' contains 'http' and 'wss' contains 'ws'.

        Probing the plain markers first would classify every secure URL as plain
        TCP -- a silent, security-relevant inversion.
        """
        assert normalize_transport(value) == base.TRANSPORT_TLS


class TestStatus:
    @pytest.mark.parametrize(
        "value", ["starting", "STARTING", "pending", "creating", "queued", "building"]
    )
    def test_not_ready_aliases(self, value):
        assert normalize_status(value) == base.STATE_STARTING

    @pytest.mark.parametrize("value", ["running", "Running", "ready", "active", "up"])
    def test_running_aliases(self, value):
        assert normalize_status(value) == base.STATE_RUNNING

    @pytest.mark.parametrize("value", ["released", "deleted", "destroyed"])
    def test_stopped_aliases(self, value):
        assert normalize_status(value) == base.STATE_STOPPED

    @pytest.mark.parametrize("value", ["expired", "timeout", "overdue"])
    def test_expired_aliases(self, value):
        """An expired target is the other half of the same failure mode."""
        assert normalize_status(value) == base.STATE_EXPIRED

    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_missing_status_means_not_ready_not_unknown(self, value):
        """Preserves the pre-refactor renderer, which treated '' as not-ready.

        'Not ready, poll again' is actionable; 'unknown' is not -- and both are
        incomplete, so the safe reading is unchanged.
        """
        assert normalize_status(value) == base.STATE_STARTING

    def test_unrecognized_status_is_unknown(self):
        assert normalize_status("teleported") == base.STATE_UNKNOWN


class TestStateFromFlags:
    def test_no_environment_required(self):
        assert state_from_flags(env_required=False) == base.STATE_NOT_REQUIRED

    def test_still_checking(self):
        assert state_from_flags(needs_check=True, has_endpoints=True) == base.STATE_STARTING

    def test_ready_with_endpoints(self):
        assert state_from_flags(needs_check=False, has_endpoints=True) == base.STATE_RUNNING

    def test_check_finished_but_no_endpoint_is_still_not_usable(self):
        """Readiness without a published endpoint is not a usable target."""
        assert state_from_flags(needs_check=False, has_endpoints=False) == base.STATE_STARTING

    def test_nothing_published_at_all(self):
        assert state_from_flags() == base.STATE_NONE


class TestBool:
    @pytest.mark.parametrize(("value", "expected"), [("true", True), ("0", False), (1, True)])
    def test_coercions(self, value, expected):
        assert normalize_bool(value) is expected

    @pytest.mark.parametrize("value", [None, "", "maybe"])
    def test_absent_stays_none_so_callers_can_tell(self, value):
        assert normalize_bool(value) is None


class TestFieldLookup:
    def test_first_present_skips_missing_and_none(self):
        assert first_present({"a": None, "b": False}, ("a", "b", "c")) is False
        assert first_present({"c": 1}, ("a", "b", "c")) == 1

    def test_non_mapping_is_safe(self):
        assert first_present(None, ("a",)) is None
        assert first_present("nope", ("a",)) is None


class TestSplitHostPort:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("host:9999", ("host", 9999)),
            ("e031.tcp-ctf2.dasctf.com:9999", ("e031.tcp-ctf2.dasctf.com", 9999)),
            ("http://host:8080/path", ("host", 8080)),
            ("tcp://host:1", ("host", 1)),
            ("host", ("host", None)),
            ("host:", ("host", None)),
            ("host:notaport", ("host", None)),
            ("host:99999", ("host", None)),
            (":8080", ("", None)),
            ("", ("", None)),
            (None, ("", None)),
        ],
    )
    def test_splits(self, text, expected):
        assert split_host_port(text) == expected

    def test_bad_port_does_not_invent_one(self):
        """A half-parsed endpoint would be dialled; 'no port' is safe."""
        host, port = split_host_port("host:notaport")
        assert host == "host" and port is None
