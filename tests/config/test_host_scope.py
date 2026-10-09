"""Scope matching must accept subdomains of an allowed host.

Measured on a live challenge: the target host was ``direct-ctf2.dasctf.com`` while
the task scope said ``dasctf.com``, and the check was a plain string comparison --
so the platform's own target was "outside allowed scope". `fetch`, `shell_command`,
`python_execute` and `http_probe_batch` were all refused, and only the browser
toolset could reach the target. Competition targets are almost always a subdomain
of the platform domain, so exact equality alone makes the primary HTTP tooling
unusable exactly when it matters.

The property that keeps this safe: a lookalike domain must NOT match.
"""

from __future__ import annotations

import pytest

from vulnclaw.config.url_utils import host_in_scope, is_ip_address


class TestDomainScope:
    def test_the_measured_case(self):
        """The regression: the platform's own subdomain its target lived on."""
        assert host_in_scope("direct-ctf2.dasctf.com", ["dasctf.com"]) is True

    def test_exact_host_still_matches(self):
        assert host_in_scope("dasctf.com", ["dasctf.com"]) is True

    def test_deeper_subdomains_match(self):
        assert host_in_scope("a.b.dasctf.com", ["dasctf.com"]) is True

    def test_explicit_wildcard_is_accepted(self):
        assert host_in_scope("x.dasctf.com", ["*.dasctf.com"]) is True

    @pytest.mark.parametrize(
        "host",
        [
            "evil-dasctf.com",       # suffix without the dot boundary
            "notdasctf.com",
            "dasctf.com.evil.com",   # the allowed domain as a prefix
            "xdasctf.com",
        ],
    )
    def test_lookalikes_stay_out_of_scope(self, host):
        assert host_in_scope(host, ["dasctf.com"]) is False

    def test_case_and_trailing_dot_are_normalised(self):
        assert host_in_scope("Direct-CTF2.Dasctf.COM.", ["dasctf.com"]) is True

    def test_no_patterns_means_no_match(self):
        assert host_in_scope("dasctf.com", []) is False
        assert host_in_scope("dasctf.com", None) is False

    def test_empty_host_never_matches(self):
        assert host_in_scope("", ["dasctf.com"]) is False
        assert host_in_scope("   ", ["dasctf.com"]) is False

    def test_several_patterns_any_of_them(self):
        assert host_in_scope("x.example.org", ["dasctf.com", "example.org"]) is True

    def test_blank_patterns_are_skipped(self):
        assert host_in_scope("x.example.org", ["", "  ", "*.", "example.org"]) is True


class TestIpPatterns:
    def test_ip_matches_exactly(self):
        assert host_in_scope("10.0.0.1", ["10.0.0.1"]) is True

    def test_an_ip_pattern_does_not_swallow_suffixes(self):
        """Nothing is "inside" an address, so no suffix matching for IPs."""
        assert host_in_scope("x.10.0.0.1", ["10.0.0.1"]) is False

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("10.0.0.1", True),
            ("255.255.255.255", True),
            ("256.0.0.1", False),
            ("10.0.0", False),
            ("dasctf.com", False),
            ("::1", True),
            ("", False),
        ],
    )
    def test_is_ip_address(self, text, expected):
        assert is_ip_address(text) is expected


class TestCidrScope:
    """A venue hands out a *network* (靶场网段), not a list of addresses.

    Measured 2026-10-08: the prefix spellings the code already used for private
    ranges (``"10."``, ``"192.168."``) matched nothing, because a bare IP pattern
    is an exact match and there was no segment form at all. CIDR is that form.
    """

    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("10.20.1.5", True),
            ("10.20.255.254", True),
            ("10.21.0.1", False),
            ("11.20.1.5", False),
        ],
    )
    def test_addresses_inside_the_segment_match(self, host, expected):
        assert host_in_scope(host, ["10.20.0.0/16"]) is expected

    def test_a_hostname_is_never_inside_a_segment(self):
        """No resolution: a DNS answer must not be able to widen scope."""
        assert host_in_scope("target.example.com", ["10.0.0.0/8"]) is False

    def test_a_hostname_pattern_is_not_a_segment(self):
        assert host_in_scope("10.0.0.5", ["example.com/8"]) is False

    def test_malformed_segments_are_skipped_not_raised(self):
        assert host_in_scope("10.0.0.5", ["10.0.0.0/99", "not-a-cidr/8"]) is False

    def test_mixed_families_do_not_match(self):
        assert host_in_scope("10.0.0.5", ["::/0"]) is False
        assert host_in_scope("::1", ["10.0.0.0/8"]) is False

    def test_segments_work_in_blocked_lists_too(self):
        """Denying a range is the same matcher (private ranges, venue ban)."""
        assert host_in_scope("192.168.1.9", ["192.168.0.0/16"]) is True

    def test_host_bits_are_accepted(self):
        """A pasted network with host bits set still means its segment."""
        assert host_in_scope("10.20.1.5", ["10.20.1.7/24"]) is True
