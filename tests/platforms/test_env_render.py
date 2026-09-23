"""EnvInfo rendering must not let a caller mistake a partial response for complete.

This mirrors ``tests/ctf_platform/test_target_state_guidance.py`` -- the same
assertions, moved onto the platform-neutral renderer.  That file pins the wording
the pre-refactor CTF2 tool used; this one requires the new layer to keep the same
contract, which is what makes the migration provably behavior-preserving instead
of a rewrite hoping to be equivalent.

The bug being pinned: the CTF2 target response has two shapes depending on
``status``.  ``starting`` omits access_url / access_urls / nc_ssl, but it is a
plausible-looking object, so a caller reads it once and never polls again.  On a
real challenge that meant a bare host:port from the create call was used against
a **TLS-wrapped** service with a raw socket, and "TCP connects then nothing" was
misread as a failed exploit for 20+ minutes.
"""

from __future__ import annotations

import pytest

from vulnclaw.platforms import base
from vulnclaw.platforms.base import EnvEndpoint, EnvInfo
from vulnclaw.platforms.refs import ChallengeRef
from vulnclaw.platforms.render import render_env_info

REF = ChallengeRef("ctf2", "practice", "12", "345")
GCS_REF = ChallengeRef("gcs", "exercise", "", "10662")
URL = "e031c98d53ce9d75dc5f4feb.tcp-ctf2.dasctf.com:9999"
EXPIRES = "2026-09-21T15:57:35.055394+08:00"

STARTING_RAW = {
    "data": {
        "created_at": "2026-09-21T14:57:35.055669+08:00",
        "description": "stack",
        "expires_at": EXPIRES,
        "friendly_id": "TGT-2026-310885",
        "id": "e031c98d-ef77-477a-a75d-51a69fe38d9a",
        "name": "practice-stack-d37ad0d4",
        "status": "starting",
    },
    "success": True,
}

RUNNING_RAW = {
    "data": {
        "access_type": "tcp",
        "access_url": URL,
        "access_urls": [{"nc_ssl": True, "type": "tcp", "url": URL}],
        "expires_at": EXPIRES,
        "nc_ssl": True,
        "status": "running",
    },
    "success": True,
}


def _starting() -> EnvInfo:
    return EnvInfo(ref=REF, state=base.STATE_STARTING, complete=False, raw=STARTING_RAW)


def _running(transport: str = base.TRANSPORT_TLS) -> EnvInfo:
    return EnvInfo(
        ref=REF,
        state=base.STATE_RUNNING,
        complete=True,
        endpoints=(EnvEndpoint(url=URL, host="e031c98d53ce9d75dc5f4feb.tcp-ctf2.dasctf.com",
                               port=9999, transport=transport),),
        expires_at=EXPIRES,
        raw=RUNNING_RAW,
    )


def _head(text: str) -> str:
    """The guidance block, without the raw JSON dump appended for the operator."""
    return text.split("\n{", 1)[0]


class TestNotReadyIsCalledOut:
    def test_starting_is_labelled_incomplete(self):
        out = _head(render_env_info(_starting()))
        assert "INCOMPLETE" in out
        assert "do not use it as the target" in out.lower()

    @pytest.mark.parametrize(
        "state",
        [base.STATE_STARTING, base.STATE_NONE, base.STATE_EXPIRED, base.STATE_STOPPED,
         base.STATE_UNKNOWN],
    )
    def test_every_incomplete_state_is_refused_as_a_target(self, state):
        """No incomplete state may be presented as a usable target."""
        info = EnvInfo(ref=REF, state=state, complete=False, raw=RUNNING_RAW)
        out = _head(render_env_info(info))
        assert "NOT READY" in out or "NOT USABLE" in out or "no target is running" in out
        assert "target status" in out

    def test_tells_the_caller_to_keep_polling(self):
        out = _head(render_env_info(_starting()))
        assert "Poll" in out and "running" in out

    def test_warns_against_reusing_the_create_call_hostport(self):
        """The host in the create response can differ from the live one."""
        out = _head(render_env_info(_starting()))
        assert "create call" in out

    def test_guidance_names_the_neutral_tools_not_the_old_ones(self):
        out = _head(render_env_info(_starting()))
        assert "platform_read_env" in out
        assert "ctf2_get_target" not in out

    def test_running_without_endpoints_is_not_treated_as_usable(self):
        """'running' plus no published endpoint is still nothing to connect to."""
        info = EnvInfo(ref=REF, state=base.STATE_RUNNING, complete=True, endpoints=())
        out = _head(render_env_info(info))
        assert "NOT READY" in out

    def test_expired_says_restart_not_poll_again(self):
        """An expired target must not be rendered as 'still starting'."""
        info = EnvInfo(ref=REF, state=base.STATE_EXPIRED, complete=False, raw=RUNNING_RAW)
        out = _head(render_env_info(info))
        assert "NOT USABLE" in out
        assert "TTL" in out
        assert "platform_start_env" in out


class TestRunningTargetTransportGuidance:
    def test_tls_target_spells_out_wrap_socket(self):
        """This is the miss that cost 20+ minutes."""
        out = _head(render_env_info(_running(base.TRANSPORT_TLS)))
        assert "TLS-WRAPPED" in out
        assert "wrap_socket" in out
        assert "ssl.SSLContext" in out

    def test_tls_warning_explains_the_misleading_symptom(self):
        """The symptom (TCP ok, then silence) must be named, or the operator
        will still read it as a failed exploit."""
        out = _head(render_env_info(_running(base.TRANSPORT_TLS)))
        assert "handshake" in out
        assert "identical to a failed exploit" in out

    def test_plain_target_is_not_warned_about(self):
        out = _head(render_env_info(_running(base.TRANSPORT_TCP)))
        assert "TLS-WRAPPED" not in out
        assert "plain TCP" in out

    def test_unknown_transport_advises_a_fallback_probe(self):
        """If the platform does not report the transport, do not guess."""
        out = _head(render_env_info(_running(base.TRANSPORT_UNKNOWN)))
        assert "not reported" in out
        assert "try TLS" in out

    def test_unknown_transport_is_never_silently_called_plain(self):
        out = _head(render_env_info(_running(base.TRANSPORT_UNKNOWN)))
        assert "plain TCP is fine" not in out

    def test_url_is_surfaced(self):
        assert URL in _head(render_env_info(_running()))

    def test_expiry_is_reported(self):
        assert "expires_at" in _head(render_env_info(_running()))


class TestWebTargetIsNotCalledPlainRawTcp:
    """A live CTF2 web target must not be rendered as a raw TCP service.

    Measured 2026-09-23 on practice challenge ``[极客大挑战 2019]BabySQL``: the target
    payload was exactly

        {"access_type": "http",
         "access_url": "http://03ac8797e2ae410f0e8a11dc.http-ctf2.dasctf.com:80",
         "access_urls": [{"nc_ssl": None, "type": "http", "url": "...:80"}]}

    ``nc_ssl`` is null, so the scheme fallback correctly yields ``tcp`` -- no TLS
    wrapper needed.  But the renderer then said "plain TCP is fine", which invites
    a bare socket against a *web* challenge: ``tcp`` answers "no TLS wrapper", not
    "raw protocol".  Nothing failed loudly, which is exactly why it needs a test.
    """

    WEB_URL = "http://03ac8797e2ae410f0e8a11dc.http-ctf2.dasctf.com:80"

    def _web(self, url: str = WEB_URL) -> EnvInfo:
        return EnvInfo(
            ref=REF,
            state=base.STATE_RUNNING,
            complete=True,
            endpoints=(EnvEndpoint(url=url, host="x.http-ctf2.dasctf.com", port=80,
                                   transport=base.TRANSPORT_TCP, note="http"),),
            raw={"data": {"access_type": "http", "access_url": url}},
        )

    def test_http_target_is_named_an_http_service(self):
        out = _head(render_env_info(self._web()))
        assert "HTTP service" in out
        assert self.WEB_URL in out

    def test_http_target_does_not_invite_a_bare_socket(self):
        out = _head(render_env_info(self._web()))
        assert "plain TCP is fine" not in out
        assert "curl" in out
        # Still honest about there being no TLS wrapper to apply.
        assert "no TLS wrapper needed" in out

    def test_http_target_is_not_treated_as_tls(self):
        """The scheme is ``http://``, so the TLS wrap_socket lecture must not fire."""
        out = _head(render_env_info(self._web()))
        assert "TLS-WRAPPED" not in out
        assert "wrap_socket" not in out

    def test_a_tls_web_target_still_gets_the_tls_warning(self):
        """``https://`` resolves to TLS, so the scheme branch must not shadow it."""
        tls_web = EnvInfo(
            ref=REF,
            state=base.STATE_RUNNING,
            complete=True,
            endpoints=(EnvEndpoint(url="https://x.example.com", transport=base.TRANSPORT_TLS),),
            raw={},
        )
        out = _head(render_env_info(tls_web))
        assert "TLS-WRAPPED" in out
        assert "HTTP service" not in out

    def test_a_plain_raw_service_keeps_its_own_wording(self):
        """No scheme (the measured pwn form: ``host:port``) stays 'plain TCP'."""
        out = _head(render_env_info(_running(base.TRANSPORT_TCP)))
        assert "plain TCP is fine" in out
        assert "HTTP service" not in out

    def test_an_http_target_over_a_nonstandard_port_is_still_http(self):
        out = _head(render_env_info(self._web("http://host.example.com:8080/app")))
        assert "HTTP service" in out
        assert "plain TCP is fine" not in out

    def test_the_real_live_web_payload_renders_as_http(self):
        """End-to-end on the recorded payload: adapter normalization + render.

        No hand-built EnvInfo here -- this is the exact JSON the platform served,
        through `normalize_target_payload`, so it also pins that the transport
        really does come out `tcp` (nc_ssl is null) and that the renderer still
        names the service from the scheme.
        """
        from vulnclaw.platforms.ctf2 import normalize_target_payload
        from tests.platforms.ctf2_payloads import WEB_RUNNING_PAYLOAD, WEB_TARGET_URL

        info = normalize_target_payload(WEB_RUNNING_PAYLOAD, REF)
        assert info.state == base.STATE_RUNNING
        assert info.complete is True
        assert info.transports() == frozenset({base.TRANSPORT_TCP})
        assert [ep.url for ep in info.endpoints] == [WEB_TARGET_URL]

        out = _head(render_env_info(info))
        assert "HTTP service" in out
        assert "curl" in out
        assert "plain TCP is fine" not in out
        assert "TLS-WRAPPED" not in out


class TestNoTarget:
    def test_null_state_explains_the_sequence(self):
        info = EnvInfo(ref=REF, state=base.STATE_NONE, complete=False, raw={"data": None,
                                                                          "success": True})
        out = _head(render_env_info(info))
        assert "no target is running" in out
        assert "platform_start_env" in out
        assert "poll" in out.lower()

    def test_not_required_explains_the_challenge_needs_no_environment(self):
        info = EnvInfo(ref=REF, state=base.STATE_NOT_REQUIRED, complete=True, raw={})
        out = _head(render_env_info(info))
        assert "needs no running environment" in out
        assert "NOT READY" not in out


class TestRawPayloadIsStillAvailable:
    def test_raw_json_is_appended_for_the_operator(self):
        """Guidance must not hide the platform's own response."""
        out = render_env_info(_running())
        assert '"access_url"' in out
        assert '"success"' in out

    def test_raw_dump_is_truncated(self):
        info = EnvInfo(
            ref=REF,
            state=base.STATE_STARTING,
            complete=False,
            raw={"blob": "x" * 20000},
        )
        out = render_env_info(info, raw_limit=200)
        assert len(out) < 1000

    def test_unserializable_raw_does_not_crash(self):
        info = EnvInfo(
            ref=REF, state=base.STATE_STARTING, complete=False, raw={"bad": object()}
        )
        assert "target status" in render_env_info(info)


class TestPlatformNeutrality:
    def test_gcs_ref_renders_with_its_own_prefix(self):
        info = EnvInfo(ref=GCS_REF, state=base.STATE_RUNNING, complete=True,
                       endpoints=(EnvEndpoint(host="10.0.0.1", port=80,
                                              transport=base.TRANSPORT_UNKNOWN),))
        out = _head(render_env_info(info))
        assert "[gcs] target status: running" in out
        assert "10.0.0.1:80" in out

    def test_adapter_supplied_guidance_is_appended(self):
        info = EnvInfo(
            ref=REF,
            state=base.STATE_STARTING,
            complete=False,
            guidance=("platform note: the field is named nc_ssl here",),
        )
        assert "platform note: the field is named nc_ssl here" in _head(render_env_info(info))


class TestModelInvariants:
    def test_incomplete_state_cannot_be_marked_complete(self):
        """The invariant is enforced by the model, not by renderer discipline."""
        with pytest.raises(ValueError):
            EnvInfo(ref=REF, state=base.STATE_STARTING, complete=True)

    def test_unknown_state_is_rejected(self):
        with pytest.raises(ValueError):
            EnvInfo(ref=REF, state="teleported", complete=False)

    def test_endpoint_rejects_an_unknown_transport_string(self):
        with pytest.raises(ValueError):
            EnvEndpoint(host="h", transport="quic")

    def test_usable_requires_both_complete_and_a_usable_state(self):
        assert _running().usable
        assert not _starting().usable

    def test_transports_reports_what_the_endpoints_say(self):
        assert _running(base.TRANSPORT_TLS).transports() == frozenset({base.TRANSPORT_TLS})
