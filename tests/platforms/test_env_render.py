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
