"""ctf2_get_target must not let a caller mistake a partial response for complete.

The bug this pins down is specific and cost real time: the CTF2 target response
has two shapes depending on ``status``.

    starting -> {id, name, status, expires_at, created_at, description}
                no access_url, no access_urls, no nc_ssl
    running  -> adds access_url, access_urls[], nc_ssl

The `starting` shape is a plausible-looking object, so a caller reads it once,
believes it has the connection info, and never polls again. On a real challenge
that is exactly what happened: the target was fetched while `starting`, the bare
host:port from the create call was used against a **TLS-wrapped** service with a
raw socket, and the resulting "TCP connects then nothing" was misread as a failed
exploit for 20+ minutes. ``nc_ssl`` (the field that explained it) only exists once
``running``.

These tests assert the *rendering contract*: the status is always stated, a
non-running target is explicitly labelled unusable with instructions, and a
TLS-wrapped running target spells out the wrap_socket requirement.
"""

from __future__ import annotations

import pytest

from vulnclaw.ctf_platform.tools import _render_target_state


def _starting() -> dict:
    return {
        "data": {
            "created_at": "2026-09-21T14:57:35.055669+08:00",
            "description": "stack",
            "expires_at": "2026-09-21T15:57:35.055394+08:00",
            "friendly_id": "TGT-2026-310885",
            "id": "e031c98d-ef77-477a-a75d-51a69fe38d9a",
            "name": "practice-stack-d37ad0d4",
            "status": "starting",
        },
        "success": True,
    }


def _running(nc_ssl=True) -> dict:
    url = "e031c98d53ce9d75dc5f4feb.tcp-ctf2.dasctf.com:9999"
    return {
        "data": {
            "access_type": "tcp",
            "access_url": url,
            "access_urls": [{"nc_ssl": nc_ssl, "type": "tcp", "url": url}],
            "expires_at": "2026-09-21T15:57:35.055394+08:00",
            "nc_ssl": nc_ssl,
            "status": "running",
        },
        "success": True,
    }


def _head(text: str) -> str:
    """The guidance block, without the raw JSON dump appended for the operator."""
    return text.split("\n{", 1)[0]


class TestNotReadyIsCalledOut:
    @pytest.mark.parametrize(
        "status", ["starting", "pending", "creating", "queued", ""]
    )
    def test_non_running_status_is_labelled_incomplete(self, status):
        payload = _starting()
        payload["data"]["status"] = status
        out = _head(_render_target_state(payload))
        assert "INCOMPLETE" in out
        assert "do not use it as the target" in out.lower() or "do NOT use" in out

    def test_tells_the_caller_to_keep_polling(self):
        out = _head(_render_target_state(_starting()))
        assert "Poll" in out and "running" in out

    def test_warns_against_reusing_the_create_call_hostport(self):
        """The host in the create response can differ from the live one."""
        out = _head(_render_target_state(_starting()))
        assert "create call" in out

    def test_status_is_always_stated(self):
        for payload in (_starting(), _running(), {"data": None, "success": True}):
            assert "target status" in _head(_render_target_state(payload)) or (
                "no target" in _head(_render_target_state(payload))
            )


class TestRunningTargetTransportGuidance:
    def test_tls_target_spells_out_wrap_socket(self):
        """This is the miss that cost 20+ minutes."""
        out = _head(_render_target_state(_running(nc_ssl=True)))
        assert "TLS-WRAPPED" in out
        assert "wrap_socket" in out
        assert "ssl.SSLContext" in out

    def test_tls_warning_explains_the_misleading_symptom(self):
        """The symptom (TCP ok, then silence) must be named, or the operator
        will still read it as a failed exploit."""
        out = _head(_render_target_state(_running(nc_ssl=True)))
        assert "handshake" in out
        assert "identical to a failed exploit" in out

    def test_plain_target_is_not_warned_about(self):
        out = _head(_render_target_state(_running(nc_ssl=False)))
        assert "TLS-WRAPPED" not in out
        assert "plain TCP" in out

    def test_url_is_surfaced(self):
        out = _head(_render_target_state(_running()))
        assert "e031c98d53ce9d75dc5f4feb.tcp-ctf2.dasctf.com:9999" in out

    def test_unknown_transport_advises_a_fallback_probe(self):
        """If the platform does not report nc_ssl, do not guess -- say what to try."""
        payload = _running()
        payload["data"].pop("nc_ssl")
        payload["data"]["access_urls"] = [{"url": payload["data"]["access_url"], "type": "tcp"}]
        out = _head(_render_target_state(payload))
        assert "not reported" in out
        assert "try TLS" in out

    def test_expiry_is_reported(self):
        """An expired target is the other half of the same failure mode."""
        out = _head(_render_target_state(_running()))
        assert "expires_at" in out


class TestNoTarget:
    def test_null_data_explains_the_sequence(self):
        out = _head(_render_target_state({"data": None, "success": True}))
        assert "no target is running" in out
        assert "ctf2_start_environment" in out
        assert "poll" in out.lower()

    def test_missing_data_key_is_handled(self):
        out = _head(_render_target_state({"success": True}))
        assert "no target is running" in out

    def test_non_dict_data_does_not_crash(self):
        out = _render_target_state({"data": "unexpected"})
        assert "no target is running" in out


class TestRawPayloadIsStillAvailable:
    def test_raw_json_is_appended_for_the_operator(self):
        """Guidance must not hide the platform's own response."""
        out = _render_target_state(_running())
        assert '"access_url"' in out
        assert '"success"' in out
