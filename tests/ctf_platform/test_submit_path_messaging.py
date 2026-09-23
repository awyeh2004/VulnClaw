"""Two submission-path failures that both used to produce a misleading message.

1. **The gate's own instruction did not work.** `platform_submit` refuses by
   default and tells the caller to set
   ``VULNCLAW_COMPETITION__ALLOW_FLAG_SUBMISSION=true``. Nothing in
   ``_overlay_env`` read that variable, so a caller who followed the instruction
   exactly saw the identical refusal and reasonably concluded the gate was broken
   rather than the variable ignored. Measured 2026-09-23 while confirming a real
   flag; the env handler now exists.

2. **A CAPTCHA looked like a rate limit.** On a real submission the session API
   answered HTTP 429 with
   ``{"data": {"risk_action": "challenge", "risk_challenge": {"image": "data:image/png;base64,..."}}}``
   -- a human-verification gate. That body has no top-level ``error``, so the caller
   was told "429 Too Many Requests": the one reading that invites a retry loop
   against an anti-automation control, which can never succeed.
"""

from __future__ import annotations

import httpx
import pytest

from vulnclaw.config import settings
from vulnclaw.ctf_platform import client as ctf2
from tests.platforms import ctf2_payloads

ENV_CANONICAL = "VULNCLAW_COMPETITION__ALLOW_FLAG_SUBMISSION"
ENV_SINGLE_UNDERSCORE = "VULNCLAW_COMPETITION_ALLOW_FLAG_SUBMISSION"


@pytest.fixture
def clean_env(monkeypatch):
    for name in (ENV_CANONICAL, ENV_SINGLE_UNDERSCORE):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


class TestTheGatesOwnInstructionWorks:
    """The message `platform_submit` prints has to be true."""

    @pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", "on"])
    def test_the_advertised_env_var_opens_the_gate(self, clean_env, value):
        clean_env.setenv(ENV_CANONICAL, value)

        from vulnclaw.platforms.tools import _flag_submission_enabled

        assert _flag_submission_enabled() is True

    @pytest.mark.parametrize("value", ["false", "FALSE", "0", "no", "off", ""])
    def test_falsy_values_keep_it_shut(self, clean_env, value):
        clean_env.setenv(ENV_CANONICAL, value)

        from vulnclaw.platforms.tools import _flag_submission_enabled

        assert _flag_submission_enabled() is False

    def test_the_single_underscore_spelling_also_works(self, clean_env):
        """Both spellings are accepted, matching the recon keys' convention."""
        clean_env.setenv(ENV_SINGLE_UNDERSCORE, "true")

        from vulnclaw.platforms.tools import _flag_submission_enabled

        assert _flag_submission_enabled() is True

    def test_no_env_var_leaves_the_gate_shut(self, clean_env):
        from vulnclaw.platforms.tools import _flag_submission_enabled

        assert _flag_submission_enabled() is False

    def test_overlay_env_reads_the_field(self, clean_env):
        """Directly on the overlay, so the wiring is pinned, not just the effect."""
        clean_env.setenv(ENV_CANONICAL, "true")
        config = settings.load_config()
        assert config.competition.allow_flag_submission is True

    def test_the_refusal_message_advertises_a_variable_that_is_read(self, clean_env):
        """The two halves must agree: message says X, overlay reads X."""
        from vulnclaw.platforms.tools import _submission_disabled_message

        assert ENV_CANONICAL in _submission_disabled_message()


def _response(status: int, payload) -> httpx.Response:
    return httpx.Response(
        status, json=payload, request=httpx.Request("POST", "https://ctf2.dasctf.com/x")
    )


class TestCaptchaIsNotReportedAsARateLimit:
    # The recorded live shape, NOT a local copy: the response that the platform
    # actually served for a submit. Kept in tests/platforms/ctf2_payloads.py so the
    # submit path has one source of truth for its payloads (the four field names that
    # were once wrong came from exactly this kind of hand-copied sample).
    CAPTCHA_429 = ctf2_payloads.SUBMIT_RISK_CONTROL_PAYLOAD

    def test_captcha_is_named_as_human_verification(self):
        with pytest.raises(RuntimeError) as excinfo:
            ctf2._raise_for_status(_response(429, self.CAPTCHA_429))

        message = str(excinfo.value)
        assert "risk_action='challenge'" in message
        assert "CAPTCHA" in message
        assert "HUMAN-VERIFICATION" in message

    def test_captcha_message_forbids_the_retry_loop(self):
        """'429' invites a retry; a human check must not."""
        with pytest.raises(RuntimeError) as excinfo:
            ctf2._raise_for_status(_response(429, self.CAPTCHA_429))

        message = str(excinfo.value)
        assert "DO NOT retry" in message
        assert "browser" in message

    def test_a_plain_rate_limit_keeps_its_own_meaning(self):
        payload = {"error": {"code": "RATE_LIMIT_EXCEEDED"}}
        with pytest.raises(RuntimeError) as excinfo:
            ctf2._raise_for_status(_response(429, payload))

        message = str(excinfo.value)
        assert "RATE_LIMIT_EXCEEDED" in message
        assert "CAPTCHA" not in message

    def test_risk_action_without_an_image_still_says_human_check(self):
        payload = {"data": {"risk_action": "verify"}}
        with pytest.raises(RuntimeError) as excinfo:
            ctf2._raise_for_status(_response(429, payload))

        assert "unspecified human check" in str(excinfo.value)

    def test_a_non_json_error_body_does_not_crash(self):
        response = httpx.Response(
            502,
            text="<html>502 Bad Gateway</html>",
            request=httpx.Request("POST", "https://ctf2.dasctf.com/x"),
        )
        with pytest.raises(RuntimeError) as excinfo:
            ctf2._raise_for_status(response)

        assert "502" in str(excinfo.value)

    def test_success_is_not_affected(self):
        assert ctf2._raise_for_status(_response(200, {"success": True})) is None

    def test_the_invalid_request_hint_is_preserved(self):
        """The Open API says which field it wants; do not swallow that.

        Uses the recorded response rather than a hand-written one: this hint is the
        only actionable thing the platform says about a rejected submit, and it came
        from omitting `confirmation`.
        """
        with pytest.raises(RuntimeError) as excinfo:
            ctf2._raise_for_status(
                _response(400, ctf2_payloads.SUBMIT_INVALID_REQUEST_HINT_PAYLOAD)
            )

        message = str(excinfo.value)
        assert "INVALID_REQUEST" in message
        assert "confirmation" in message
