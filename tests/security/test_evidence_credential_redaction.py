"""The harness's own credentials must not reach evidence, state files or reports.

Measured (2026-09-27): `~/.vulnclaw/runs/<run>/targets/<t>/state/current.json` held the
operator's config file verbatim inside `agent_state.evidence[12].content`, including a live
`gcs.access_key` and LLM `api_key`. Evidence is the surface that feeds previews, snapshots and
the written report, and it is exactly how a credential spread from the config into run
artifacts.

The scope decision these tests pin is the important half: only credentials the HARNESS owns are
redacted. A credential found on the target is the deliverable of a pentest/IR run and must
survive -- a blanket "sk-…" filter would delete the finding the operator asked for.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.utils import redaction

# Values that look like real credentials but belong to a TARGET, not to this harness.
TARGET_KEY = "sk-" + "targetside" + "0123456789abcdef"      # 30 chars, not one of ours
OUR_KEY = "sk-" + "ourside" + "9876543210fedcba"            # 30 chars, registered as ours
OUR_GCS = "ak_live_" + "OurOwnGcsKey123456"
WEB_TOKEN = "web-" + "tokenvalue" + "0123456789"


@pytest.fixture()
def secrets(monkeypatch):
    """A frozen own-secret set: no config file, no environment, no web token on disk."""
    table = {OUR_KEY: "config.llm.api_key", OUR_GCS: "config.gcs.access_key",
             WEB_TOKEN: "web_token"}
    monkeypatch.setattr(redaction, "local_secret_values", lambda force=False: dict(table))
    return table


class TestOwnCredentialsAreRedacted:
    def test_an_own_key_is_masked_with_a_label_and_digest(self, secrets):
        text = f'api_key: "{OUR_KEY}"'
        out = redaction.redact_credentials(text)

        assert OUR_KEY not in out
        assert "config.llm.api_key" in out, out
        assert "sk-o…" in out, "a short recognisable head must survive for the operator"

    def test_every_own_credential_in_one_blob(self, secrets):
        """The real shape: a config file dumped into evidence."""
        blob = (
            "gcs:\n"
            f"  access_key: {OUR_GCS}\n"
            "llm:\n"
            f"  api_key: {OUR_KEY}\n"
            f"  provider_keys:\n    ds: {OUR_KEY}\n"
        )
        out = redaction.redact_credentials(blob)

        assert OUR_KEY not in out and OUR_GCS not in out
        assert out.count("[redacted") == 3, out

    def test_it_is_idempotent(self, secrets):
        once = redaction.redact_credentials(f"k={OUR_KEY}")
        assert redaction.redact_credentials(once) == once

    def test_a_superset_key_is_not_half_replaced(self, secrets):
        """Longest-first, or the longer value would be mangled into a partial mask."""
        longer = OUR_KEY + "EXTRA"
        out = redaction.redact_credentials(f"v={longer}", secrets={**secrets, longer: "longer"})

        assert longer not in out
        assert out.count("[redacted") == 1, out

    def test_empty_and_non_string_input_is_safe(self, secrets):
        assert redaction.redact_credentials("") == ""
        assert redaction.redact_credentials(None) == ""


class TestTargetCredentialsSurvive:
    """The deliberate scope limit -- this is the difference between a fix and a footgun."""

    def test_a_target_side_key_is_left_alone(self, secrets):
        out = redaction.redact_credentials(f"the attacker used {TARGET_KEY} to call the API")

        assert TARGET_KEY in out
        assert "[redacted" not in out

    def test_a_password_found_on_the_target_survives(self, secrets):
        out = redaction.redact_credentials("body: admin:P@ssw0rd-found-on-target")
        assert "P@ssw0rd-found-on-target" in out


class TestCollectingWhatWeOwn:
    def test_credentials_are_found_by_field_name(self, monkeypatch):
        redaction.reset_cache()
        payload = {
            "llm": {"api_key": OUR_KEY, "max_tokens": 8192, "oauth_token_url": "https://x/y"},
            "gcs": {"access_key": OUR_GCS, "base_url": "https://pro.dasctf.com"},
            "recon": {"fofa_key": "", "shodan_key": "short"},
            "mcp": {"servers": {"x": {"env": {"SERVICE_TOKEN": "mcp-" + "0123456789abcdef"}}}},
        }

        class _Cfg:
            def model_dump(self, mode="json"):
                return payload

        monkeypatch.setattr("vulnclaw.config.settings.load_config", lambda: _Cfg())
        monkeypatch.setattr(redaction, "_web_token", lambda: WEB_TOKEN)

        found = redaction.local_secret_values(force=True)

        assert OUR_KEY in found and OUR_GCS in found
        assert "mcp-" + "0123456789abcdef" in found, "nested mcp env tokens count too"
        # look-alikes must NOT be collected: they are not secrets, and a short value is noise
        assert "https://x/y" not in found
        assert 8192 not in found and "8192" not in found
        assert "short" not in found, "below the length floor"
        assert "" not in found, "an empty field is not a credential"

    def test_the_secret_set_is_cached(self, monkeypatch):
        """It runs on the evidence path: re-reading the config per tool result is the very
        per-call parse the platform gates were just fixed to stop doing."""
        redaction.reset_cache()
        calls: list[int] = []

        class _Cfg:
            def model_dump(self, mode="json"):
                calls.append(1)
                return {"llm": {"api_key": OUR_KEY}}

        monkeypatch.setattr("vulnclaw.config.settings.load_config", lambda: _Cfg())
        monkeypatch.setattr(redaction, "_web_token", lambda: "")

        for _ in range(25):
            redaction.redact_credentials(f"x {OUR_KEY} y")

        assert calls == [1], f"the config was read {len(calls)} times for 25 redactions"


class TestTheEvidenceFunnelUsesIt:
    def test_remember_tool_result_stores_a_redacted_body(self, secrets):
        state = AgentState(goal="capture the flag", origin="http://x")
        output = json.dumps({"cfg": {"llm": {"api_key": OUR_KEY}}})

        record = state.remember_tool_result(tool="shell_command", arguments={}, output=output)

        assert OUR_KEY not in record.content
        assert OUR_KEY not in record.preview
        assert OUR_KEY not in record.summary
        assert "config.llm.api_key" in record.content

    def test_the_duplicate_hash_follows_the_redacted_body(self, secrets):
        """Two outputs differing only in an own key are the same evidence -- and hashing the
        raw text would have kept the value in the state file through the hash alone (it does
        not store the input, but the identity must not depend on a secret either)."""
        state = AgentState(goal="g", origin="http://x")
        first = state.remember_tool_result(tool="t", arguments={}, output=f"key={OUR_KEY}")
        second = state.remember_tool_result(tool="t", arguments={}, output=f"key={OUR_KEY}")

        assert second.content_hash == first.content_hash
        assert second.duplicate_of == first.id

    def test_target_evidence_is_untouched_end_to_end(self, secrets):
        state = AgentState(goal="g", origin="http://x")
        record = state.remember_tool_result(
            tool="t", arguments={}, output=f"found on target: {TARGET_KEY}"
        )
        assert TARGET_KEY in record.content

    def test_a_state_file_written_to_disk_has_no_own_key(self, secrets, tmp_path):
        """The measured leak was in a state file, so assert on the file, not just the object."""
        state = AgentState(goal="g", origin="http://x")
        state.remember_tool_result(tool="t", arguments={}, output=f"api_key: {OUR_KEY}")
        target = tmp_path / "current.json"
        target.write_text(json.dumps({"agent_state": state.model_dump(mode="json")}),
                          encoding="utf-8")

        assert OUR_KEY not in target.read_text(encoding="utf-8")


class TestTheRealConfigIsNotLeaked:
    def test_the_live_configs_own_values_are_the_ones_masked(self, monkeypatch):
        """Against the real config object, whatever it happens to contain at run time."""
        redaction.reset_cache()
        from vulnclaw.config.settings import load_config

        config = load_config()
        secrets = redaction.local_secret_values(force=True)
        if not secrets:
            pytest.skip("no credentials configured in this environment")

        dumped = json.dumps(config.model_dump(mode="json"), ensure_ascii=False, default=str)
        out = redaction.redact_credentials(dumped, secrets=secrets)

        for value in secrets:
            assert value not in out, "an own credential survived the redaction"
