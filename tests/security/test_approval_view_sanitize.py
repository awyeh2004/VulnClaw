"""The approval prompt masks credentials; the evidence keeps them.

Two requirements pull in opposite directions and both are real:

- An operator judging a pending ``curl -u admin:P@ssw0rd`` must SEE enough of the
  command to decide, and the prompt is a surface that gets copied into chat and
  tickets. A live password there is a leak.
- In a pentest run, a credential found in the target's data is the deliverable
  ("the attacker used this API key"). A blanket mask would eat the finding.

So the masking lives on the approval view only. ``utils/redaction.py`` keeps its
own, deliberately narrow scope (harness-owned credentials, everywhere).
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.exec_gate import (
    GateRequest,
    get_execution_gate,
    reset_execution_gate,
)
from vulnclaw.utils.sanitize_display import MASK, mask_display_secrets, mask_for_approval


class TestMaskPatterns:
    def test_curl_basic_auth(self):
        out = mask_display_secrets("curl -u admin:hunter2 https://x/api")
        assert MASK in out
        assert "hunter2" not in out
        # The URL survives: the operator still sees what is being hit.
        assert "https://x/api" in out

    def test_curl_long_user_flag(self):
        out = mask_display_secrets("curl --user 'svc:p@ss w0rd' https://x")
        assert "p@ss w0rd" not in out
        assert MASK in out

    def test_authorization_header(self):
        out = mask_display_secrets("curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9' https://x")
        assert "eyJhbGciOiJIUzI1NiJ9" not in out
        # The header NAME stays, so the operator knows auth is in play.
        assert "Authorization" in out

    def test_cookie_header(self):
        out = mask_display_secrets("curl -H 'Cookie: session=abc123def456' https://x")
        assert "abc123def456" not in out
        assert "Cookie" in out

    def test_private_key_block(self):
        text = (
            "cat > k.pem <<EOF\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA1234567890abcdef\n"
            "-----END RSA PRIVATE KEY-----\n"
            "EOF"
        )
        out = mask_display_secrets(text)
        assert "MIIEowIBAAKCAQEA" not in out
        # The surrounding shell structure is untouched.
        assert "cat > k.pem" in out
        assert "EOF" in out

    def test_url_userinfo(self):
        out = mask_display_secrets("psql postgres://app:s3cret@db.internal:5432/x")
        assert "s3cret" not in out
        assert "db.internal" in out

    def test_key_value_assignment(self):
        out = mask_display_secrets("export API_KEY=abcd1234efgh5678")
        assert "abcd1234efgh5678" not in out
        assert "API_KEY" in out

    def test_well_known_prefixes(self):
        # The AKIA literal is assembled at runtime so this file does not itself
        # trip tests/security/test_no_committed_secrets.py -- that scanner is
        # right to flag the shape, and the fixture does not need to be literal.
        aws_like = "AKIA" + "IOSFODNN7EXAMPLE"
        for value in ("sk-live-abcdef123456", "ghp_abcdefghij1234", aws_like):
            out = mask_display_secrets(f"echo {value}")
            assert value not in out, value

    def test_plain_command_untouched(self):
        cmd = "nmap -sV -p 80,443 10.0.0.5"
        assert mask_display_secrets(cmd) == cmd

    def test_port_list_is_not_a_password(self):
        # The attached-password rule is scoped to a command that already names a
        # ``-u`` user; without that scope ``-p80,443`` looks like a password.
        for cmd in (
            "nmap -sV -p80,443 10.0.0.5",
            "nmap -p- -T4 10.0.0.5",
            "ssh -p 2222 user@host",
        ):
            assert mask_display_secrets(cmd) == cmd, cmd

    def test_mysql_attached_password(self):
        out = mask_display_secrets("mysql -uroot -pS3cretPw -h db")
        assert "S3cretPw" not in out
        assert "-uroot" in out

    def test_empty_is_passthrough(self):
        assert mask_display_secrets("") == ""
        assert mask_display_secrets(None) is None  # type: ignore[arg-type]

    def test_never_raises_on_odd_input(self):
        # The approval path must not crash; best-effort by contract.
        assert mask_display_secrets("-----BEGIN PRIVATE KEY-----\nunterminated") is not None


class TestApprovalViewIsMasked:
    """The gate builds the view; this is the surface the operator reads."""

    def setup_method(self):
        reset_execution_gate()

    def teardown_method(self):
        reset_execution_gate()

    def test_sync_hook_sees_masked_command(self, monkeypatch):
        seen: list = []
        gate = get_execution_gate()
        gate.set_mode("ask")
        gate.install_sync_confirm_hook(lambda view: (seen.append(view), False)[1])

        gate.confirm_sync(
            GateRequest(
                kind="shell",
                display="curl -u admin:hunter2 https://target/api",
                cwd="/tmp",
            )
        )
        assert seen, "hook was not called"
        view = seen[0]
        assert "hunter2" not in view.display_escaped
        assert MASK in view.display_escaped
        assert "https://target/api" in view.display_escaped

    def test_event_payload_is_masked(self, monkeypatch):
        gate = get_execution_gate()
        gate.set_mode("ask")
        captured: list = []

        async def _channel(view):
            captured.append(view)
            return "deny"

        class _Ch:
            async def request_approval(self, view):
                return await _channel(view)

        gate.install_channel(_Ch())

        import asyncio

        asyncio.run(
            gate.authorize(
                GateRequest(
                    kind="shell",
                    display="mysql -u root -pS3cretPw -h db",
                    cwd="/tmp",
                )
            )
        )
        assert captured
        payload = captured[0].to_event_payload()
        assert "S3cretPw" not in payload["question"]
        assert MASK in payload["question"]


class TestEvidenceKeepsRawValue:
    """The other half of the contract: the mask must not reach evidence."""

    def test_agent_state_evidence_is_not_display_masked(self):
        from vulnclaw.agent.agent_state import AgentState

        state = AgentState()
        state.remember_tool_result(
            tool="http_probe_batch",
            arguments={"url": "https://x"},
            output="Set-Cookie: session=abc123def456; password=hunter2",
        )
        # Evidence is the deliverable surface: the credential found on the
        # target must still be there.
        assert "hunter2" in state.evidence_text()


class TestMaskForApprovalCombinesLayers:
    def test_harness_own_key_masked_even_though_patterns_may_miss_it(self, monkeypatch):
        # A harness key that does not look like any credential pattern is still
        # caught by the exact-value substitution.
        from vulnclaw.utils import sanitize_display as module
        from vulnclaw.utils import redaction

        monkeypatch.setattr(
            redaction, "local_secret_values", lambda **_: {"zzzunusualkey": "env.TEST"}
        )
        masked, _ = mask_for_approval("run --with zzzunusualkey")
        assert "zzzunusualkey" not in masked