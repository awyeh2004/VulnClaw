"""C-1/C-2 execution-boundary contract tests.

These freeze the process-spawn attack surface: every spawn call site must
live inside the reviewed allowlist of ``scripts/verify_execution_boundary.py``,
and the model-reachable dangerous tools must refuse leaf agents.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "verify_execution_boundary.py"


@pytest.fixture(autouse=True)
def _isolated_execution_gate():
    """Reset the process-wide execution gate around every test in this file.

    Round-5 review N10: ``test_main_agent_passes_guard_into_execution_path``
    installs an ``AutoApproveChannel`` on the singleton returned by
    ``get_execution_gate()`` and never removed it, so "approve everything" leaked
    into every later test in the same process — the very failure mode that test's
    own docstring describes (a test that only passed because an earlier test had
    left a pre-armed approval behind). Resetting on both sides makes each test
    measure the guard rather than the ambient state.
    """
    from vulnclaw.agent.exec_gate import reset_execution_gate

    reset_execution_gate()
    yield
    reset_execution_gate()


def _run_script(*extra: str) -> subprocess.CompletedProcess[str]:
    """Run the verifier and decode its output as UTF-8.

    The script prints non-ASCII (it names unreviewed sites with an em dash and
    ``ensure_ascii=False`` JSON), so relying on the platform default encoding
    fails on a CP936/GBK console: the read thread raises UnicodeDecodeError, the
    CompletedProcess comes back with EMPTY stdout, and every assertion below
    reports a misleading failure (a returncode mismatch instead of the real
    message). Pinning the child's stdio encoding makes the check
    locale-independent, which is what a CI-grade gate needs anyway.
    """
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, str(SCRIPT), *extra],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        env=env,
    )


class TestMechanicalBoundary:
    def test_verify_script_passes_on_current_tree(self):
        result = _run_script()
        assert result.returncode == 0, result.stdout + result.stderr

    def test_model_reachable_sites_are_explicitly_allowlisted(self):
        """Every current spawn site needs its own reviewed baseline entry."""
        from scripts.verify_execution_boundary import (
            ALLOWED_SPAWN_SITES,
            _partition_sites,
            scan_tree,
        )

        reviewed, violations = _partition_sites(scan_tree())
        assert reviewed, "scan found no reviewed sites -- the scan itself is broken"
        assert [v for v in violations] == []

    def test_new_site_in_reviewed_file_is_not_implicitly_allowed(self):
        from scripts.verify_execution_boundary import ALLOWED_SPAWN_SITES, SpawnSite

        probe = SpawnSite(
            file="vulnclaw/agent/builtin_tools.py",
            line=999999,
            call="subprocess.run",
            scope="_spawn_captured",
            invariant="deadbeef",
        )
        assert probe.key() not in ALLOWED_SPAWN_SITES

    def test_line_shift_does_not_rekey_a_reviewed_site(self):
        """The whole point of the scope+hash key: moving code must stay reviewed."""
        from scripts.verify_execution_boundary import SpawnSite

        a = SpawnSite("f.py", 10, "subprocess.run", "fn", "abc12345")
        b = SpawnSite("f.py", 9999, "subprocess.run", "fn", "abc12345")
        assert a.key() == b.key()

    def test_count_budget_flags_an_extra_site_under_a_reviewed_key(self):
        """A second identical spawn next to an approved one is still a violation."""
        from scripts.verify_execution_boundary import SpawnSite, _partition_sites

        key_holder = SpawnSite(
            "vulnclaw/agent/builtin_tools.py", 457, "subprocess.Popen",
            "_spawn_captured", "1eacb151",
        )
        # Only valid while that key is in the allowlist with a budget.
        from scripts.verify_execution_boundary import ALLOWED_SPAWN_SITES

        if key_holder.key() not in ALLOWED_SPAWN_SITES:
            pytest.skip("baseline key changed; budget assertion not applicable")
        reviewed, violations = _partition_sites([key_holder, key_holder])
        assert len(reviewed) == 1
        assert len(violations) == 1
        assert "reviewed for 1 site(s), found 2" in str(violations[0]["reason"])

    def test_json_report_lists_reviewed_sites(self):
        result = _run_script("--json")
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(result.stdout)
        assert report["ok"] is True
        # Line numbers are reported but are NOT the key, so assert on the stable
        # fields instead of a line number that drifts on unrelated edits.
        reviewed = {
            (s["file"], s["scope"], s["call"], s["invariant"])
            for s in report["reviewed_sites"]
        }
        assert (
            "vulnclaw/agent/builtin_tools.py",
            "_spawn_captured",
            "subprocess.Popen",
            "1eacb151",
        ) in reviewed
        assert all(s["line"] > 0 for s in report["reviewed_sites"])


class TestSubagentDangerousToolRefusal:
    """Leaf agents can never reach host execution, whatever their role globs."""

    def _make_agent(self, depth: int = 0):
        import sys

        from vulnclaw.agent.subagent.models import SubagentContext

        sys.path.insert(0, str(REPO_ROOT / "tests" / "agent"))
        try:
            from test_builtin_tools import DummyAgent
        finally:
            sys.path.pop(0)

        agent = DummyAgent()
        agent._subagent_ctx = SubagentContext(depth=depth)
        return agent

    async def test_main_agent_passes_guard_into_execution_path(self, monkeypatch):
        """Depth-0 reaches the spawn path; the refusal is reserved for leaf agents.

        This test used to patch ``builtin_tools.subprocess.run``, which the code
        path does not call -- ``execute_shell_command`` goes through
        ``_spawn_captured``, and that uses ``subprocess.Popen``. So the stub never
        fired and the test only "passed" when some earlier test happened to have
        left a patched Popen (or a pre-armed approval) behind: run alone it
        really executed ``id`` against the host shell. It then failed in the full
        suite, because the process-wide gate singleton
        (``exec_gate._default_gate``) had been created by whichever test ran
        first -- and DummyConfig carries no ``permission_mode``, so the gate
        defaulted to "ask" and refused with ``no_channel`` before any spawn.

        Patching the seam the code actually uses, plus installing an approving
        channel, makes the assertion measure the guard instead of the ambient
        state of the process.
        """
        from vulnclaw.agent import builtin_tools
        from vulnclaw.agent.exec_gate import get_execution_gate, reset_execution_gate

        sys.path.insert(0, str(REPO_ROOT / "tests" / "agent"))
        try:
            from test_builtin_tools import AutoApproveChannel
        finally:
            sys.path.pop(0)

        reset_execution_gate()
        get_execution_gate().install_channel(AutoApproveChannel())

        agent = self._make_agent(depth=0)
        seen = {}

        def fake_spawn(*args, **kwargs):
            seen["called"] = True
            return 1, "", "stub: stop-before-spawn", False

        monkeypatch.setattr(builtin_tools, "_spawn_captured", fake_spawn)
        result = await builtin_tools.execute_shell_command(agent, {"command": "id"})
        assert seen.get("called") is True, (
            "the main agent never reached the spawn path: " + result
        )
        # Guard passed the main agent through; the non-zero exit is the stub's,
        # not a refusal.
        assert "not available to subagents" not in result
        assert "stub: stop-before-spawn" in result

    async def test_subagent_shell_command_refused(self):
        from vulnclaw.agent.builtin_tools import execute_mcp_tool, execute_shell_command

        agent = self._make_agent(depth=1)
        expected = "not available to subagents"
        assert expected in await execute_shell_command(agent, {"command": "id"})
        assert expected in await execute_mcp_tool(agent, "shell_command", {"command": "id"})

    async def test_subagent_python_execute_refused_even_with_valid_code(self):
        from vulnclaw.agent.builtin_tools import execute_mcp_tool, execute_python

        agent = self._make_agent(depth=1)
        expected = "not available to subagents"
        code = 'print("hello")'
        assert expected in await execute_python(agent, {"code": code})
        assert expected in await execute_mcp_tool(agent, "python_execute", {"code": code})

    async def test_refusal_precedes_all_other_validation(self):
        """A leaf agent gets the refusal even for input that would fail earlier checks."""
        from vulnclaw.agent.builtin_tools import execute_python

        agent = self._make_agent(depth=1)
        result = await execute_python(agent, {"code": ""})  # empty code fails first otherwise
        assert "not available to subagents" in result

    async def test_non_dangerous_tools_unaffected_by_guard(self):
        from vulnclaw.agent.builtin_tools import dangerous_tool_refusal

        assert dangerous_tool_refusal("memory_search") is None
        assert dangerous_tool_refusal("http_probe_batch") is None

    def test_depth_zero_is_main_agent(self):
        from vulnclaw.agent.builtin_tools import is_subagent

        assert is_subagent(self._make_agent(depth=0)) is False
        assert is_subagent(self._make_agent(depth=2)) is True


def test_auto_approve_channel_does_not_leak_into_later_tests():
    """Guards the autouse fixture above (N10).

    Runs after the channel-installing test in file order; also passes on its own,
    because a freshly created gate has no channel.
    """
    from vulnclaw.agent.exec_gate import get_execution_gate

    assert get_execution_gate().channel is None, (
        "an AutoApproveChannel from an earlier test is still installed"
    )
