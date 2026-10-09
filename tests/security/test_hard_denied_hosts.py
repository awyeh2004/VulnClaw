"""`safety.denied_hosts` — the operator's hard denylist.

Why this exists (2026-10-08): the competition guide names the scoring platform
(`https://tp.qianxin.com`) and the event notice forbids attacking "竞赛平台、赛事
系统及第三方服务", with 非有效操作 treated as grounds for disqualification. The
project had every *scope* knob (allowed/blocked hosts, strict mode) but no place
to say "this host is off-limits in every run, whatever the task scope says".

A scope flag alone would not have been enough, and that is the point of these
tests: scope arrives from several directions (CLI flags, the Web task API,
natural-language scope parsing, a platform hand-off), so a denylist that one
path can widen is not a denylist. The merge therefore happens on the two paths
that install a run's constraints, and `enforce_host_path_constraints` checks
blocked hosts *after* allowed hosts — re-adding a denied host to the allowed
list must not re-authorise it.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.builtin_tools import enforce_host_path_constraints
from vulnclaw.agent.core import AgentCore
from vulnclaw.config.domain_models import TaskConstraints
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.config.settings import _overlay_env
from vulnclaw.task_service import build_scope_constraints

PLATFORM_HOST = "tp.qianxin.com"


def _agent(*denied: str) -> AgentCore:
    config = VulnClawConfig()
    config.safety.denied_hosts = list(denied)
    return AgentCore(config)


class TestConstraintsMerge:
    def test_apply_task_constraints_carries_the_denylist(self):
        agent = _agent(PLATFORM_HOST)
        constraints = TaskConstraints()
        agent.apply_task_constraints(constraints)

        assert PLATFORM_HOST in constraints.blocked_hosts
        # The same object is what the runtime and the MCP side see.
        assert agent.runtime.task_constraints is constraints
        assert agent.session_state.task_constraints is constraints

    def test_a_subdomain_is_denied_too(self):
        agent = _agent(PLATFORM_HOST)
        constraints = TaskConstraints()
        agent.apply_task_constraints(constraints)
        agent.session_state.task_constraints = constraints

        assert enforce_host_path_constraints(agent, host=f"api.{PLATFORM_HOST}") is not None

    def test_a_suffix_lookalike_is_not_denied(self):
        """Domain scope cannot be fooled by a lookalike registrable domain."""
        agent = _agent(PLATFORM_HOST)
        constraints = TaskConstraints()
        agent.apply_task_constraints(constraints)
        agent.session_state.task_constraints = constraints

        assert enforce_host_path_constraints(agent, host="tp.qianxin.com.evil.test") is None
        assert enforce_host_path_constraints(agent, host="evil-tp.qianxin.com") is None

    def test_allowed_hosts_cannot_re_authorise_a_denied_host(self):
        """The denylist must win over a scope that names the platform."""
        agent = _agent(PLATFORM_HOST)
        constraints = TaskConstraints(allowed_hosts=[PLATFORM_HOST])
        agent.apply_task_constraints(constraints)
        agent.session_state.task_constraints = constraints

        violation = enforce_host_path_constraints(agent, host=PLATFORM_HOST)
        assert violation is not None
        assert "blocked" in violation

    def test_repeat_application_is_idempotent(self):
        """Context resets re-harden; the prompt block must not grow each round."""
        agent = _agent(PLATFORM_HOST)
        constraints = TaskConstraints()
        for _ in range(3):
            agent.apply_task_constraints(constraints)

        assert constraints.blocked_hosts == [PLATFORM_HOST]

    def test_no_denylist_changes_nothing(self):
        agent = _agent()
        constraints = TaskConstraints(allowed_hosts=["example.com"])
        agent.apply_task_constraints(constraints)
        agent.session_state.task_constraints = constraints

        assert constraints.blocked_hosts == []
        assert enforce_host_path_constraints(agent, host="example.com") is None

    def test_run_reset_merges_even_when_scope_came_from_prose(self):
        """A pasted description is the widest scope source; it still cannot
        authorise the platform."""
        agent = _agent(PLATFORM_HOST)
        agent._reset_runtime_state(f"帮我测一下 {PLATFORM_HOST} 这个站")

        constraints = agent.runtime.task_constraints
        assert PLATFORM_HOST in constraints.blocked_hosts
        agent.session_state.task_constraints = constraints
        assert enforce_host_path_constraints(agent, host=PLATFORM_HOST) is not None


class TestTaskService:
    """The Web/CLI task API builds constraints purely, then installs them.

    `build_scope_constraints` must stay environment-independent (the same task
    payload cannot produce different scope on different machines), so the
    denylist is asserted where the run installs the constraints instead.
    """

    def test_web_task_constraints_are_hardened_when_installed(self):
        agent = _agent(PLATFORM_HOST)
        prepared = build_scope_constraints("https://example.com", {})
        assert prepared.blocked_hosts == [], "the builder itself stays pure"

        agent.apply_task_constraints(prepared)
        agent.session_state.task_constraints = prepared

        assert PLATFORM_HOST in prepared.blocked_hosts
        assert prepared.allowed_hosts == ["example.com"]
        assert enforce_host_path_constraints(agent, host=PLATFORM_HOST) is not None

    def test_the_builder_never_reads_the_config(self, monkeypatch):
        """A config failure must not be able to break task creation.

        Structural guard: if a config read is ever reintroduced here, the same
        task payload starts producing machine-dependent scope, and this fails.
        """

        def boom():
            raise RuntimeError("no config")

        monkeypatch.setattr("vulnclaw.config.settings.load_config", boom)
        constraints = build_scope_constraints("https://example.com", {})

        assert constraints.allowed_hosts == ["example.com"]
        assert constraints.blocked_hosts == []


class TestEnvOverride:
    def test_denied_hosts_from_env_accepts_commas_and_newlines(self, monkeypatch):
        monkeypatch.setenv(
            "VULNCLAW_SAFETY_DENIED_HOSTS",
            f"{PLATFORM_HOST}, event.example.com\n#not-a-host",
        )
        config = _overlay_env(VulnClawConfig())

        assert config.safety.denied_hosts == [
            PLATFORM_HOST,
            "event.example.com",
            "#not-a-host",
        ]

    def test_absent_env_leaves_the_default_empty(self, monkeypatch):
        monkeypatch.delenv("VULNCLAW_SAFETY_DENIED_HOSTS", raising=False)
        assert _overlay_env(VulnClawConfig()).safety.denied_hosts == []


@pytest.mark.parametrize("raw", ["TP.Qianxin.COM", " tp.qianxin.com. "])
def test_entries_are_normalised(raw):
    constraints = TaskConstraints()
    constraints.add_blocked_hosts([raw])
    assert constraints.blocked_hosts == [PLATFORM_HOST]
