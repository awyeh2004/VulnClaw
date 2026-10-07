"""Round-22 (2026-10-06): a spawn request that names only task_kind gets its role.

Postmortem context (nginx-ui run, CVE-2026-27944): the group leader called
``agent_run`` with ``task_kind="execute"`` and no ``agent_type``. The default
"general" role only handles task_kind "general", so ``TaskService._register``
refused -- "role general cannot handle task_kind execute" -- twice, and the group
could never build the executor that does the actual work. The run burned 771,589
input tokens discovering this by trial and error.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.roles import get_role
from vulnclaw.agent.subagent.integration import resolve_agent_type


@pytest.mark.parametrize(
    ("task_kind", "expected"),
    [
        ("execute", "executor"),
        ("research", "researcher"),
        ("verify", "verifier"),
        ("coordinate", "group-leader"),
        ("general", "general"),
        ("  EXECUTE  ", "executor"),
    ],
)
def test_task_kind_alone_selects_a_capable_role(task_kind, expected):
    resolved = resolve_agent_type(None, task_kind)
    assert resolved == expected
    role = get_role(resolved)
    assert role is not None
    # The selected role must actually accept the task_kind, otherwise the spawn
    # would be refused again in TaskService._register.
    assert task_kind.strip().lower() in role.task_kinds


def test_explicit_agent_type_still_wins():
    """No silent override: a deliberate mismatch is still refused downstream."""
    assert resolve_agent_type("researcher", "execute") == "researcher"
    assert resolve_agent_type("group-leader", "coordinate") == "group-leader"


def test_defaults_when_nothing_is_specified():
    assert resolve_agent_type(None, None) == "general"
    assert resolve_agent_type("", "") == "general"
    assert resolve_agent_type(None, "no-such-kind") == "general"


def test_the_real_run_call_now_resolves():
    """The exact (agent_type, task_kind) pair the leader sent."""
    assert resolve_agent_type(None, "execute") == "executor"
    assert "execute" in get_role("executor").task_kinds
