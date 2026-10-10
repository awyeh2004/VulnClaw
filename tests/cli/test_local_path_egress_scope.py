"""A local-file task must not become outbound recon against the operator's LAN.

`_apply_local_path_constraints` scopes an autonomous run whose target is a local
file/path: allowed_paths is the target, and loopback/private ranges are blocked.

Measured 2026-10-08 — the guard was **inert**: it listed ``"10."``,
``"192.168."``, ``"172.16."`` … but ``host_in_scope`` matches a bare IP pattern
*exactly* and has no prefix form, so none of those entries could ever match an
address. The 2026-10-08 change moved them to CIDR (and taught ``host_in_scope``
CIDR), which is what these tests pin down.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.cli.main import _apply_local_path_constraints
from vulnclaw.config.domain_models import TaskConstraints
from vulnclaw.agent.builtin_tools import enforce_host_path_constraints

LOCAL_TARGET = r"D:\vulnclaw\work\ir-collection\case-01"


def _agent() -> SimpleNamespace:
    """The same constraint object on both handles the helpers reach for.

    `_apply_local_path_constraints` writes through ``context.state``, while the
    scope gates read ``session_state`` -- on the real agent both are the same
    object (``AgentCore.session_state`` is a property over ``context.state``),
    so the double has to mirror that or it tests nothing.
    """
    state = SimpleNamespace(task_constraints=TaskConstraints())
    return SimpleNamespace(context=SimpleNamespace(state=state), session_state=state)


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "10.4.5.6", "172.20.9.9", "192.168.31.7"],
)
def test_private_and_loopback_targets_are_blocked(host):
    agent = _agent()
    _apply_local_path_constraints(agent, LOCAL_TARGET)

    violation = enforce_host_path_constraints(agent, host=host)
    assert violation is not None and "blocked" in violation


def test_a_public_target_is_untouched():
    """The guard is about the operator's own network, not the whole internet."""
    agent = _agent()
    _apply_local_path_constraints(agent, LOCAL_TARGET)

    assert enforce_host_path_constraints(agent, host="203.0.113.7") is None


def test_a_network_target_is_not_treated_as_a_local_path():
    """A URL/IP target keeps its normal scope handling."""
    agent = _agent()
    _apply_local_path_constraints(agent, "https://lab.example.com")

    assert agent.context.state.task_constraints.blocked_hosts == []
    assert agent.context.state.task_constraints.strict_mode is False


def test_the_local_target_is_the_allowed_path():
    agent = _agent()
    _apply_local_path_constraints(agent, LOCAL_TARGET)

    constraints = agent.context.state.task_constraints
    assert constraints.allowed_paths == [LOCAL_TARGET]
    assert constraints.strict_mode is True


def test_a_broken_agent_is_reported_not_silently_unscoped(capsys):
    """Failing to install the guard must be visible, not a silent no-op.

    This is the only place a local-file run gets its network lockdown, and it
    runs before the autonomous loop. If it raises and is swallowed, the operator
    believes the sweep is confined to the target while the run is actually
    unscoped -- so the failure has to surface.
    """

    class _Boom:
        @property
        def task_constraints(self):  # pragma: no cover - reached via attribute access
            raise RuntimeError("state unavailable")

    agent = SimpleNamespace(context=SimpleNamespace(state=_Boom()))

    _apply_local_path_constraints(agent, LOCAL_TARGET)

    printed = capsys.readouterr().err
    assert "网络封锁未能安装" in printed
