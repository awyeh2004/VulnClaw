"""The agent's per-run evidence anchor.

``AgentCore.run_dir`` is the seam that lets the evidence writers (the traffic
bind tool) and the evidence readers (the report generator) agree on *which* run
a capture belongs to, instead of both silently resolving to the process-wide
``CONFIG_DIR/evidence`` root.

It is deliberately a plain, **non-serialized** attribute: the run directory is
execution context supplied by the orchestrator, not part of the persisted
session snapshot -- so it must never leak into ``SessionState`` or a checkpoint
payload. Persisting it would pin a resumed run to a stale directory layout.
"""

from __future__ import annotations

from vulnclaw.agent.agent_context import AgentContext
from vulnclaw.agent.core import AgentCore
from vulnclaw.config.schema import VulnClawConfig


def test_agent_defaults_to_no_run_dir() -> None:
    # An agent used outside a run (chat, an ad-hoc helper call) has no run to
    # anchor to; writers must read "" as "fall back to the config-scoped root".
    assert AgentCore(VulnClawConfig()).run_dir == ""


def test_agent_context_exposes_run_dir() -> None:
    # The protocol is the drift guard for helpers that read ``agent.run_dir``.
    assert "run_dir" in AgentContext.__annotations__


def test_run_dir_is_not_part_of_the_session_snapshot() -> None:
    agent = AgentCore(VulnClawConfig())
    agent.run_dir = "E:/vulnclaw/runs/abc"
    assert "run_dir" not in agent.session_state.model_dump()
    assert not hasattr(agent.session_state, "run_dir")
