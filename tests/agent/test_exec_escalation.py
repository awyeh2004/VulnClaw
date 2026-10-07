"""Round-22 (2026-10-06): sub-agent execution requests run via the main agent.

Postmortem context (nginx-ui run, CVE-2026-27944): the main agent's
``python_execute`` was short-circuited by the repeat guard, so the craft-and-fire
work was delegated; the group then could not execute anything at all, because
``dangerous_tool_refusal`` denies host execution to every sub-agent. 771,589
input tokens produced zero payloads on the wire.

``exec_escalation`` implements the policy that refusal always described: a
sub-agent's request is re-issued through the main agent, where the normal
operator-approval path (ExecutionGate) applies. These tests pin both halves:
the channel works, and every failure mode still falls back to the old refusal.
"""

from __future__ import annotations

import types

import pytest

from vulnclaw.agent import builtin_tools
from vulnclaw.agent.subagent import exec_escalation as esc
from vulnclaw.agent.subagent.models import SubagentContext

CODE_ARGS = {"code": 'print("probe")', "purpose": "craft restore backup"}


def _cfg(**overrides):
    values = {
        "escalate_execution_to_main": True,
        "max_exec_escalations_per_leaf": 6,
    }
    values.update(overrides)
    return types.SimpleNamespace(subagent=types.SimpleNamespace(**values))


def _agent(depth, *, runtime=None, config=None, task_id=""):
    context = SubagentContext(depth=depth, runtime=runtime)
    if task_id:
        context.task_context = types.SimpleNamespace(task_id=task_id)
    return types.SimpleNamespace(_subagent_ctx=context, config=config, active_role=None)


def _run_pair(**cfg_overrides):
    config = _cfg(**cfg_overrides)
    main = _agent(0, config=config)
    runtime = types.SimpleNamespace(root_agent=main)
    sub = _agent(1, runtime=runtime, config=config, task_id="a-0002")
    return main, sub


class _Spy:
    """Async stub standing in for the main agent's executor."""

    def __init__(self, output="STUB-OUTPUT", raises=None):
        self.output = output
        self.raises = raises
        self.calls: list[tuple[object, dict]] = []

    async def __call__(self, agent, args):
        self.calls.append((agent, dict(args)))
        if self.raises is not None:
            raise self.raises
        return self.output


@pytest.mark.asyncio
async def test_escalation_runs_through_the_main_agent(monkeypatch):
    main, sub = _run_pair()
    spy = _Spy(output="HTTP 500 {'code':4511}")
    monkeypatch.setattr(builtin_tools, "execute_python", spy)

    result = await esc.escalate_dangerous_call(sub, "python_execute", CODE_ARGS)

    assert result is not None
    assert esc.PROVENANCE_TAG in result
    assert "HTTP 500 {'code':4511}" in result
    assert "a-0002" in result
    # Executed by MAIN, never by the leaf that asked.
    assert len(spy.calls) == 1
    executed_by, forwarded = spy.calls[0]
    assert executed_by is main
    # Provenance tag + one-way escalation onto the operator path.
    assert forwarded["purpose"].startswith("[sub-agent a-0002]")
    assert forwarded["risk_self_assessment"] == "review"
    assert "sub-agents may not execute directly" in forwarded["assessment_reason"]


@pytest.mark.asyncio
async def test_shell_command_uses_the_same_channel(monkeypatch):
    main, sub = _run_pair()
    spy = _Spy(output="uid=0(root)")
    monkeypatch.setattr(builtin_tools, "execute_shell_command", spy)

    result = await esc.escalate_dangerous_call(
        sub, "shell_command", {"command": "id", "purpose": "read flag env"}
    )

    assert result is not None and "uid=0(root)" in result
    assert spy.calls[0][0] is main


@pytest.mark.asyncio
async def test_dispatch_replaces_the_refusal_with_the_escalated_result(monkeypatch):
    """The model-facing path (execute_mcp_tool) is what actually escalates."""
    main, sub = _run_pair()
    spy = _Spy(output="ESCALATED-OK")
    monkeypatch.setattr(builtin_tools, "execute_python", spy)

    out = await builtin_tools.execute_mcp_tool(sub, "python_execute", CODE_ARGS)

    assert "ESCALATED-OK" in out
    assert esc.PROVENANCE_TAG in out
    assert "not available to subagents" not in out


@pytest.mark.asyncio
async def test_main_agent_is_never_escalated(monkeypatch):
    main, _sub = _run_pair()
    spy = _Spy()
    monkeypatch.setattr(builtin_tools, "execute_python", spy)

    assert await esc.escalate_dangerous_call(main, "python_execute", CODE_ARGS) is None
    assert spy.calls == []


@pytest.mark.asyncio
async def test_without_a_delegation_runtime_the_plain_refusal_stands():
    """A bare leaf (no runtime) must keep the fail-closed refusal."""
    sub = _agent(1, runtime=None, config=_cfg())
    assert await esc.escalate_dangerous_call(sub, "python_execute", CODE_ARGS) is None

    out = await builtin_tools.execute_mcp_tool(sub, "python_execute", {"code": "print(1)"})
    assert "not available to subagents" in out


@pytest.mark.asyncio
async def test_direct_execute_python_from_a_leaf_still_refuses():
    """The channel lives at dispatch only: the tool function itself stays closed.

    Direct callers (and hand-crafted calls that bypass dispatch) must keep the
    fail-closed refusal -- this is the invariant tests/security/test_spawn_boundary.py
    pins.
    """
    _main, sub = _run_pair()

    out = await builtin_tools.execute_python(sub, {"code": "print(1)"})

    assert "not available to subagents" in out


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"escalate_execution_to_main": False},
        {"max_exec_escalations_per_leaf": 0},
    ],
)
async def test_disabled_channel_falls_back_to_the_refusal(overrides):
    sub = _agent(1, runtime=types.SimpleNamespace(root_agent=_agent(0)), config=_cfg(**overrides))
    assert await esc.escalate_dangerous_call(sub, "python_execute", CODE_ARGS) is None


@pytest.mark.asyncio
async def test_no_config_means_no_channel():
    main = _agent(0)
    sub = _agent(1, runtime=types.SimpleNamespace(root_agent=main), config=None)
    assert await esc.escalate_dangerous_call(sub, "python_execute", CODE_ARGS) is None


@pytest.mark.asyncio
async def test_non_escalatable_tool_is_not_routed(monkeypatch):
    _main, sub = _run_pair()
    spy = _Spy()
    monkeypatch.setattr(builtin_tools, "execute_python", spy)

    assert await esc.escalate_dangerous_call(sub, "memory_search", {}) is None
    assert spy.calls == []


@pytest.mark.asyncio
async def test_per_leaf_cap_stops_the_channel_with_a_usable_message(monkeypatch):
    _main, sub = _run_pair(max_exec_escalations_per_leaf=1)
    spy = _Spy()
    monkeypatch.setattr(builtin_tools, "execute_python", spy)

    assert await esc.escalate_dangerous_call(sub, "python_execute", CODE_ARGS) is not None
    exhausted = await esc.escalate_dangerous_call(sub, "python_execute", CODE_ARGS)

    assert exhausted is not None
    assert "escalation budget" in exhausted and "1/1" in exhausted
    assert "agent_result" in exhausted  # tells the leaf how to hand work back
    assert len(spy.calls) == 1
    assert sub._subagent_ctx.exec_escalations_used == 1


@pytest.mark.asyncio
async def test_executor_exception_is_reported_not_raised(monkeypatch):
    _main, sub = _run_pair()
    monkeypatch.setattr(
        builtin_tools, "execute_python", _Spy(raises=RuntimeError("gate exploded"))
    )

    out = await esc.escalate_dangerous_call(sub, "python_execute", CODE_ARGS)

    assert out is not None
    assert out.startswith("[!] python_execute escalation failed")
    assert "RuntimeError" in out


def test_main_agent_for_never_creates_a_runtime():
    """get_task_runtime would root a fresh runtime at the leaf: must not be used."""
    sub = _agent(1, runtime=None)
    assert esc.main_agent_for(sub) is None
    assert getattr(sub._subagent_ctx, "runtime", None) is None


@pytest.mark.asyncio
async def test_end_to_end_leaf_request_runs_real_code_via_main():
    """No stubs anywhere: leaf request -> main executor -> gate -> real Python.

    This is the whole round-22 fix in one test: a sub-agent asks for
    ``python_execute``, the main agent executes it (the leaf never does), and the
    operator approval prompt carries the sub-agent provenance.
    """
    import sys
    from pathlib import Path

    from vulnclaw.agent.exec_gate import get_execution_gate, reset_execution_gate

    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root / "tests" / "agent"))
    try:
        from test_builtin_tools import AutoApproveChannel, DummyAgent
    finally:
        sys.path.pop(0)

    reset_execution_gate()
    channel = AutoApproveChannel()
    get_execution_gate().install_channel(channel)

    try:
        config = _cfg()
        main = DummyAgent()
        main.config.subagent = config.subagent
        main._subagent_ctx = SubagentContext(depth=0)

        sub = DummyAgent()
        sub.config.subagent = config.subagent
        sub._subagent_ctx = SubagentContext(
            depth=1, runtime=types.SimpleNamespace(root_agent=main)
        )
        sub._subagent_ctx.task_context = types.SimpleNamespace(task_id="a-0002")

        out = await builtin_tools.execute_mcp_tool(
            sub,
            "python_execute",
            {"code": "print(6*7)", "purpose": "e2e escalation"},
        )

        assert "42" in out, f"the escalated call did not execute: {out[:300]}"
        assert esc.PROVENANCE_TAG in out
        assert "not available to subagents" not in out
        # What the operator is asked to approve must name the requester.
        assert channel.views, "no approval was requested"
        assert channel.views[-1].kind == "python"
        assert "sub-agent a-0002" in channel.views[-1].detail
    finally:
        reset_execution_gate()
