"""Sub-agent request deduplication, cancellation, and tool usage guards."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from vulnclaw.agent.subagent.models import get_subagent_context

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


META_TOOLS = {"agent_job"}


def partition_calls(
    agent: AgentContext,
    message: Any,
    calls: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    context = get_subagent_context(agent)
    task = context.task_context if context else None
    if str(getattr(task, "session_kind", "") or "") == "group_leader":
        wave_id = f"{getattr(task, 'task_id', 'leader')}:{id(message)}"
        for item in calls:
            if item["func_name"] == "agent_run":
                item["func_args"]["_wave_id"] = wave_id
    return (
        [item for item in calls if item["func_name"] in META_TOOLS],
        [item for item in calls if item["func_name"] not in META_TOOLS],
    )


def raise_if_cancelled(agent: AgentContext) -> None:
    context = get_subagent_context(agent)
    token = context.cancel_token if context else None
    if token is not None and bool(getattr(token, "cancelled", False)):
        raise asyncio.CancelledError(
            str(getattr(token, "reason", "") or "sub-agent cancellation requested")
        )


def reserve_tool_call(agent: AgentContext) -> None:
    raise_if_cancelled(agent)
    context = get_subagent_context(agent)
    if context is None or context.depth <= 0:
        return
    config = getattr(getattr(agent, "config", None), "subagent", None)
    limit = (
        int(getattr(config, "max_steps_per_leaf", 0) or 0)
        * int(getattr(config, "leaf_max_tool_rounds", 0) or 0)
    )
    if limit > 0 and context.tool_calls_used >= limit:
        raise RuntimeError(
            "sub-agent tool-call budget exhausted: "
            f"{context.tool_calls_used} >= {limit}"
        )
    context.tool_calls_used += 1


def record_evidence_bytes(agent: AgentContext, tool_result: Any) -> None:
    raise_if_cancelled(agent)
    context = get_subagent_context(agent)
    if context is None or context.depth <= 0:
        return
    context.evidence_bytes_used += len(
        str(tool_result or "").encode("utf-8", errors="replace")
    )
