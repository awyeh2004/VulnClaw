"""Controlled execution channel: a sub-agent's execution request runs via main.

Round-22 (2026-10-06) postmortem -- the nginx-ui run (CVE-2026-27944,
``direct-ctf2.dasctf.com:25973``). The main agent's ``python_execute`` was
short-circuited by the repetition guard after 30 calls against the single host
in scope, so the craft-and-fire work was delegated to a group. That group could
never execute anything: ``dangerous_tool_refusal`` denies host execution to
every sub-agent (fail-closed, by design) and its leader could not spawn an
executor either (see ``roles_for_task_kind`` / ``TaskService._register``). The
group spent 771,589 input tokens over 23 requests and 48 tool calls; not one
crafted ``POST /api/restore`` ever reached the wire, and the flag was never
read.

The comment on that refusal has always described what *should* happen instead:

    "Arbitrary execution requests must be issued by the main agent and
     approved by the local operator."

This module implements exactly that, and nothing more:

* only sub-agent requests are affected -- the main agent keeps its own path;
* the request is re-issued through the MAIN agent's context, so every existing
  guard on that path still applies: host/path constraints,
  ``safety.enable_python_execute``, the blocked-pattern and sandbox-bypass
  checks, the audit log, and the ExecutionGate's per-request operator approval;
* the escalation is forced onto the human path (``risk_self_assessment`` is set
  to ``"review"``), so the read-only command classifier can never auto-approve
  a request that originated inside a sub-agent;
* escalations are capped per sub-agent;
* every failure mode -- no runtime, no main agent, channel disabled, cap
  reached, gate denied, no trusted channel installed, executor exception --
  returns a message and falls back to the caller's existing refusal. A leaf
  never gains execution rights of its own.

Provenance: the call runs on the main agent's executor, so audit lines and the
approval prompt are main-agent-side (the prompt carries a ``[sub-agent a-0002]``
tag), while the tool result is recorded as evidence of the sub-agent that asked
for it.
"""

from __future__ import annotations

import copy
from typing import Any

#: Tools that may be escalated. Both are DANGEROUS_TOOLS; the set is explicit so
#: a future dangerous tool cannot silently inherit this channel.
ESCALATABLE_TOOLS = frozenset({"python_execute", "shell_command"})

_DEFAULT_LIMIT = 6
PROVENANCE_TAG = "[escalated→main]"


def _subagent_context(agent: Any) -> Any:
    from vulnclaw.agent.subagent.models import get_subagent_context

    return get_subagent_context(agent)


def main_agent_for(agent: Any) -> Any | None:
    """Return the run's root (main) agent, or None when there is no runtime.

    Deliberately does *not* use ``get_task_runtime``: that helper creates a
    fresh runtime rooted at whichever agent calls it first, which here would
    root the runtime at the sub-agent and make the escalation recursive. A leaf
    with no delegation runtime must keep getting the plain refusal.
    """
    context = _subagent_context(agent)
    runtime = getattr(context, "runtime", None) if context is not None else None
    if runtime is None:
        return None
    root = getattr(runtime, "root_agent", None)
    if root is None or root is agent:
        return None
    return root


def _config(agent: Any) -> Any:
    return getattr(getattr(agent, "config", None), "subagent", None)


def _enabled(agent: Any) -> bool:
    config = _config(agent)
    if config is None:
        return False
    return bool(getattr(config, "escalate_execution_to_main", True))


def _limit(agent: Any) -> int:
    config = _config(agent)
    try:
        return int(getattr(config, "max_exec_escalations_per_leaf", _DEFAULT_LIMIT))
    except (TypeError, ValueError):
        return _DEFAULT_LIMIT


def _escalated_args(tool_name: str, args: dict[str, Any], task_id: str) -> dict[str, Any]:
    """Copy the leaf's args, tagging provenance and forcing the human path."""
    escalated = copy.deepcopy(dict(args or {}))
    tag = f"[sub-agent {task_id}]" if task_id else "[sub-agent]"
    purpose = str(escalated.get("purpose") or "").strip()
    escalated["purpose"] = f"{tag} {purpose}".strip()
    # One-way escalation (see ExecutionGate): "review" can only force the human
    # path, never skip it. A sub-agent must not be auto-approved by the
    # read-only classifier on the strength of its own risk claim.
    escalated["risk_self_assessment"] = "review"
    escalated["assessment_reason"] = (
        f"escalated from sub-agent {task_id or 'leaf'}: sub-agents may not execute "
        f"directly, so {tool_name} is issued by the main agent"
    )[:300]
    return escalated


async def escalate_dangerous_call(
    agent: Any, tool_name: str, args: dict[str, Any]
) -> str | None:
    """Re-issue a sub-agent's dangerous call through the main agent.

    Returns the model-visible result, or None to let the caller keep its
    existing fail-closed refusal (main agent, unknown tool, no runtime, channel
    disabled, or cap of zero).
    """
    from vulnclaw.agent.builtin_tools import is_subagent

    if not is_subagent(agent):
        return None
    if tool_name not in ESCALATABLE_TOOLS:
        return None
    if not _enabled(agent):
        return None
    limit = _limit(agent)
    if limit <= 0:
        return None
    main_agent = main_agent_for(agent)
    if main_agent is None:
        return None

    context = _subagent_context(agent)
    used = int(getattr(context, "exec_escalations_used", 0) or 0)
    if used >= limit:
        return (
            f"[!] {tool_name} escalation budget for this sub-agent is exhausted "
            f"({used}/{limit}). Stop probing: record what you already have and hand "
            "the summary back with agent_result."
        )

    task = getattr(context, "task_context", None)
    task_id = str(getattr(task, "task_id", "") or "")
    if context is not None:
        context.exec_escalations_used = used + 1

    from vulnclaw.agent import builtin_tools

    try:
        if tool_name == "python_execute":
            result = await builtin_tools.execute_python(
                main_agent, _escalated_args(tool_name, args, task_id)
            )
        else:
            result = await builtin_tools.execute_shell_command(
                main_agent, _escalated_args(tool_name, args, task_id)
            )
    except Exception as exc:  # an escalation must never crash the leaf's loop
        return (
            f"[!] {tool_name} escalation failed in the main agent: "
            f"{exc.__class__.__name__}: {exc}"
        )
    return (
        f"{PROVENANCE_TAG} {tool_name} was executed by the main agent "
        f"(requested by sub-agent {task_id or 'leaf'}; sub-agents may not execute "
        f"directly). Operator approval governs this path.\n{result}"
    )
