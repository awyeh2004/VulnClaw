"""VulnClaw AgentCore integration for the compact task runtime."""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
import logging
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from vulnclaw.agent.agent_state import AgentState, clip_text, one_line
from vulnclaw.agent.roles import get_role, roles_for_task_kind
from vulnclaw.agent.subagent.budget import UsageBudget
from vulnclaw.agent.subagent.merge import EvidenceCommitter
from vulnclaw.agent.subagent.models import (
    AgentResult,
    AgentSpec,
    SubagentContext,
    TaskContext,
    get_subagent_context,
)
from vulnclaw.agent.subagent.service import (
    AgentRunner,
    DelegationDenied,
    TaskService,
)

logger = logging.getLogger(__name__)
_MAX_SUBAGENT_EVENTS = 256


def tool_schemas() -> list[dict[str, Any]]:
    """Return the two model-facing task-control tools."""

    return [
        {
            "type": "function",
            "function": {
                "name": "agent_run",
                "description": (
                    "Launch one fresh agent with a self-contained assignment. Main may launch "
                    "a group-leader in the background. A Group Leader may launch researcher, "
                    "executor, or verifier leaves in the foreground; issue multiple calls in "
                    "the same assistant turn to run one parallel wave."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": "Short UI label for the task.",
                        },
                        "prompt": {
                            "type": "string",
                            "description": (
                                "Self-contained fresh-colleague briefing: target/scope, known "
                                "evidence, objective, expected return, and stopping condition."
                            ),
                        },
                        "agent_type": {
                            "type": "string",
                            "enum": [
                                "group-leader",
                                "researcher",
                                "executor",
                                "verifier",
                                "general",
                            ],
                        },
                        "task_kind": {
                            "type": "string",
                            "enum": [
                                "coordinate",
                                "research",
                                "execute",
                                "verify",
                                "general",
                            ],
                            "description": (
                                "Declared work kind checked against the code-enforced role "
                                "registry. Group Leader leaf calls should explicitly use "
                                "research, execute, or verify."
                            ),
                        },
                        "name": {
                            "type": "string",
                            "description": "Optional stable name for a background agent.",
                        },
                        "background": {
                            "type": "boolean",
                            "description": (
                                "Return a task handle immediately. Group Leaders must be "
                                "background when launched by Main; Leader leaves must be false."
                            ),
                        },
                        "max_steps": {
                            "type": "integer",
                            "description": "Optional execution step cap; server bounded.",
                        },
                    },
                    "required": ["description", "prompt", "agent_type"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "agent_job",
                "description": (
                    "List, collect, message, or cancel background agents. Terminal results are "
                    "stable and can be collected repeatedly; completion is also delivered as "
                    "an automatic notification."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "collect", "message", "cancel"],
                        },
                        "job_id": {"type": "string"},
                        "message": {"type": "string"},
                        "reason": {"type": "string"},
                    },
                    "required": ["action"],
                },
            },
        },
    ]


def _leaf_role_registry() -> str:
    lines: list[str] = []
    for name in ("researcher", "executor", "verifier"):
        role = get_role(name)
        assert role is not None
        tools = ", ".join(role.allowed_tool_globs) or "none"
        task_kinds = ", ".join(role.task_kinds)
        lines.append(
            f"- {name}: task_kind={task_kinds}; {role.persona} "
            f"Bound tool patterns: {tools}."
        )
    return "\n".join(lines)


def group_leader_prompt(*, target: str, assignment: str) -> str:
    return (
        "You are a Group Leader in an authorized penetration test.\n"
        f"Target: {target or '(inherited target)'}\n"
        f"Collaborative assignment:\n{assignment}\n\n"
        "You coordinate; you do not execute target-facing probes yourself.\n"
        "The code-enforced leaf role registry is:\n"
        f"{_leaf_role_registry()}\n"
        "1. Before freezing the first parallel wave, launch exactly one foreground "
        "researcher for a bounded shared-baseline reconnaissance pass (at most one safe "
        "fetch plus minimal common checks). Summarize its returned parent evidence ids, "
        "then give that same baseline to every wave leaf.\n"
        "2. Split the assignment into distinct, non-overlapping scopes. Each leaf prompt "
        "must say which sibling work it must not repeat.\n"
        "3. Launch parallel leaf agents by issuing multiple agent_run calls in the SAME "
        "assistant turn. Use only researcher, executor, or verifier leaves, set "
        "task_kind to research, execute, or verify to match the selected role, and set "
        "background=false. A tool-facing scan such as Nmap is execute, not research.\n"
        "4. Every leaf prompt must be a self-contained fresh-colleague briefing with scope, "
        "known evidence, expected return, and a stopping condition.\n"
        "5. Read the complete wave, compare conflicts and gaps, then revise the plan. Do not "
        "use completion order as implicit communication between leaves.\n"
        "6. Completion-critical claims require a fresh verifier using a different method or "
        "control; never ask an original executor to verify itself.\n"
        "7. Do not create another Group Leader and do not use agent_job to build a member "
        "mailbox. Collaboration proceeds in bounded result waves.\n"
        "8. Finish with FINAL: containing a bounded synthesis, evidence ids, conflicts, "
        "blockers, and remaining unknowns. Use NO_PATH: only for an evidence-backed dead end."
    )


def leaf_prompt(*, target: str, assignment: str, agent_type: str) -> str:
    verification = (
        "Independently recheck the claim with a different method, input, control, "
        "or evidence class. Do not trust the original executor's conclusion.\n"
        if agent_type == "verifier"
        else ""
    )
    return (
        f"You are a fresh {agent_type} leaf agent in an authorized penetration test.\n"
        f"Target: {target or '(inherited target)'}\n"
        f"Assignment:\n{assignment}\n\n"
        f"{verification}"
        "Work only inside inherited constraints. Choose your own procedures without "
        "expanding scope. Record concrete tool evidence for every important claim. "
        "You cannot ask the user and cannot delegate another agent. Stop when the "
        "requested return or stopping condition is reached. Finish with FINAL: or an "
        "evidence-backed NO_PATH:, citing the new evidence ids you created and clearly "
        "separating observations, inference, blockers, and remaining unknowns."
    )


def sanitize_checkpoint(
    session: Any, data: dict[str, Any]
) -> dict[str, Any]:
    """Remove uncommitted conclusions from non-terminal child checkpoints."""

    if session.lifecycle_status in {
        "completed",
        "no_path",
        "budget_exhausted",
        "needs_user",
    }:
        return data
    agent_data = data.get("agent_state")
    if isinstance(agent_data, dict):
        agent_data["verified_claims"] = []
        agent_data["pinned_facts"] = []
        agent_data["completed"] = False
        agent_data["complete_reason"] = ""
        agent_data["final_answer"] = ""
    data["findings"] = []
    data["confirmed_facts"] = []
    return data


class VulnClawTaskRuntime:
    """Bind one root AgentCore to one compact TaskService."""

    def __init__(self, root_agent: Any):
        self.root_agent = root_agent
        self.agents: dict[str, Any] = {"main": root_agent}
        root_state = root_agent.context.state
        self.run_id = str(getattr(root_state, "run_id", "") or uuid4().hex)
        root_state.run_id = self.run_id
        context = get_subagent_context(root_agent)
        self._ui_event_sink = context.event_sink if context is not None else None
        self.runner = AgentRunner(self._execute)
        cfg = root_agent.config.subagent
        self.committer = EvidenceCommitter(
            max_records=int(cfg.merge_max_evidence_per_group)
        )
        self.evidence_maps: dict[tuple[str, str], dict[str, str]] = {}
        self.usage_budget = UsageBudget(
            solve_limit=int(cfg.max_model_tokens_per_solve),
            group_limit=int(cfg.max_model_tokens_per_group),
        )
        self.service = TaskService(
            runner=self.runner,
            max_background_groups=int(cfg.max_background_groups),
            max_concurrent_leaf_total=int(cfg.max_concurrent_leaf_total),
            max_concurrent_leaf_per_group=int(
                cfg.max_concurrent_leaf_per_group
            ),
            max_leaf_per_group=int(cfg.max_leaf_per_group),
            max_waves_per_group=int(cfg.max_waves_per_group),
            leaf_timeout_seconds=float(cfg.leaf_timeout_seconds),
            group_timeout_seconds=float(cfg.group_timeout_seconds),
            shutdown_timeout_seconds=float(
                cfg.finalization_timeout_seconds
            ),
            usage_budget=self.usage_budget,
            event_sink=self._record_event,
        )

    def _record_event(self, kind: str, payload: dict[str, object]) -> None:
        state = self.root_agent.context.state
        state.subagent_events.append(
            {
                "event": kind,
                "at": datetime.now(timezone.utc).isoformat(),
                **dict(payload),
            }
        )
        state.subagent_events = state.subagent_events[-_MAX_SUBAGENT_EVENTS:]
        try:
            state._notify_checkpoint("subagent_event")
        except Exception:
            logger.warning("failed to checkpoint sub-agent event", exc_info=True)
        if callable(self._ui_event_sink):
            try:
                self._ui_event_sink(kind, payload)
            except Exception:
                logger.warning("sub-agent UI event callback failed", exc_info=True)

    def state_seed(
        self,
        parent: TaskContext,
        *,
        wave_id: str,
    ) -> AgentState:
        parent_agent = self.agents.get(parent.task_id)
        if parent_agent is None:
            raise RuntimeError(f"missing parent agent for task {parent.task_id}")
        current = parent_agent.context.state.agent_state
        if parent.session_kind != "group_leader" or not wave_id:
            return _seed_child_agent_state(current)
        cached = parent.session.local_state
        if not (
            isinstance(cached, dict)
            and cached.get("wave_id") == wave_id
            and isinstance(cached.get("agent_state"), AgentState)
        ):
            cached = {
                "wave_id": wave_id,
                "agent_state": _seed_child_agent_state(current),
            }
            parent.session.local_state = cached
        return _seed_child_agent_state(cached["agent_state"])

    async def _execute(self, definition, spec, _session, context) -> AgentResult:
        """Run one isolated AgentCore and commit its terminal evidence."""

        from vulnclaw.agent.solver import solve as child_solve

        parent = self.agents.get(context.parent_id)
        if parent is None:
            raise RuntimeError(f"missing parent agent for task {context.task_id}")

        cfg = parent.config.subagent
        step_limit = (
            int(cfg.max_steps_per_leaf)
            if definition.session_kind == "leaf"
            else 100
        )
        max_steps = int(spec.max_steps or cfg.max_steps_per_leaf)
        max_steps = max(1, min(max_steps, step_limit))
        parent_state = parent.context.state
        state_seed = spec.metadata.get("state_seed")
        if not isinstance(state_seed, AgentState):
            state_seed = _seed_child_agent_state(parent_state.agent_state)
        baseline_fingerprints = {
            item.fingerprint
            for item in state_seed.evidence
            if item.fingerprint
        }
        baseline_evidence_ids = {
            item.id for item in state_seed.evidence
        }
        child = parent._child_factory()
        self._configure_child(
            child,
            parent=parent,
            definition=definition,
            context=context,
            state_seed=state_seed,
        )
        self.agents[context.task_id] = child
        prompt = (
            group_leader_prompt(
                target=parent_state.target or "",
                assignment=spec.prompt,
            )
            if definition.session_kind == "group_leader"
            else leaf_prompt(
                target=parent_state.target or "",
                assignment=spec.prompt,
                agent_type=definition.name,
            )
        )
        child.context.add_user_message(prompt)
        child_state = child.context.state
        child_state.resume_summary = (
            f"{definition.name} task {context.task_id}: "
            f"{one_line(spec.description, 160)}"
        )
        _save_child_checkpoint(child_state)

        status = "completed"
        reason = ""
        final_text = ""
        include_session_state = True
        evidence_ids: list[str] = []
        try:
            try:
                result = await child_solve(
                    child,
                    origin=child_state.target or spec.prompt,
                    goal=spec.prompt,
                    max_steps=max_steps,
                    max_tool_rounds=int(cfg.leaf_max_tool_rounds),
                    stream_sink=None,
                    on_event=None,
                )
                reason = one_line(result.reason, 240)
                final_text = clip_text(
                    str(result.agent_state.final_answer or ""),
                    int(cfg.result_max_chars),
                )
                if not result.completed:
                    if result.needs_user:
                        status = "needs_user"
                    elif "no viable path" in reason.lower():
                        status = "no_path"
                    else:
                        status = "budget_exhausted"
            except asyncio.CancelledError:
                status = "cancelled"
                reason = context.token.reason or "agent cancelled"
                include_session_state = False
                _strip_unvalidated_partial_state(child_state)
            except Exception as exc:
                status = "failed"
                reason = one_line(str(exc), 240)
                include_session_state = False
                _strip_unvalidated_partial_state(child_state)

            try:
                if definition.session_kind == "group_leader":
                    await self.service.settle_children(
                        context.task_id,
                        reason=reason or status,
                    )
                merge_report = self.committer.commit(
                    parent,
                    child_state,
                    task_id=context.task_id,
                    agent_type=definition.name,
                    baseline_fingerprints=baseline_fingerprints,
                    include_session_state=include_session_state,
                )
                self.evidence_maps[
                    (context.task_id, context.parent_id)
                ] = dict(merge_report.id_map)
                evidence_ids = list(merge_report.evidence_ids)
                final_text = _rewrite_evidence_ids(
                    final_text,
                    merge_report.id_map,
                    allowed_unmapped=baseline_evidence_ids,
                )
                reason = _rewrite_evidence_ids(
                    reason,
                    merge_report.id_map,
                    allowed_unmapped=baseline_evidence_ids,
                )
            except Exception as exc:
                status = "failed"
                reason = one_line(str(exc), 240)
                final_text = ""
                _strip_unvalidated_partial_state(child_state)
        finally:
            self.agents.pop(context.task_id, None)
            close_error = await _close_child_resources(parent, child)
            if close_error:
                status = "failed"
                reason = close_error
                final_text = ""
                _strip_unvalidated_partial_state(child_state)
            child_state.lifecycle_status = status
            _save_child_checkpoint(child_state)
        usage = _child_usage(child)
        summary = final_text or reason or status
        return AgentResult(
            status=status,
            summary=summary,
            content=final_text,
            usage=usage,
            evidence=evidence_ids,
            error=reason if status == "failed" else "",
        )

    def project_result(
        self,
        task_id: str,
        result: AgentResult,
        *,
        viewer_task_id: str,
    ) -> tuple[AgentResult | None, bool]:
        """Translate a result into the caller's evidence namespace."""

        record = self.service.records.get(task_id)
        if record is None:
            return None, True
        projected = copy.deepcopy(result)
        namespace = record.parent_id
        while namespace != viewer_task_id:
            owner = self.service.records.get(namespace)
            if owner is None:
                return None, True
            parent_namespace = owner.parent_id
            key = (namespace, parent_namespace)
            if key not in self.evidence_maps:
                return None, True
            id_map = self.evidence_maps[key]
            projected.evidence = [
                id_map[str(evidence_id)]
                for evidence_id in projected.evidence
                if str(evidence_id) in id_map
            ]
            projected.summary = _rewrite_evidence_ids(
                projected.summary,
                id_map,
                allowed_unmapped=set(),
            )
            projected.content = _rewrite_evidence_ids(
                projected.content,
                id_map,
                allowed_unmapped=set(),
            )
            projected.error = _rewrite_evidence_ids(
                projected.error,
                id_map,
                allowed_unmapped=set(),
            )
            namespace = parent_namespace
        return projected, False

    def _configure_child(
        self,
        child: Any,
        *,
        parent: Any,
        definition: Any,
        context: TaskContext,
        state_seed: AgentState,
    ) -> None:
        parent_state = parent.context.state
        child_state = child.context.state
        child_state.target = parent_state.target
        child_state.phase = parent_state.phase
        child_state.task_constraints = parent_state.task_constraints.model_copy(
            deep=True
        )
        child_state.agent_state = state_seed
        child_state.session_kind = definition.session_kind
        child_state.run_id = self.run_id
        child_state.parent_session_id = context.parent_id
        child_state.task_id = context.task_id
        child_state.lifecycle_status = "running"
        child_state._checkpoint_transform = sanitize_checkpoint
        child_state.set_save_path(
            _child_checkpoint_path(self.run_id, context.task_id)
        )

        child.active_role = definition.name
        context.session.messages = child.context.messages

        child._subagent_ctx = SubagentContext(
            depth=context.depth,
            cancel_token=context.token,
            task_context=context,
            runtime=self,
            service=self.service,
            usage_budget=self.usage_budget,
        )

        pool = getattr(child, "_key_pool", None) or []
        if len(pool) > 1:
            child._key_index = len(self.agents) % len(pool)


def _seed_child_agent_state(parent: AgentState) -> AgentState:
    """Copy knowledge, not the parent's execution history."""

    return AgentState(
        origin=parent.origin,
        goal=parent.goal,
        evidence=[
            item.model_copy(update={"arguments": dict(item.arguments)})
            for item in parent.evidence
        ],
        verified_claims=[
            item.model_copy(deep=True) for item in parent.verified_claims
        ],
        pinned_facts=[item.model_copy(deep=True) for item in parent.pinned_facts],
        compact_summary=parent.compact_summary,
        evidence_seq=parent.evidence_seq,
        claim_seq=parent.claim_seq,
    )


def _child_checkpoint_path(run_id: str, task_id: str) -> Path:
    from vulnclaw.config.settings import SESSIONS_DIR

    safe_run = re.sub(r"[^A-Za-z0-9_.-]+", "_", run_id).strip("._") or "run"
    safe_task = re.sub(r"[^A-Za-z0-9_.-]+", "_", task_id).strip("._") or "agent"
    return SESSIONS_DIR / f"subagent_{safe_run}_{safe_task}.json"


def _save_child_checkpoint(session: Any) -> None:
    try:
        session.save()
    except Exception:
        logger.warning(
            "failed to save sub-agent checkpoint for %s",
            getattr(session, "task_id", "unknown"),
            exc_info=True,
        )


def _strip_unvalidated_partial_state(session: Any) -> None:
    agent_state = session.agent_state
    agent_state.verified_claims = []
    agent_state.pinned_facts = []
    agent_state.completed = False
    agent_state.complete_reason = ""
    agent_state.final_answer = ""
    session.findings = []
    session.confirmed_facts = []


async def _close_child_resources(parent: Any, child: Any) -> str:
    client = getattr(child, "_client", None)
    if client is None or client is getattr(parent, "_client", None):
        return ""
    close = getattr(client, "close", None)
    if not callable(close):
        return ""
    try:
        value = close()
        if inspect.isawaitable(value):
            await value
    except Exception as exc:
        return one_line(f"child resource cleanup failed: {exc}", 240)
    return ""


def _child_usage(child: Any) -> dict[str, int]:
    context = get_subagent_context(child)
    return {
        "requests": int(context.llm_requests_used if context else 0),
        "input_tokens": int(context.input_tokens_used if context else 0),
        "output_tokens": int(context.output_tokens_used if context else 0),
        "tool_calls": int(context.tool_calls_used if context else 0),
        "evidence_bytes": int(context.evidence_bytes_used if context else 0),
    }


def _rewrite_evidence_ids(
    text: str,
    id_map: dict[str, str],
    *,
    allowed_unmapped: set[str] | None = None,
) -> str:
    if not text:
        return text

    def replace(match: re.Match[str]) -> str:
        evidence_id = match.group(0)
        if evidence_id in id_map:
            return id_map[evidence_id]
        if allowed_unmapped is None or evidence_id in allowed_unmapped:
            return evidence_id
        return "[uncommitted evidence]"

    return re.sub(r"(?<![A-Za-z0-9_])e\d+(?![A-Za-z0-9_])", replace, text)


def get_task_runtime(agent: Any) -> VulnClawTaskRuntime:
    context = get_subagent_context(agent, create=True)
    assert context is not None
    runtime = context.runtime
    if isinstance(runtime, VulnClawTaskRuntime):
        return runtime
    runtime = VulnClawTaskRuntime(agent)
    context.runtime = runtime
    context.service = runtime.service
    context.service_owner = True
    return runtime


def _parent_context(agent: Any, service: TaskService) -> TaskContext:
    subagent = get_subagent_context(agent)
    context = subagent.task_context if subagent else None
    return context if context is not None else service.main_context()


def _owned_task_service(agent: Any) -> TaskService | None:
    context = get_subagent_context(agent)
    service = context.service if context else None
    return service if isinstance(service, TaskService) and context.service_owner else None


async def finalize_tasks_for_parent(agent: Any) -> list[str]:
    service = _owned_task_service(agent)
    if service is None:
        return []
    for task in service.list():
        if not task.status.terminal:
            await service.cancel(task.task_id, reason="parent completion")
    return [
        task.task_id for task in service.list() if not task.status.terminal
    ]


async def shutdown_task_service(agent: Any) -> None:
    service = _owned_task_service(agent)
    if service is not None:
        await service.shutdown()


async def execute_agent_run(agent: Any, args: dict[str, Any]) -> str:
    runtime = get_task_runtime(agent)
    service = runtime.service
    parent = _parent_context(agent, service)
    agent_type = str(args.get("agent_type") or "general").strip()
    role = get_role(agent_type)
    task_kind = str(
        args.get("task_kind")
        or (role.task_kinds[0] if role and role.task_kinds else "")
    ).strip().lower()
    if parent.session_kind == "main" and agent_type == "group-leader":
        task_kind = "coordinate"
    wave_id = str(args.get("_wave_id") or "")
    background = bool(args.get("background", False))
    spec = AgentSpec(
        description=str(args.get("description") or args.get("prompt") or "agent")[:160],
        prompt=str(args.get("prompt") or "").strip(),
        agent_type=agent_type,
        task_kind=task_kind,
        name=str(args.get("name") or "").strip(),
        max_steps=args.get("max_steps"),
        metadata={"wave_id": wave_id},
    )
    if not spec.prompt:
        return json.dumps({"ok": False, "error": "prompt is required"}, ensure_ascii=False)
    if (
        parent.session_kind == "main"
        and spec.agent_type == "group-leader"
        and not background
    ):
        return json.dumps(
            {
                "ok": False,
                "error": "Main must launch a group-leader with background=true",
            },
            ensure_ascii=False,
        )
    spec.metadata["state_seed"] = runtime.state_seed(
        parent,
        wave_id=wave_id,
    )
    try:
        if background:
            handle = await service.spawn_background(spec, parent)
            return json.dumps(
                {
                    "ok": True,
                    "task_id": handle.task_id,
                    "name": handle.name,
                    "status": handle.status.value,
                    "background": True,
                },
                ensure_ascii=False,
            )

        result = await service.run_foreground(spec, parent)
        return json.dumps(
            {
                "ok": True,
                "status": result.status,
                "summary": result.summary,
                "content": result.content,
                "usage": result.usage,
                "parent_evidence_ids": result.evidence,
                "evidence_namespace": parent.task_id,
                "citation_instruction": (
                    "Cite only parent_evidence_ids. Never cite a leaf-local "
                    "evidence id."
                ),
            },
            ensure_ascii=False,
        )
    except DelegationDenied as exc:
        return json.dumps(
            {
                "ok": False,
                "error": str(exc),
                "allowed_roles": list(roles_for_task_kind(task_kind)),
            },
            ensure_ascii=False,
        )


async def execute_agent_job(agent: Any, args: dict[str, Any]) -> str:
    runtime = get_task_runtime(agent)
    service = runtime.service
    action = str(args.get("action") or "list").strip().lower()
    task_id = str(args.get("job_id") or "").strip()
    viewer_task_id = _parent_context(agent, service).task_id

    if action == "list":
        return json.dumps(
            {
                "tasks": [
                    _snapshot_payload(
                        item,
                        runtime=runtime,
                        viewer_task_id=viewer_task_id,
                    )
                    for item in service.list()
                ],
                "budget": (
                    service.usage_budget.snapshot()
                    if service.usage_budget is not None
                    else None
                ),
            },
            ensure_ascii=False,
        )
    if not task_id:
        return json.dumps({"ok": False, "error": "job_id is required"}, ensure_ascii=False)
    if action == "collect":
        return json.dumps(
            _snapshot_payload(
                await service.collect(task_id),
                runtime=runtime,
                viewer_task_id=viewer_task_id,
            ),
            ensure_ascii=False,
        )
    if action == "message":
        await service.message(task_id, str(args.get("message") or ""))
        return json.dumps({"ok": True, "task_id": task_id}, ensure_ascii=False)
    if action == "cancel":
        snapshot = await service.cancel(
            task_id,
            reason=str(args.get("reason") or "cancelled by parent"),
        )
        return json.dumps(
            _snapshot_payload(
                snapshot,
                runtime=runtime,
                viewer_task_id=viewer_task_id,
            ),
            ensure_ascii=False,
        )
    return json.dumps({"ok": False, "error": f"unknown action: {action}"}, ensure_ascii=False)


def _snapshot_payload(
    snapshot: Any,
    *,
    runtime: VulnClawTaskRuntime,
    viewer_task_id: str,
) -> dict[str, Any]:
    payload = asdict(snapshot)
    payload["status"] = snapshot.status.value
    result = snapshot.result
    if result is not None:
        projected, pending = runtime.project_result(
            snapshot.task_id,
            result,
            viewer_task_id=viewer_task_id,
        )
        if pending:
            payload["result"] = {
                "status": result.status,
                "summary": (
                    "Result is terminal but its evidence has not been committed "
                    "into the caller namespace. Wait for the Group terminal "
                    "notification."
                ),
                "content": "",
                "usage": dict(result.usage),
                "parent_evidence_ids": [],
                "error": "",
            }
            payload["result_pending_parent_commit"] = True
            payload["error"] = ""
        else:
            assert projected is not None
            result_payload = asdict(projected)
            result_payload.pop("evidence", None)
            result_payload["parent_evidence_ids"] = list(
                projected.evidence
            )
            payload["result"] = result_payload
        payload["evidence_namespace"] = viewer_task_id
        payload["citation_instruction"] = (
            "Cite only parent_evidence_ids. Never cite a leaf-local evidence id."
        )
    return payload
