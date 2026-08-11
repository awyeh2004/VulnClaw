"""Small solve-loop hooks owned by the compact sub-agent runtime."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from vulnclaw.agent.subagent.models import SubagentContext, get_subagent_context

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext
    from vulnclaw.agent.agent_state import AgentState


def available(agent: AgentContext) -> bool:
    config = getattr(getattr(agent, "config", None), "subagent", None)
    session_kind = str(
        getattr(getattr(agent, "session_state", None), "session_kind", "") or ""
    )
    context = get_subagent_context(agent)
    return bool(
        config
        and getattr(config, "enabled", False)
        and ((context is None or context.depth == 0) or session_kind == "group_leader")
    )


def prompt_guidance(agent: AgentContext) -> str:
    if not available(agent):
        return ""
    session_kind = str(
        getattr(getattr(agent, "session_state", None), "session_kind", "") or ""
    )
    guidance = (
        "Use agent_run when an autonomous investigation benefits from an isolated context or "
        "parallel work. Give every agent a self-contained fresh-colleague briefing with scope, "
        "known evidence, objective, expected return, and stopping condition. Main should launch "
        "collaborative Group Leaders with background=true, continue useful independent work, "
        "and consume their terminal notifications instead of polling. Keep global synthesis "
        "and completion judgment with Main.\n"
    )
    if session_kind == "group_leader":
        return guidance + (
            "You are a Group Leader. Before freezing the first parallel wave, launch exactly "
            "one foreground researcher for a bounded shared-baseline reconnaissance pass "
            "(at most one safe fetch plus minimal common checks), then summarize its returned "
            "parent evidence ids. "
            "Issue multiple foreground researcher/executor/verifier agent_run calls in the same "
            "assistant turn. Give every leaf a distinct, non-overlapping scope and explicitly "
            "state what sibling work it must not repeat. Compare the complete wave before "
            "starting another, resolve gaps or conflicts, and independently verify "
            "completion-critical claims. Never create another Leader.\n"
        )
    return guidance + (
        "Background Group Leaders report terminal notifications automatically. Use "
        "agent_job only to list, collect, message, or cancel them.\n"
    )


def delegation_contract(enabled: bool) -> str:
    if not enabled:
        return ""
    return (
        "\n# Delegation decision (required)\n"
        "- Launch a background group-leader for related multi-step work that benefits from "
        "parallel leaf investigation and independent review.\n"
        "- Work directly for one exact probe or a prerequisite that determines later work.\n"
        "- Make each prompt self-contained; never assume an agent can see this conversation.\n"
        "- Group Leaders establish one bounded shared baseline before the first wave, assign "
        "non-overlapping leaf scopes, compare the whole wave, then use a fresh verifier for "
        "critical claims.\n"
        "- Do not busy-poll background work or treat uncollected results as evidence.\n"
    )


def reset_root_context(agent: AgentContext) -> None:
    context = get_subagent_context(agent)
    if context is None or context.depth == 0:
        agent._subagent_ctx = SubagentContext()


def inject_messages(agent: AgentContext) -> None:
    """Inject queued Leader messages or Main task notifications."""

    subagent = get_subagent_context(agent)
    task_context = subagent.task_context if subagent else None
    if task_context is not None:
        task_context.session.compact_if_needed()
        for message in task_context.session.drain_pending_messages():
            agent.context.add_user_message(
                f"<agent-message>\n{message}\n</agent-message>"
            )
        return

    service = subagent.service if subagent else None
    if service is None:
        return
    for notification in service.drain_notifications():
        result = notification.result
        payload = {
            "task_id": notification.task_id,
            "name": notification.name,
            "status": notification.status.value,
            "summary": str(result.summary if result else ""),
            "parent_evidence_ids": list(result.evidence if result else []),
            "evidence_namespace": "main",
            "citation_instruction": (
                "Cite only parent_evidence_ids. Never cite a leaf-local evidence id."
            ),
            "error": notification.error,
        }
        agent.context.add_user_message(
            "<task-notification>\n"
            f"{json.dumps(payload, ensure_ascii=False)}\n"
            "</task-notification>"
        )


def owner_ids(session: Any, evidence_ids: list[str]) -> set[str]:
    owners: set[str] = set()
    provenance_by_evidence = getattr(
        session, "subagent_evidence_provenance", {}
    )
    for evidence_id in evidence_ids:
        provenance = provenance_by_evidence.get(evidence_id)
        if not isinstance(provenance, dict):
            continue
        contributors = provenance.get("contributors")
        if not isinstance(contributors, list) or not contributors:
            contributors = [provenance]
        for contributor in contributors:
            if isinstance(contributor, dict):
                task_id = str(contributor.get("task_id") or "").strip()
                if task_id:
                    owners.add(task_id)
    return owners


def sync_verified_findings(
    agent: AgentContext,
    final_text: str,
    evidence_ids: list[str],
) -> list[str]:
    """Promote pending findings explicitly named by an evidence-gated FINAL."""

    session = getattr(getattr(agent, "context", None), "state", None)
    if session is None or not evidence_ids:
        return []
    text = final_text.lower()
    state = getattr(session, "agent_state", None)
    cited_records = [
        state.get_evidence(evidence_id)
        for evidence_id in evidence_ids
        if state is not None
    ]
    cited_records = [record for record in cited_records if record is not None]
    if not cited_records:
        return []
    evidence_text = "\n".join(
        (
            f"{record.tool} {record.summary} {record.content} "
            f"{json.dumps(record.arguments, ensure_ascii=False, sort_keys=True)}"
        ).lower()
        for record in cited_records
    )
    aliases = {
        "sqli": ("sqli", "sql injection", "sql注入", "sql 注入"),
        "xss": ("xss", "cross-site scripting", "跨站脚本"),
        "rce": ("rce", "remote code execution", "远程代码执行"),
        "idor": ("idor", "broken object level authorization", "越权"),
        "ssrf": ("ssrf", "server-side request forgery", "服务端请求伪造"),
        "csrf": ("csrf", "cross-site request forgery", "跨站请求伪造"),
    }
    owners = owner_ids(session, evidence_ids)
    promoted: list[str] = []
    for finding in getattr(session, "findings", []) or []:
        if getattr(finding, "verified", False) or str(
            getattr(finding, "verification_status", "")
        ).lower() in {"verified", "rejected"}:
            continue
        haystack = f"{finding.title} {finding.vuln_type}".lower()
        matching_aliases = [
            names
            for names in aliases.values()
            if any(alias in haystack for alias in names)
        ]
        named_in_final = any(
            any(alias in text for alias in names) for names in matching_aliases
        )
        named_in_evidence = any(
            any(alias in evidence_text for alias in names)
            for names in matching_aliases
        )
        endpoint = str(getattr(finding, "endpoint", "") or "").strip().lower()
        if not (
            matching_aliases
            and named_in_final
            and named_in_evidence
            and (not endpoint or endpoint in text)
            and (not endpoint or endpoint in evidence_text)
        ):
            continue
        provenance = (
            f"; subagent_tasks={','.join(sorted(owners))}" if owners else ""
        )
        finding.mark_verified(
            note=(
                f"Evidence-gated FINAL cites {', '.join(evidence_ids)}"
                f"{provenance}"
            ),
            evidence_level="L4",
        )
        promoted.append(str(getattr(finding, "finding_id", "") or finding.title))
    return promoted


async def finalize_parent(agent: AgentContext, state: AgentState) -> str:
    if not state.completed:
        return ""
    from vulnclaw.agent.subagent.integration import finalize_tasks_for_parent

    unreleased = await finalize_tasks_for_parent(agent)
    if unreleased:
        return (
            "parent completion withheld: sub-agent task handles are still running: "
            + ", ".join(unreleased)
        )
    evidence_ids = (
        list(state.verified_claims[-1].evidence_ids)
        if state.verified_claims
        else []
    )
    sync_verified_findings(agent, state.final_answer, evidence_ids)
    return ""


async def shutdown(agent: AgentContext) -> None:
    from vulnclaw.agent.subagent.integration import shutdown_task_service

    await shutdown_task_service(agent)
