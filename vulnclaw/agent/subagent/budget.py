"""Small request-level model usage budget.

Concurrency, wall time, tool calls, evidence size, and task counts belong to
their respective runtime components.  This module accounts only for model
tokens, including estimates for requests that are currently in flight.
"""

from __future__ import annotations

import asyncio
import copy
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from vulnclaw.agent.subagent.models import get_subagent_context
from vulnclaw.agent.token_counter import estimate_tokens

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext

_FIELD_MIN_CHARS = 256
_FIELD_MARKER = " … [active context compacted] … "


class BudgetExceeded(RuntimeError):
    """A model request would exceed the solve or group token ceiling."""

    def __init__(self, dimension: str, limit: int, pressure: int):
        self.dimension = dimension
        self.limit = limit
        self.pressure = pressure
        super().__init__(f"{dimension} token budget exceeded: {pressure} > {limit}")


@dataclass(frozen=True)
class Admission:
    call_id: str
    group_id: str
    estimated_tokens: int


@dataclass
class UsageBudget:
    """One solve-wide counter shared by Main, leaders, and leaves."""

    solve_limit: int
    group_limit: int
    used_total: int = 0
    used_by_group: dict[str, int] = field(default_factory=dict)
    inflight: dict[str, Admission] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.solve_limit <= 0 or self.group_limit <= 0:
            raise ValueError("token limits must be positive")

    def try_begin(
        self,
        call_id: str,
        group_id: str,
        estimated_tokens: int,
    ) -> Admission:
        """Atomically admit one request.

        There is deliberately no ``await`` in this method, so calls are atomic
        when the solve runs on one asyncio event loop.
        """

        call_id = str(call_id or "").strip()
        group_id = str(group_id or "").strip()
        estimate = max(0, int(estimated_tokens))
        if not call_id:
            raise ValueError("call_id is required")
        if call_id in self.inflight:
            raise ValueError(f"duplicate model call id: {call_id}")

        solve_pressure = self.used_total + sum(
            item.estimated_tokens for item in self.inflight.values()
        )
        if solve_pressure + estimate > self.solve_limit:
            raise BudgetExceeded("solve", self.solve_limit, solve_pressure + estimate)

        if group_id:
            group_pressure = self.used_by_group.get(group_id, 0) + sum(
                item.estimated_tokens
                for item in self.inflight.values()
                if item.group_id == group_id
            )
            if group_pressure + estimate > self.group_limit:
                raise BudgetExceeded("group", self.group_limit, group_pressure + estimate)

        admission = Admission(call_id, group_id, estimate)
        self.inflight[call_id] = admission
        return admission

    def settle(self, call_id: str, actual_tokens: int) -> None:
        """Replace an in-flight estimate with provider-reported usage."""

        admission = self.inflight.pop(call_id, None)
        if admission is None:
            return
        actual = max(0, int(actual_tokens))
        self.used_total += actual
        if admission.group_id:
            self.used_by_group[admission.group_id] = (
                self.used_by_group.get(admission.group_id, 0) + actual
            )

    def charge_estimate(self, call_id: str) -> None:
        """Conservatively charge the estimate after an indeterminate failure."""

        admission = self.inflight.get(call_id)
        if admission is not None:
            self.settle(call_id, admission.estimated_tokens)

    def snapshot(self) -> dict[str, object]:
        inflight_total = sum(item.estimated_tokens for item in self.inflight.values())
        return {
            "solve_limit": self.solve_limit,
            "group_limit": self.group_limit,
            "used_total": self.used_total,
            "used_by_group": dict(self.used_by_group),
            "inflight_tokens": inflight_total,
            "inflight_calls": len(self.inflight),
            "pressure_total": self.used_total + inflight_total,
        }


def is_subagent(agent: AgentContext) -> bool:
    context = get_subagent_context(agent)
    return bool(context and context.depth > 0)


def _clip_context_field(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    available = max(2, max_chars - len(_FIELD_MARKER))
    head = max(1, int(available * 0.7))
    tail = max(1, available - head)
    return (
        value[:head].rstrip()
        + _FIELD_MARKER
        + value[-tail:].lstrip()
    )[:max_chars]


def fit_messages(
    messages: list[dict[str, Any]], budget: int
) -> list[dict[str, Any]]:
    """Enforce a child cap even when recent messages are individually large."""

    fitted = copy.deepcopy(messages)
    while estimate_tokens(fitted) > budget:
        excess_chars = max(
            _FIELD_MIN_CHARS,
            (estimate_tokens(fitted) - budget) * 4 + 64,
        )
        changed = False
        for message in fitted[1:]:
            content = message.get("content")
            if isinstance(content, str) and len(content) > _FIELD_MIN_CHARS:
                message["content"] = _clip_context_field(
                    content,
                    max(_FIELD_MIN_CHARS, len(content) - excess_chars),
                )
                changed = True
                break
            for tool_call in message.get("tool_calls") or []:
                if not isinstance(tool_call, dict):
                    continue
                function = tool_call.get("function")
                if not isinstance(function, dict):
                    continue
                arguments = function.get("arguments")
                if (
                    isinstance(arguments, str)
                    and len(arguments) > _FIELD_MIN_CHARS
                ):
                    function["arguments"] = _clip_context_field(
                        arguments,
                        max(
                            _FIELD_MIN_CHARS,
                            len(arguments) - excess_chars,
                        ),
                    )
                    changed = True
                    break
            if changed:
                break
        if not changed:
            break
    return fitted


def prepare_request(
    agent: AgentContext,
    messages: list[dict[str, Any]],
    max_tokens: int | None,
) -> int | None:
    if not is_subagent(agent):
        return max_tokens
    context = get_subagent_context(agent)
    assert context is not None
    configured = int(
        getattr(getattr(agent.config, "llm", None), "max_tokens", 0) or 0
    )
    requested = max_tokens if max_tokens is not None else configured
    bounded = max(1, int(requested)) if requested else None
    estimated_input = estimate_tokens(messages)
    context.next_input_token_estimate = estimated_input
    context.next_model_token_reservation = estimated_input + int(
        bounded or 0
    )
    return bounded


def reserve_request(agent: AgentContext) -> Any:
    if not is_subagent(agent):
        return None
    context = get_subagent_context(agent)
    assert context is not None
    token = context.cancel_token
    if token is not None and bool(getattr(token, "cancelled", False)):
        raise asyncio.CancelledError(
            str(
                getattr(token, "reason", "")
                or "sub-agent cancellation requested"
            )
        )

    budget = context.usage_budget
    if budget is None:
        context.llm_requests_used += 1
        return None
    context.model_call_sequence += 1
    task = context.task_context
    admission = budget.try_begin(
        (
            f"{getattr(task, 'task_id', 'agent') or 'agent'}"
            f".llm{context.model_call_sequence}"
        ),
        str(getattr(task, "group_id", "") or ""),
        context.next_model_token_reservation,
    )
    context.llm_requests_used += 1
    return admission


def settle_request(
    agent: AgentContext, admission: Any, actual_tokens: int
) -> None:
    if admission is None:
        return
    context = get_subagent_context(agent)
    budget = context.usage_budget if context else None
    call_id = str(getattr(admission, "call_id", "") or "")
    if budget is not None and call_id:
        budget.settle(call_id, actual_tokens)


def fail_request(agent: AgentContext, admission: Any) -> None:
    context = get_subagent_context(agent)
    budget = context.usage_budget if context else None
    call_id = str(getattr(admission, "call_id", "") or "")
    if budget is not None and call_id:
        budget.charge_estimate(call_id)


def record_usage(agent: AgentContext, response: Any) -> int:
    if not is_subagent(agent):
        return 0
    context = get_subagent_context(agent)
    assert context is not None
    usage = getattr(response, "usage", None)
    input_tokens = int(
        getattr(usage, "prompt_tokens", None)
        or getattr(usage, "input_tokens", None)
        or context.next_input_token_estimate
    )
    output_tokens = int(
        getattr(usage, "completion_tokens", None)
        or getattr(usage, "output_tokens", None)
        or 0
    )
    if output_tokens <= 0:
        choices = getattr(response, "choices", None) or []
        rendered = " ".join(
            str(
                getattr(
                    getattr(choice, "message", None), "content", ""
                )
                or ""
            )
            for choice in choices
        )
        output_tokens = estimate_tokens(rendered)
    context.input_tokens_used += input_tokens
    context.output_tokens_used += output_tokens
    return input_tokens + output_tokens
