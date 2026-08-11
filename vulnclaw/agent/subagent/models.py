"""Runtime contracts for the compact sub-agent architecture."""

from __future__ import annotations

import asyncio
import copy
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    KILLED = "killed"

    @property
    def terminal(self) -> bool:
        return self in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.KILLED}


class CancellationToken:
    def __init__(self) -> None:
        self.reason = ""

    @property
    def cancelled(self) -> bool:
        return bool(self.reason)

    def cancel(self, reason: str = "") -> None:
        if not self.cancelled:
            self.reason = str(reason or "cancelled")


@dataclass(frozen=True)
class AgentDefinition:
    name: str
    session_kind: str
    persistent: bool = False
    allowed_child_types: tuple[str, ...] = ()
    task_kinds: tuple[str, ...] = ()


@dataclass
class AgentSpec:
    description: str
    prompt: str
    agent_type: str = "general"
    task_kind: str = ""
    name: str = ""
    max_steps: Optional[int] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    status: str = "completed"
    summary: str = ""
    content: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    evidence: list[Any] = field(default_factory=list)
    error: str = ""


@dataclass
class AgentSession:
    prompt: str
    messages: list[Any] = field(default_factory=list)
    pending_messages: deque[str] = field(default_factory=deque)
    local_state: Any = None

    def queue_message(self, message: str) -> None:
        self.pending_messages.append(str(message))

    def drain_pending_messages(self) -> list[str]:
        messages = list(self.pending_messages)
        self.pending_messages.clear()
        return messages

    def compact_if_needed(self, max_messages: int = 80) -> None:
        """Bound a persistent Leader transcript at a model-turn boundary."""

        limit = max(8, int(max_messages))
        if len(self.messages) <= limit:
            return
        keep = max(4, limit // 2)
        older = self.messages[:-keep]
        highlights: list[str] = []
        for message in older[-8:]:
            if isinstance(message, dict):
                role = str(message.get("role") or "message")
                content = str(message.get("content") or "")
            else:
                role = str(getattr(message, "role", "message") or "message")
                content = str(getattr(message, "content", "") or "")
            compact = " ".join(content.split())
            if compact:
                highlights.append(f"- {role}: {compact[:500]}")
        summary = "\n".join(
            [
                f"Goal: {self.prompt}",
                f"Earlier leader messages compacted: {len(older)}",
                *highlights,
            ]
        )
        retained = self.messages[-keep:]
        self.messages[:] = [
            {
                "role": "system",
                "content": (
                    "<leader-compaction>\n"
                    f"{summary}\n"
                    "</leader-compaction>"
                ),
            },
            *retained,
        ]


@dataclass
class TaskContext:
    task_id: str
    parent_id: str
    depth: int
    session_kind: str
    group_id: str
    token: CancellationToken
    session: AgentSession


@dataclass
class SubagentContext:
    """All optional task-runtime state attached to one agent."""

    depth: int = 0
    cancel_token: Optional[CancellationToken] = None
    task_context: Optional[TaskContext] = None
    runtime: Any = None
    service: Any = None
    service_owner: bool = False
    usage_budget: Any = None
    tool_calls_used: int = 0
    llm_requests_used: int = 0
    input_tokens_used: int = 0
    output_tokens_used: int = 0
    evidence_bytes_used: int = 0
    next_input_token_estimate: int = 0
    next_model_token_reservation: int = 0
    model_call_sequence: int = 0
    event_sink: Any = None


def get_subagent_context(agent: Any, *, create: bool = False) -> Optional[SubagentContext]:
    context = getattr(agent, "_subagent_ctx", None)
    if isinstance(context, SubagentContext):
        return context
    if not create:
        return None
    context = SubagentContext()
    agent._subagent_ctx = context
    return context


@dataclass(frozen=True)
class TaskHandle:
    task_id: str
    name: str
    status: TaskStatus


@dataclass(frozen=True)
class TaskSnapshot:
    task_id: str
    parent_id: str
    name: str
    agent_type: str
    status: TaskStatus
    revision: int
    created_at: float
    started_at: Optional[float]
    ended_at: Optional[float]
    child_ids: tuple[str, ...]
    leaf_count: int
    wave_count: int
    result: Optional[AgentResult]
    error: str


@dataclass(frozen=True)
class TaskNotification:
    task_id: str
    name: str
    status: TaskStatus
    result: Optional[AgentResult]
    error: str = ""


@dataclass
class TaskRecord:
    task_id: str
    parent_id: str
    name: str
    spec: AgentSpec
    definition: AgentDefinition
    background: bool
    status: TaskStatus = TaskStatus.PENDING
    revision: int = 0
    created_at: float = field(default_factory=time.monotonic)
    started_at: Optional[float] = None
    ended_at: Optional[float] = None
    child_ids: list[str] = field(default_factory=list)
    leaf_count: int = 0
    wave_count: int = 0
    seen_wave_ids: set[str] = field(default_factory=set)
    result: Optional[AgentResult] = None
    error: str = ""
    notified: bool = False
    token: CancellationToken = field(default_factory=CancellationToken)
    session: AgentSession = field(default_factory=lambda: AgentSession(prompt=""))
    context: Optional[TaskContext] = None
    asyncio_task: Optional[asyncio.Task[Any]] = field(default=None, repr=False)

    def snapshot(self) -> TaskSnapshot:
        return TaskSnapshot(
            task_id=self.task_id,
            parent_id=self.parent_id,
            name=self.name,
            agent_type=self.definition.name,
            status=self.status,
            revision=self.revision,
            created_at=self.created_at,
            started_at=self.started_at,
            ended_at=self.ended_at,
            child_ids=tuple(self.child_ids),
            leaf_count=self.leaf_count,
            wave_count=self.wave_count,
            result=copy.deepcopy(self.result),
            error=self.error,
        )
