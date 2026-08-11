"""Single task control plane for Main, Group Leaders, and leaf agents."""

from __future__ import annotations

import asyncio
import copy
import inspect
import itertools
import time
from collections import deque
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any, Optional

from vulnclaw.agent.roles import subagent_roles
from vulnclaw.agent.subagent.budget import UsageBudget
from vulnclaw.agent.subagent.models import (
    AgentDefinition,
    AgentResult,
    AgentSession,
    AgentSpec,
    CancellationToken,
    TaskContext,
    TaskHandle,
    TaskNotification,
    TaskRecord,
    TaskSnapshot,
    TaskStatus,
)

AgentExecutor = Callable[
    [AgentDefinition, AgentSpec, AgentSession, TaskContext],
    Awaitable[AgentResult | str] | AgentResult | str,
]


class AgentRunner:
    """Normalize an injected child execution callback to ``AgentResult``."""

    def __init__(self, execute: AgentExecutor):
        self._execute = execute

    async def run(
        self,
        definition: AgentDefinition,
        spec: AgentSpec,
        session: AgentSession,
        context: TaskContext,
    ) -> AgentResult:
        if context.token.cancelled:
            raise asyncio.CancelledError(context.token.reason)
        value: Any = self._execute(definition, spec, session, context)
        if inspect.isawaitable(value):
            value = await value
        if isinstance(value, AgentResult):
            return value
        return AgentResult(summary=str(value))


class DelegationDenied(RuntimeError):
    pass


EventSink = Callable[[str, dict[str, object]], None]


DEFAULT_DEFINITIONS: tuple[AgentDefinition, ...] = tuple(
    AgentDefinition(
        name=role.name,
        session_kind=role.session_kind,
        persistent=role.persistent,
        allowed_child_types=role.allowed_child_types,
        task_kinds=role.task_kinds,
    )
    for role in subagent_roles()
)


class TaskService:
    """The only owner of task records and live ``asyncio.Task`` objects."""

    def __init__(
        self,
        *,
        runner: AgentRunner,
        definitions: tuple[AgentDefinition, ...] = DEFAULT_DEFINITIONS,
        max_background_groups: int = 3,
        max_concurrent_leaf_total: int = 4,
        max_concurrent_leaf_per_group: int = 3,
        max_leaf_per_group: int = 6,
        max_waves_per_group: int = 3,
        leaf_timeout_seconds: float = 900,
        group_timeout_seconds: float = 1200,
        shutdown_timeout_seconds: float = 120,
        usage_budget: Optional[UsageBudget] = None,
        event_sink: Optional[EventSink] = None,
    ) -> None:
        self.runner = runner
        self.usage_budget = usage_budget
        self.definitions = {item.name: item for item in definitions}
        self.max_background_groups = max(1, int(max_background_groups))
        self.max_leaf_per_group = max(1, int(max_leaf_per_group))
        self.max_waves_per_group = max(1, int(max_waves_per_group))
        self.leaf_timeout_seconds = max(0.01, float(leaf_timeout_seconds))
        self.group_timeout_seconds = max(0.01, float(group_timeout_seconds))
        self.shutdown_timeout_seconds = max(
            0.01,
            float(shutdown_timeout_seconds),
        )
        self.records: dict[str, TaskRecord] = {}
        self._ids = itertools.count(1)
        self._leaf_total = asyncio.Semaphore(max(1, int(max_concurrent_leaf_total)))
        self._leaf_group_limit = max(1, int(max_concurrent_leaf_per_group))
        self._leaf_by_group: dict[str, asyncio.Semaphore] = {}
        self._event_sink = event_sink
        self._notifications: deque[TaskNotification] = deque()
        self._shutting_down = False
        self._main_session = AgentSession(prompt="")
        self._main_token = CancellationToken()

    def main_context(self) -> TaskContext:
        return TaskContext(
            task_id="main",
            parent_id="",
            depth=0,
            session_kind="main",
            group_id="",
            token=self._main_token,
            session=self._main_session,
        )

    async def spawn_background(
        self,
        spec: AgentSpec,
        parent: TaskContext,
    ) -> TaskHandle:
        record = self._register(spec, parent, background=True)
        record.asyncio_task = asyncio.create_task(
            self._run_record(record),
            name=f"subagent:{record.task_id}",
        )
        return TaskHandle(record.task_id, record.name, record.status)

    async def run_foreground(
        self,
        spec: AgentSpec,
        parent: TaskContext,
    ) -> AgentResult:
        record = self._register(spec, parent, background=False)
        record.asyncio_task = asyncio.create_task(
            self._run_record(record),
            name=f"subagent:{record.task_id}",
        )
        await record.asyncio_task
        if record.status is TaskStatus.KILLED:
            raise asyncio.CancelledError(record.error or record.token.reason)
        if record.status is TaskStatus.FAILED:
            raise RuntimeError(record.error or "agent failed")
        return record.result or AgentResult()

    def _register(
        self,
        spec: AgentSpec,
        parent: TaskContext,
        *,
        background: bool,
    ) -> TaskRecord:
        if self._shutting_down:
            raise RuntimeError("task service is shutting down")
        definition = self.definitions.get(spec.agent_type)
        if definition is None:
            raise DelegationDenied(f"unknown agent type: {spec.agent_type}")
        spec.task_kind = str(
            spec.task_kind
            or (definition.task_kinds[0] if definition.task_kinds else "")
        ).strip().lower()
        if spec.task_kind not in definition.task_kinds:
            raise DelegationDenied(
                f"role {definition.name} cannot handle task_kind {spec.task_kind}"
            )
        parent_record = self.records.get(parent.task_id)
        if parent.session_kind != "main" and (
            parent_record is None
            or parent_record.status.terminal
            or parent_record.token.cancelled
        ):
            raise DelegationDenied("parent agent is not active")
        self._validate_delegation(
            parent,
            parent_record,
            definition,
            background,
        )
        if parent.session_kind == "group_leader":
            self._admit_leaf(parent, spec)

        if definition.session_kind == "group_leader" and background:
            active_groups = sum(
                1
                for item in self.records.values()
                if item.definition.session_kind == "group_leader"
                and item.background
                and not item.status.terminal
            )
            if active_groups >= self.max_background_groups:
                raise DelegationDenied("background group limit reached")

        task_id = f"a-{next(self._ids):04d}"
        name = str(spec.name or spec.description or task_id)
        group_id = (
            task_id
            if definition.session_kind == "group_leader"
            else parent.group_id
        )
        session = AgentSession(prompt=spec.prompt)
        record = TaskRecord(
            task_id=task_id,
            parent_id=parent.task_id,
            name=name,
            spec=spec,
            definition=definition,
            background=background,
            session=session,
        )
        record.context = TaskContext(
            task_id=task_id,
            parent_id=parent.task_id,
            depth=parent.depth + 1,
            session_kind=definition.session_kind,
            group_id=group_id,
            token=record.token,
            session=session,
        )
        self.records[task_id] = record
        if parent.task_id in self.records:
            self.records[parent.task_id].child_ids.append(task_id)
            self.records[parent.task_id].revision += 1
        if definition.session_kind == "group_leader":
            self._emit_group(
                record,
                "group_created",
                phase="created",
                status="pending",
            )
        elif parent.session_kind == "group_leader":
            self._emit_group_progress(
                parent.task_id,
                member=record,
                member_event="created",
            )
        return record

    def _admit_leaf(self, parent: TaskContext, spec: AgentSpec) -> None:
        leader = self.records.get(parent.task_id)
        if leader is None:
            raise DelegationDenied("group leader task record is missing")
        if leader.leaf_count >= self.max_leaf_per_group:
            raise DelegationDenied("group leaf limit reached")
        wave_id = str(spec.metadata.get("wave_id") or "")
        if wave_id and wave_id not in leader.seen_wave_ids:
            if leader.wave_count >= self.max_waves_per_group:
                raise DelegationDenied("group wave limit reached")
            leader.seen_wave_ids.add(wave_id)
            leader.wave_count += 1
        leader.leaf_count += 1
        leader.revision += 1

    @staticmethod
    def _validate_delegation(
        parent: TaskContext,
        parent_record: Optional[TaskRecord],
        child: AgentDefinition,
        background: bool,
    ) -> None:
        if parent.session_kind == "main":
            return
        if parent.session_kind != "group_leader":
            raise DelegationDenied("leaf agents cannot delegate")
        if child.session_kind == "group_leader":
            raise DelegationDenied("group leaders cannot create group leaders")
        allowed = (
            parent_record.definition.allowed_child_types
            if parent_record is not None
            else ()
        )
        if child.name not in allowed:
            raise DelegationDenied(f"agent type {child.name!r} is not allowed for leaders")
        if background:
            raise DelegationDenied("group leaders can launch foreground leaf agents only")
        if parent.depth != 1:
            raise DelegationDenied("maximum agent depth exceeded")

    async def _run_record(self, record: TaskRecord) -> None:
        if record.status.terminal:
            return
        context = record.context
        assert context is not None
        execution: Optional[asyncio.Task[AgentResult]] = None
        try:
            async with self._execution_slot(record, context):
                if record.token.cancelled:
                    raise asyncio.CancelledError(record.token.reason)
                record.status = TaskStatus.RUNNING
                record.started_at = time.monotonic()
                record.revision += 1
                if record.definition.session_kind == "group_leader":
                    self._emit_group(
                        record,
                        "group_started",
                        phase="executing",
                        status="running",
                    )
                elif context.group_id:
                    self._emit_group_progress(
                        context.group_id,
                        member=record,
                        member_event="started",
                    )
                execution = asyncio.create_task(
                    self.runner.run(
                        record.definition,
                        record.spec,
                        record.session,
                        context,
                    ),
                    name=f"subagent-execution:{record.task_id}",
                )
                timeout = (
                    self.group_timeout_seconds
                    if record.definition.session_kind == "group_leader"
                    else self.leaf_timeout_seconds
                )
                done, _pending = await asyncio.wait(
                    {execution},
                    timeout=timeout,
                )
                if not done:
                    record.token.cancel("task wall timeout")
                    result = await self._cancel_execution(execution)
                    await self._finish_record(
                        record,
                        TaskStatus.FAILED,
                        result=result,
                        error="task wall timeout",
                    )
                    return
                result = await execution
            if record.token.cancelled:
                await self._finish_record(
                    record,
                    TaskStatus.KILLED,
                    result=result,
                    error=record.token.reason,
                )
            elif result.status in {"failed", "error"}:
                await self._finish_record(
                    record,
                    TaskStatus.FAILED,
                    result=result,
                    error=result.error or result.summary,
                )
            elif result.status in {"killed", "cancelled"}:
                await self._finish_record(
                    record,
                    TaskStatus.KILLED,
                    result=result,
                    error=result.error or result.summary,
                )
            else:
                await self._finish_record(
                    record,
                    TaskStatus.COMPLETED,
                    result=result,
                )
        except asyncio.CancelledError:
            record.token.cancel(record.token.reason or "cancelled")
            result = await self._cancel_execution(execution)
            await self._finish_record(
                record,
                TaskStatus.KILLED,
                result=result,
                error=record.token.reason or "cancelled",
            )
        except BaseException as exc:
            await self._finish_record(
                record,
                TaskStatus.FAILED,
                error=str(exc),
            )
        finally:
            if record.background and record.status.terminal:
                self._notify(record)

    @staticmethod
    async def _cancel_execution(
        execution: Optional[asyncio.Task[AgentResult]],
    ) -> Optional[AgentResult]:
        if execution is None:
            return None
        if not execution.done():
            execution.cancel()
        values = await asyncio.gather(execution, return_exceptions=True)
        value = values[0]
        return value if isinstance(value, AgentResult) else None

    async def _finish_record(
        self,
        record: TaskRecord,
        status: TaskStatus,
        *,
        result: Optional[AgentResult] = None,
        error: str = "",
    ) -> None:
        if record.definition.session_kind == "group_leader":
            settle_reason = (
                error
                or (result.summary if result is not None else "")
                or status.value
            )
            await self.settle_children(
                record.task_id,
                reason=settle_reason,
            )
        self._terminalize(record, status, result=result, error=error)

    async def settle_children(self, task_id: str, *, reason: str) -> None:
        """Cancel and await every direct child before a Group becomes terminal."""

        record = self._record(task_id)
        for child_id in tuple(record.child_ids):
            child = self.records.get(child_id)
            if child is None:
                continue
            if not child.status.terminal:
                await self._cancel_tree(child, reason)
                continue
            task = child.asyncio_task
            if (
                task is not None
                and task is not asyncio.current_task()
                and not task.done()
            ):
                await asyncio.gather(task, return_exceptions=True)

    @asynccontextmanager
    async def _execution_slot(
        self,
        record: TaskRecord,
        context: TaskContext,
    ):
        if record.definition.session_kind != "leaf" or not context.group_id:
            yield
            return
        group_gate = self._leaf_by_group.setdefault(
            context.group_id,
            asyncio.Semaphore(self._leaf_group_limit),
        )
        async with self._leaf_total:
            async with group_gate:
                yield

    def _terminalize(
        self,
        record: TaskRecord,
        status: TaskStatus,
        *,
        result: Optional[AgentResult] = None,
        error: str = "",
    ) -> None:
        if record.status.terminal:
            return
        record.status = status
        record.ended_at = time.monotonic()
        record.result = result
        record.error = str(error or "")
        record.revision += 1
        if record.definition.session_kind == "group_leader":
            kind = {
                TaskStatus.COMPLETED: "group_finished",
                TaskStatus.FAILED: "group_failed",
                TaskStatus.KILLED: "group_cancelled",
            }[status]
            event_status = (
                "cancelled" if status is TaskStatus.KILLED else status.value
            )
            self._emit_group(
                record,
                kind,
                phase=event_status,
                status=event_status,
            )
        elif record.context is not None and record.context.group_id:
            self._emit_group_progress(
                record.context.group_id,
                member=record,
                member_event="terminal",
            )

    def _emit_group_progress(
        self,
        group_id: str,
        *,
        member: Optional[TaskRecord] = None,
        member_event: str = "",
    ) -> None:
        group = self.records.get(group_id)
        if group is None:
            return
        self._emit_group(
            group,
            "group_progress",
            phase="executing",
            status=group.status.value,
            member=member,
            member_event=member_event,
        )

    def _emit_group(
        self,
        record: TaskRecord,
        kind: str,
        *,
        phase: str,
        status: str,
        member: Optional[TaskRecord] = None,
        member_event: str = "",
    ) -> None:
        if self._event_sink is None:
            return
        children = [
            self.records[task_id]
            for task_id in record.child_ids
            if task_id in self.records
        ]
        payload: dict[str, object] = {
            "group_id": record.task_id,
            "name": record.name,
            "goal": record.spec.description,
            "phase": phase,
            "status": status,
            "member_total": record.leaf_count,
            "member_done": sum(item.status.terminal for item in children),
            "member_failed": sum(
                item.status in {TaskStatus.FAILED, TaskStatus.KILLED}
                for item in children
            ),
            "wave_count": record.wave_count,
            "evidence_count": len(
                getattr(record.result, "evidence", []) or []
            ),
            "conclusion": str(
                getattr(record.result, "summary", "") or record.error
            ),
        }
        if member is not None:
            payload.update(
                {
                    "member_task_id": member.task_id,
                    "member_type": member.definition.name,
                    "member_event": member_event,
                    "member_status": member.status.value,
                    "member_usage": dict(
                        getattr(member.result, "usage", {}) or {}
                    ),
                    "member_error": member.error,
                }
            )
        if kind in {"group_finished", "group_failed", "group_cancelled"}:
            payload["budget"] = (
                self.usage_budget.snapshot()
                if self.usage_budget is not None
                else None
            )
        try:
            self._event_sink(kind, payload)
        except Exception:
            return

    def _notify(self, record: TaskRecord) -> None:
        if record.notified:
            return
        record.notified = True
        notification = TaskNotification(
            task_id=record.task_id,
            name=record.name,
            status=record.status,
            result=copy.deepcopy(record.result),
            error=record.error,
        )
        self._notifications.append(notification)
        if record.definition.session_kind == "group_leader":
            self._emit_group(
                record,
                "group_notified",
                phase="notified",
                status=(
                    "cancelled"
                    if record.status is TaskStatus.KILLED
                    else record.status.value
                ),
            )

    def drain_notifications(self) -> list[TaskNotification]:
        notifications = list(self._notifications)
        self._notifications.clear()
        return notifications

    async def message(self, task_id: str, text: str) -> None:
        record = self._record(task_id)
        if record.status.terminal:
            raise RuntimeError("cannot message a terminal task")
        if not record.definition.persistent:
            raise RuntimeError("only persistent agents accept messages")
        record.session.queue_message(text)
        record.revision += 1

    async def collect(self, task_id: str) -> TaskSnapshot:
        return self._record(task_id).snapshot()

    def list(self) -> list[TaskSnapshot]:
        return [record.snapshot() for record in self.records.values()]

    async def cancel(self, task_id: str, reason: str = "") -> TaskSnapshot:
        record = self._record(task_id)
        await self._cancel_tree(record, reason or "cancelled")
        return record.snapshot()

    async def _cancel_tree(self, record: TaskRecord, reason: str) -> None:
        # Close delegation synchronously before recursion yields control.
        record.token.cancel(reason)
        for child_id in tuple(record.child_ids):
            child = self.records.get(child_id)
            if child is not None:
                await self._cancel_tree(child, reason)

        task = record.asyncio_task
        current = asyncio.current_task()
        if task is not None and task is not current and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await self._finish_record(record, TaskStatus.KILLED, error=reason)
        if record.background:
            self._notify(record)

    async def shutdown(self) -> None:
        if self._shutting_down:
            return
        self._shutting_down = True
        roots = [
            record
            for record in self.records.values()
            if record.parent_id == "main" and not record.status.terminal
        ]
        if roots:
            cancellation_tasks = {
                asyncio.create_task(
                    self._cancel_tree(
                        record,
                        "task service shutdown",
                    )
                )
                for record in roots
            }
            done, pending = await asyncio.wait(
                cancellation_tasks,
                timeout=self.shutdown_timeout_seconds,
            )
            if done:
                await asyncio.gather(*done, return_exceptions=True)
            if pending:
                for task in pending:
                    task.cancel()
                unfinished = [
                    record
                    for record in self.records.values()
                    if not record.status.terminal
                ]
                for record in unfinished:
                    if record.status.terminal:
                        continue
                    record.token.cancel("task service shutdown timeout")
                    task = record.asyncio_task
                    if task is not None and not task.done():
                        task.cancel()
                for record in sorted(
                    unfinished,
                    key=lambda item: item.definition.session_kind
                    == "group_leader",
                ):
                    self._terminalize(
                        record,
                        TaskStatus.KILLED,
                        error="task service shutdown timeout",
                    )
        pending = [
            record.asyncio_task
            for record in self.records.values()
            if record.background
            and record.asyncio_task is not None
            and not record.asyncio_task.done()
        ]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    def _record(self, task_id: str) -> TaskRecord:
        record = self.records.get(task_id)
        if record is None:
            raise KeyError(task_id)
        return record
