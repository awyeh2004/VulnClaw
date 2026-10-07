"""run_repl_call 的 CancelledError 边界（round15b F-G 兜底）。

裸 CancelledError 冲出 call() 曾直穿 asyncio.run 变成裸栈 traceback 炸死整个
REPL。边界把它转成 KeyboardInterrupt，复用 REPL 既有的中断 UX（含 sticky-auto
提示）；TUI 后端不经此路径，其 task_cancelled 契约不受影响。
"""

from __future__ import annotations

import asyncio

import pytest

from vulnclaw.repl_runner import run_repl_call


async def test_result_forwarded_to_after_result_hook():
    seen = []

    async def call():
        return 42

    async def after_result(result):
        seen.append(result)

    assert await run_repl_call(call=call, after_result=after_result) == 42
    assert seen == [42]


async def test_cancellation_becomes_keyboard_interrupt_not_crash():
    ran_hook = []

    async def call():
        raise asyncio.CancelledError()

    async def after_result(result):  # pragma: no cover - must not run
        ran_hook.append(result)

    with pytest.raises(KeyboardInterrupt):
        await run_repl_call(call=call, after_result=after_result)

    assert ran_hook == [], "取消后不得再执行 after_result"


async def test_cancellation_with_message_is_swallowed_into_interrupt():
    async def call():
        raise asyncio.CancelledError("Cancelled via cancel scope 16f97f93950")

    with pytest.raises(KeyboardInterrupt):
        await run_repl_call(call=call, after_result=_noop)


async def test_non_cancellation_errors_propagate_unchanged():
    async def call():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await run_repl_call(call=call, after_result=_noop)


async def _noop(result):
    return None
