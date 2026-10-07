"""Tool-local cancellation must not poison the enclosing task.

REPL-killer reproduced 2026-10-06: an MCP tool's 40s anyio request scope
expired, ``_execute_single`` caught the CancelledError and recorded a failed
tool result — but on Python 3.11+ catching does NOT retire the task's
cancellation. The very next await on the same task (the follow-up LLM call)
re-raised the still-armed CancelledError, which escaped the retry loop
(``except asyncio.CancelledError: raise``) and took the whole REPL process
down, traceback and all.
"""

from __future__ import annotations

import asyncio

import pytest

from vulnclaw.agent import tool_call_manager as tcm


class TestLocalCancellationRetirement:
    @pytest.mark.asyncio
    async def test_uncancel_retires_the_swallowed_cancellation(self):
        """task.cancel(msg='...cancel scope...') inside the task, caught and
        swallowed → without uncancel() the next await re-raises; with it the
        task keeps running."""

        async def poisoned():
            task = asyncio.current_task()
            task.cancel(msg="Cancelled via cancel scope 259d6e4ebd0")
            with pytest.raises(asyncio.CancelledError):
                await asyncio.sleep(10)
            assert task.cancelling() == 1, "the armed state that killed the REPL"
            assert tcm._looks_like_tool_local_cancellation(
                asyncio.CancelledError("Cancelled via cancel scope 259d6e4ebd0")
            )
            tcm._restore_after_local_cancellation()
            assert task.cancelling() == 0
            await asyncio.sleep(0)  # re-raises CancelledError if still armed
            return "survived"

        assert await poisoned() == "survived"

    @pytest.mark.asyncio
    async def test_user_cancellation_is_classified_as_user(self):
        """A plain user interrupt carries no scope message: the guard must
        classify it as user cancellation (re-raise, never uncancel). Note the
        Python 3.12 delivery semantics visible here: a plain task.cancel()
        delivers ONCE — catching it and awaiting again does not re-raise.
        The repeated re-delivery that killed the REPL came from the anyio
        scope still being armed, which is why the tool-local branch needs the
        uncancel() retirement in the first place."""

        async def user_interrupted():
            task = asyncio.current_task()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.sleep(10)
            assert not tcm._looks_like_tool_local_cancellation(asyncio.CancelledError())
            await asyncio.sleep(0)  # plain cancel: no re-delivery on 3.12
            return "completed"

        assert await user_interrupted() == "completed"

    @pytest.mark.asyncio
    async def test_stacked_cancellations_are_all_retired(self):
        """Round15b (2026-10-07): ``uncancel()`` retires exactly ONE level.
        Cancel scopes stack — the tool's own scope plus an enclosing
        ``wait_for``/parent scope — and the remainder stayed armed, so a single
        ``uncancel()`` left ``cancelling() == 1``: the same poisoning, one scope
        deeper. ``_restore_after_local_cancellation`` must retire the depth it
        found.
        """

        async def poisoned_twice():
            task = asyncio.current_task()
            task.cancel(msg="Cancelled via cancel scope a")
            task.cancel(msg="Cancelled via cancel scope b")
            with pytest.raises(asyncio.CancelledError):
                await asyncio.sleep(10)
            assert task.cancelling() == 2, "two stacked scopes"
            tcm._restore_after_local_cancellation()
            assert task.cancelling() == 0, "every level must be retired"
            await asyncio.sleep(0)
            return "survived"

        assert await poisoned_twice() == "survived"
