"""Shared REPL execution helpers."""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _retire_task_cancellation() -> None:
    """Retire every armed cancellation level on the current task."""
    task = asyncio.current_task()
    if task is None or not hasattr(task, "uncancel"):
        return
    for _ in range(task.cancelling()):
        task.uncancel()


async def run_repl_call(
    *,
    call: Callable[[], Awaitable[T]],
    after_result: Callable[[T], Awaitable[None]],
) -> T:
    """Run a REPL call and forward the result to a post-processing hook.

    Boundary for the round15b F-G crash class: a CancelledError escaping the
    call used to blow out of asyncio.run as a raw traceback and kill the whole
    REPL (e.g. anyio cancel-scope delivery reaching the main task). Convert it
    to KeyboardInterrupt so the REPL's existing interrupt handling — sticky-auto
    resume hint included — applies instead of process death. The TUI backend
    does not go through this helper, so its own task_cancelled contract is
    untouched.
    """
    try:
        result = await call()
    except asyncio.CancelledError as exc:
        # Round15b (2026-10-07): retire the cancellation before converting it.
        # Catching CancelledError does not un-arm the task, so converting to
        # KeyboardInterrupt while ``cancelling()`` stays > 0 merely moves the
        # crash one await later -- the REPL's next await would re-raise
        # CancelledError out of asyncio.run as the raw traceback this helper
        # exists to prevent.
        _retire_task_cancellation()
        logger.warning("REPL run was cancelled; converting to interrupt handling: %r", exc)
        raise KeyboardInterrupt from None
    await after_result(result)
    return result
