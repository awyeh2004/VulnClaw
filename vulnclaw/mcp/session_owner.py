"""Own an MCP ClientSession's lifecycle inside a dedicated asyncio task.

round15b F-G root fix. ``ClientSession.__aenter__`` enters its internal anyio
task-group cancel scope with the *calling* task as the scope host, and for a
persistent session that scope never exits while the session lives. The
lifecycle manager used to create sessions inline in whichever task first used
them — the main solve task for single-tool turns — so the solve task stayed
registered in the session's cancellation domain for the whole run. When the
session or its transport died, anyio delivered
``task.cancel("Cancelled via cancel scope …")`` into the solve task itself and
the unhandled CancelledError escaped ``asyncio.run``, killing the REPL with a
raw traceback.

This owner task is the scope host instead: cancellation delivery for a dying
session lands here, where it is absorbed, the real cause is logged, the cache
entry is dropped via the ``on_death`` callback, and the caller's task is never
touched. It also fixes the pre-existing cross-task ``__aexit__`` problem:
teardown now always runs in the task that entered the scopes, so lifecycle's
suppressed "exit cancel scope in a different task" RuntimeErrors disappear
along with the partial-teardown leaks they masked.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

import anyio

logger = logging.getLogger(__name__)

try:
    from mcp import ClientSession
except ImportError:  # pragma: no cover - optional runtime dependency
    ClientSession = None

#: Planned teardown must fit inside stop_server()'s run_coroutine_threadsafe
#: future.result(timeout=5) budget.
STOP_GRACE_SECONDS = 4.0

#: Mirrors lifecycle._BENIGN_SHUTDOWN_KEYWORDS; kept here because lifecycle
#: imports this module (the reverse import would be circular).
_BENIGN_SHUTDOWN_KEYWORDS = (
    "cancel scope",
    "generator didn't stop",
)

TransportFactory = Callable[[], Awaitable[tuple[Any, Any, Any]]]
SessionFactory = Callable[[Any, Any], Any]
DeathCallback = Callable[["OwnedMcpSession"], None]


def _default_session_factory(read_stream: Any, write_stream: Any) -> Any:
    if ClientSession is None:
        raise RuntimeError("MCP Python SDK is not installed")
    return ClientSession(read_stream, write_stream)


def _is_benign_shutdown_exception(exc: BaseException) -> bool:
    if hasattr(exc, "exceptions"):
        subs = list(getattr(exc, "exceptions", []))
        return bool(subs) and all(_is_benign_shutdown_exception(sub) for sub in subs)
    if isinstance(exc, RuntimeError):
        msg = str(exc).lower()
        if any(kw in msg for kw in _BENIGN_SHUTDOWN_KEYWORDS):
            return True
    return isinstance(exc, (GeneratorExit, asyncio.CancelledError))


def _describe_exception(exc: BaseException | None) -> str:
    """Flatten an ExceptionGroup chain into a single message."""
    if exc is None:
        return ""
    subs = getattr(exc, "exceptions", None)
    if subs:
        return "; ".join(filter(None, (_describe_exception(s) for s in subs)))
    return str(exc) or exc.__class__.__name__


class _DeathSignalWriteStream:
    """Write-stream proxy whose close by the receive loop is the death signal.

    mcp's ``_receive_loop`` swallows its own exceptions and clean EOFs (it logs
    "Unhandled exception in receive loop" and returns), so a dead session
    almost never cancels its task group — cancellation delivery alone cannot
    detect session death. The receive loop does always exit its
    ``async with (read_stream, write_stream)`` though, which closes the write
    stream; intercepting that close gives a uniform death signal for EOF,
    swallowed exceptions and real crashes alike.
    """

    def __init__(self, inner: Any, on_close: Callable[[], None]) -> None:
        self._inner = inner
        self._on_close = on_close

    async def send(self, item: Any) -> None:
        await self._inner.send(item)

    def send_nowait(self, item: Any) -> None:
        self._inner.send_nowait(item)

    async def aclose(self) -> None:
        try:
            await self._inner.aclose()
        finally:
            self._on_close()

    async def __aenter__(self) -> "_DeathSignalWriteStream":
        return self

    async def __aexit__(self, *exc: Any) -> Any:
        # The receive loop leaves its `async with` via __aexit__, not aclose —
        # route the death signal through here as well.
        await self.aclose()
        return False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class OwnedMcpSession:
    """Run one MCP ClientSession (and its transport context) inside an owner task."""

    def __init__(
        self,
        name: str,
        factory: TransportFactory,
        *,
        session_factory: SessionFactory | None = None,
        on_death: DeathCallback | None = None,
    ) -> None:
        self.name = name
        self._factory = factory
        self._session_factory = session_factory or _default_session_factory
        self._on_death = on_death
        self.session: Any = None
        self.dead = False
        self._cm: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._task: asyncio.Task | None = None
        self._stop_event: asyncio.Event | None = None
        self._death_event = asyncio.Event()
        self._ready: asyncio.Future | None = None
        self._stop_requested = False

    @property
    def cm(self) -> Any:
        """The transport context manager entered by the owner task."""
        return self._cm

    async def start(self, startup_timeout: float) -> Any:
        """Spawn the owner task and return the initialized session."""
        if self._task is not None:
            raise RuntimeError(f"MCP session {self.name} is already started")
        if ClientSession is None and self._session_factory is _default_session_factory:
            raise RuntimeError("MCP Python SDK is not installed")
        self._loop = asyncio.get_running_loop()
        self._stop_event = asyncio.Event()
        self._ready = self._loop.create_future()
        self._task = self._loop.create_task(self._run())
        try:
            # shield: a timeout here must not cancel the ready future out from
            # under the owner task; aclose() below stops the owner explicitly.
            return await asyncio.wait_for(asyncio.shield(self._ready), startup_timeout)
        except BaseException:
            await self.aclose()
            raise

    async def aclose(self, timeout: float = STOP_GRACE_SECONDS) -> None:
        """Planned teardown: request stop, then wait for the owner's cleanup."""
        self._stop_requested = True
        if self._stop_event is not None:
            self._stop_event.set()
        task = self._task
        if task is None or task.done():
            return
        if self._loop is None or self._loop.is_closed():
            return
        if task is asyncio.current_task():
            return
        # A plain cancel() reaches the owner even while it is still inside
        # initialize(), where the stop event alone cannot interrupt it.
        task.cancel()
        try:
            await asyncio.wait({task}, timeout=timeout)
        finally:
            if task.done():
                try:
                    task.exception()
                except BaseException:  # noqa: BLE001 - retrieval only, never propagated
                    pass

    async def _run(self) -> None:
        try:
            self._cm, read_stream, write_stream = await self._factory()
            self.session = self._session_factory(
                read_stream, _DeathSignalWriteStream(write_stream, self._death_event.set)
            )
            await self.session.__aenter__()
            await self.session.initialize()
            self._resolve_ready()
        except BaseException as exc:
            self._fail_ready(exc)
            await self._teardown(died=False, cancelled=False)
            return
        stop_wait = asyncio.ensure_future(self._stop_event.wait())
        death_wait = asyncio.ensure_future(self._death_event.wait())
        died = False
        cancelled = False
        try:
            done, _ = await asyncio.wait(
                {stop_wait, death_wait}, return_when=asyncio.FIRST_COMPLETED
            )
            died = death_wait in done and not self._stop_requested
        except asyncio.CancelledError:
            # Cancellation delivered through a cancel scope of the session or
            # its transport: this task is the scope host precisely so the
            # caller's task never sees this delivery. A cancellation that
            # races our own planned stop counts as the planned stop.
            died = not self._stop_requested
            cancelled = died
        finally:
            stop_wait.cancel()
            death_wait.cancel()
        await self._teardown(died=died, cancelled=cancelled)

    def _resolve_ready(self) -> None:
        if self._ready is not None and not self._ready.done():
            self._ready.set_result(self.session)

    def _fail_ready(self, exc: BaseException) -> None:
        if self._ready is None or self._ready.done():
            return
        if isinstance(exc, asyncio.CancelledError):
            self._ready.cancel()
        else:
            self._ready.set_exception(exc)

    async def _teardown(self, *, died: bool, cancelled: bool) -> None:
        """Exit session then transport contexts, in the task that entered them.

        Shaped around two anyio facts (both verified against the installed
        anyio): a cancel scope must be exited as the task's *current* innermost
        scope — wrapping the exit in a shield raises "Attempted to exit a
        cancel scope that isn't the current tasks's current cancel scope" — and
        after a scope cancellation the delivery keeps re-cancelling every
        unprotected await of a registered task until the task leaves the scope,
        while a task that ends without leaving it leaves a busy reschedule
        loop behind. Hence:

        - the session's task-group scope is exited unshielded first;
          ``TaskGroup.__aexit__`` is pressure-immune by design (anyio #695
          self-shielding wait scope, cancel-shielded checkpoint) and re-raises
          any parked child exception;
        - plain cleanup awaits (the session exit stack) run under a shield,
          which removes this task from the cancelled scope's delivery set;
        - the transport context is exited normally — including the silent
          zombie path where mcp swallowed a receive-loop failure — and only
          when that exit is itself cut down by an active delivery (the origin
          was the transport scope: its OS resources died with the crash) does
          the owner park under a permanent shield, letting the origin scope's
          delivery set drain instead of spinning on a done host task.
        """
        errors: list[BaseException] = []
        session = self.session
        cm = self._cm
        task_group = getattr(session, "_task_group", None)
        exit_stack = getattr(session, "_exit_stack", None)

        if session is not None:
            if task_group is not None:
                # Mirror BaseSession.__aexit__: cancel the receive loop, then
                # exit. When death was already delivered the scope is cancelled
                # and the loop dead; cancel() is idempotent there.
                task_group.cancel_scope.cancel()
                try:
                    await task_group.__aexit__(None, None, None)
                except BaseException as exc:  # noqa: BLE001 - teardown noise is data here
                    errors.append(exc)
            else:  # pragma: no cover - mcp builds without the private attrs
                try:
                    await session.__aexit__(None, None, None)
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

        if session is not None and exit_stack is not None:
            try:
                with anyio.CancelScope(shield=True):
                    await exit_stack.aclose()
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        abandoned_transport = False
        if cm is not None:
            try:
                await cm.__aexit__(None, None, None)
            except asyncio.CancelledError:
                # The delivery origin was the transport scope itself: exiting
                # its context under active delivery cannot complete. Its OS
                # resources died with the crash; abandon the frame and park.
                if died and cancelled:
                    abandoned_transport = True
                else:
                    raise
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        if died:
            self.dead = True
            real = [e for e in errors if not _is_benign_shutdown_exception(e)]
            if real:
                logger.warning(
                    "MCP session %s terminated by its own transport/receive loop: %s",
                    self.name,
                    _describe_exception(real[0]),
                )
            else:
                logger.info(
                    "MCP session %s terminated without a captured transport error", self.name
                )
            if abandoned_transport:
                logger.warning(
                    "MCP session %s transport scope was cancelled; transport "
                    "context abandoned (resources died with the crash)",
                    self.name,
                )
            if self._on_death is not None:
                try:
                    self._on_death(self)
                except Exception:  # noqa: BLE001
                    logger.debug(
                        "MCP session %s on_death callback failed", self.name, exc_info=True
                    )
            if abandoned_transport:
                # Never returns: park shielded so the origin scope's delivery
                # loop drains instead of spinning on this (done) host task.
                with anyio.CancelScope(shield=True):
                    await asyncio.Event().wait()
            return

        if errors:
            logger.debug(
                "MCP session %s teardown notes: %s",
                self.name,
                _describe_exception(errors[0]),
            )
