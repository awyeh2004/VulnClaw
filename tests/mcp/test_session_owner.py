"""OwnedMcpSession — 会话生命周期收敛到专用 owner task（round15b F-G 根因修复）。

背景（账本 round15b / F-G）：持久 MCP ClientSession 的内部 anyio task-group
cancel scope 以"进入 __aenter__ 的任务"为 host，且持久会话期间永不退出。
lifecycle 曾在首次使用会话的任务里内联建会话——单工具回合即主 solve 任务——
于是 solve 任务终身留在该会话的取消投递域里；传输/接收循环一死，anyio 把
task.cancel("Cancelled via cancel scope …") 直接投进 solve 任务，裸
CancelledError 冲出 asyncio.run 炸掉整个 REPL。

本套件钉两件事：
1. 机制反差——内联形态下 host 任务确实收到投递（F-G 根因的机制锚点）；
2. owner 形态下调用方任务与投递域完全隔离，真实死因落日志、缓存被清。
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress

import anyio
import pytest

from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.mcp.lifecycle import MCPLifecycleManager
from vulnclaw.mcp.session_owner import OwnedMcpSession


class FakeTransport:
    """Transport cm 桩：记录进入/退出，退出即视为真实释放。"""

    def __init__(self):
        self.entered = False
        self.exited = False

    async def __aenter__(self):
        self.entered = True
        return "read", "write"

    async def __aexit__(self, *exc):
        self.exited = True
        return False


class FakeExitStack:
    def __init__(self):
        self.closed = False

    async def aclose(self):
        self.closed = True


class FakeSession:
    """ClientSession 形状桩：真实 anyio task group + 可控崩溃的泵任务。

    与 mcp.ClientSession 的关键同构点：__aenter__ 进入 task group（其 cancel
    scope 的 host task = 调用者），泵任务崩溃 → scope 被取消 → anyio 投递到
    host task；私有属性名 _task_group/_exit_stack 与 BaseSession 对齐，使
    teardown 的主路径（而非 fallback）被测到。
    """

    def __init__(self):
        self._task_group = None
        self._exit_stack = FakeExitStack()
        self._crash = None

    async def __aenter__(self):
        self._task_group = anyio.create_task_group()
        await self._task_group.__aenter__()
        self._crash = anyio.Event()
        self._task_group.start_soon(self._pump)
        return self

    async def _pump(self):
        await self._crash.wait()
        raise RuntimeError("transport exploded")

    def crash(self):
        self._crash.set()

    async def __aexit__(self, *exc):
        return await self._task_group.__aexit__(*exc)

    async def initialize(self):
        return True


def _make_owned(session, transport, on_death=None):
    async def factory():
        await transport.__aenter__()
        return transport, "read", "write"

    return OwnedMcpSession(
        "srv",
        factory,
        session_factory=lambda read, write: session,
        on_death=on_death,
    )


async def _wait_until(predicate, timeout=2.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


class TestInlineHostDocumentsFgMechanism:
    async def test_inline_session_death_cancels_host_task(self):
        """机制反差锚点：谁进 session 的 task group，谁就是投递目标。

        这是修复前 lifecycle 内联建会话时主 solve 任务被炸的机制本身
        （round15b F-G）。owner 形态下没有任何调用方任务再处于这个位置。
        """
        host = asyncio.current_task()
        session = FakeSession()
        await session.__aenter__()
        session.crash()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.sleep(0.05)
        # 归还取消计数，测试任务自身干净收场
        while host.cancelling() > 0:
            host.uncancel()


class TestOwnerAbsorbsDeath:
    async def test_owner_death_isolated_from_caller(self, caplog):
        transport = FakeTransport()
        session = FakeSession()
        deaths = []
        owned = _make_owned(session, transport, on_death=deaths.append)
        got = await owned.start(5.0)
        assert got is session

        with caplog.at_level(logging.WARNING, logger="vulnclaw.mcp.session_owner"):
            session.crash()
            assert await _wait_until(lambda: owned.dead), "owner 未吸收会话死亡"

        assert deaths == [owned], "on_death 必须恰好回调一次"
        assert transport.exited, "死亡路径必须退出 transport"
        assert session._exit_stack.closed, "死亡路径必须关闭 session exit stack"
        assert "transport exploded" in caplog.text, "真实死因必须落日志"
        # 调用方任务不在任何取消域里，事件循环保持健康
        assert await asyncio.sleep(0, result="alive") == "alive"

    async def test_owner_planned_aclose_is_not_death(self):
        transport = FakeTransport()
        session = FakeSession()
        deaths = []
        owned = _make_owned(session, transport, on_death=deaths.append)
        await owned.start(5.0)

        await owned.aclose()

        assert not owned.dead, "计划内停机不得判为死亡"
        assert deaths == []
        assert transport.exited and session._exit_stack.closed
        assert owned._task.done()


class TestOwnerStartup:
    async def test_start_failure_surfaces_and_cleans_partial_state(self):
        transport = FakeTransport()
        deaths = []

        async def factory():
            await transport.__aenter__()
            return transport, "read", "write"

        def broken_session_factory(read, write):
            raise RuntimeError("connection refused")

        owned = OwnedMcpSession(
            "srv", factory, session_factory=broken_session_factory, on_death=deaths.append
        )
        with pytest.raises(RuntimeError, match="connection refused"):
            await owned.start(5.0)

        assert await _wait_until(lambda: transport.exited), "半开 transport 必须在 owner task 内退出"
        assert deaths == [], "启动失败不是死亡"
        assert owned._task.done()

    async def test_start_timeout_stops_owner(self):
        async def factory():
            await asyncio.Event().wait()

        owned = OwnedMcpSession("srv", factory, session_factory=lambda r, w: FakeSession())
        with pytest.raises(asyncio.TimeoutError):
            await owned.start(0.05)
        assert owned._task.done(), "超时后 owner 必须被收掉"


class TestRealMcpSdkSession:
    async def test_real_client_session_death_isolated_from_caller(self, caplog):
        """真 mcp.ClientSession 端到端：传输假死 → owner 吸收 → 调用方无恙。

        内存流对上手工应答 initialize 握手；读流在第二条消息处引爆，模拟
        接收循环崩溃（即实战崩溃日志的触发形态）。
        """
        pytest.importorskip("mcp")
        from mcp import ClientSession as RealClientSession
        from mcp.shared.message import SessionMessage
        from mcp.types import (
            Implementation,
            InitializeResult,
            JSONRPCMessage,
            JSONRPCNotification,
            JSONRPCResponse,
            ServerCapabilities,
        )

        class ExplodingReceiveStream:
            """trigger 置位后下一条消息起 RuntimeError 的读流桩。

            async for 走类型级查找，__aiter__/__anext__ 必须显式定义。不能在
            initialize 收尾前就引爆——receive loop 崩溃会经 async-with 关闭
            整个通道对（含 session 写端），让在途的 initialize 必然以
            ClosedResourceError 告终；因此握手完成后再由测试显式触发。
            """

            def __init__(self, inner, trigger: asyncio.Event):
                self._inner = inner
                self._trigger = trigger

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self._trigger.is_set():
                    raise RuntimeError("transport exploded")
                return await self._inner.__anext__()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return await self._inner.__aexit__(*exc)

            def aclose(self):
                return self._inner.aclose()

        to_session_send, to_session_recv = anyio.create_memory_object_stream(16)
        from_session_send, from_session_recv = anyio.create_memory_object_stream(16)
        transport = FakeTransport()
        explode = asyncio.Event()

        async def factory():
            await transport.__aenter__()
            return transport, ExplodingReceiveStream(to_session_recv, explode), from_session_send

        async def fake_server():
            request = await from_session_recv.receive()
            result = InitializeResult(
                protocolVersion="2024-11-05",
                capabilities=ServerCapabilities(),
                serverInfo=Implementation(name="fake", version="0"),
            )
            response = JSONRPCResponse(
                jsonrpc="2.0",
                id=request.message.root.id,
                result=result.model_dump(by_alias=True, mode="json", exclude_none=True),
            )
            await to_session_send.send(SessionMessage(message=JSONRPCMessage(response)))

        deaths = []
        owned = OwnedMcpSession(
            "real",
            factory,
            session_factory=lambda read, write: RealClientSession(read, write),
            on_death=deaths.append,
        )
        responder = asyncio.create_task(fake_server())
        try:
            got = await owned.start(5.0)
            assert got is not None, "initialize 握手应完成"
        finally:
            responder.cancel()

        with caplog.at_level(logging.INFO):
            # 触发接收循环崩溃：唤醒挂起的 __anext__，下一次迭代引爆。
            # mcp 的 receive loop 会把该异常吞成 ERROR 日志后干净收场
            # （zombie 形态），死亡信号走写流关闭 → death_event。
            explode.set()
            notification = JSONRPCMessage(
                JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized")
            )
            with suppress(anyio.BrokenResourceError, anyio.ClosedResourceError):
                await to_session_send.send(SessionMessage(message=notification))
            assert await _wait_until(lambda: owned.dead, timeout=5.0), (
                "真 SDK 会话崩溃未被 owner 吸收"
            )

        assert deaths == [owned]
        assert transport.exited, "zombie 路径无取消压力，transport 必须完整退出（回收子进程）"
        assert "transport exploded" in caplog.text, "死因必须可观测（mcp receive loop ERROR 日志）"
        # F-G 的核心断言：调用方任务与投递域隔离，循环保持健康
        assert await asyncio.sleep(0, result="alive") == "alive"

    async def test_transport_origin_delivery_parks_owner(self, caplog):
        """传输源取消投递且 cm 退出被砍 → owner 永久盾牌停车，不空转不泄漏。"""
        transport = FakeTransport()
        session = FakeSession()
        deaths = []

        class CmCutByDelivery:
            async def __aenter__(self):
                return "r", "w"

            async def __aexit__(self, *exc):
                raise asyncio.CancelledError()

        async def factory():
            cm = CmCutByDelivery()
            await cm.__aenter__()
            return cm, "read", "write"

        owned = OwnedMcpSession(
            "srv",
            factory,
            session_factory=lambda r, w: session,
            on_death=deaths.append,
        )
        await owned.start(5.0)

        with caplog.at_level(logging.WARNING, logger="vulnclaw.mcp.session_owner"):
            session.crash()
            assert await _wait_until(lambda: owned.dead, timeout=5.0)

        assert deaths == [owned]
        assert "transport scope was cancelled" in caplog.text
        assert not owned._task.done(), "owner 应永久停车（盾牌内等待）"
        owned._task.cancel()  # 清理：原始 asyncio cancel 可穿透盾牌
        with suppress(asyncio.CancelledError):
            await owned._task


class TestLifecycleWiring:
    def _manager(self) -> MCPLifecycleManager:
        return MCPLifecycleManager(VulnClawConfig())

    async def test_aclose_session_meta_routes_through_owner(self):
        m = self._manager()

        class FakeOwned:
            def __init__(self):
                self.closed = False

            async def aclose(self, *args, **kwargs):
                self.closed = True

        owned = FakeOwned()
        meta = {"kind": "persistent-http", "owner": owned, "session": object()}
        await m._aclose_session_meta(meta)
        assert owned.closed, "有 owner 时必须经 owner 关闭（同 task 退出 scope）"

    def test_on_owned_session_death_drops_only_its_entry(self):
        m = self._manager()
        m.registry.register_server("srv")
        m.registry.register_server("other")
        dead_owner = object()
        other_owner = object()
        m._mcp_clients["srv"] = {"kind": "persistent-http", "owner": dead_owner}
        m._mcp_clients["other"] = {"kind": "persistent-http", "owner": other_owner}

        m._on_owned_session_death(dead_owner)

        assert "srv" not in m._mcp_clients
        assert "other" in m._mcp_clients
        assert m.registry.get_all_servers()["srv"].running is False

    async def test_stop_owned_session_stops_and_pops(self):
        m = self._manager()

        class FakeOwned:
            def __init__(self):
                self.closed = False

            async def aclose(self, *args, **kwargs):
                self.closed = True

        owned = FakeOwned()
        m._mcp_clients["srv"] = {"kind": "persistent-stdio", "owner": owned}
        await m._stop_owned_session("srv")
        assert owned.closed
        assert "srv" not in m._mcp_clients

        await m._stop_owned_session("missing")  # 无 owner / 无条目均为 no-op
