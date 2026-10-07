"""真 stdio 传输的端到端会话死亡→吸收→自动重建（round15b F-G 收口验证）。

单测层（test_session_owner.py）已钉住 owner 的取消投递吸收与真 SDK 死亡
信号；本文件把同一机制放到**真实 stdio 子进程 + 真实 lifecycle 接线**上：
服务器进程 os._exit 自毁（实战"会话死亡"的形态）后，调用方任务必须无恙、
缓存必须被清、下一次调用必须自动重建全新会话并工作。

修复前的行为：传输死亡把 CancelledError 直接投进调用方任务，整个 REPL
裸栈炸死；即便不炸，死会话也会滞留缓存，后续调用烧满 tool timeout。
"""

from __future__ import annotations

import asyncio
import sys
import textwrap

import pytest

from vulnclaw.config.schema import MCPServerConfig, VulnClawConfig
from vulnclaw.mcp.lifecycle import MCPLifecycleManager

pytest.importorskip("mcp")

SERVER_SCRIPT = textwrap.dedent(
    """
    import os, sys
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("die-hard")

    @mcp.tool()
    def ping() -> str:
        return "pong"

    @mcp.tool()
    def die() -> str:
        sys.stdout.flush()
        os._exit(0)  # 进程直接消失: 实战会话死亡形态
        return "never"

    mcp.run()
    """
)


def _manager(script_path) -> MCPLifecycleManager:
    cfg = VulnClawConfig()
    cfg.mcp.servers["die-hard"] = MCPServerConfig(
        name="die-hard",
        transport={
            "type": "stdio",
            "command": sys.executable,
            "args": [str(script_path)],
            "startup_timeout": 30000,
            "tool_timeout": 30000,
        },
    )
    return MCPLifecycleManager(cfg)


async def _wait_until(predicate, timeout=15.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return predicate()


class TestStdioServerDeathEndToEnd:
    async def test_death_absorbed_cache_cleared_and_rebuilt(self, tmp_path, caplog):
        script = tmp_path / "die_hard_server.py"
        script.write_text(SERVER_SCRIPT, encoding="utf-8")
        m = _manager(script)

        # 第一跳: 惰性建会话（owner task 承接）+ 真 stdio 调用成功
        content, _structured = await m._call_attached_server("die-hard", "ping", {})
        assert "pong" in content
        first_session = m._mcp_clients["die-hard"]["session"]
        assert first_session is not None

        # 第二跳: 服务器进程自毁——调用必须以**普通失败**收场, 绝不允许
        # CancelledError 冲出调用方任务
        with pytest.raises(Exception) as exc_info:
            await m._call_attached_server("die-hard", "die", {})
        assert not isinstance(exc_info.value, asyncio.CancelledError), (
            "传输死亡不得以取消形式命中调用方（F-G 原始崩溃形态）"
        )

        # 死亡信号(写流关闭)→ owner 清缓存; 调用方任务全程存活
        assert await _wait_until(
            lambda: "die-hard" not in m._mcp_clients
        ), "会话死亡后缓存必须被清, 便于下次调用重建"

        # 第三跳: 自动重建——新进程、新会话、工具照常工作
        content, _structured = await m._call_attached_server("die-hard", "ping", {})
        assert "pong" in content
        rebuilt = m._mcp_clients["die-hard"]
        assert rebuilt["session"] is not first_session
        assert rebuilt["owner"] is not None and not rebuilt["owner"].dead

        # 收尾: 计划内停机走 owner 的干净退出
        await m._aclose_session_meta(rebuilt)
        assert rebuilt["owner"]._task.done()

    async def test_caller_task_never_sees_scope_cancellation(self, tmp_path):
        """F-G 的核心不变量: 服务器死亡前后, 调用方任务的 cancelling() 恒为 0。"""
        script = tmp_path / "die_hard_server.py"
        script.write_text(SERVER_SCRIPT, encoding="utf-8")
        m = _manager(script)
        me = asyncio.current_task()

        await m._call_attached_server("die-hard", "ping", {})
        assert me.cancelling() == 0
        with pytest.raises(Exception):
            await m._call_attached_server("die-hard", "die", {})
        assert await _wait_until(lambda: "die-hard" not in m._mcp_clients)
        assert me.cancelling() == 0, "服务器死亡不得给调用方任务武装任何取消级别"
        await m._call_attached_server("die-hard", "ping", {})
        assert me.cancelling() == 0
