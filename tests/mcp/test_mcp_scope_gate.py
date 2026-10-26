"""Regression tests for generic MCP task-scope enforcement."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from vulnclaw.config.domain_models import TaskConstraints
from vulnclaw.config.schema import MCPServerConfig, VulnClawConfig
from vulnclaw.mcp.lifecycle import MCPLifecycleManager


class DummySession:
    def __init__(self):
        self.calls = []

    async def call_tool(self, tool_name, arguments=None):
        self.calls.append((tool_name, arguments))
        return {"ok": True, "content": "ok"}


def _manager(session):
    manager = MCPLifecycleManager(VulnClawConfig())
    manager.config.mcp.servers["custom"] = MCPServerConfig(
        name="custom",
        transport={"type": "stdio", "command": "custom-mcp"},
    )
    manager.registry.register_server("custom")
    manager.registry.register_tool(
        "custom",
        {"name": "inspect", "inputSchema": {"type": "object", "properties": {}}},
    )
    manager._get_or_create_session = AsyncMock(return_value=session)
    return manager


@pytest.mark.asyncio
async def test_generic_mcp_nested_blocked_url_is_rejected_before_session_call():
    session = DummySession()
    manager = _manager(session)
    manager.set_task_constraints(
        TaskConstraints(allowed_hosts=["allowed.test"], blocked_hosts=["blocked.test"], strict_mode=True)
    )

    result = await manager.call_tool(
        "inspect",
        {"meta": {"items": [{"url": "https://blocked.test/secret"}]}},
    )

    assert result["ok"] is False
    assert result["error_type"] == "constraint_violation"
    assert "blocked.test" in result["message"]
    assert session.calls == []


@pytest.mark.asyncio
async def test_generic_mcp_allowed_url_and_non_network_strings_are_not_overblocked():
    session = DummySession()
    manager = _manager(session)
    manager.set_task_constraints(
        TaskConstraints(allowed_hosts=["allowed.test"], strict_mode=True)
    )

    result = await manager.call_tool(
        "inspect",
        {"target": "allowed.test", "label": "blocked.test is just a filename"},
    )

    assert result["ok"] is True
    assert session.calls == [("inspect", {"target": "allowed.test", "label": "blocked.test is just a filename"})]


@pytest.mark.asyncio
async def test_generic_mcp_path_and_port_are_checked_before_session_call():
    session = DummySession()
    manager = _manager(session)
    manager.set_task_constraints(
        TaskConstraints(
            allowed_hosts=["allowed.test"],
            allowed_paths=["/safe"],
            allowed_ports=[443],
            strict_mode=True,
        )
    )

    result = await manager.call_tool("inspect", {"url": "https://allowed.test/admin"})
    assert result["ok"] is False
    assert result["error_type"] == "constraint_violation"
    assert "/admin" in result["message"]
    assert session.calls == []


@pytest.mark.asyncio
async def test_generic_mcp_without_constraints_keeps_existing_dispatch():
    session = DummySession()
    manager = _manager(session)
    result = await manager.call_tool("inspect", {"url": "https://anything.test/x"})
    assert result["ok"] is True
    assert len(session.calls) == 1


def test_blocked_control_plane_endpoint_is_not_started():
    manager = MCPLifecycleManager(VulnClawConfig())
    config = MCPServerConfig(
        name="remote",
        transport={"type": "streamable-http", "url": "https://blocked.test/mcp"},
    )
    manager.set_task_constraints(TaskConstraints(blocked_hosts=["blocked.test"], strict_mode=True))
    manager._try_attach_http_client = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("blocked endpoint must not be probed")
    )

    assert manager._start_server("remote", config) is False
    state = manager.registry.get_all_servers().get("remote")
    assert state is None or state.health_status == "blocked"
