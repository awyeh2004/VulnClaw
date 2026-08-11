"""Tests for the team role registry and hard tool allow-list (vulnclaw.agent.roles)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent.builtin_tools import execute_mcp_tool
from vulnclaw.agent.roles import (
    ROLE_REGISTRY,
    filter_tools_for_role,
    get_role,
    normalize_role_name,
    require_role,
    role_prompt_block,
    role_tool_violation,
    tool_allowed_for_role,
)


def _tool(name: str) -> dict:
    return {"type": "function", "function": {"name": name, "parameters": {}}}


class TestRoleLookup:
    def test_normalize_role_name(self):
        assert normalize_role_name(" Researcher ") == "researcher"
        assert normalize_role_name("") is None
        assert normalize_role_name(None) is None

    def test_get_role_known_and_unknown(self):
        assert get_role("executor").name == "executor"
        assert get_role("nope") is None
        assert get_role(None) is None

    def test_require_role_raises_on_unknown(self):
        assert require_role("adviser").name == "adviser"
        try:
            require_role("ghost")
        except ValueError as exc:
            assert "ghost" in str(exc)
        else:
            raise AssertionError("expected ValueError for unknown role")


class TestToolGating:
    def test_no_role_allows_everything(self):
        assert tool_allowed_for_role("anything_at_all", None) is True

    def test_unknown_role_blocks_everything(self):
        assert tool_allowed_for_role("evidence_list", "ghost") is False

    def test_researcher_allows_recon_blocks_exploitation(self):
        # glob "evidence_*" allows evidence_list; shell/nmap are not in the list.
        assert tool_allowed_for_role("evidence_list", "researcher") is True
        assert tool_allowed_for_role("subdomain_enum", "researcher") is True
        assert tool_allowed_for_role("shell_command", "researcher") is False
        assert tool_allowed_for_role("nmap_scan", "researcher") is False

    def test_researcher_http_is_limited_to_safe_reconnaissance(self):
        assert (
            role_tool_violation(
                "researcher",
                "fetch",
                {"url": "https://target.local/status", "method": "GET"},
            )
            is None
        )
        for args in (
            {
                "url": "https://target.local/login",
                "method": "POST",
                "data": {"username": "admin"},
            },
            {"url": "https://target.local/?payload=test"},
            {
                "url": "https://target.local/status",
                "headers": {"Authorization": "Bearer token"},
            },
        ):
            blocked = role_tool_violation("researcher", "fetch", args)
            assert blocked is not None
            assert "active requests require role 'executor'" in blocked

        assert (
            role_tool_violation(
                "executor",
                "fetch",
                {
                    "url": "https://target.local/login",
                    "method": "POST",
                    "data": {"username": "admin"},
                },
            )
            is None
        )

    def test_researcher_batch_http_rejects_active_member(self):
        safe = {
            "requests": [
                {"url": "https://target.local/health", "method": "HEAD"},
                {
                    "url": "https://target.local/version",
                    "headers": {"Accept": "application/json"},
                },
            ]
        }
        assert role_tool_violation("researcher", "http_probe_batch", safe) is None

        active = {
            "requests": [
                {"url": "https://target.local/health"},
                {
                    "url": "https://target.local/action",
                    "method": "POST",
                    "json": {"run": True},
                },
            ]
        }
        assert (
            role_tool_violation("researcher", "http_probe_batch", active)
            is not None
        )

    def test_adviser_has_only_read_only_memory_search(self):
        assert ROLE_REGISTRY["adviser"].allowed_tool_globs == ("memory_search", "vault_*")
        assert tool_allowed_for_role("memory_search", "adviser") is True
        assert tool_allowed_for_role("evidence_list", "adviser") is False
        # Vault management is read-only-safe: it never touches the target.
        assert tool_allowed_for_role("vault_search", "adviser") is True

    def test_filter_tools_for_role(self):
        tools = [_tool("evidence_list"), _tool("shell_command"), _tool("subdomain_enum")]
        kept = {t["function"]["name"] for t in filter_tools_for_role(tools, "researcher")}
        assert kept == {"evidence_list", "subdomain_enum"}
        # No active role → unchanged.
        assert filter_tools_for_role(tools, None) == tools


class TestViolationAndPrompt:
    @pytest.mark.asyncio
    async def test_execution_boundary_rejects_active_researcher_http(self):
        result = await execute_mcp_tool(
            SimpleNamespace(active_role="researcher"),
            "fetch",
            {
                "url": "https://target.local/login",
                "method": "POST",
                "data": {"username": "admin"},
            },
        )
        assert result.startswith("[role_tool_violation]")
        assert "active requests require role 'executor'" in result

    def test_role_tool_violation_messages(self):
        assert role_tool_violation(None, "shell_command") is None
        assert role_tool_violation("researcher", "evidence_list") is None
        blocked = role_tool_violation("researcher", "shell_command")
        assert blocked is not None and "shell_command" in blocked and "researcher" in blocked
        unknown = role_tool_violation("ghost", "evidence_list")
        assert unknown is not None and "unknown active role" in unknown

    def test_role_prompt_block(self):
        assert role_prompt_block(None) == ""
        block = role_prompt_block("executor")
        assert "Active Specialist Role" in block
        assert "executor" in block
        assert "Allowed tool patterns:" in block
