"""The legacy per-platform tool names are hidden from the model, but still dispatch.

Two properties are pinned here, and the second is the one that actually bites:

1. **The model's view shrinks.** With both faces exposed the schema carried 17
   platform tools (measured 2187 tokens per request); with only the neutral face it
   carries 7 (978). The duplicate names are what once led an agent to call
   `gcs_submit_flag` for a CTF2 challenge.

2. **The code's capability does not shrink.** `CTF_TOOL_NAMES_BY_SCHEMA` used to be
   derived from `ctf2_tool_schemas()`, so making that function return [] made every
   legacy call fail with "unknown CTF2 tool" -- hiding a tool from the model also
   broke the CLI and every programmatic caller. `gcs_platform/tools.py` documents
   having hit the same trap first; this is the regression test for not repeating it.
"""

from __future__ import annotations

import pytest

from vulnclaw.ctf_platform import tools as ctf2_tools
from vulnclaw.ctf_platform.tools import (
    CTF_TOOL_NAMES,
    CTF_TOOL_NAMES_BY_SCHEMA,
    ctf2_tool_schemas,
)

NEUTRAL_CORE = (
    "platform_list",
    "platform_read",
    "platform_start_env",
    "platform_read_env",
    "platform_stop_env",
    "platform_submit",
)


@pytest.fixture(autouse=True)
def _legacy_off(monkeypatch):
    """Default: the legacy face is hidden."""
    monkeypatch.setattr(ctf2_tools, "ctf2_tools_enabled", lambda: False)


class TestSchemaIsHiddenByDefault:
    def test_no_legacy_schemas(self):
        assert ctf2_tool_schemas() == []

    def test_the_handlers_are_all_still_dispatchable(self):
        """The trap: deriving the dispatch list from the schema hid the tools."""
        assert set(CTF_TOOL_NAMES_BY_SCHEMA) == set(CTF_TOOL_NAMES)
        assert len(CTF_TOOL_NAMES_BY_SCHEMA) == 10

    @pytest.mark.asyncio
    async def test_a_legacy_call_still_executes(self, monkeypatch):
        """End to end: hidden from the model, still callable by code."""
        monkeypatch.setattr(ctf2_tools, "_guard_config", lambda: _noop())

        async def _fake_list(limit=20):
            return {"data": {"items": [], "total": 0}}

        monkeypatch.setattr(ctf2_tools._client, "list_practice", _fake_list)
        out = await ctf2_tools.dispatch_ctf2_tool("ctf2_list_practice", {"limit": 1})
        assert "unknown CTF2 tool" not in out


class TestSwitchRestoresThem:
    def test_enabled_returns_all_ten(self, monkeypatch):
        monkeypatch.setattr(ctf2_tools, "ctf2_tools_enabled", lambda: True)
        names = {s["function"]["name"] for s in ctf2_tool_schemas()}
        assert names == set(CTF_TOOL_NAMES)

    def test_enabled_schemas_are_unchanged(self, monkeypatch):
        """Restoring must give back the same schemas, not a rebuilt approximation."""
        monkeypatch.setattr(ctf2_tools, "ctf2_tools_enabled", lambda: True)
        schemas = ctf2_tool_schemas()
        assert len(schemas) == 10
        assert all(s["type"] == "function" for s in schemas)


class TestTheSwitchFailsClosed:
    def test_unreadable_config_hides_the_legacy_face(self, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("config exploded")

        monkeypatch.setattr("vulnclaw.config.settings.load_config", boom)
        assert ctf2_tools.ctf2_tools_enabled() is False

    def test_the_neutral_face_is_unaffected(self):
        """Hiding the legacy names must never take the neutral face down with it.

        The neutral tools live in platforms/, are pinned in _ALWAYS_KEEP_TOOLS, and
        do not consult this switch at all.
        """
        from vulnclaw.agent.builtin_tools import _ALWAYS_KEEP_TOOLS

        assert set(NEUTRAL_CORE) <= set(_ALWAYS_KEEP_TOOLS)


async def _noop():
    return None
