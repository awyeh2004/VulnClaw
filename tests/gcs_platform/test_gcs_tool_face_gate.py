"""The GCS tool-face gate: the fix for the agent calling the wrong platform.

Why these live in their own module
----------------------------------
`test_gcs_platform_tools.py` installs an autouse fixture that opts the GCS tool
face IN, because those tests cover the tool implementation. A module-scoped
autouse fixture cannot be cleanly undone inside a single test, so asserting the
*default-off* behaviour there would assert against the fixture's stub rather
than the real function. Measured: it did exactly that and passed for the wrong
reason. Splitting the gate tests into a module with no such fixture keeps them
honest.
"""

from __future__ import annotations

import pytest

from vulnclaw.gcs_platform import tools as gcs_tools
from vulnclaw.gcs_platform.tools import GCS_TOOL_NAMES


class TestToolFaceDefaultsOff:
    def test_schemas_are_empty_by_default(self, monkeypatch):
        """The whole point: a tool the model cannot see is one it cannot call."""
        monkeypatch.delenv("VULNCLAW_GCS__TOOLS_ENABLED", raising=False)
        assert gcs_tools.gcs_tools_enabled() is False
        assert gcs_tools.gcs_tool_schemas() == []

    def test_default_is_declared_off_in_the_schema_config(self):
        from vulnclaw.config.schema import VulnClawConfig

        assert VulnClawConfig().gcs.tools_enabled is False

    def test_gate_fails_closed_when_config_is_unreadable(self, monkeypatch):
        """Not being able to read the setting must not expose the tool face.

        The GCS face performs irreversible actions (flag submission) against a
        platform, so an unreadable config has to resolve to 'hidden'.
        """
        import vulnclaw.config.settings as settings

        def boom():
            raise RuntimeError("config unreadable")

        monkeypatch.setattr(settings, "load_config", boom)
        assert gcs_tools.gcs_tools_enabled() is False
        assert gcs_tools.gcs_tool_schemas() == []

    def test_enabling_restores_every_tool(self, monkeypatch):
        import vulnclaw.config.settings as settings
        from vulnclaw.config.schema import VulnClawConfig

        cfg = VulnClawConfig()
        cfg.gcs.tools_enabled = True
        monkeypatch.setattr(settings, "load_config", lambda: cfg)
        schemas = gcs_tools.gcs_tool_schemas()
        assert {s["function"]["name"] for s in schemas} == set(GCS_TOOL_NAMES)
        assert len(schemas) == 9


class TestDisablingDoesNotBreakDispatch:
    """Disabling the FACE must not disable the CODE.

    Regression: `GCS_TOOL_NAMES_BY_SCHEMA` used to be derived from
    `gcs_tool_schemas()`. Once the schema function could return [], that
    derivation made dispatch reject every call with "unknown GCS tool" --
    breaking the `vulnclaw gcs` command and any programmatic caller, even though
    they never go through the agent schema at all.
    """

    def test_name_list_is_static(self):
        assert len(gcs_tools.GCS_TOOL_NAMES_BY_SCHEMA) == 9
        assert set(gcs_tools.GCS_TOOL_NAMES_BY_SCHEMA) == set(GCS_TOOL_NAMES)

    async def test_dispatch_still_routes_when_face_is_off(self, monkeypatch):
        from vulnclaw.gcs_platform import client as gcs_client

        monkeypatch.delenv("VULNCLAW_GCS__TOOLS_ENABLED", raising=False)
        assert gcs_tools.gcs_tool_schemas() == [], "precondition: face is hidden"

        monkeypatch.setenv("VULNCLAW_GCS_ACCESS_KEY", "ak_test")
        calls: dict[str, object] = {}

        async def fake_recover(exercise_id):
            calls["recovered"] = exercise_id
            return {"code": "00000", "data": {}}

        monkeypatch.setattr(gcs_client, "recover_environment", fake_recover)
        out = await gcs_tools.dispatch_gcs_tool("gcs_recover_env", {"exercise_id": 42})
        assert calls.get("recovered") == 42, out
        assert "unknown GCS tool" not in out

    async def test_unknown_tool_is_still_rejected(self):
        out = await gcs_tools.dispatch_gcs_tool("gcs_nope", {})
        assert "unknown GCS tool" in out
