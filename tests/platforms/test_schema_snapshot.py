"""Schema snapshot: the agent's platform tool face must stay the neutral 7.

This is the guard for the token win. Measured before the legacy names were hidden:
17 platform tools (old 10 + neutral 7) cost **2187 tokens per request**; the neutral
face alone is **978**. Two commits bought that (41a395a, 65607d6) and nothing else in
the suite would notice if it were given back -- a re-exposed legacy face is not an
error, it is just a quieter, more expensive prompt.

So this file pins three things: the exact tool NAMES the model sees by default, the
absence of any platform-bound name, and a token ceiling. The last test demonstrates
that the ceiling actually bites by re-exposing the legacy face and measuring it.
"""

from __future__ import annotations

import json

import pytest

from vulnclaw.ctf_platform.tools import ctf2_tool_schemas
from vulnclaw.gcs_platform.tools import gcs_tool_schemas
from vulnclaw.platforms import base, bootstrap, registry
from vulnclaw.platforms.tools import CORE_TOOL_NAMES, platform_tool_schemas

# The measured neutral face: 6 verbs + CTF2's one extra capability.
EXPECTED_DEFAULT_TOOLS = set(CORE_TOOL_NAMES) | {"platform_submissions"}

# Measured 978 for the neutral face; the ceiling leaves room for wording changes but
# would not survive the legacy 10 coming back (~+1209).
TOKEN_CEILING = 1100


class _ConfiguredAdapter:
    """Minimal stand-in: the registry only needs to consider CTF2 exposed."""

    name = "ctf2"
    capabilities = frozenset({base.CAP_SUBMISSIONS})
    enabled_by_default = True

    def is_configured(self) -> bool:
        return True


def _tokens(schemas: list[dict]) -> int:
    """Rough token count of a tool schema block (chars/4, the usual heuristic)."""
    return len(json.dumps(schemas, ensure_ascii=False)) // 4


@pytest.fixture(autouse=True)
def _own_registry(monkeypatch):
    registry.clear_adapters()
    bootstrap.reset_bootstrap()
    monkeypatch.setattr(
        "vulnclaw.platforms.bootstrap.ensure_adapters",
        lambda force=False: registry.all_adapters(),
    )
    registry.register_adapter(_ConfiguredAdapter())
    yield
    registry.clear_adapters()
    bootstrap.reset_bootstrap()


class TestDefaultFace:
    def test_exactly_the_neutral_tools_are_exposed(self):
        names = {t["function"]["name"] for t in platform_tool_schemas()}
        assert names == EXPECTED_DEFAULT_TOOLS

    def test_no_platform_bound_name_survives(self):
        names = {t["function"]["name"] for t in platform_tool_schemas()}
        offenders = {n for n in names if n.startswith("ctf2_") or n.startswith("gcs_")}
        assert offenders == set(), f"legacy names are back in the schema: {offenders}"

    def test_both_legacy_faces_are_empty_by_default(self):
        assert ctf2_tool_schemas() == []
        assert gcs_tool_schemas() == []

    def test_the_neutral_verbs_are_all_there(self):
        names = {t["function"]["name"] for t in platform_tool_schemas()}
        assert set(CORE_TOOL_NAMES) <= names

    def test_every_tool_is_a_valid_openai_function_schema(self):
        for tool in platform_tool_schemas():
            assert tool["type"] == "function"
            function = tool["function"]
            assert function["name"] and function["description"]
            assert function["parameters"]["type"] == "object"


class TestTokenBudget:
    def test_the_neutral_face_fits_the_budget(self):
        assert _tokens(platform_tool_schemas()) <= TOKEN_CEILING

    def test_the_legacy_face_would_break_the_budget(self, monkeypatch):
        """Proves the ceiling is not decorative: this is the regression it catches."""
        monkeypatch.setattr(
            "vulnclaw.ctf_platform.tools.ctf2_tools_enabled", lambda: True
        )
        combined = platform_tool_schemas() + ctf2_tool_schemas()
        assert len(combined) == len(EXPECTED_DEFAULT_TOOLS) + 10
        assert _tokens(combined) > TOKEN_CEILING

    def test_hiding_the_legacy_face_changes_nothing_about_capability(self):
        """The saving is prompt-only: dispatch keeps all 10 handlers."""
        from vulnclaw.ctf_platform.tools import CTF_TOOL_NAMES, CTF_TOOL_NAMES_BY_SCHEMA

        assert set(CTF_TOOL_NAMES_BY_SCHEMA) == set(CTF_TOOL_NAMES)
