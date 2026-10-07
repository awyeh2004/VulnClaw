"""Legacy tool-name dispatch follows the face the caller actually read.

Measured on 2026-10-07: the CTF2 platform's own MCP server ships a tool ALSO
named ``ctf2_submit_flag`` whose schema takes ``practice_ground_id``, while the
builtin legacy face takes ``practice_id``. With the legacy face hidden
(``expose_legacy_tool_names: false`` — the default), the model's schema contains
ONLY the MCP version, so the MCP-vocabulary call arrived in
``execute_mcp_tool``, matched the builtin table, and died on a bare
``KeyError('practice_id')`` AFTER the flag was already solved. The solve loop
then churned instead of submitting: no completion, no playbook capture.

Three properties are pinned here:

1. **Hidden face yields to a shadowing MCP server.** When the builtin face is
   hidden AND the MCP registry owns the name, the call goes to
   ``mcp_manager.call_tool`` — the face the model could only have been talking
   to. For the submit verb this is the EXECUTOR too (operator decision
   2026-10-07): the schema the model sees is the schema that runs.
2. **The code's capability does not shrink.** With no MCP owner (or no manager
   at all) the builtin route still executes a hidden-face name — the property
   ``CTF_TOOL_NAMES_BY_SCHEMA``'s docstring pins for CLI/programmatic callers.
3. **The submit master switch is not delegated.** Yielding a submit past the
   gate requires ``allow_flag_submission`` ON (fail closed); with no MCP owner
   the builtin path still crosses the full shared policy, absorbing both
   argument vocabularies.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import vulnclaw.agent.builtin_tools as bt
from vulnclaw.ctf_platform import tools as ctf2_tools
from vulnclaw.platforms.submit_guard import SubmitGuard

PRACTICE_ID = "b9bbb32f-f186-458f-b90b-12440c0f6aea"
CHALLENGE_ID = "31bf6864-5a93-4920-9d63-f2c36cd0e693"
FLAG = "flag{fffffed31f645055f9}"


def _agent(owns: set[str], config: object | None = None, *, with_manager: bool = True):
    """Minimal agent stand-in: only what execute_mcp_tool's routing touches."""

    def get_server_for_tool(name: str):
        return "ctf2-mcp" if name in owns else None

    manager = None
    if with_manager:
        mcp_calls: list[tuple] = []

        async def call_tool(name: str, args: dict):
            mcp_calls.append((name, args))
            return "MCP-SENTINEL"

        manager = SimpleNamespace(
            registry=SimpleNamespace(get_server_for_tool=get_server_for_tool),
            call_tool=call_tool,
        )
    return (
        SimpleNamespace(mcp_manager=manager, config=config),
        mcp_calls if with_manager else [],
    )


def _hidden(*a, **k):
    return False


def _exposed(*a, **k):
    return True


@pytest.fixture()
def no_platform_submit_gate(monkeypatch):
    """The submit tests must not touch the real guard state file."""
    monkeypatch.setattr(
        "vulnclaw.platforms.tools._flag_submission_enabled", lambda: True
    )
    monkeypatch.setattr(
        "vulnclaw.platforms.tools.get_guard",
        lambda: SubmitGuard(state_path=None),
    )


class TestHiddenFaceYieldsToShadowingMcpServer:
    @pytest.mark.asyncio
    async def test_a_non_submit_name_goes_to_the_mcp_manager(self, monkeypatch):
        monkeypatch.setattr(bt, "ctf2_tools_enabled", _hidden)
        agent, mcp_calls = _agent(owns={"ctf2_list_practice"})

        out = await bt.execute_mcp_tool(agent, "ctf2_list_practice", {"limit": 1})

        assert out == "MCP-SENTINEL"
        assert mcp_calls == [("ctf2_list_practice", {"limit": 1})]

    @pytest.mark.asyncio
    async def test_the_gcs_face_yields_the_same_way(self, monkeypatch):
        monkeypatch.setattr(bt, "gcs_tools_enabled", _hidden)
        agent, mcp_calls = _agent(owns={"gcs_overview"})

        out = await bt.execute_mcp_tool(agent, "gcs_overview", {})

        assert out == "MCP-SENTINEL"
        assert mcp_calls == [("gcs_overview", {})]

    @pytest.mark.asyncio
    async def test_the_switch_answers_from_the_runtime_config_object(
        self, monkeypatch
    ):
        """Dispatch agrees with the schema build: same config object, no file read."""
        monkeypatch.setattr(
            "vulnclaw.config.settings.load_config",
            lambda: (_ for _ in ()).throw(RuntimeError("config file exploded")),
        )
        config = SimpleNamespace(
            competition=SimpleNamespace(expose_legacy_tool_names=False)
        )
        agent, mcp_calls = _agent(owns={"ctf2_list_practice"}, config=config)

        out = await bt.execute_mcp_tool(agent, "ctf2_list_practice", {})

        assert out == "MCP-SENTINEL"
        assert mcp_calls


class TestProgrammaticCallersKeepTheBuiltinRoute:
    @pytest.mark.asyncio
    async def test_no_mcp_owner_executes_the_hidden_face(self, monkeypatch):
        """The property CTF_TOOL_NAMES_BY_SCHEMA pins: hiding != breaking."""
        monkeypatch.setattr(bt, "ctf2_tools_enabled", _hidden)
        monkeypatch.setattr(ctf2_tools, "_guard_config", _async_none)

        async def _fake_list(limit=20):
            return {"data": {"items": [], "total": 0}}

        monkeypatch.setattr(ctf2_tools._client, "list_practice", _fake_list)
        agent, mcp_calls = _agent(owns=set())  # registry owns nothing relevant

        out = await bt.execute_mcp_tool(agent, "ctf2_list_practice", {"limit": 1})

        assert "unknown CTF2 tool" not in out
        assert mcp_calls == []

    @pytest.mark.asyncio
    async def test_no_manager_at_all_still_executes(self, monkeypatch):
        monkeypatch.setattr(bt, "ctf2_tools_enabled", _hidden)
        monkeypatch.setattr(ctf2_tools, "_guard_config", _async_none)

        async def _fake_list(limit=20):
            return {"data": {"items": [], "total": 0}}

        monkeypatch.setattr(ctf2_tools._client, "list_practice", _fake_list)
        agent, mcp_calls = _agent(owns=set(), with_manager=False)

        out = await bt.execute_mcp_tool(agent, "ctf2_list_practice", {})

        assert "unknown CTF2 tool" not in out
        assert mcp_calls == []


class TestSubmitYieldsPastTheGate:
    @pytest.fixture()
    def gate_on(self, monkeypatch):
        monkeypatch.setattr(bt, "_flag_submission_enabled", lambda: True)

    @pytest.fixture()
    def gate_off(self, monkeypatch):
        monkeypatch.setattr(bt, "_flag_submission_enabled", lambda: False)

    @pytest.mark.asyncio
    async def test_mcp_vocabulary_submit_executes_on_the_mcp_face(
        self, monkeypatch, gate_on
    ):
        """Operator decision 2026-10-07: the MCP face is the submit executor.

        The model speaks the only schema it was shown (practice_ground_id +
        confirmation) and that schema is the one that runs.
        """
        monkeypatch.setattr(bt, "ctf2_tools_enabled", _hidden)
        agent, mcp_calls = _agent(owns={"ctf2_submit_flag"})

        args = {
            "practice_ground_id": PRACTICE_ID,
            "challenge_id": CHALLENGE_ID,
            "flag": FLAG,
            "confirmation": True,
        }
        out = await bt.execute_mcp_tool(agent, "ctf2_submit_flag", args)

        assert out == "MCP-SENTINEL"
        assert mcp_calls == [("ctf2_submit_flag", args)]

    @pytest.mark.asyncio
    async def test_gate_off_stops_the_submit_before_mcp(self, monkeypatch, gate_off):
        """The master switch is NOT delegated: fail closed, same text as the policy."""
        monkeypatch.setattr(bt, "ctf2_tools_enabled", _hidden)
        agent, mcp_calls = _agent(owns={"ctf2_submit_flag"})

        out = await bt.execute_mcp_tool(
            agent,
            "ctf2_submit_flag",
            {
                "practice_ground_id": PRACTICE_ID,
                "challenge_id": CHALLENGE_ID,
                "flag": FLAG,
                "confirmation": True,
            },
        )

        assert "[platform_submit_disabled]" in out
        assert mcp_calls == []

    @pytest.mark.asyncio
    async def test_no_mcp_owner_submit_crosses_the_shared_policy(
        self, monkeypatch, no_platform_submit_gate
    ):
        """The builtin path survives for programmatic callers: dual vocabulary,
        real policy, adapter called with the ids intact."""
        monkeypatch.setattr(bt, "ctf2_tools_enabled", _hidden)
        agent, mcp_calls = _agent(owns=set())

        seen: dict = {}

        class _FakeAdapter:
            async def submit_flag(self, ref, flag):
                seen["ref"] = ref
                seen["flag"] = flag
                return SimpleNamespace(accepted=True, message="ok", raw={})

        monkeypatch.setattr(
            "vulnclaw.platforms.tools.adapter_for_platform",
            lambda name: _FakeAdapter(),
        )

        out = await bt.execute_mcp_tool(
            agent,
            "ctf2_submit_flag",
            {
                "practice_ground_id": PRACTICE_ID,
                "challenge_id": CHALLENGE_ID,
                "flag": FLAG,
                "confirmation": True,
            },
        )

        assert mcp_calls == []
        assert seen["ref"].group == PRACTICE_ID
        assert seen["ref"].id == CHALLENGE_ID
        assert seen["flag"] == FLAG
        assert "ACCEPTED" in out

    @pytest.mark.asyncio
    async def test_missing_ids_return_an_actionable_error_not_a_keyerror(
        self, monkeypatch, no_platform_submit_gate
    ):
        monkeypatch.setattr(bt, "ctf2_tools_enabled", _hidden)
        agent, mcp_calls = _agent(owns=set())
        monkeypatch.setattr(
            "vulnclaw.platforms.tools.adapter_for_platform",
            lambda name: pytest.fail("adapter must not be built without ids"),
        )

        out = await bt.execute_mcp_tool(
            agent, "ctf2_submit_flag", {"flag": FLAG, "confirmation": True}
        )

        assert "KeyError" not in out
        assert "practice_ground_id" in out
        assert mcp_calls == []


class TestExposedFaceKeepsPrecedence:
    @pytest.mark.asyncio
    async def test_an_exposed_face_still_claims_the_shadowed_name(self, monkeypatch):
        """Both schemas in the model's view: builtin stays authoritative."""
        monkeypatch.setattr(bt, "ctf2_tools_enabled", _exposed)
        monkeypatch.setattr(ctf2_tools, "_guard_config", _async_none)

        async def _fake_list(limit=20):
            return {"data": {"items": [], "total": 0}}

        monkeypatch.setattr(ctf2_tools._client, "list_practice", _fake_list)
        agent, mcp_calls = _agent(owns={"ctf2_list_practice"})

        out = await bt.execute_mcp_tool(agent, "ctf2_list_practice", {})

        assert "unknown CTF2 tool" not in out
        assert mcp_calls == []


async def _async_none():
    return None
