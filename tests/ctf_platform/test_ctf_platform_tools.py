import pytest

from vulnclaw.ctf_platform import (
    CTF_TOOL_NAMES,
    CTF_READ_TOOLS,
    ctf2_tool_schemas,
    dispatch_ctf2_tool,
)
from vulnclaw.ctf_platform import tools as ctf_tools
from vulnclaw.ctf_platform.client import (
    api_base_url,
    api_token,
    is_configured,
)


def test_schemas_expose_submit_flag():
    names = {s["function"]["name"] for s in ctf2_tool_schemas()}
    assert "ctf2_submit_flag" in names


def test_tool_names_match_schemas():
    schema_names = {s["function"]["name"] for s in ctf2_tool_schemas()}
    assert schema_names == set(CTF_TOOL_NAMES)


def test_read_tools_subset_of_names():
    assert CTF_READ_TOOLS <= set(CTF_TOOL_NAMES)


def test_defaults_point_at_public_ctf2(monkeypatch):
    monkeypatch.delenv("VULNCLAW_CTF2_BASE_URL", raising=False)
    monkeypatch.delenv("VULNCLAW_CTF2_API_KEY", raising=False)
    monkeypatch.delenv("VULNCLAW_CTF2_SESSION_TOKEN", raising=False)
    monkeypatch.setattr(
        "vulnclaw.ctf_platform.session.read_edge_session_token", lambda: ""
    )
    assert api_base_url() == "https://ctf2.dasctf.com"
    assert api_token() == ""
    assert is_configured() is False


def test_token_read_from_env(monkeypatch):
    monkeypatch.setenv("VULNCLAW_CTF2_API_KEY", "pat_123")
    assert api_token() == "pat_123"
    assert is_configured() is True


@pytest.mark.asyncio
async def test_dispatch_unknown_tool_returns_structured_error():
    out = await dispatch_ctf2_tool("ctf2_nope", {})
    assert "[ctf2_error]" in out


@pytest.mark.asyncio
async def test_dispatch_config_guard_message(monkeypatch):
    monkeypatch.setattr(ctf_tools._client, "is_configured", lambda: False)
    out = await dispatch_ctf2_tool("ctf2_list_practice", {})
    assert "[ctf2_config]" in out


@pytest.mark.asyncio
async def test_dispatch_routes_to_registered_handler(monkeypatch):
    async def fake(args):
        return "ROUTED:" + args.get("flag", "")

    monkeypatch.setitem(ctf_tools._HANDLERS, "ctf2_submit_flag", fake)
    out = await dispatch_ctf2_tool(
        "ctf2_submit_flag",
        {"practice_id": "p1", "challenge_id": "c1", "flag": "flag{abc}"},
    )
    assert out == "ROUTED:flag{abc}"