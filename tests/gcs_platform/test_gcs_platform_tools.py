import pytest

from vulnclaw.gcs_platform import (
    GCS_READ_TOOLS,
    GCS_TOOL_NAMES,
    api_base_url,
    dispatch_gcs_tool,
    gcs_tool_schemas,
)
from vulnclaw.gcs_platform import tools as gcs_tools
from vulnclaw.gcs_platform import client as gcs_client
from vulnclaw.gcs_platform.client import GCSError, _unwrap


def test_schemas_expose_submit_flag_and_env_lifecycle():
    names = {s["function"]["name"] for s in gcs_tool_schemas()}
    assert {"gcs_submit_flag", "gcs_build_env", "gcs_recover_env"} <= names


def test_tool_names_match_schemas():
    schema_names = {s["function"]["name"] for s in gcs_tool_schemas()}
    assert schema_names == set(GCS_TOOL_NAMES)


def test_read_tools_subset_of_names():
    assert GCS_READ_TOOLS <= set(GCS_TOOL_NAMES)


def test_defaults_point_at_gcsis(monkeypatch):
    monkeypatch.delenv("VULNCLAW_GCS_BASE_URL", raising=False)
    monkeypatch.delenv("VULNCLAW_GCS_ACCESS_KEY", raising=False)
    assert api_base_url() == "https://gcsis.dasctf.com"
    assert gcs_client.is_configured() is False


def test_access_key_read_from_env(monkeypatch):
    monkeypatch.setenv("VULNCLAW_GCS_ACCESS_KEY", "ak_test")
    assert gcs_client.access_key() == "ak_test"
    assert gcs_client.is_configured() is True


def test_unwrap_ok():
    out = _unwrap({"code": "00000", "message": "", "data": {"isCorrect": True}})
    assert out == {"isCorrect": True}


def test_unwrap_non_success_raises():
    with pytest.raises(GCSError) as err:
        _unwrap({"code": "40301", "message": "denied", "data": None})
    assert err.value.code == "40301"


@pytest.mark.asyncio
async def test_dispatch_unknown_tool_returns_structured_error():
    out = await dispatch_gcs_tool("gcs_nope", {})
    assert "[gcs_error]" in out


@pytest.mark.asyncio
async def test_dispatch_config_guard_message(monkeypatch):
    monkeypatch.setattr(gcs_tools._client, "is_configured", lambda: False)
    out = await dispatch_gcs_tool("gcs_match_info", {})
    assert "[gcs_config]" in out


@pytest.mark.asyncio
async def test_dispatch_routes_to_registered_handler(monkeypatch):
    async def fake(args):
        return "ROUTED:" + args.get("flag", "")

    monkeypatch.setitem(gcs_tools._HANDLERS, "gcs_submit_flag", fake)
    out = await dispatch_gcs_tool(
        "gcs_submit_flag", {"exercise_id": 1001, "flag": "flag{abc}"}
    )
    assert out == "ROUTED:flag{abc}"


@pytest.mark.asyncio
async def test_submit_flag_records_accepted(monkeypatch):
    monkeypatch.setattr(gcs_tools, "_get_submit_guard", _FakeGuard)
    monkeypatch.setenv("VULNCLAW_GCS_ACCESS_KEY", "ak_test")
    calls = {}

    async def fake_submit(exercise_id, flag):
        calls["submitted"] = (exercise_id, flag)
        return {"code": "00000", "data": {"isCorrect": True}}

    monkeypatch.setattr(gcs_client, "submit_answer", fake_submit)
    out = await dispatch_gcs_tool(
        "gcs_submit_flag", {"exercise_id": 1001, "flag": "flag{abc}"}
    )
    assert calls["submitted"] == (1001, "flag{abc}")
    assert _FakeGuard.records[-1][2] is True
    assert '"isCorrect": true' in out


@pytest.mark.asyncio
async def test_submit_flag_escalates_to_confirmation(monkeypatch):
    class DenyGuard:
        @staticmethod
        def allow(ex, cid, flag):
            return False, "after automatic attempts this challenge requires human confirmation"

        @staticmethod
        def record(ex, cid, accepted, flag):
            pass

    monkeypatch.setattr(gcs_tools, "_get_submit_guard", lambda: DenyGuard())
    monkeypatch.setenv("VULNCLAW_GCS_ACCESS_KEY", "ak_test")
    out = await dispatch_gcs_tool(
        "gcs_submit_flag", {"exercise_id": 1001, "flag": "flag{abc}"}
    )
    assert "[gcs_confirm]" not in out
    assert "[ctf2_confirm]" in out


@pytest.mark.asyncio
async def test_build_env_runs(monkeypatch):
    monkeypatch.setenv("VULNCLAW_GCS_ACCESS_KEY", "ak_test")
    calls = {}

    async def fake_build(exercise_id):
        calls["built"] = exercise_id
        return {"code": "00000", "data": {}}

    monkeypatch.setattr(gcs_client, "build_environment", fake_build)
    out = await dispatch_gcs_tool("gcs_build_env", {"exercise_id": 1001})
    assert calls["built"] == 1001
    assert "[gcs_error]" not in out


@pytest.mark.asyncio
async def test_recover_env_runs(monkeypatch):
    monkeypatch.setenv("VULNCLAW_GCS_ACCESS_KEY", "ak_test")
    calls = {}

    async def fake_recover(exercise_id):
        calls["recovered"] = exercise_id
        return {"code": "00000", "data": {}}

    monkeypatch.setattr(gcs_client, "recover_environment", fake_recover)
    out = await dispatch_gcs_tool("gcs_recover_env", {"exercise_id": 1001})
    assert calls["recovered"] == 1001


@pytest.mark.asyncio
async def test_exercise_ready_poll_returns_when_ready(monkeypatch):
    async def ready(exercise_id):
        return {"code": "00000", "data": {"isNeedCheck": False, "endpoints": []}}

    monkeypatch.setattr(gcs_client, "exercise", ready)
    out = await gcs_tools.exercise_ready_poll(1001, timeout=2.0)
    assert "isNeedCheck" in out


class _FakeGuard:
    records: list = []

    @staticmethod
    def allow(practice_id, challenge_id, flag):
        return True, ""

    @staticmethod
    def record(practice_id, challenge_id, accepted, flag):
        _FakeGuard.records.append((practice_id, challenge_id, accepted, flag))