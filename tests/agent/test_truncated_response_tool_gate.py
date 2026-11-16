"""A response cut at the output-token limit must not execute any of its tool calls.

The failure this guards against is subtle: a stream truncated mid-generation can
still close its JSON, so the provider hands back a syntactically valid tool call
whose arguments are semantically incomplete (a target list cut short, a command
missing its trailing flags). Running it issues half an operation against a live
target. The whole batch is therefore refused and the ids get matching refusal
messages, because OpenAI-style tool calling requires one ``role=tool`` message
per requested id.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent import llm_client
from vulnclaw.agent.tool_call_manager import (
    TRUNCATED_TOOL_CALL_MESSAGE,
    handle_tool_calls,
    handle_tool_calls_with_results,
    response_was_output_truncated,
)


class _Func:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class _ToolCall:
    def __init__(self, call_id: str, name: str, arguments: str) -> None:
        self.id = call_id
        self.function = _Func(name, arguments)


class _Safety:
    tool_parallel = True
    tool_max_concurrent = 5


class _Config:
    safety = _Safety()


class _Agent:
    """Agent stub that fails the test if any tool is actually executed."""

    def __init__(self) -> None:
        from vulnclaw.agent.context import ContextManager
        from vulnclaw.agent.subagent.models import SubagentContext

        self.context = ContextManager()
        self.mcp_manager = None
        self.config = _Config()
        self.executed: list[str] = []
        self._subagent_ctx = SubagentContext()

    async def _execute_mcp_tool(self, func_name, func_args):
        self.executed.append(func_name)
        return "should not run"


def _message(finish_reason: str | None) -> SimpleNamespace:
    calls = [
        _ToolCall("c0", "shell_command", '{"command":"nmap -p 1-1000 10.0.0."}'),
        _ToolCall("c1", "http_probe", '{"url":"http://target.local/admin"}'),
    ]
    return SimpleNamespace(content="", tool_calls=calls, finish_reason=finish_reason)


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["length", "max_tokens", "max_output_tokens", "LENGTH"])
async def test_truncated_response_refuses_every_tool_call(reason: str):
    agent = _Agent()

    results, skipped = await handle_tool_calls_with_results(agent, _message(reason))

    assert agent.executed == [], "a truncated response must not execute anything"
    assert [r["tool_call_id"] for r in results] == ["c0", "c1"]
    for result in results:
        assert TRUNCATED_TOOL_CALL_MESSAGE in result["content"]
    assert skipped == [TRUNCATED_TOOL_CALL_MESSAGE]


@pytest.mark.asyncio
async def test_truncated_refusal_keeps_one_response_per_requested_id():
    """Dropping the ids would make the follow-up request malformed, not just empty."""

    agent = _Agent()

    results, _ = await handle_tool_calls_with_results(agent, _message("length"))

    assert len(results) == 2
    assert {r["tool_call_id"] for r in results} == {"c0", "c1"}
    assert agent.executed == []


@pytest.mark.asyncio
async def test_legacy_handler_also_refuses_truncated_batch():
    agent = _Agent()

    output = await handle_tool_calls(agent, _message("length"))

    assert agent.executed == []
    assert output.count(TRUNCATED_TOOL_CALL_MESSAGE) == 2


@pytest.mark.asyncio
async def test_complete_response_still_executes():
    agent = _Agent()

    results, skipped = await handle_tool_calls_with_results(agent, _message("tool_calls"))

    assert agent.executed == ["shell_command", "http_probe"]
    assert skipped == []
    assert len(results) == 2


@pytest.mark.asyncio
async def test_missing_finish_reason_is_not_treated_as_truncation():
    """Hand-built messages (subagents, tests) carry no flag and must keep working."""

    agent = _Agent()

    results, _ = await handle_tool_calls_with_results(agent, _message(None))

    assert agent.executed == ["shell_command", "http_probe"]
    assert len(results) == 2


def test_response_was_output_truncated_ignores_other_stop_reasons():
    assert response_was_output_truncated(_message("length")) is True
    assert response_was_output_truncated(_message("stop")) is False
    assert response_was_output_truncated(_message("tool_calls")) is False
    assert response_was_output_truncated(_message(None)) is False
    # A malformed flag must not crash the gate.
    assert response_was_output_truncated(SimpleNamespace(tool_calls=[])) is False


def test_stamp_finish_reason_copies_from_choice():
    message = SimpleNamespace(content="", tool_calls=[])

    llm_client._stamp_finish_reason(message, SimpleNamespace(finish_reason="length"))

    assert message.finish_reason == "length"


def test_stamp_finish_reason_survives_a_read_only_message():
    """SDK message models can reject unknown attributes; the stamp must not raise."""

    class _Frozen:
        @property
        def finish_reason(self):  # noqa: D401 - read-only by construction
            return ""

        def __setattr__(self, name, value):
            raise ValueError("model is frozen")

    llm_client._stamp_finish_reason(_Frozen(), SimpleNamespace(finish_reason="length"))


def test_stamp_finish_reason_noop_when_provider_sends_nothing():
    message = SimpleNamespace(content="", tool_calls=[])

    llm_client._stamp_finish_reason(message, SimpleNamespace(finish_reason=None))

    assert not hasattr(message, "finish_reason")