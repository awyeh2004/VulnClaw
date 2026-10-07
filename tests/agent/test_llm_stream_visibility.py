"""round13 follow-up (2026-10-06 field feedback): live tool-event visibility in
non-streaming auto runs, and the streaming watchdog.

Field report that motivated this: with ``disable_streaming`` on, the operator's
plain terminal showed NOTHING while the agent worked (the non-streaming body
never emitted tool events; the sink only got the final text at end of turn),
and the flag-accepted line landed ~60s after the platform had it. And on a
streaming run, a gateway stall used to idle the turn for 10-40 minutes because
nothing bounded the wait for the next chunk.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import vulnclaw.agent.llm_client as mod
from vulnclaw.agent.llm_client import (
    _ChunkWatchdog,
    _StreamStalled,
    _stream_timeouts,
)


class _RecordingSink:
    def __init__(self):
        self.tool_calls: list[tuple] = []
        self.tool_results: list[str] = []
        self.content: list[str] = []
        self.ended = 0

    def on_status(self, message: str) -> None:
        pass

    def on_thinking_token(self, token: str) -> None:
        pass

    def on_content_token(self, token: str) -> None:
        self.content.append(token)

    def on_tool_call(self, tool_name: str, args: str) -> None:
        self.tool_calls.append((tool_name, args))

    def on_tool_result(self, result_summary: str) -> None:
        self.tool_results.append(result_summary)

    def on_stream_end(self) -> None:
        self.ended += 1


class TestNonstreamToolEventPassthrough:
    """disable_streaming must not blind the terminal: tool calls and results
    stream to the sink live, per round, exactly like the streaming path."""

    def _agent(self, disable=True):
        agent = SimpleNamespace(config=SimpleNamespace(session=SimpleNamespace(disable_streaming=disable)))
        return agent

    @pytest.mark.asyncio
    async def test_tool_events_reach_the_sink_before_the_final_replay(self, monkeypatch):
        message = SimpleNamespace(
            content="calling the platform",
            tool_calls=[SimpleNamespace(function=SimpleNamespace(name="platform_submit", arguments='{"flag": "x"}'))],
        )
        response = SimpleNamespace(choices=[SimpleNamespace(message=message)])
        monkeypatch.setattr(mod, "_build_tool_loop_messages",
                            lambda agent, sp, rc, include_history: ([{"role": "system", "content": sp}], {}))
        monkeypatch.setattr(mod, "build_chat_completion_kwargs", lambda agent, m, t: {})
        monkeypatch.setattr(mod, "_fit_context_window", lambda agent, m, t, purpose: m)
        monkeypatch.setattr(mod, "_fit_tool_loop_context", lambda agent, m, rm: m)
        monkeypatch.setattr(mod, "_apply_repetition_guard", lambda agent, t, detected_count=0: t)
        monkeypatch.setattr(mod, "_resolve_auto_tool_rounds", lambda agent, cap: 0)

        async def fake_retries(agent, factory, label, **kwargs):
            return response, 0

        monkeypatch.setattr(mod, "_call_with_persistent_retries", fake_retries)

        tool_call_obj = SimpleNamespace(function=SimpleNamespace(name="platform_submit", arguments="{}"))
        async def fake_handle(agent, message):
            return [{"tool_call": None, "content": "[platform] flag ACCEPTED"}], []

        monkeypatch.setattr(mod, "handle_tool_calls_with_results", fake_handle)

        sink = _RecordingSink()
        agent = self._agent(disable=True)
        agent._build_openai_tools = lambda: []
        result = await mod.call_llm_auto(agent, "sys", "ctx", stream_sink=sink)

        assert "ACCEPTED" in result
        assert ("platform_submit", '{"flag": "x"}') in sink.tool_calls
        assert any("ACCEPTED" in r for r in sink.tool_results)
        assert any("calling the platform" in c for c in sink.content), sink.content
        assert sink.ended >= 1

    @pytest.mark.asyncio
    async def test_streaming_path_untouched_when_not_disabled(self, monkeypatch):
        async def fake_auto_stream(agent, sp, rc, sink, include_history=True, max_tool_rounds=None):
            return "streamed"

        monkeypatch.setattr(mod, "call_llm_auto_stream", fake_auto_stream)
        agent = self._agent(disable=False)
        assert await mod.call_llm_auto(agent, "sys", "ctx", stream_sink=_RecordingSink()) == "streamed"


class TestStreamWatchdog:
    def test_timeouts_read_from_runtime_config_with_floors(self):
        agent = SimpleNamespace(config=SimpleNamespace(session=SimpleNamespace(
            llm_first_token_timeout_s=5, llm_inter_chunk_timeout_s=3)))
        # floors: below 10s clamps to 10 so a misconfig cannot busy-loop
        assert _stream_timeouts(agent) == (10.0, 10.0)
        agent2 = SimpleNamespace(config=SimpleNamespace(session=SimpleNamespace(
            llm_first_token_timeout_s=90, llm_inter_chunk_timeout_s=45)))
        assert _stream_timeouts(agent2) == (90.0, 45.0)

    def _stream(self, chunks, hang_after=None, hang_forever=False):
        class _S:
            def __init__(self):
                self._it = iter(chunks)
                self._hung = False

            def __aiter__(self):
                return self

            async def __anext__(self):
                if hang_forever:
                    await asyncio.sleep(3600)
                if hang_after is not None and self._hung:
                    await asyncio.sleep(3600)
                try:
                    item = next(self._it)
                except StopIteration:
                    raise StopAsyncIteration from None
                if hang_after is not None and item == hang_after:
                    self._hung = True
                return item

        return _S()

    @pytest.mark.asyncio
    async def test_first_token_stall_raises_within_budget(self):
        wd = _ChunkWatchdog(self._stream([], hang_forever=True), first_timeout_s=0.05, inter_chunk_s=0.05)
        with pytest.raises(_StreamStalled, match="first token"):
            await wd.__anext__()

    @pytest.mark.asyncio
    async def test_inter_chunk_stall_raises_after_first_chunk(self):
        wd = _ChunkWatchdog(self._stream(["a"], hang_after="a"), first_timeout_s=0.05, inter_chunk_s=0.05)
        assert await wd.__anext__() == "a"
        with pytest.raises(_StreamStalled, match="inter-chunk"):
            await wd.__anext__()

    @pytest.mark.asyncio
    async def test_healthy_stream_passes_through(self):
        wd = _ChunkWatchdog(self._stream(["a", "b", "c"]), first_timeout_s=1, inter_chunk_s=1)
        got = []
        async for chunk in wd:
            got.append(chunk)
        assert got == ["a", "b", "c"]

    @pytest.mark.asyncio
    async def test_stall_closes_the_underlying_stream(self):
        """Round15b (2026-10-07) postmortem: a stall raised ``_StreamStalled``
        from inside the caller's ``async for`` and neither streaming caller
        closed the response afterwards (one falls back to non-streaming, the
        other re-raises for its dispatcher), so the abandoned transport stayed
        alive for ~10 minutes. The watchdog now closes it on the way out.
        """
        closed = {"n": 0}

        class _Closable:
            def __aiter__(self):
                return self

            async def __anext__(self):
                await asyncio.sleep(3600)

            async def aclose(self):
                closed["n"] += 1

        wd = _ChunkWatchdog(_Closable(), first_timeout_s=0.05, inter_chunk_s=0.05)
        with pytest.raises(_StreamStalled, match="first token"):
            await wd.__anext__()
        assert closed["n"] == 1, "the stalled stream must be closed before unwinding"

    @pytest.mark.asyncio
    async def test_auto_stream_stall_falls_back_to_nonstream_without_pingpong(self, monkeypatch):
        """A deterministic stall must finish the turn non-streaming ONCE —
        auto_stream re-raises _StreamStalled instead of recursing into
        call_llm_auto (which would re-enter streaming forever)."""
        calls = {"stream": 0, "nonstream": 0}

        async def stalled_stream(*a, **k):
            calls["stream"] += 1
            raise _StreamStalled("streaming stalled: no first token within 120s")

        async def fake_nonstream(
            agent, sp, rc, *, stream_sink=None, include_history=True, max_tool_rounds=None, hard=False
        ):
            calls["nonstream"] += 1
            assert stream_sink is sink
            assert hard is True, "a stream-stall fallback must hard-compact the payload"
            return "nonstream answer"

        monkeypatch.setattr(mod, "call_llm_auto_stream", stalled_stream)
        monkeypatch.setattr(mod, "_call_llm_auto_nonstream", fake_nonstream)

        agent = SimpleNamespace(config=SimpleNamespace(session=SimpleNamespace(disable_streaming=False)))
        sink = _RecordingSink()
        result = await mod.call_llm_auto(agent, "sys", "ctx", stream_sink=sink)

        assert result == "nonstream answer"
        assert calls["stream"] == 1, "exactly one streaming attempt, no ping-pong"
        assert calls["nonstream"] == 1


import asyncio  # noqa: E402  (placed last to keep the import section header clean)
