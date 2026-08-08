"""Tests for the single-response self-repetition guard in llm_client.

The guard detects a model repeating the same reasoning block verbatim within
one LLM response (no new evidence / tool calls), truncates the duplicated tail
so only the first copy survives, and injects a guard notice into context so the
next model call converges instead of re-running the same analysis.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from vulnclaw.agent.llm_client import (
    _apply_repetition_guard,
    _self_repetition_cut,
)

REPEATED_BLOCK = """Actually, let me reconsider. Maybe the code is:
```php
$password = $_GET['password'];
if ($password == $flag) {
    echo $flag;
} else {
    echo "password is wrong: " . $password;
}
```
And when $password is an array, $password == $flag.
But we see empty. Unless the array-to-string conversion works.
Let me try a different approach. Let me test the runtime diff probe now.
"""


def _repeated_response(copies: int) -> str:
    prefix = (
        "The array returned empty reflection, which is a strong signal. "
        "Let me think about what the correct password might be.\n\n"
    )
    return prefix + "\n\n".join(REPEATED_BLOCK.strip() for _ in range(copies))


class TestSelfRepetitionCut:
    def test_detects_single_response_repetition(self):
        text = _repeated_response(16)
        cut = _self_repetition_cut(text)
        assert cut is not None
        cut_line, count = cut
        assert count >= 3
        kept = text.splitlines()[:cut_line]
        assert len(kept) < len(text.splitlines())

    def test_keeps_first_copy(self):
        text = _repeated_response(5)
        cut = _self_repetition_cut(text)
        assert cut is not None
        cut_line, _ = cut
        kept = "\n".join(text.splitlines()[:cut_line])
        assert kept.count(REPEATED_BLOCK.strip()) >= 1

    def test_no_false_positive_on_normal_text(self):
        normal = (
            "First line about the target.\n"
            + "\n".join(f"fact {i}: nothing suspicious in this line" for i in range(40))
            + "\nFinal conclusion grounded in evidence e001."
        )
        assert _self_repetition_cut(normal) is None

    def test_no_false_positive_when_code_quoted_twice(self):
        code = "Here is the source:\n```php\n$flag = 'x';\nif ($a == $flag) {}\n```\n"
        text = code + "We also quote it once more below for reference:\n" + code
        assert _self_repetition_cut(text) is None

    def test_short_repeat_is_ignored(self):
        assert _self_repetition_cut("Done.\nDone.\nDone.\nDone.\nDone.") is None

    def test_empty_and_short_text(self):
        assert _self_repetition_cut("") is None
        assert _self_repetition_cut("short") is None


class TestApplyRepetitionGuard:
    def test_truncates_and_appends_notice(self):
        agent = MagicMock()
        agent.context.add_message = MagicMock()
        text = _repeated_response(10)
        result = _apply_repetition_guard(agent, text)
        assert "runtime diff probe" in result
        # Only the first copy survives: the duplicate tail is gone.
        assert result.count(REPEATED_BLOCK.strip()) == 1
        assert len(result) < len(text)
        assert agent.context.add_message.called
        call_args = agent.context.add_message.call_args[0][0]
        assert call_args["role"] == "user"
        assert "Repetition guard" in call_args["content"]

    def test_passthrough_when_no_repetition(self):
        agent = MagicMock()
        agent.context.add_message = MagicMock()
        text = "A normal, non-repeating response for the target."
        result = _apply_repetition_guard(agent, text)
        assert result == text
        assert not agent.context.add_message.called

    def test_uses_passed_detected_count(self):
        agent = MagicMock()
        agent.context.add_message = MagicMock()
        result = _apply_repetition_guard(agent, "short", detected_count=4)
        assert result == "short"
        assert agent.context.add_message.called
        call_args = agent.context.add_message.call_args[0][0]
        assert "4 times" in call_args["content"]


class TestStreamingAbort:
    def test_stream_breaks_on_repetition(self):
        import asyncio

        from vulnclaw.agent.llm_client import _stream_chat_completion_message

        class MockDelta:
            def __init__(self, content=""):
                self.content = content
                self.reasoning_content = ""

        class MockChoice:
            def __init__(self, content=""):
                self.delta = MockDelta(content)

        class MockChunk:
            def __init__(self, content=""):
                self.choices = [MockChoice(content)]

        class MockAsyncStream:
            def __init__(self, chunks):
                self._chunks = chunks

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self._chunks:
                    return self._chunks.pop(0)
                raise StopAsyncIteration

        full = _repeated_response(12)
        # Stream one line at a time so repetition grows as it would live.
        chunks = [MockChunk(line + "\n") for line in full.splitlines()]

        agent = MagicMock()
        agent._get_client.return_value.chat.completions.create.return_value = (
            MockAsyncStream(chunks)
        )
        agent.config.llm.provider = "openai"
        agent.config.llm.model = "gpt-4"
        agent.config.llm.max_tokens = None
        agent.config.llm.temperature = None

        class Sink:
            def on_status(self, m):
                pass

            def on_thinking_token(self, t):
                pass

            def on_content_token(self, t):
                pass

            def on_tool_call(self, n, a):
                pass

            def on_tool_result(self, r):
                pass

            def on_stream_end(self):
                pass

        message = asyncio.run(
            _stream_chat_completion_message(agent, [{"role": "user", "content": "x"}], [], Sink())
        )
        assert getattr(message, "repetition_count", 0) >= 3
        body = message.content or ""
        assert body.count(REPEATED_BLOCK.strip()) == 1
