"""The path-stall guard must be visible to the OPERATOR, not only to the model.

A guard whose whole purpose is to change a run's course is useless if the operator
cannot tell it intervened: an interrupted run then looks identical to one that is
simply stuck. That is what a measured stall looked like -- 15 minutes, 53 tool
results, and no visible signal of any kind, because the hint went into the agent's
prompt and `emit()` is only wired under `--stream` (the CLI passes
``on_event=None`` otherwise).

Two halves are pinned here:
  * the solver-side plumbing (`_notify_operator`) reaches a sink that can render;
  * both sinks actually render a notice through their own transport.
"""

from __future__ import annotations

import io
import json

import pytest
from rich.console import Console

from vulnclaw.agent.solver import _notify_operator
from vulnclaw.cli._helpers import JsonlStreamSink, TerminalStreamSink


class _RecordingSink:
    def __init__(self) -> None:
        self.notices: list[str] = []

    def on_notice(self, message: str) -> None:
        self.notices.append(message)


class _BrokenSink:
    def on_notice(self, message: str) -> None:
        raise RuntimeError("renderer exploded")


class TestNotifyOperator:
    def test_a_sink_that_can_render_gets_the_message(self):
        sink = _RecordingSink()
        _notify_operator(sink, "[stall guard] try a different angle")
        assert sink.notices == ["[stall guard] try a different angle"]

    @pytest.mark.parametrize("sink", [None, object(), "not-a-sink"])
    def test_a_sink_without_the_method_is_ignored(self, sink):
        """The solver must not require every sink to implement notices."""
        _notify_operator(sink, "anything")

    def test_a_raising_renderer_never_breaks_the_solve(self):
        """Rendering is best-effort; the guard must still work without it."""
        _notify_operator(_BrokenSink(), "anything")


class TestTerminalSinkRendersNotices:
    def test_notice_reaches_the_console(self):
        output = io.StringIO()
        sink = TerminalStreamSink(
            Console(file=output, force_terminal=True), show_thinking=False
        )

        sink.on_notice("[stall guard] Path stall: try a DIFFERENT angle")
        sink.on_stream_end()

        rendered = output.getvalue()
        assert "stall guard" in rendered
        assert "DIFFERENT angle" in rendered

    def test_a_notice_mid_stream_starts_its_own_line(self):
        """Otherwise the note runs into the model's text and reads as its output."""
        output = io.StringIO()
        sink = TerminalStreamSink(
            Console(file=output, force_terminal=True), show_thinking=False
        )

        sink.on_content_token("partial model text")
        sink.on_notice("[stall guard] note")
        sink.on_stream_end()

        rendered = output.getvalue()
        assert "partial model text" in rendered
        assert "\n" in rendered.split("partial model text", 1)[1]


class TestJsonlSinkRendersNotices:
    def _events(self, stream: io.StringIO) -> list[dict]:
        return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]

    def test_notice_is_emitted_as_a_log_line(self):
        stream = io.StringIO()
        sink = JsonlStreamSink(stream, show_thinking=False)

        sink.on_notice("[stall guard] Path stall: try a DIFFERENT angle")

        events = self._events(stream)
        assert events == [
            {"type": "log", "message": "[stall guard] Path stall: try a DIFFERENT angle"}
        ]

    def test_buffered_content_is_flushed_before_the_notice(self):
        """The TUI protocol is ordered, so the note must not overtake pending text."""
        stream = io.StringIO()
        sink = JsonlStreamSink(stream, show_thinking=False)

        sink.on_content_token("model text")
        sink.on_notice("[stall guard] note")

        events = self._events(stream)
        assert [event["type"] for event in events] == ["log", "log"]
        assert events[0]["message"] == "model text"
        assert events[1]["message"] == "[stall guard] note"
