"""The tee sink exists so a finished run leaves a reviewable transcript.

Motivation, measured 2026-11-17 on the oldsvr run: the run's central mistake —
reading a fact in the goal as "the operator knows the password" — appeared only in
the model's own narration. It never reached the blackboard, and the terminal
renderer drops thinking unless ``show_thinking`` is on. With nothing captured, the
only reviewable trace was a hand-redirected stdout.

Two properties matter more than the plumbing:

* thinking is written **regardless** of the wrapped sink's display preference —
  the terminal honours a UI setting, an audit trail must not;
* the file is usable **when the run dies badly**. A budget kill is the case worth
  reviewing, so every event flushes immediately and ``close`` is called on all
  exit paths.
"""

from __future__ import annotations

from pathlib import Path

from vulnclaw.cli._helpers import TeeStreamSink


class _RecordingSink:
    """Wraps the sink protocol and remembers what it was told."""

    def __init__(self, *, show_thinking: bool = True) -> None:
        self.show_thinking = show_thinking
        self.events: list[tuple[str, tuple]] = []

    def on_status(self, message: str) -> None:
        self.events.append(("status", (message,)))

    def on_thinking_token(self, token: str) -> None:
        self.events.append(("thinking", (token,)))

    def on_content_token(self, token: str) -> None:
        self.events.append(("content", (token,)))

    def on_tool_call(self, name: str, args: str) -> None:
        self.events.append(("tool_call", (name, args)))

    def on_tool_result(self, result: str) -> None:
        self.events.append(("tool_result", (result,)))

    def on_notice(self, message: str) -> None:
        self.events.append(("notice", (message,)))

    def on_stream_end(self) -> None:
        self.events.append(("stream_end", ()))


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_events_reach_both_sides(tmp_path):
    inner = _RecordingSink()
    out = tmp_path / "run.log"
    sink = TeeStreamSink(inner, out)

    sink.on_status("Thinking...")
    sink.on_tool_call("fetch", '{"url":"http://t/"}')
    sink.on_tool_result("[+] ok")
    sink.close()

    assert ("status", ("Thinking...",)) in inner.events
    assert ("tool_call", ("fetch", '{"url":"http://t/"}')) in inner.events
    text = _read(out)
    assert "[status] Thinking..." in text
    assert "fetch" in text
    assert "[+] ok" in text


def test_thinking_is_recorded_even_when_the_terminal_hides_it(tmp_path):
    """The wrapped sink has show_thinking=False; the file must not care."""
    inner = _RecordingSink(show_thinking=False)
    out = tmp_path / "run.log"
    sink = TeeStreamSink(inner, out)

    sink.on_thinking_token("the operator knows ")
    sink.on_thinking_token("the password")
    sink.on_stream_end()
    sink.close()

    text = _read(out)
    assert "the operator knows the password" in text
    assert "<thinking>" in text


def test_thinking_does_not_bleed_into_content(tmp_path):
    inner = _RecordingSink()
    out = tmp_path / "run.log"
    sink = TeeStreamSink(inner, out)

    sink.on_thinking_token("private reasoning")
    sink.on_content_token("public answer")
    sink.on_stream_end()
    sink.close()

    text = _read(out)
    # The thinking block closes before the answer text appears.
    assert text.index("</thinking>") < text.index("public answer")


def test_file_is_usable_when_the_run_is_killed(tmp_path):
    """No close() — simulating a budget kill — must still leave the tail."""
    inner = _RecordingSink()
    out = tmp_path / "run.log"
    sink = TeeStreamSink(inner, out)

    sink.on_thinking_token("about to die")
    sink.on_tool_call("python_execute", '{"code":"x"}')

    # Deliberately no close(): each event flushed on its own.
    text = _read(out)
    assert "about to die" in text
    assert "python_execute" in text


def test_tool_args_are_truncated_in_the_file(tmp_path):
    inner = _RecordingSink()
    out = tmp_path / "run.log"
    sink = TeeStreamSink(inner, out)

    sink.on_tool_call("shell_command", "x" * 2000)
    sink.close()

    line = next(l for l in _read(out).splitlines() if "shell_command" in l)
    assert len(line) < 600


def test_unwritable_path_never_breaks_the_run(tmp_path):
    """An audit convenience must not take a solve down."""
    inner = _RecordingSink()
    # A directory where a file is expected: open() raises.
    blocked = tmp_path / "adir"
    blocked.mkdir()

    sink = TeeStreamSink(inner, blocked)

    sink.on_status("still works")
    sink.on_tool_call("fetch", "{}")
    sink.close()

    assert ("status", ("still works",)) in inner.events


def test_broken_inner_sink_does_not_stop_the_file(tmp_path):
    class _Exploding:
        def on_status(self, message):
            raise RuntimeError("renderer died")

        def on_tool_call(self, name, args):
            raise RuntimeError("renderer died")

    out = tmp_path / "run.log"
    sink = TeeStreamSink(_Exploding(), out)

    sink.on_status("after the crash")
    sink.on_tool_call("fetch", "{}")
    sink.close()

    text = _read(out)
    assert "after the crash" in text
    assert "fetch" in text


def test_unknown_methods_fall_through_to_the_inner_sink(tmp_path):
    class _WithExtra:
        def on_interrupt(self, reason):
            self.seen = reason

    inner = _WithExtra()
    sink = TeeStreamSink(inner, tmp_path / "run.log")

    sink.on_interrupt("operator pressed Ctrl-C")

    assert inner.seen == "operator pressed Ctrl-C"


def test_close_is_idempotent(tmp_path):
    sink = TeeStreamSink(_RecordingSink(), tmp_path / "run.log")

    sink.on_status("once")
    sink.close()
    sink.close()  # must not raise

    assert "once" in _read(tmp_path / "run.log")


def test_parent_directory_is_created(tmp_path):
    out = tmp_path / "nested" / "deeper" / "run.log"
    sink = TeeStreamSink(_RecordingSink(), out)

    sink.on_status("hi")
    sink.close()

    assert out.is_file()