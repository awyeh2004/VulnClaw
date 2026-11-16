"""A failed tool's diagnosis lives at the end of its output; the preview must keep more of it.

Measured failure mode this pins down: a symmetric head/tail split over a long
traceback or shell log gives the tail only half the budget, so the last lines --
exit status, the frames immediately before the failure, an unterminated progress
bar -- fall outside it. The model then sees a truncated log whose reason is gone
and cannot correct the call.

``clip_text`` always keeps both ends; what ``ok=False`` changes is the **share**
of the budget the tail gets (``_FAILED_PREVIEW_HEAD_RATIO``). These tests
therefore measure how many trailing bytes survive, not whether any tail does.

Also pinned here: the assembled preview must respect ``limit``. It used to leak
past it whenever no signal line matched, because only the body was clipped and
the header was not counted.
"""

from __future__ import annotations

from vulnclaw.agent.agent_state import (
    AgentState,
    _FAILED_PREVIEW_HEAD_RATIO,
    clip_text,
    make_evidence_preview,
)

#: Written last and matches no signal marker, so only the tail budget can keep it.
_TAIL_ONLY_MARKER = "Killed by signal 9 (SIGKILL) after 300s"


def _long_output() -> str:
    body = "\n".join(f"[verbose] chunk {i} processed" for i in range(400))
    return f"[verbose] starting long job\n{body}\n{_TAIL_ONLY_MARKER}"


def _retained_trailing_lines(preview: str, raw: str) -> int:
    """How many raw lines, counting back from the end, the preview still holds."""

    count = 0
    for line in reversed(raw.splitlines()):
        if line in preview:
            count += 1
        else:
            break
    return count


def test_failed_preview_keeps_the_trailing_diagnosis():
    raw = _long_output()

    preview = make_evidence_preview(raw, 1500, ok=False)

    assert _TAIL_ONLY_MARKER in preview


def test_failed_preview_keeps_more_tail_than_a_successful_one():
    raw = _long_output()

    failed = make_evidence_preview(raw, 1500, ok=False)
    successful = make_evidence_preview(raw, 1500, ok=True)

    assert _retained_trailing_lines(failed, raw) > _retained_trailing_lines(successful, raw)


def test_successful_preview_still_keeps_some_tail():
    """Symmetry is not "drop the tail": both ends always survive, at 50/50."""

    raw = _long_output()

    preview = make_evidence_preview(raw, 1500, ok=True)

    assert "[verbose] starting long job" in preview
    assert _retained_trailing_lines(preview, raw) >= 1


def test_preview_never_exceeds_the_limit_without_signal_lines():
    """Regression: a header-only preview used to overrun ``limit`` by ~200 chars."""

    raw = _long_output()  # no marker matches -> the early-return branch
    assert _retained_trailing_lines(raw, raw) > 0

    for ok in (True, False):
        assert len(make_evidence_preview(raw, 1500, ok=ok)) <= 1500


def test_preview_never_exceeds_the_limit_with_signal_lines():
    body = "\n".join(f"[verbose] chunk {i} processed" for i in range(400))
    raw = f"error: upstream refused\n{body}\n{_TAIL_ONLY_MARKER}"

    for ok in (True, False):
        assert len(make_evidence_preview(raw, 1500, ok=ok)) <= 1500


def test_remember_tool_result_propagates_failure_to_the_preview():
    state = AgentState(origin="http://t", goal="run a long job")
    raw = _long_output()

    failed = state.remember_tool_result(
        tool="shell_command",
        arguments={"command": "long-job --all"},
        output=raw,
        ok=False,
    )

    assert _TAIL_ONLY_MARKER in failed.preview
    # Raw evidence is untouched either way.
    assert _TAIL_ONLY_MARKER in failed.content


def test_remember_tool_result_tail_bias_depends_on_ok():
    raw = _long_output()
    state = AgentState(origin="http://t", goal="run a long job")

    failed = state.remember_tool_result(
        tool="shell_command", arguments={"command": "a"}, output=raw, ok=False
    )
    successful = state.remember_tool_result(
        tool="shell_command", arguments={"command": "b"}, output=raw, ok=True
    )

    assert _retained_trailing_lines(failed.preview, raw) > _retained_trailing_lines(
        successful.preview, raw
    )


def test_clip_text_head_ratio_zero_is_tail_only():
    text = "HEADMARK" + ("x" * 5000) + "TAILMARK"

    clipped = clip_text(text, 200, head_ratio=0.0)

    assert "TAILMARK" in clipped
    assert "HEADMARK" not in clipped
    assert len(clipped) <= 200


def test_clip_text_head_ratio_one_is_head_only():
    text = "HEADMARK" + ("x" * 5000) + "TAILMARK"

    clipped = clip_text(text, 200, head_ratio=1.0)

    assert "HEADMARK" in clipped
    assert "TAILMARK" not in clipped
    assert len(clipped) <= 200


def test_clip_text_ratio_is_clamped():
    text = "A" * 5000 + "TAIL"

    # Out-of-range ratios clamp instead of producing a negative slice length.
    assert len(clip_text(text, 100, head_ratio=5.0)) <= 100
    assert len(clip_text(text, 100, head_ratio=-2.0)) <= 100


def test_clip_text_default_stays_symmetric():
    text = "HEADMARK" + ("x" * 5000) + "TAILMARK"

    clipped = clip_text(text, 400)

    assert "HEADMARK" in clipped
    assert "TAILMARK" in clipped


def test_failed_ratio_constant_is_tail_biased():
    assert 0 < _FAILED_PREVIEW_HEAD_RATIO < 0.5