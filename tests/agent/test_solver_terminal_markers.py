"""Terminal markers must survive formatting drift.

2026-10-16 measured (www.ys7.com round): the model wrote its conclusion as
"**FINAL — www.ys7.com 未登录面轮 穷尽结论**" — markdown-bold, em dash, no
colon. ``_FINAL_MARKERS`` only carried colon forms, so the loop never saw a
terminal marker, kept asking it to continue, and the model re-emitted FINAL
for turns 16/17/18 until the operator pressed Ctrl+C. The dash and full-width
colon variants are accepted now; casing/plain-prose behaviour is unchanged.
"""

from vulnclaw.agent.solver import (
    _ASK_MARKERS,
    _FINAL_MARKERS,
    _NO_PATH_MARKERS,
    _has_marker,
)


class TestTerminalMarkerVariants:
    def test_bold_em_dash_final_matches(self):
        text = "**FINAL — www.ys7.com 未登录面轮 穷尽结论（0 条可立案发现）**"
        assert _has_marker(text, _FINAL_MARKERS) is True

    def test_full_width_colon_final_matches(self):
        assert _has_marker("FINAL：结论", _FINAL_MARKERS) is True

    def test_no_path_dash_matches(self):
        assert _has_marker("NO_PATH — 无可行路径", _NO_PATH_MARKERS) is True
        assert _has_marker("NO_PATH：无可行路径", _NO_PATH_MARKERS) is True

    def test_ask_user_dash_matches(self):
        assert _has_marker("ASK_USER — 请确认靶机", _ASK_MARKERS) is True

    def test_plain_prose_is_not_a_marker(self):
        assert _has_marker("the final answer is 42", _FINAL_MARKERS) is False
        assert _has_marker("最终结果将在稍后给出", _FINAL_MARKERS) is False

    def test_existing_colon_forms_still_match(self):
        assert _has_marker("FINAL: done", _FINAL_MARKERS) is True
        assert _has_marker("[DONE]", _FINAL_MARKERS) is True
        assert _has_marker("完成：结案", _FINAL_MARKERS) is True
