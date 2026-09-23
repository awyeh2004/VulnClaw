"""Verification-claim detection: one vocabulary, and negation that does not invert.

Two things were wrong before this file existed, and both were measured, not assumed.

1. **The vocabulary was maintained twice.** `detect_verification_success` had its own
   30-marker list; `update_ctf_state` had a second 31-marker list and OR-ed the two at
   the function's only call site. They overlapped on 21 entries and each held markers
   the other lacked (`challenge solved` / `got the flag` only inline; `the flag is` /
   `captured` / `成功破解` only in the function), so the function's real contribution was
   its unique entries and the pair was drifting silently -- the same failure
   FLAG_PREFIX_PATTERNS had when its finding_parser copy fell to 3 of 17 prefixes.

2. **Neither handled negation**, and a substring test gets the meaning exactly
   backwards on a denial. Measured false positives:

       "无法验证成功"                    contains "验证成功"
       "尚未验证成功"                    contains "验证成功"
       "not confirmed"                  contains "confirmed"
       "the flag is not the correct one" contains "the flag is"

   `update_ctf_state` turns this into `flag_verified`, which stops the run after two
   post-flag rounds -- so a denial could end a run the model had just said had failed.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.context import ContextManager
from vulnclaw.agent.ctf_mode import (
    VERIFICATION_CLAIM_MARKERS,
    _is_negated,
    detect_verification_success,
)
from vulnclaw.agent.finding_parser import FindingParser
from vulnclaw.agent.runtime_state import RuntimeState


class TestDenialsAreNotClaims:
    @pytest.mark.parametrize(
        "text",
        [
            "无法验证成功",
            "尚未验证成功",
            "未验证成功",
            "没有确认flag",
            "not confirmed",
            "the flag is not the correct one",
            "flag is not verified",
            "we never captured the flag",
            "submission failed, not verified",
            "could not confirm the flag",
        ],
    )
    def test_a_denial_is_not_a_success_claim(self, text):
        assert detect_verification_success(text) is False

    @pytest.mark.parametrize(
        "text",
        [
            "验证成功，flag 为 flag{abc}",
            "已确认flag",
            "复现成功",
            "challenge solved",
            "got the flag",
            "the flag is flag{abc}",
            "verification passed",
            "成功破解，拿到flag",
            "captured the flag",
            "obtained the flag",
        ],
    )
    def test_a_real_claim_still_works(self, text):
        assert detect_verification_success(text) is True

    def test_a_negation_in_the_next_sentence_does_not_suppress(self):
        """The look-ahead must stay short, or every claim followed by a caveat dies."""
        text = "验证成功。未发现其他问题。"
        assert detect_verification_success(text) is True


class TestTheVocabularyIsOneList:
    """Both former lists' unique markers must be recognised by the single predicate."""

    @pytest.mark.parametrize(
        "marker",
        [
            # formerly only inside update_ctf_state's inline list
            "challenge solved",
            "got the flag",
            "submission successful",
            "flag acquired",
            # formerly only inside detect_verification_success
            "the flag is",
            "captured",
            "成功破解",
            "confirms the flag",
        ],
    )
    def test_markers_from_both_former_lists_are_in_the_single_list(self, marker):
        assert marker in VERIFICATION_CLAIM_MARKERS

    def test_no_marker_is_listed_twice(self):
        assert len(VERIFICATION_CLAIM_MARKERS) == len(set(VERIFICATION_CLAIM_MARKERS))

    def test_the_inline_duplicate_is_gone_from_the_module(self):
        """A leftover inline list would silently re-create the drift."""
        import inspect

        import vulnclaw.agent.ctf_mode as ctf_mode

        source = inspect.getsource(ctf_mode.update_ctf_state)
        assert "verification_markers" not in source
        assert source.count("detect_verification_success") == 1


class TestIsNegated:
    def test_marks_a_leading_cue(self):
        text = "尚未验证成功"
        start = text.index("验证成功")
        assert _is_negated(text, start, start + len("验证成功")) is True

    def test_marks_a_trailing_cue(self):
        text = "the flag is not the correct one"
        start = text.index("the flag is")
        assert _is_negated(text, start, start + len("the flag is")) is True

    def test_a_clean_occurrence_is_not_negated(self):
        text = "验证成功"
        assert _is_negated(text, 0, len(text)) is False

    def test_a_negation_far_away_does_not_count(self):
        """Otherwise one '未' anywhere in a long paragraph would kill every claim."""
        text = "未" + "x" * 60 + "验证成功"
        start = text.index("验证成功")
        assert _is_negated(text, start, start + len("验证成功")) is False


class TestTheFactExtractorAlsoRespectsNegation:
    """`未确认该漏洞存在` used to produce the confirmed fact `确认该漏洞存在`."""

    @staticmethod
    def _facts(response: str) -> list[str]:
        context = ContextManager()
        FindingParser(context, RuntimeState()).parse(response)
        return list(getattr(context.state, "confirmed_facts", []) or [])

    def test_a_denial_does_not_become_a_confirmed_fact(self):
        assert self._facts("未确认该漏洞存在") == []

    def test_a_real_confirmation_still_does(self):
        facts = self._facts("已确认该漏洞存在")
        assert any("确认该漏洞存在" in fact for fact in facts)

    def test_an_explicit_confirmation_marker_still_works(self):
        facts = self._facts("已确认：目标存在 SQL 注入")
        assert any("SQL" in fact for fact in facts)
