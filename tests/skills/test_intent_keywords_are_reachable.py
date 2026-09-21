"""Regression guard: every SKILL_INTENT_MAP keyword must actually be reachable.

Why this file exists (a measured, silent failure)
-------------------------------------------------
``SkillQuery.from_input()`` lowercases the input, and ``matched_text()`` exposes
that lowercased text. ``SKILL_INTENT_MAP`` keywords are hand-written prose, and
several contained uppercase ASCII -- ``DDoS``, ``CC攻击``, and even the mixed
token ``webshell查杀``. The matcher compared them case-sensitively, so:

    keyword_present("DDoS",        "服务器被ddos打挂了")            -> False
    keyword_present("webshell查杀", "网站被植入webshell，帮我查杀")   -> False
    keyword_present("ddos",        "服务器被ddos打挂了")            -> True

The consequence was silent: the whole keyword group scored 0, and the phrasing
fell through to a fallback skill (``pentest-flow``) or to nothing at all. Nobody
noticed because the *lowercase* spellings of the same words kept working, so the
skill still looked routable.

Fixed in ``keyword_present`` by lowercasing the keyword. This test makes the
class of bug impossible to reintroduce: it asserts the invariant directly --
"a keyword must be able to match a sentence built from itself" -- for every
keyword of every skill, so an uppercase-ASCII keyword fails immediately instead
of silently never firing.
"""

from __future__ import annotations

import pytest

from vulnclaw.skills.dispatcher import SKILL_INTENT_MAP, SkillDispatcher
from vulnclaw.skills.routing import keyword_present


def _all_keywords() -> list[tuple[str, str, tuple[str, ...]]]:
    """(keyword, owning_skill, sibling_keywords) for every map entry."""
    out: list[tuple[str, str, tuple[str, ...]]] = []
    for pattern, skill_names in SKILL_INTENT_MAP.items():
        keywords = tuple(k for k in pattern.split("|") if k)
        for skill in skill_names:
            for kw in keywords:
                out.append((kw, skill, keywords))
    return out


class TestKeywordSelfMatch:
    """The invariant that was violated: a keyword must match its own spelling."""

    def test_no_empty_keyword_groups(self):
        for pattern in SKILL_INTENT_MAP:
            assert [k for k in pattern.split("|") if k], f"empty group: {pattern!r}"

    @pytest.mark.parametrize(
        "keyword",
        [kw for kw, _, _ in _all_keywords()],
        ids=lambda k: k if k.isascii() else k.encode("unicode_escape").decode(),
    )
    def test_each_keyword_matches_its_own_lowercased_form(self, keyword):
        """A keyword placed in a lowercased sentence must be detected.

        This is exactly the check that would have caught the uppercase-ASCII bug:
        ``DDoS`` failed it because the haystack is lowercased upstream.
        """
        haystack = f"这是一句包含 {keyword.lower()} 的话".lower()
        assert keyword_present(keyword, haystack), (
            f"keyword {keyword!r} cannot match its own lowercased form "
            f"({haystack!r}) -- it is dead and can never fire"
        )

    def test_keywords_with_uppercase_ascii_are_not_dead(self):
        """Regression pin for the uppercase-ASCII tokens.

        NOTE on the third case: this test originally asserted that
        ``webshell查杀`` matches "网站被植入webshell，帮我查杀". It does not, and
        should not -- those are TWO words separated by a comma, so a
        contiguous-substring keyword can never match. That was a second,
        independent defect (an over-glued keyword, not a case problem), fixed by
        splitting it into ``webshell`` and ``查杀木马``/``webshell查杀``.
        So the assertion here is: the SPLIT words match the sentence, and the
        glued form still matches when the user writes it glued.
        """
        for kw, text in (
            ("DDoS", "服务器被ddos打挂了"),
            ("CC攻击", "网站被cc攻击"),
            # split form matches the comma-separated sentence
            ("webshell", "网站被植入webshell，帮我查杀"),
            ("查杀木马", "帮我查杀木马"),
            # glued form still matches when written glued
            ("webshell查杀", "webshell查杀"),
        ):
            assert keyword_present(kw, text.lower()), f"{kw!r} is dead again"


class TestRoutingEndToEnd:
    """Each keyword must route to its owning skill, not to a fallback."""

    @pytest.mark.parametrize(
        "skill,keyword",
        [
            ("incident-response", "DDoS"),
            ("incident-response", "CC攻击"),
            ("incident-response", "数据泄露"),
            ("incident-response", "拖库"),
            ("incident-response", "应急响应"),
            ("incident-response", "webshell查杀"),
            ("incident-response", "查杀木马"),
        ],
    )
    def test_incident_response_phrasings_resolve(self, skill, keyword):
        d = SkillDispatcher()
        result = d.resolve(f"情况：{keyword}")
        assert getattr(result, "primary", None) == skill, (
            f"{keyword!r} routed to {getattr(result, 'primary', None)!r} instead of {skill!r}"
        )

    def test_non_security_input_still_selects_nothing(self):
        """The guard must not make the matcher over-eager."""
        d = SkillDispatcher()
        assert getattr(d.resolve("写一个python脚本处理csv"), "primary", None) is None

    def test_pentest_phrasing_is_not_hijacked(self):
        d = SkillDispatcher()
        assert getattr(d.resolve("帮我渗透测试这个网站"), "primary", None) == "pentest-flow"


class TestCaseNormalizationIsSymmetric:
    """Pin the mechanism itself, not just its symptom."""

    def test_uppercase_keyword_matches_lowercase_text(self):
        assert keyword_present("DDoS", "服务器被ddos打挂了") is True

    def test_lowercase_keyword_matches_lowercase_text(self):
        assert keyword_present("ddos", "服务器被ddos打挂了") is True

    def test_ascii_boundaries_still_apply(self):
        """The reason ASCII gets regex treatment at all -- must not regress."""
        assert keyword_present("rce", "source code here") is False
        assert keyword_present("rce", "got rce via upload") is True
        assert keyword_present("java", "javascript") is False

    def test_chinese_uses_substring_matching(self):
        assert keyword_present("应急响应", "这是一次应急响应任务") is True
