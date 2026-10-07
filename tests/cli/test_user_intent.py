"""Tests for conversational check-in routing helpers."""

from vulnclaw.cli.main import _extract_target_from_input, _should_auto_pentest
from vulnclaw.cli.user_intent import (
    continue_task_prompt,
    is_affirmative_continue,
    is_conversational_checkin,
)


class TestIsConversationalCheckin:
    def test_ready_to_begin_bug_hunting(self):
        assert is_conversational_checkin("ready to begin bug hunting?") is True

    def test_are_we_ready(self):
        assert is_conversational_checkin("are we ready?") is True

    def test_zh_readiness(self):
        assert is_conversational_checkin("准备好开始了吗？") is True

    def test_short_meta_question(self):
        assert is_conversational_checkin("what's the plan?") is True

    def test_affirmative_not_checkin(self):
        assert is_conversational_checkin("yes") is False
        assert is_affirmative_continue("yes") is True

    def test_operational_with_url_not_checkin(self):
        assert is_conversational_checkin("scan https://example.com for XSS?") is False

    def test_imperative_start_not_checkin(self):
        assert is_conversational_checkin("start recon") is False
        assert is_conversational_checkin("scan it") is False

    def test_plain_work_order_not_checkin(self):
        assert is_conversational_checkin("recon crypto.com") is False

    def test_operational_request_phrased_as_question_not_checkin(self):
        # A concrete testing directive must still run, even without a URL and
        # even when politely phrased as a question.
        assert is_conversational_checkin("Can you test the login for SQL injection?") is False
        assert is_conversational_checkin("could you check the upload form for XSS?") is False
        assert is_conversational_checkin("能帮我测一下登录框的 SQL 注入吗？") is False

    def test_readiness_question_still_checkin_even_with_action_word(self):
        assert is_conversational_checkin("ready to begin bug hunting?") is True
        assert is_conversational_checkin("should we start scanning now?") is True


class TestShouldAutoPentestRespectsCheckin:
    def test_checkin_never_enters_auto_even_with_target(self):
        assert _should_auto_pentest("ready to begin bug hunting?", "https://hackerone.com") is False

    def test_explicit_recon_still_auto(self):
        assert _should_auto_pentest("start recon", "https://api.example.com") is True


class TestContinueTaskPrompt:
    def test_uses_prior_task(self):
        prompt = continue_task_prompt("/hackerone crypto", "https://hackerone.com")
        assert "Prior task" in prompt
        assert "crypto" in prompt

    def test_fallback_to_target(self):
        prompt = continue_task_prompt("yes", "https://web.crypto.com")
        assert "web.crypto.com" in prompt


class TestCtf2PracticeTaskRouting:
    """The platform hands the operator a fixed sentence whose only ids are bare
    UUIDs. Every generic target pattern misses it, so before this it failed the
    target gate and the turn went to single-turn chat -- the ctf2 tools and
    platform_submit were never reached (2026-10-06)."""

    PRACTICE = "b9bbb32f-f186-458f-b90b-12440c0f6aea"
    CHALLENGE = "d3fac26a-05c4-44cd-bc6f-73c467f14ac7"
    REF = f"ctf2:practice:{PRACTICE}:{CHALLENGE}"
    SENTENCE = (
        f"用 ctf2 工具解练习场 {PRACTICE} 的题目 {CHALLENGE}：ezAlgebra。"
        "解题过程中用 ctf2_agent_log_note 记录思路。"
    )

    def test_platform_sentence_enters_auto_without_prior_target(self):
        assert _should_auto_pentest(self.SENTENCE, None) is True

    def test_task_identity_is_the_platform_ref_token(self):
        # The same string the `vulnclaw ctf2` hand-off and the platform's own
        # `solve --target` use, so a note captured through either entry path is
        # found by the other.
        assert _extract_target_from_input(self.SENTENCE) == self.REF

    def test_spacing_and_colon_variants(self):
        for text in (
            f"解练习场{self.PRACTICE}的题目{self.CHALLENGE}",
            f"解练习场：{self.PRACTICE} 的题目：{self.CHALLENGE}",
        ):
            assert _extract_target_from_input(text) == self.REF

    def test_description_url_never_becomes_the_target(self):
        # The platform sentence carries the challenge description, which cites the
        # vulhub documentation URL. Mining that URL used to file the run's notes
        # under github.com (measured 2026-10-06) and derived scope from a doc link.
        text = (
            f"用 ctf2 工具解练习场 {self.PRACTICE} 的题目 {self.CHALLENGE}："
            "[Showdoc] CNVD-2020-26585。环境来源与官方说明: "
            "https://github.com/vulhub/vulhub/tree/master/showdoc/CNVD-2020-26585"
        )
        assert _extract_target_from_input(text) == self.REF

    def test_practice_only_sentence_falls_back_to_the_practice_id(self):
        assert (
            _extract_target_from_input(f"用 ctf2 工具解练习场 {self.PRACTICE} 的题")
            == self.PRACTICE
        )

    def test_other_practice_grounds_are_recognised_too(self):
        practice, challenge = (
            "2de971ac-26fe-448a-8719-01829e52c1d5",
            "44c0f2e9-b3fb-4bf3-848a-4ff5715506d5",
        )
        sentence = f"用 ctf2 工具解练习场 {practice} 的题目 {challenge}：[Showdoc] CNVD-2020-26585"
        assert _extract_target_from_input(sentence) == f"ctf2:practice:{practice}:{challenge}"
        assert _should_auto_pentest(sentence, None) is True

    def test_bare_uuid_or_plain_prose_is_not_a_ctf2_task(self):
        assert _extract_target_from_input(f"做一下这道题 {self.CHALLENGE}") is None
        assert _should_auto_pentest("帮我看看这个系统有没有弱口令", None) is False
        # "练习场" without a UUID is not a task reference either.
        assert _extract_target_from_input("用 ctf2 工具解练习场的题目 ezAlgebra") is None
