"""CLI guard: pasted knowledge-quiz questions must not reset session context.

Quiz question text often cites IPs/domains ("192.168.1.1 属于哪类地址",
"www.example.com 是否…"). Extracting those as a "new target" used to print
目标切换 and wipe the blackboard/evidence mid-run (same failure family as the
"/证据" mis-extraction fixed in 7419eec).
"""

from vulnclaw.agent.solver import _looks_like_quiz
from vulnclaw.cli.main import _extract_target_from_input, _should_switch_target

CURRENT_TARGET = "http://quiz-platform.example.com:8080"

QUIZ_WITH_IP = (
    "知识竞赛：1. IP 地址 192.168.1.1 属于哪类地址？ A. A类 B. B类 C. C类 D. D类"
)
QUIZ_WITH_DOMAIN = "（判断题）www.example.com 是政府域名。"
REAL_PENTEST_ASK = "接着对 http://real-target.example.com 进行渗透测试"


class TestQuizTargetSwitchGuard:
    def test_quiz_text_extracts_decoy_targets(self):
        # The extraction itself still fires — the guard, not the regex, is
        # what neutralizes it.
        assert _extract_target_from_input(QUIZ_WITH_IP) == "192.168.1.1"
        assert _extract_target_from_input(QUIZ_WITH_DOMAIN) == "www.example.com"

    def test_quiz_decoy_target_does_not_switch(self):
        assert _should_switch_target(
            QUIZ_WITH_IP, _extract_target_from_input(QUIZ_WITH_IP), CURRENT_TARGET
        ) is False
        assert _should_switch_target(
            QUIZ_WITH_DOMAIN, _extract_target_from_input(QUIZ_WITH_DOMAIN), CURRENT_TARGET
        ) is False

    def test_real_new_target_still_switches(self):
        assert _should_switch_target(
            REAL_PENTEST_ASK,
            _extract_target_from_input(REAL_PENTEST_ASK),
            CURRENT_TARGET,
        ) is True

    def test_guard_is_narrow(self):
        assert _looks_like_quiz(REAL_PENTEST_ASK) is False
        assert _looks_like_quiz(QUIZ_WITH_IP) is True
