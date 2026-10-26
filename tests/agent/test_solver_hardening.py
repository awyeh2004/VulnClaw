"""Security-hardening prompt and tool-routing tests.

The hardening path is deliberately separate from the knowledge-quiz path:
a hardening run still needs the platform's flag, so it must not inherit the
quiz gate exemption. These tests pin the detector, the prompt directive, and
the tool bundle that keeps `remediation_advice` visible even when the goal
also mentions Web/login/http (which would otherwise match the web bundle).
"""

from types import SimpleNamespace

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.agent.solver import (
    _completion_gate,
    _looks_like_hardening,
    _looks_like_quiz,
    _system_prompt,
)

HARDEN_GOAL = (
    "对 10.0.0.5 做安全加固：修 SSH/Nginx/MySQL/权限，保证服务可用，"
    "跑检查器拿 flag"
)


class TestLooksLikeHardening:
    def test_chinese_keywords(self):
        assert _looks_like_hardening("安全加固")
        assert _looks_like_hardening("系统加固：修 SSH 和权限")
        assert _looks_like_hardening("中间件加固与权限配置")

    def test_english_keywords(self):
        assert _looks_like_hardening("security hardening baseline")
        assert _looks_like_hardening("harden this host")

    def test_pentest_and_quiz_are_not_hardening(self):
        assert not _looks_like_hardening("对 http://target 进行渗透测试，找出flag")
        assert not _looks_like_hardening("知识竞赛：以下说法正确的是")

    def test_ir_hardening_subquestion_stays_ir(self):
        assert not _looks_like_hardening("应急响应：排查后门并加固")

    def test_explicit_hardening_survives_ir_vocabulary(self):
        assert _looks_like_hardening("安全加固：清除后门并修权限")

    def test_pentest_with_remediation_advice_is_not_hardening(self):
        assert not _looks_like_hardening("对目标做渗透测试并给出加固建议")
        assert _looks_like_hardening("安全加固：不要渗透，只修配置")

    def test_hardening_goal_is_not_quiz(self):
        assert not _looks_like_quiz(HARDEN_GOAL)


class TestHardeningPrompt:
    def test_hardening_goal_gets_directive(self):
        prompt = _system_prompt(SimpleNamespace(), AgentState(goal=HARDEN_GOAL))
        assert "Security Hardening Mode" in prompt
        # The two failure modes the directive must keep visible.
        assert "remote_exec" in prompt
        assert "shell_command" in prompt
        assert "chmod 777" in prompt
        assert "8-turn fail-fast" in prompt

    def test_pentest_goal_has_no_hardening_directive(self):
        prompt = _system_prompt(
            SimpleNamespace(),
            AgentState(goal="渗透测试 http://target 并找出flag"),
        )
        assert "Security Hardening Mode" not in prompt

    def test_hardening_goal_with_flag_still_needs_grounded_flag(self):
        """No quiz-style gate exemption: a flag-demanding hardening goal must
        still produce a flag that appears in recorded evidence."""
        st = AgentState(goal=HARDEN_GOAL)
        ok, reason, _ = _completion_gate(st, "FINAL: 加固完成，检查器已通过")
        assert not ok
        assert "flag" in reason


class TestHardeningToolBundle:
    def test_web_and_hardening_goal_keeps_remediation_and_remote(self):
        from vulnclaw.agent.builtin_tools import _infer_allowed_tools

        allowed = _infer_allowed_tools(
            "对 http://10.0.0.5 做安全加固，修 Web 登录和 SSH 权限"
        )
        assert allowed is not None
        assert {
            "remote_exec",
            "remote_collect",
            "remediation_advice",
            "http_probe_batch",
        } <= allowed

    def test_plain_hardening_goal_keeps_remediation(self):
        from vulnclaw.agent.builtin_tools import _infer_allowed_tools

        allowed = _infer_allowed_tools("安全加固：修系统基线和权限配置")
        assert allowed is not None
        assert "remediation_advice" in allowed
        assert "remote_exec" in allowed
