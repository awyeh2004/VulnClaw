"""task_mode: one explicit mode instead of four independent keyword guesses."""

from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.agent import tool_registry as tr
from vulnclaw.agent.task_mode import (
    detect_task_mode,
    effective_task_mode,
    mode_instruction,
)


def _cfg(task_mode="auto"):
    return SimpleNamespace(session=SimpleNamespace(task_mode=task_mode))


class TestDetectTaskMode:
    def test_ir_goal_detected(self):
        mode, why = detect_task_mode("排查被入侵服务器 找出攻击者利用的漏洞")
        assert mode == "ir"
        assert "IR marker" in why

    def test_ir_beats_ctf_when_both_present(self):
        mode, _ = detect_task_mode("应急响应赛题：找出攻击者IP并提交")
        assert mode == "ir"

    def test_ctf_goal_detected(self):
        mode, why = detect_task_mode("pwn the service and capture the flag{...}")
        assert mode == "ctf"

    def test_plain_pentest_default(self):
        mode, why = detect_task_mode("security assessment of https://target.example.com")
        assert mode == "pentest"


class TestEffectiveTaskMode:
    def test_explicit_config_beats_detection(self):
        mode, why = effective_task_mode(_cfg("ir"), "capture the flag")
        assert mode == "ir"
        assert why == "session.task_mode"

    def test_auto_falls_back_to_detection_and_says_so(self):
        mode, why = effective_task_mode(_cfg("auto"), "webshell 排查")
        assert mode == "ir"
        assert why.startswith("auto:")

    def test_invalid_config_falls_back_to_auto(self):
        mode, _ = effective_task_mode(_cfg("bogus"), "webshell 排查")
        assert mode == "ir"  # detection still ran


class TestModeInstruction:
    def test_ir_discipline_mentions_text_answers_and_surface_budget(self):
        text = mode_instruction("ir")
        assert "TEXT" in text and "5-minute" in text
        assert "flag{" in text  # explicitly tells the model NOT to hunt flags

    def test_ctf_discipline_mentions_flag_and_fail_fast(self):
        text = mode_instruction("ctf")
        assert "flag" in text and "fail-fast" in text

    def test_pentest_has_no_extra_discipline(self):
        assert mode_instruction("pentest") == ""


class TestToolCardModeGating:
    def _fake_detect(self, entry):
        return entry.get("cmd") or f"cmd-{entry['name']}"

    def test_ir_mode_renders_only_ir_section(self, monkeypatch):
        monkeypatch.setattr(tr, "_detect", self._fake_detect)
        monkeypatch.setattr(tr, "_is_ir_goal", lambda g: True)
        card = tr.build_tool_card("排查 事件日志 webshell 攻击者IP", mode="ir")
        assert "Incident-response" in card
        assert "sqlmap" not in card
        # bg_launch cracking hint is attack-side only
        assert "bg_launch" not in card

    def test_pentest_mode_drops_ir_section(self, monkeypatch):
        monkeypatch.setattr(tr, "_detect", self._fake_detect)
        monkeypatch.setattr(tr, "_is_ir_goal", lambda g: True)
        card = tr.build_tool_card("破解密码 sqli 注入 排查 事件日志", mode="pentest")
        assert "Incident-response" not in card
        assert "sqlmap" in card or "hashcat" in card

    def test_auto_keeps_legacy_both_sections(self, monkeypatch):
        monkeypatch.setattr(tr, "_detect", self._fake_detect)
        monkeypatch.setattr(tr, "_is_ir_goal", lambda g: True)
        card = tr.build_tool_card("破解密码 sqli 注入 排查 事件日志", mode="auto")
        assert "Incident-response" in card
        assert "sqlmap" in card or "hashcat" in card


class TestSystemPromptIntegration:
    def test_prompt_carries_mode_block_and_ir_card(self, monkeypatch):
        from vulnclaw.agent.solver import _system_prompt

        monkeypatch.setattr(tr, "_detect", TestToolCardModeGating()._fake_detect)
        monkeypatch.setattr(tr, "_is_ir_goal", lambda g: True)

        class _RT:
            prior_playbook_brief = ""

        class _Agent:
            config = _cfg("ir")
            runtime = _RT()

        class _State:
            goal = "排查被入侵服务器 webshell"
            origin = "http://target"

        prompt = _system_prompt(_Agent(), _State())
        assert "INCIDENT-RESPONSE" in prompt
        # runtime got the resolved mode for the run log
        agent = _Agent()
        _system_prompt(agent, _State())
        assert agent.runtime.task_mode == "ir"
