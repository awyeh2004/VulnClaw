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


class TestAMissingRuntimeCannotBreakThePrompt:
    """Regression found while the full suite was run after 481d7ab.

    `mode_block` was assigned only inside the `try` and consumed after it. Any raise
    part-way through -- here, an agent object with no `runtime` attribute, which several
    entry points and `tests/agent/test_solver_quiz.py` both pass -- left it unbound and the
    `f"{mode_block}"` in the prompt f-string raised:

        UnboundLocalError: cannot access local variable 'mode_block'
        where it is not associated with a value

    That turned "the capability card is unavailable" into "no system prompt at all",
    which is the opposite of what the handler exists for. Both blocks must degrade to
    empty instead.
    """

    def _state(self):
        class _State:
            goal = "capture the flag from http://target"
            origin = "http://target"

        return _State()

    def test_an_agent_without_runtime_still_renders_a_prompt(self):
        from vulnclaw.agent.solver import _system_prompt

        class _Agent:
            config = _cfg("auto")

        prompt = _system_prompt(_Agent(), self._state())
        assert "You are VulnClaw's" in prompt, "the prompt must render without a runtime"

    def test_a_raising_tool_card_degrades_to_an_empty_block(self, monkeypatch):
        """The handler must empty BOTH blocks, not just the one it was written for."""
        from vulnclaw.agent import solver

        monkeypatch.setattr(
            solver, "_tool_card_enabled", lambda: True, raising=False
        )
        monkeypatch.setattr(
            "vulnclaw.agent.tool_registry.build_tool_card",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("card exploded")),
        )

        class _RT:
            prior_playbook_brief = ""

        class _Agent:
            config = _cfg("auto")
            runtime = _RT()

        prompt = solver._system_prompt(_Agent(), self._state())
        assert "You are VulnClaw's" in prompt
