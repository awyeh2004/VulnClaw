"""The solve report must not fabricate a method, and must declare AI use.

Two rules, both from the 2026-10-29 强网杯 official Q&A:

* "可以使用 AI 辅助解题, 后续在 WP 中须注明" -- a writeup has to state that AI was
  used, and the person writing it works from this report hours after the run, so
  the declaration has to already be in the file.
* a human-authored writeup inherits whatever the report asserts, so the chain
  section may only describe work the run actually did.

Measured before this: every non-web run got "通过模型选择的 HTTP/浏览器工具建立
目标页面和接口基线" -- an nc firmware challenge that used nothing but
python_execute included.
"""

from __future__ import annotations

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.report.solve_report import render_solve_report


def _state(*steps) -> AgentState:
    state = AgentState(origin="4371b3824ec5.tcp-ctf2.dasctf.com", goal="capture the flag")
    for reason, tools in steps:
        state.record_step(reason=reason, observation="observed", tool_calls=list(tools))
    state.mark_complete("flag = CTF2{abc}", final_answer="FINAL: CTF2{abc}", evidence_ids=[])
    return state


class TestAIUseDeclaration:
    def test_report_carries_a_copy_paste_declaration(self):
        report = render_solve_report(_state())
        assert "AI 使用声明" in report
        assert "AI 辅助解题" in report
        assert "VulnClaw" in report

    def test_declaration_names_the_configured_model(self):
        from vulnclaw.config.settings import load_config

        report = render_solve_report(_state())
        model = str(getattr(load_config().llm, "model", "") or "")
        if model:
            assert model in report

    def test_declaration_survives_an_unreadable_config(self, monkeypatch):
        """The real failure mode is load_config raising, not the helper throwing:
        a broken/absent config must still yield a report that declares AI use."""
        import vulnclaw.config.settings as settings

        def boom():
            raise RuntimeError("no config")

        monkeypatch.setattr(settings, "load_config", boom)
        report = render_solve_report(_state())
        assert "AI 使用声明" in report
        assert "`unknown`" in report


class TestChainIsNotFabricated:
    def test_non_web_run_describes_its_own_steps(self):
        report = render_solve_report(
            _state(
                ("连上 TLS 控制台并读 HELP", ["python_execute"]),
                ("按 4 位十六进制长度前缀切帧并解 base64", ["python_execute"]),
            )
        )
        assert "连上 TLS 控制台并读 HELP" in report
        assert "按 4 位十六进制长度前缀切帧并解 base64" in report
        assert "HTTP/浏览器工具" not in report

    def test_chain_numbering_is_contiguous(self):
        report = render_solve_report(_state(("step one", ["python_execute"])))
        chain = report.split("## 1.")[1].split("## 2.")[0] if "## 1." in report else ""
        numbers = [line.split(".")[0] for line in chain.splitlines()
                   if line[:2].strip().rstrip(".").isdigit()]
        assert numbers == [str(i) for i in range(1, len(numbers) + 1)], chain

    def test_run_with_nothing_recorded_says_so(self):
        report = render_solve_report(_state())
        assert "无法从证据还原攻击链" in report
        assert "HTTP/浏览器工具" not in report