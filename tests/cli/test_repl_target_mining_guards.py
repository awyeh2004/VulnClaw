"""CLI guard: Chinese prose must not mine a fake target from a dotted token.

Measured 2026-10-15 (live REPL session): pasting an engagement brief whose rule
text contained "…建议使用console.log；" made ``_extract_target_from_input``
return ``'建议使用console.log'`` — a bogus *local file* target. The session
retargeted away from the real host, reset its context, and applied local-path
constraints ("仅允许测试路径: 建议使用console.log"). Root causes: ``\\w`` matches
CJK in the file-like branch, and the domain branch lacked the agent layer's
lookbehind + plausible-host guards (``input_analysis.detect_target``).
"""

import pytest

from vulnclaw.cli.repl import _extract_target_from_input


class TestCjkProseIsNotATarget:
    def test_the_exact_brief_line_mines_nothing(self):
        text = "存储型XSS应使用不影响他人的测试Payload，禁止弹窗，建议使用console.log；"
        assert _extract_target_from_input(text) is None

    def test_glued_ascii_word_in_prose_is_skipped(self):
        assert _extract_target_from_input("然后调整 预期使用app.log 观察") is None

    def test_version_strings_are_not_hosts(self):
        assert _extract_target_from_input("目标环境 glibc 2.27 崩溃") is None

    def test_space_separated_prose_still_mines_the_real_file(self):
        # Residual of the same incident class: the adjacent-CJK guard missed the
        # space-separated form, so the leading prose was absorbed into the stem
        # ("请分析 target.zip" instead of "target.zip").
        assert _extract_target_from_input("请分析 target.zip 的漏洞") == "target.zip"
        assert _extract_target_from_input("下载 misc2.zip 后分析") == "misc2.zip"

    def test_spaced_prose_matches_agent_layer(self):
        from vulnclaw.agent.input_analysis import detect_target

        text = "请分析 target.zip 的漏洞"
        assert _extract_target_from_input(text) == detect_target(text)

    def test_domain_glued_to_cjk_is_intentionally_not_mined(self):
        # Alignment with agent.input_analysis.detect_target: the CJK-aware
        # lookbehind is what blocks "…使用console.log"; the cost is that a domain
        # glued straight onto CJK prose is not mined either. Fixing one without
        # re-breaking the other requires the lookbehind, so this stays None.
        assert _extract_target_from_input("访问www.example.com看看") is None


class TestRealTargetsStillMine:
    def test_ascii_file_target(self):
        assert _extract_target_from_input("misc2.zip") == "misc2.zip"

    def test_cjk_stem_file_target(self):
        assert _extract_target_from_input("报告.pdf") == "报告.pdf"

    @pytest.mark.parametrize(
        "name",
        [
            "café.zip",
            "résumé.pdf",
            "Отчёт.zip",
            "报告2024.pdf",
        ],
    )
    def test_unicode_and_mixed_stem_file_targets(self, name):
        assert _extract_target_from_input(name) == name

    def test_url_domain_ip_unchanged(self):
        # The URL branch has always kept the host only (no path) — unchanged.
        assert (
            _extract_target_from_input("打 https://box.example.com/a")
            == "https://box.example.com"
        )
        assert (
            _extract_target_from_input("（判断题）www.example.com 是政府域名。")
            == "www.example.com"
        )
        assert (
            _extract_target_from_input("1. IP 地址 192.168.1.1 属于哪类地址？")
            == "192.168.1.1"
        )
