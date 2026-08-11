"""Bilingual regression tests for vulnclaw.agent.input_analysis display text.

extract_user_vuln_hint / get_payload_examples build a directive that gets
injected into the LLM prompt. The directive's prose must be language-aware;
the vulnerability keywords used for *matching* (vuln_keywords, and the
found_vulns membership checks in get_payload_examples) are classification
logic and must keep working identically regardless of UI language.
"""

from __future__ import annotations

import re

from vulnclaw.agent.input_analysis import (
    detect_phase,
    detect_target,
    extract_task_constraints,
    extract_user_vuln_hint,
    get_payload_examples,
)

_CJK_RE = re.compile(r"[一-鿿]")


def test_extract_user_vuln_hint_localizes_directive_text_in_english(i18n_language):
    i18n_language("en")
    hint = extract_user_vuln_hint(
        "这个点有SQL注入，测试一下 https://example.com/login"
    )

    assert hint != ""
    assert "You must immediately craft and send a PoC test request" in hint
    assert "SQL injection test (boolean-based blind)" in hint
    # The matched vulnerability keyword is a classification value, not
    # translatable display prose, and must survive verbatim in the directive.
    assert "SQL注入" in hint
    # But no *other* Chinese prose should leak into the English directive.
    remaining = hint.replace("SQL注入", "")
    assert not _CJK_RE.search(remaining)


def test_extract_user_vuln_hint_preserves_chinese_directive_text(i18n_language):
    i18n_language("zh")
    hint = extract_user_vuln_hint(
        "这个点有SQL注入，测试一下 https://example.com/login"
    )

    assert hint.startswith("【用户明确提示 — 第1轮】")
    assert "你必须立即构造并发送 PoC 测试请求" in hint
    assert "SQL注入测试（布尔盲注）" in hint


def test_extract_user_vuln_hint_no_target_branch_localizes(i18n_language):
    i18n_language("en")
    hint = extract_user_vuln_hint("帮我测一下未授权")
    assert hint != ""
    assert hint.startswith("[Explicit user hint]")
    assert "do not do additional recon first" in hint

    i18n_language("zh")
    hint_zh = extract_user_vuln_hint("帮我测一下未授权")
    assert hint_zh.startswith("【用户明确提示】")


def test_extract_user_vuln_hint_empty_when_no_keyword_matches(i18n_language):
    i18n_language("en")
    assert extract_user_vuln_hint("just say hello") == ""


def test_get_payload_examples_localizes_headers_but_keeps_target_verbatim(
    i18n_language,
):
    i18n_language("en")
    examples = get_payload_examples(["XSS"], "https://example.com/search")

    assert "[PoC payload examples]" in examples
    assert "XSS test:" in examples
    assert "https://example.com/search?q=<script>alert(1)</script>" in examples
    assert not _CJK_RE.search(examples)


def test_get_payload_examples_zh_output_unchanged(i18n_language):
    i18n_language("zh")
    examples = get_payload_examples(["XSS"], "https://example.com/search")

    assert examples == (
        "【PoC payload 示例】\n"
        "XSS测试:\n"
        "  GET https://example.com/search?q=<script>alert(1)</script>  → 页面是否回显该内容\n"
        "  GET https://example.com/search?q=<img src=x onerror=alert(1)>"
    )


# ── Regression: matching / classification logic must be language-agnostic ──


def test_detect_phase_keyword_matching_unaffected_by_language(i18n_language):
    from vulnclaw.agent.context import PentestPhase

    i18n_language("en")
    assert detect_phase("帮我做信息收集") == PentestPhase.RECON
    i18n_language("zh")
    assert detect_phase("帮我做信息收集") == PentestPhase.RECON


def test_detect_target_unaffected_by_language(i18n_language):
    i18n_language("en")
    assert detect_target("scan https://example.com now") == "https://example.com"
    i18n_language("zh")
    assert detect_target("扫描一下 https://example.com") == "https://example.com"


def test_extract_task_constraints_chinese_matching_unaffected_by_language(
    i18n_language,
):
    i18n_language("en")
    constraints = extract_task_constraints("对 https://example.com 只测试 443 端口")
    assert constraints.allowed_ports == [443]
    assert constraints.strict_mode is True

    i18n_language("zh")
    constraints_zh = extract_task_constraints("对 https://example.com 只测试 443 端口")
    assert constraints_zh.allowed_ports == [443]
    assert constraints_zh.strict_mode is True
