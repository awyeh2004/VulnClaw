from vulnclaw.agent.context import ContextManager
from vulnclaw.agent.finding_parser import FindingParser
from vulnclaw.agent.runtime_state import RuntimeState


def test_finding_parser_localizes_display_text_but_preserves_vulnerability_type(
    i18n_language,
):
    context = ContextManager()
    parser = FindingParser(context, RuntimeState())

    i18n_language("en")
    parser.parse(
        "发现 SQL注入 漏洞，访问 https://example.com/search?id=1 后返回 SQL 错误，差异: 155"
    )

    finding = context.state.findings[0]
    assert finding.title == "[Auto] SQL Injection"
    assert finding.description == "Automatically detected: SQL注入"
    assert finding.vuln_type == "SQL注入"


def test_finding_parser_preserves_chinese_display_text(i18n_language):
    context = ContextManager()
    parser = FindingParser(context, RuntimeState())

    i18n_language("zh")
    parser.parse("发现 SQL注入 漏洞，返回 SQL 错误，差异: 155")

    finding = context.state.findings[0]
    assert finding.title == "[自动] SQL注入"
    assert finding.description.startswith("自动检测：")
    assert finding.vuln_type == "SQL注入"


def test_finding_parser_deduplicates_across_languages(i18n_language):
    """Verify that the same underlying vulnerability parsed in different languages
    is correctly deduplicated using the stable vuln_type identity, not the localized title.
    """
    context = ContextManager()
    parser = FindingParser(context, RuntimeState())

    # Parse SQL injection evidence in Chinese
    i18n_language("zh")
    parser.parse("发现 SQL注入 漏洞，访问 https://example.com/search?id=1 返回 SQL 错误，差异: 155")

    # Should have one finding with Chinese title
    assert len(context.state.findings) == 1
    first_finding = context.state.findings[0]
    assert first_finding.title == "[自动] SQL注入"
    assert first_finding.vuln_type == "SQL注入"

    # Switch to English
    i18n_language("en")

    # Parse the same evidence (same vuln_type) in English context
    parser.parse(
        "Found SQL injection vulnerability, access https://example.com/search?id=2 returns SQL error, diff: 200"
    )

    # Should still have only one finding (dedup worked across languages)
    assert len(context.state.findings) == 1
    # The original finding should remain unchanged
    assert context.state.findings[0].title == "[自动] SQL注入"
    assert context.state.findings[0].vuln_type == "SQL注入"
