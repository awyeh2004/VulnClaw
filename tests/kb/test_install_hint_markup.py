"""Rich markup must not swallow the extras bracket in install hints.

``console.print("pip install vulnclaw[kb]")`` renders as
``pip install vulnclaw`` — Rich parses ``[kb]`` as a style tag and drops it,
turning the remediation hint into a command that installs nothing and never
fixes the degraded state it is advertised to fix. The bracket has to be
escaped (``vulnclaw\\[kb]``) in every Rich-rendered string.
"""

import pytest

import vulnclaw.agent.core as core_mod
from vulnclaw.i18n import current_lang, init_i18n
from vulnclaw.kb.retriever import RetrieverStatus


@pytest.fixture(autouse=True)
def _wide_console(monkeypatch):
    """Keep Rich from wrapping the hint mid-token on a narrow default width."""
    monkeypatch.setenv("COLUMNS", "200")


class _KeywordFallbackRetriever:
    """Stands in for a KnowledgeRetriever with chromadb unavailable."""

    store = None

    def get_status(self):
        return RetrieverStatus.KEYWORD_FALLBACK


class TestKbDegradationHint:
    def test_hint_keeps_the_kb_extra(self, monkeypatch, capsys):
        monkeypatch.setattr(core_mod, "KnowledgeRetriever", _KeywordFallbackRetriever)

        prev_lang = current_lang()
        init_i18n(lang="zh")  # the degradation warning is localized; pin zh
        try:
            agent = object.__new__(core_mod.AgentCore)
            agent._report_kb_status()

            out = capsys.readouterr().out
            assert "降级为关键词模式" in out, "expected the degradation warning to be printed"
            assert "pip install vulnclaw[kb]" in out, (
                f"install hint lost its [kb] extra to Rich markup parsing; got: {out!r}"
            )
        finally:
            init_i18n(lang=prev_lang)


class TestWebExtraHints:
    """The `web` command's missing-dependency hint has the same bug shape."""

    def test_fastapi_hint_keeps_the_web_extra(self, monkeypatch):
        from typer.testing import CliRunner

        import vulnclaw.web.app as web_app
        from vulnclaw.cli.main import app

        # The command reads FASTAPI_AVAILABLE from vulnclaw.web.app at call time.
        monkeypatch.setattr(web_app, "FASTAPI_AVAILABLE", False)

        result = CliRunner().invoke(app, ["web", "--host", "127.0.0.1"])

        assert result.exit_code == 1
        combined = result.output + (result.stderr if result.stderr_bytes else "")
        assert "FastAPI is missing" in combined
        assert "pip install vulnclaw[web]" in combined, (
            f"install hint lost its [web] extra to Rich markup parsing; got: {combined!r}"
        )
