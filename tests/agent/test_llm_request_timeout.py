"""A non-streamed LLM request must not outlive the turn that issued it.

Measured 2026-11-22, mid-competition. `session.disable_streaming` was on, so the
first-token (120 s) and inter-chunk (60 s) stream timeouts never armed. The only
remaining bound was the OpenAI SDK's own default (600 s per request), while
`llm_turn_budget_s` was checked *between* retry attempts — so one stalled request
blocked for ten minutes before the budget could fire. Three runs froze at 5, 7
and 11 minutes after their last tool result; each had already produced its answer,
so the cost was pure wall-clock and burned retry budget.

The fix reuses the turn budget as the per-request timeout. That keeps the two
consistent (a request may not outlive its turn) and adds no new configuration.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent.core import AgentCore, _request_timeout


def _config(*, budget):
    return SimpleNamespace(session=SimpleNamespace(llm_turn_budget_s=budget))


# ── the helper ──────────────────────────────────────────────────────────


def test_budget_becomes_the_request_timeout():
    assert _request_timeout(_config(budget=240)) == 240.0


def test_disabled_budget_leaves_the_sdk_default():
    """0 is the documented "no budget" value; it must not become timeout=0,
    which would abort every request instantly."""
    assert _request_timeout(_config(budget=0)) is None


@pytest.mark.parametrize("budget", [None, "", "garbage"])
def test_unusable_budget_degrades_to_the_sdk_default(budget):
    assert _request_timeout(_config(budget=budget)) is None


def test_missing_session_is_tolerated():
    assert _request_timeout(SimpleNamespace()) is None
    assert _request_timeout(object()) is None


def test_negative_budget_is_treated_as_disabled():
    assert _request_timeout(_config(budget=-5)) is None


# ── the call site ───────────────────────────────────────────────────────


class _StubAgent:
    """Just enough surface for the unbound AgentCore._get_client."""

    def __init__(self, budget):
        self.config = SimpleNamespace(
            llm=SimpleNamespace(base_url="https://api.example/v1", auth_mode="static"),
            session=SimpleNamespace(llm_turn_budget_s=budget),
        )
        self._client = None

    def _current_api_key(self):
        return "k"


def _build(monkeypatch, *, budget):
    seen: dict = {}

    def fake_make_openai_client(**kwargs):
        seen.update(kwargs)
        return SimpleNamespace(api_key="k")

    monkeypatch.setattr(
        "vulnclaw.agent.core.make_openai_client", fake_make_openai_client
    )
    monkeypatch.setattr(
        "vulnclaw.agent.core.is_gateway_url", lambda url: False
    )
    monkeypatch.setattr(
        "vulnclaw.config.token_provider.load_oauth_tokens", lambda: {}
    )

    AgentCore._get_client(_StubAgent(budget))
    return seen


def test_client_is_built_with_the_turn_budget(monkeypatch):
    seen = _build(monkeypatch, budget=240)

    assert seen["timeout"] == 240.0
    assert seen["base_url"] == "https://api.example/v1"


def test_client_keeps_the_sdk_default_when_the_budget_is_off(monkeypatch):
    seen = _build(monkeypatch, budget=0)

    assert seen.get("timeout") is None
