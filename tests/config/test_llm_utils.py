"""build_chat_completion_kwargs (config/llm_utils) — provider mapping contract.

The DeepSeek tier switch (5ae4e27) lives here: fast tier = reasoning_effort
none/unset -> the field is OMITTED (the API's default mode is no reasoning);
deep tier = low/medium/high/max -> forwarded as the top-level reasoning_effort.
Round-10 finding #2: this matrix ran only as an inline session script when the
tier switch landed — no repo artifact guarded it. It lives here now.
"""

from types import SimpleNamespace

import pytest

from vulnclaw.config.llm_utils import build_chat_completion_kwargs


def _llm(provider: str, model: str, effort: str | None):
    return SimpleNamespace(
        provider=provider,
        model=model,
        max_tokens=100,
        temperature=0.1,
        reasoning_effort=effort,
    )


def _kwargs(effort, provider="ds", model="deepseek-flash"):
    return build_chat_completion_kwargs(
        _llm(provider, model, effort), [{"role": "user", "content": "x"}]
    )


class TestDeepseekTierMapping:
    def test_deep_tier_forwards_high(self):
        assert _kwargs("high")["reasoning_effort"] == "high"

    def test_deep_tier_forwards_low(self):
        assert _kwargs("low")["reasoning_effort"] == "low"

    def test_deep_tier_forwards_medium_and_max(self):
        assert _kwargs("medium")["reasoning_effort"] == "medium"
        assert _kwargs("max")["reasoning_effort"] == "max"

    @pytest.mark.parametrize("effort", ["none", "minimal", "", None, "bogus"])
    def test_fast_tier_and_stale_values_omit_the_field(self, effort):
        # omitting the field = API default no-reasoning mode; a stale/invalid
        # config value degrades to fast instead of a 422
        assert "reasoning_effort" not in _kwargs(effort)

    def test_max_tokens_uses_legacy_field_for_deepseek(self):
        assert _kwargs("high")["max_tokens"] == 100


class TestOtherProviderPathsUnchanged:
    def test_zhipu_still_maps_low_high_max(self):
        for effort in ("low", "high", "max"):
            assert (
                _kwargs(effort, provider="zhipu", model="glm-5.3")["reasoning_effort"]
                == effort
            )

    def test_openai_reasoning_models_keep_reasoning_effort(self):
        kw = _kwargs("high", provider="openai", model="o4-mini")
        assert kw["reasoning_effort"] == "high"
        assert "max_completion_tokens" in kw  # legacy max_tokens swapped

    def test_plain_openai_model_has_no_reasoning_field(self):
        assert "reasoning_effort" not in _kwargs("high", provider="openai", model="gpt-4o")

    def test_env_override_is_the_tier_switch(self, monkeypatch):
        from vulnclaw.config.settings import load_config

        monkeypatch.setenv("VULNCLAW_LLM_REASONING_EFFORT", "none")
        monkeypatch.setenv("VULNCLAW_CONFIG_DIR", r"D:\GitClone\VulnClaw\VulnClaw\.test-tmp\tier-cfg\fast")
        cfg = load_config()
        assert cfg.llm.reasoning_effort == "none"
        kw = build_chat_completion_kwargs(cfg.llm, [{"role": "user", "content": "x"}])
        assert "reasoning_effort" not in kw  # fast arm sends no reasoning field
