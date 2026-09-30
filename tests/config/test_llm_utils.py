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

    def test_env_override_is_the_tier_switch(self, monkeypatch, tmp_path):
        """The env tier switch must override the config FILE's reasoning_effort.

        Round-11 finding #2: the previous version monkeypatched the CONFIG_DIR
        env var, but settings.CONFIG_DIR/CONFIG_FILE are import-time constants —
        the patch did nothing, the test read the developer's real config.yaml,
        and only passed because the env override outranks the file. Now the
        file lives in tmp_path (patched via setattr, which load_config DOES
        honor) and asserts the file value loses to the env value explicitly.
        """
        import vulnclaw.config.settings as settings_mod

        config_file = tmp_path / "config.yaml"
        # the FILE says deep; the env says none — env must win
        config_file.write_text(
            "llm:\n"
            "  provider: ds\n"
            "  model: deepseek-flash\n"
            "  base_url: https://api.deepseek.com/v1\n"
            "  api_key: sk-test\n"
            "  reasoning_effort: high\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(settings_mod, "CONFIG_FILE", config_file)
        monkeypatch.setenv("VULNCLAW_LLM_REASONING_EFFORT", "none")

        from vulnclaw.config.settings import load_config

        cfg = load_config()
        assert cfg.llm.provider == "ds", "tmp config file must actually be loaded"
        assert cfg.llm.reasoning_effort == "none"
        kw = build_chat_completion_kwargs(cfg.llm, [{"role": "user", "content": "x"}])
        assert "reasoning_effort" not in kw  # fast arm sends no reasoning field

    def test_config_file_value_used_without_env(self, monkeypatch, tmp_path):
        import vulnclaw.config.settings as settings_mod

        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "llm:\n"
            "  provider: ds\n"
            "  model: deepseek-flash\n"
            "  base_url: https://api.deepseek.com/v1\n"
            "  api_key: sk-test\n"
            "  reasoning_effort: high\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(settings_mod, "CONFIG_FILE", config_file)
        monkeypatch.delenv("VULNCLAW_LLM_REASONING_EFFORT", raising=False)

        from vulnclaw.config.settings import load_config

        cfg = load_config()
        assert cfg.llm.reasoning_effort == "high"
        kw = build_chat_completion_kwargs(cfg.llm, [{"role": "user", "content": "x"}])
        assert kw["reasoning_effort"] == "high"  # deep arm sends the field
