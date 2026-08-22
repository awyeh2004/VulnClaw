"""Tests for competition-mode strategy (latency probe / easy-first plan)."""

import pytest

from vulnclaw.config.llm_utils import probe_llm_latency


class _LLM:
    api_key = ""
    base_url = ""
    model = ""


def test_probe_llm_latency_no_credentials():
    avg, ok = probe_llm_latency(_LLM())
    assert avg == 0.0
    assert ok is False


def test_probe_llm_latency_unreachable():
    class _LLM2:
        api_key = "sk-x"
        base_url = "http://127.0.0.1:1"  # nothing listening
        model = "m"

    avg, ok = probe_llm_latency(_LLM2(), samples=1)
    assert ok is False


def test_competition_config_defaults():
    from vulnclaw.config.schema import CompetitionConfig

    c = CompetitionConfig()
    assert c.enabled is False
    assert c.slow_llm_threshold_s == 5.0
    assert c.stall_turns == 8
    assert c.easy_first is True
    assert c.predownload_attachments is True


def test_competition_config_registered():
    from vulnclaw.config.schema import VulnClawConfig

    cfg = VulnClawConfig()
    assert cfg.competition.stall_turns == 8
