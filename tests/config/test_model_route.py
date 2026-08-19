"""Regression tests for the per-category model routing feature.

Run with: pytest -m regression
These guard the routing additions so enabling ``llm.route_enabled`` cannot
silently break the default single-model behavior.
"""

import pytest

from vulnclaw.config.schema import LLMRouteConfig, VulnClawConfig
from vulnclaw.config.settings import apply_llm_route, resolve_llm_route


def _config(**overrides) -> VulnClawConfig:
    cfg = VulnClawConfig()
    cfg.llm.model = "default-model"
    cfg.llm.base_url = "https://default.example"
    for key, value in overrides.items():
        setattr(cfg.llm, key, value)
    return cfg


def _routes() -> list[LLMRouteConfig]:
    return [
        LLMRouteConfig(
            name="glm",
            provider="zhipu",
            base_url="https://glm.example",
            api_key="gk",
            model="glm-5.3",
            categories=["CRYPTO", "Misc", "Pwn"],
            max_difficulty="MEDIUM",
        ),
        LLMRouteConfig(
            name="ds",
            provider="deepseek",
            base_url="https://ds.example",
            api_key="dk",
            model="deepseek-v4-pro",
            categories=["Web"],
        ),
    ]


@pytest.mark.regression
def test_routing_disabled_by_default_uses_top_level_model():
    cfg = _config(routes=_routes())
    # route_enabled defaults to False -> no route is applied.
    assert cfg.llm.route_enabled is False
    assert resolve_llm_route(cfg, "CRYPTO", "MEDIUM") is None


@pytest.mark.regression
def test_routing_matches_category_and_difficulty():
    cfg = _config(route_enabled=True, routes=_routes())
    assert resolve_llm_route(cfg, "CRYPTO", "MEDIUM").name == "glm"
    assert resolve_llm_route(cfg, "Misc", "EASY").name == "glm"
    assert resolve_llm_route(cfg, "Pwn", "EASY").name == "glm"
    assert resolve_llm_route(cfg, "Web", "MEDIUM").name == "ds"


@pytest.mark.regression
def test_routing_respects_max_difficulty():
    cfg = _config(route_enabled=True, routes=_routes())
    # CRYPTO route caps at MEDIUM; HARD falls through to no match -> default model.
    assert resolve_llm_route(cfg, "CRYPTO", "HARD") is None


@pytest.mark.regression
def test_routing_unmatched_category_returns_none():
    cfg = _config(route_enabled=True, routes=_routes())
    assert resolve_llm_route(cfg, "Reverse", "MEDIUM") is None


@pytest.mark.regression
def test_apply_llm_route_overrides_top_level_fields():
    cfg = _config(route_enabled=True, routes=_routes())
    route = resolve_llm_route(cfg, "CRYPTO", "MEDIUM")
    apply_llm_route(cfg, route)
    assert cfg.llm.model == "glm-5.3"
    assert cfg.llm.base_url == "https://glm.example"
    assert cfg.llm.api_key == "gk"
    assert cfg.llm.provider == "zhipu"


@pytest.mark.regression
def test_apply_llm_route_none_is_noop():
    cfg = _config(route_enabled=True, routes=_routes())
    apply_llm_route(cfg, None)
    assert cfg.llm.model == "default-model"
    assert cfg.llm.base_url == "https://default.example"


@pytest.mark.regression
def test_no_routes_configured_keeps_default_behavior():
    cfg = _config(route_enabled=True)  # routes empty
    assert resolve_llm_route(cfg, "CRYPTO", "MEDIUM") is None


@pytest.mark.regression
def test_apply_llm_route_ignores_empty_fields():
    cfg = _config(route_enabled=True, routes=_routes())
    route = LLMRouteConfig(name="empty", model="")  # empty model should be skipped
    apply_llm_route(cfg, route)
    assert cfg.llm.model == "default-model"
