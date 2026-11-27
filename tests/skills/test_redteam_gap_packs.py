"""Regression pins for the gap-domain packs.

These packs were added because the catalog had no deep reference for Host-header
injection, SAML/SSO takeover chains, framework-specific surface, CI/CD
supply-chain work, SPA/shadow APIs, enterprise appliances, or race conditions.
Two failure modes are pinned here:

1. A pack is loadable and advertises its own deep reference — a pack whose
   reference cannot load is just another empty router.
2. A representative query resolves to the pack as **primary**, because
   ``format_selection_context`` only lists the primary skill's references
   (supporting skills appear as name + description, without their files).
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.skill_context import get_active_skill_context
from vulnclaw.skills.loader import load_skill_by_name, load_skill_reference
from vulnclaw.skills.resolver import SkillQuery, SkillResolver

CASES = [
    (
        "目标有密码重置，试试 Host 头注入",
        "redteam-host-header-detail-pack",
        "host-header-injection.md",
    ),
    (
        "这个站用 SAML 单点登录，测 XSW",
        "redteam-sso-ato-detail-pack",
        "saml-oauth-jwt-ato.md",
    ),
    (
        "Spring Boot actuator heapdump 未授权",
        "redteam-framework-detail-pack",
        "framework-specific-surface.md",
    ),
    (
        "GitHub Actions pull_request_target 注入",
        "redteam-cicd-supply-chain-detail-pack",
        "cicd-supply-chain.md",
    ),
    (
        "这个站是单页应用，找找隐藏接口",
        "redteam-spa-shadow-api-detail-pack",
        "spa-shadow-api-surface.md",
    ),
    (
        "目标是 vCenter 和 FortiGate，先指纹再找预认证面",
        "redteam-enterprise-appliance-detail-pack",
        "enterprise-appliance-surface.md",
    ),
    (
        "优惠券并发竞争，能不能重复兑换",
        "redteam-race-condition-detail-pack",
        "race-condition-playbook.md",
    ),
]


@pytest.mark.parametrize(("query", "skill", "reference"), CASES)
def test_gap_pack_is_primary_and_reference_loads(query, skill, reference):
    selection = SkillResolver().resolve(SkillQuery.from_input(query))
    assert selection.primary == skill

    loaded = load_skill_by_name(skill)
    assert loaded is not None
    assert reference in loaded["references"]
    assert load_skill_reference(skill, reference)


@pytest.mark.parametrize(("query", "skill", "reference"), CASES)
def test_gap_reference_is_advertised_in_prompt(query, skill, reference):
    context = get_active_skill_context(query) or ""
    assert skill in context
    assert reference in context


def test_jwt_decode_still_routes_to_crypto_toolkit():
    """The JWT-bearing SSO pack must not steal decode/encode requests."""
    selection = SkillResolver().resolve(SkillQuery.from_input("JWT 解码"))
    assert selection.primary == "crypto-toolkit"


def test_generic_sqli_still_routes_to_web_advanced():
    """Adding gap packs must not disturb the established SQLi bundle."""
    selection = SkillResolver().resolve(SkillQuery.from_input("SQL注入怎么打"))
    assert selection.primary == "web-security-advanced"
