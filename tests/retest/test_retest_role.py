"""Retester role registration (A1): 复测员是独立角色，且工具面只够做最小定向复测."""

from __future__ import annotations

from vulnclaw.agent.roles import (
    get_role,
    role_prompt_block,
    roles_for_task_kind,
    tool_allowed_for_role,
)


def test_retester_role_is_registered_for_the_subagent_runtime():
    role = get_role("retester")

    assert role is not None
    assert role.session_kind == "leaf"
    assert "retest" in role.task_kinds


def test_retester_is_discoverable_by_task_kind():
    assert "retester" in roles_for_task_kind("retest")


def test_retester_persona_forbids_rerunning_the_original_task():
    role = get_role("retester")
    persona = role.persona.lower()

    assert "retest" in persona or "复测" in role.persona
    assert "do not" in persona


def test_retester_tool_surface_stays_read_and_probe_only():
    # 复测只需要「读证据 + 定向探测」；写入类/破坏类工具不得进入白名单
    assert tool_allowed_for_role("fetch", "retester")
    assert tool_allowed_for_role("evidence_read", "retester")
    assert not tool_allowed_for_role("shell_command", "retester")
    assert not tool_allowed_for_role("python_execute", "retester")
    assert not tool_allowed_for_role("agent_run", "retester")


def test_role_prompt_block_renders_for_retester():
    block = role_prompt_block("retester")

    assert "retester" in block.lower()
