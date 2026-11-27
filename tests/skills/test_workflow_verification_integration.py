"""verify_finding is wired into the shipped workflows and the live tool face.

Workflow tool names are advisory (the live face is pruned per task), so this
test pins the two things that must stay true:

1. every shipped workflow parses clean and its report phase offers
   verify_finding alongside report_finding;
2. the tool is actually registered and dispatchable (schema + always-keep +
   execute_mcp_tool reaches the implementation).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from vulnclaw.agent.builtin_tools import (
    _ALWAYS_KEEP_TOOLS,
    build_openai_tools,
    execute_mcp_tool,
)
from vulnclaw.agent.context import SessionState
from vulnclaw.agent.skill_context import format_selection_context
from vulnclaw.skills.loader import list_specialized_skills, load_specialized_skill
from vulnclaw.skills.resolver import SkillSelection
from vulnclaw.skills.workflow import parse_workflow

WORKFLOW_SKILLS = ["ai-mcp-security", "electron-desktop-audit", "web-pentest"]


@pytest.mark.parametrize("name", WORKFLOW_SKILLS)
def test_report_phase_offers_verify_finding(name):
    skill = load_specialized_skill(name)
    assert skill is not None
    wf = parse_workflow(skill.get("workflow"))
    assert wf is not None
    assert wf.warnings == []

    report = next((phase for phase in wf.phases if phase.id == "report"), None)
    assert report is not None
    assert "verify_finding" in report.tools
    assert "report_finding" in report.tools


def test_all_workflow_skills_parse_clean():
    seen = 0
    for name in list_specialized_skills():
        skill = load_specialized_skill(name)
        if skill is None or not skill.get("workflow"):
            continue
        seen += 1
        wf = parse_workflow(skill["workflow"])
        assert wf is not None and wf.warnings == [], name
    assert seen >= 3


def test_explicit_invocation_mentions_poc_verification():
    selection = SkillSelection(
        primary="web-pentest",
        signals=["explicit"],
        reason="explicit: test",
        confidence=1.0,
    )
    context = format_selection_context(selection)
    assert "verify_finding" in context
    assert "poc_verification" in context


def test_tool_is_registered_and_kept():
    names = {tool["function"]["name"] for tool in build_openai_tools(None)}
    assert "verify_finding" in names
    assert "verify_finding" in _ALWAYS_KEEP_TOOLS


def test_dispatch_reaches_the_tool():
    agent = SimpleNamespace(session_state=SessionState(target="http://app.test"))
    message = asyncio.run(
        execute_mcp_tool(agent, "verify_finding", {"finding": "does-not-exist"})
    )
    assert "未找到" in message
