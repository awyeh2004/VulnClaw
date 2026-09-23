"""两个"面向模型"的消融开关：默认开启，关闭后只影响模型可见面。

存在的理由是可测量性：2026-09-19 与当前版本的 A/B 显示，当前版本在 3/3 同样解出的
前提下多花 1.8 倍工具调用、2.3 倍时长，而"推理图仪式"是嫌疑之一。要判定这个嫌疑，
必须能单独关掉它，并且保证关掉后**只有模型可见面**变化：

* 13 个 blackboard_* 工具从工具表消失；
* 系统提示里的 Blackboard / LOCK-ANGLES-TENSION 段消失；
* 运行时黑板对象、自动笔记（capture_run_notes）、停滞守卫**照旧**——
  否则量到的就不是"仪式的成本"，而是"功能被拆掉后的成本"。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent import solver
from vulnclaw.agent.blackboard import Blackboard, reasoning_graph_enabled
from vulnclaw.agent.builtin_tools import build_openai_tools
from vulnclaw.config import settings as settings_module


def _cfg(*, reasoning: bool = True, tool_card: bool = True):
    return SimpleNamespace(
        session=SimpleNamespace(
            reasoning_graph_enabled=reasoning, tool_card_enabled=tool_card
        )
    )


@pytest.fixture()
def config_switch(monkeypatch):
    """Point every config read at a stub so the test never touches the real file."""

    def install(*, reasoning: bool, tool_card: bool):
        monkeypatch.setattr(
            settings_module,
            "load_config",
            lambda: _cfg(reasoning=reasoning, tool_card=tool_card),
        )

    return install


def _names(tools: list[dict]) -> list[str]:
    return [t["function"]["name"] for t in tools]


def test_reasoning_graph_defaults_on(config_switch):
    config_switch(reasoning=True, tool_card=True)
    assert reasoning_graph_enabled() is True
    names = _names(build_openai_tools(None))
    assert any(n.startswith("blackboard_") for n in names)


def test_reasoning_graph_off_hides_the_whole_tool_family(config_switch):
    config_switch(reasoning=False, tool_card=True)
    names = _names(build_openai_tools(None))
    assert not [n for n in names if n.startswith("blackboard_")], names
    # Everything else must survive: this knob removes one feature, not the face.
    for keep in ("python_execute", "shell_command", "evidence_list", "lookup_playbook"):
        assert keep in names


def test_reasoning_graph_fails_open(monkeypatch):
    def boom():
        raise RuntimeError("config exploded")

    monkeypatch.setattr(settings_module, "load_config", boom)
    assert reasoning_graph_enabled() is True, "a config error must not strip the tool face"


def test_runtime_blackboard_still_exists_when_the_model_face_is_off(config_switch):
    """Auto-capture and the stall guard read the runtime board, so it must stay."""
    config_switch(reasoning=False, tool_card=False)
    board = Blackboard()
    node = board.create_fact("a fact the run produced without the ceremony")
    assert board.get_node(node.id) is not None
    assert board.confirmed_facts() == []


def test_prompt_block_is_omitted_when_disabled(config_switch, monkeypatch):
    agent = SimpleNamespace(
        context=SimpleNamespace(state=SimpleNamespace(target="http://example.com")),
        runtime=SimpleNamespace(blackboard=Blackboard(), prior_playbook_brief=""),
        session_state=SimpleNamespace(task_constraints=None, target="http://example.com"),
        config=SimpleNamespace(safety=SimpleNamespace(python_execute_enabled=True)),
        active_role=None,
    )
    state = SimpleNamespace(
        goal="capture the flag", origin="http://example.com", correction_hints=[],
        compact_summary="", steps=[], evidence=[],
    )

    config_switch(reasoning=True, tool_card=True)
    on = solver._system_prompt(agent, state)
    assert "# Blackboard" in on and "blackboard_set_lock" in on

    config_switch(reasoning=False, tool_card=True)
    off = solver._system_prompt(agent, state)
    assert "# Blackboard" not in off
    assert "blackboard_set_lock" not in off
    assert len(off) < len(on), "hiding the block must also shrink the prompt"
