"""每一件对外公布的黑板工具都必须真的能回答。

回归守卫，针对一个没有任何测试能看见的缺陷：三个已公布的工具
（``blackboard_review`` / ``blackboard_start_intent`` /
``blackboard_reject_intent``）的 handler 分支被粘到了**另一个函数**
一条 ``return`` 之后（该函数本身没有任何调用者）。于是：

* 分支成了死代码，永不执行；
* ``dispatch_blackboard_tool`` 走到函数末尾，隐式返回 ``None``；
* 工具环把 ``None`` 字符串化成字面量 ``"None"`` 交给模型 —— 模型请求一次
  审查，拿回一个 ``None``，既没有信息也没有错误可诊断。

行为测试看不见这种缺陷：名字在 schema 里、handler 代码也在文件里。因此这里
同时钉住行为（每个工具都回文本）和结构（每个名字都有自己的分支、模块内没有
``return`` 之后的死代码）。
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.agent.blackboard import (
    Blackboard,
    NodeStatus,
    NodeType,
    dispatch_blackboard_tool,
)
from vulnclaw.agent.builtin_tools import build_openai_tools, execute_mcp_tool
from vulnclaw.agent.context import ContextManager, TaskConstraints


def _make_agent():
    """Agent with a real ContextManager/AgentState and a live blackboard."""

    class Runtime:
        def __init__(self) -> None:
            self.blackboard = Blackboard()

    class Session:
        def __init__(self) -> None:
            self.target = "https://example.com"
            self.task_constraints = TaskConstraints()

    class Safety:
        enable_python_execute = True
        python_execute_restricted = False
        python_execute_mode = "trusted-local"
        python_execute_max_lines = 50
        python_execute_show_warning = False
        python_execute_max_output_chars = 0
        python_execute_audit_enabled = True

    agent = SimpleNamespace(
        config=SimpleNamespace(safety=Safety()),
        context=ContextManager(),
        runtime=Runtime(),
        session_state=Session(),
        mcp_manager=None,
        active_role=None,
    )
    agent.context.state.agent_state = AgentState()
    agent.context.state.target = "https://example.com"
    return agent


def _advertised_names() -> list[str]:
    """Tool names the model can actually see, straight from the built schema."""
    tools = build_openai_tools(None)
    return sorted(
        t["function"]["name"]
        for t in tools
        if t["function"]["name"].startswith("blackboard_")
    )


async def _seed(agent) -> dict[NodeType, list[str]]:
    await execute_mcp_tool(agent, "blackboard_add_fact", {"description": "candidate fact"})
    await execute_mcp_tool(agent, "blackboard_add_intent", {"description": "intent: probe id=1"})
    await execute_mcp_tool(
        agent,
        "blackboard_set_lock",
        {"description": "LOCK: boolean-blind SQLi in id; flag in admin row"},
    )
    await execute_mcp_tool(agent, "blackboard_create_angle", {"description": "ANGLE: UNION"})
    by_type: dict[NodeType, list[str]] = {}
    for node in agent.runtime.blackboard.all_nodes():
        by_type.setdefault(node.type, []).append(node.id)
    return by_type


def _args_for(name: str, ids: dict[NodeType, list[str]]) -> dict:
    first = lambda kind: (ids.get(kind) or ["missing"])[0]  # noqa: E731
    if name == "blackboard_verify_fact" or name == "blackboard_challenge_fact":
        return {"node_id": first(NodeType.FACT)}
    if name in {"blackboard_hit_angle", "blackboard_miss_angle"}:
        return {"node_id": first(NodeType.ANGLE)}
    if name in {"blackboard_start_intent", "blackboard_reject_intent"}:
        return {"node_id": first(NodeType.INTENT)}
    if name in {"blackboard_summary", "blackboard_review"}:
        return {}
    return {"description": "LOCK: SQLi in id param; flag in admin row"}


@pytest.mark.asyncio
async def test_every_advertised_blackboard_tool_returns_text():
    agent = _make_agent()
    ids = await _seed(agent)
    offenders = []
    for name in _advertised_names():
        out = await execute_mcp_tool(agent, name, _args_for(name, ids))
        if not isinstance(out, str) or not out.strip() or out.strip() == "None":
            offenders.append(f"{name} -> {out!r}")
    assert not offenders, "advertised blackboard tools fell through to None: " + "; ".join(
        offenders
    )


@pytest.mark.asyncio
async def test_dispatch_never_returns_none_for_advertised_names():
    """Same guarantee one layer down, where the None actually originated."""
    agent = _make_agent()
    ids = await _seed(agent)
    for name in _advertised_names():
        out = await dispatch_blackboard_tool(agent, name, _args_for(name, ids))
        assert isinstance(out, str) and out.strip(), f"{name} -> {out!r}"


@pytest.mark.asyncio
async def test_unknown_blackboard_tool_is_reported():
    agent = _make_agent()
    out = await dispatch_blackboard_tool(agent, "blackboard_not_a_tool", {})
    assert isinstance(out, str) and "unknown blackboard tool" in out


def test_every_advertised_name_has_its_own_branch():
    """A name with no branch is the defect; the catch-all only makes it visible."""
    source = inspect.getsource(dispatch_blackboard_tool)
    missing = [n for n in _advertised_names() if f'"{n}"' not in source]
    assert not missing, (
        "advertised in the schema but no branch in dispatch_blackboard_tool: "
        + ", ".join(missing)
    )


def _unreachable_after_terminator(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    terminators = (ast.Return, ast.Raise, ast.Continue, ast.Break)
    found: list[str] = []

    def walk(node: ast.AST, func: str) -> None:
        for field in ("body", "orelse", "finalbody"):
            block = getattr(node, field, None)
            if not isinstance(block, list) or not block:
                continue
            for index, stmt in enumerate(block[:-1]):
                if isinstance(stmt, terminators):
                    after = block[index + 1]
                    found.append(f"{func}: line {after.lineno} after line {stmt.lineno}")
        for child in ast.iter_child_nodes(node):
            walk(child, func)

    for item in ast.walk(tree):
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            walk(item, item.name)
    return found


def test_blackboard_module_has_no_dead_code():
    """The defect class itself: handlers pasted after an early return.

    Repo-wide scan lives in tests/test_no_dead_code.py; this one keeps the
    original offender pinned where a reader of this file will find it.
    """
    from vulnclaw.agent import blackboard as module

    found = _unreachable_after_terminator(Path(module.__file__))
    assert not found, "unreachable statements in blackboard.py: " + "; ".join(found)


@pytest.mark.asyncio
async def test_review_challenges_fact_that_evidence_does_not_witness():
    agent = _make_agent()
    state = agent.context.state.agent_state
    ev = state.remember_tool_result(
        tool="python_execute", arguments={}, output="unrelated output about DNS records"
    )
    bb = agent.runtime.blackboard
    stale = bb.create_fact(
        "the flag lives in /proc/self/environ", evidence_ref=ev.id, verified=True
    )
    out = await execute_mcp_tool(agent, "blackboard_review", {})
    assert "CHALLENGED" in out and stale.id in out
    assert bb.get_node(stale.id).status == NodeStatus.CHALLENGED


@pytest.mark.asyncio
async def test_review_reports_clean_board_without_lying():
    agent = _make_agent()
    out = await execute_mcp_tool(agent, "blackboard_review", {})
    assert out == "[blackboard review] No actionable findings"


@pytest.mark.asyncio
async def test_start_then_reject_intent_lifecycle():
    agent = _make_agent()
    await execute_mcp_tool(agent, "blackboard_add_intent", {"description": "intent: try LFI"})
    bb = agent.runtime.blackboard
    node = bb.nodes_by_type(NodeType.INTENT)[0]

    out = await execute_mcp_tool(agent, "blackboard_start_intent", {"node_id": node.id})
    assert "in_progress" in out
    assert bb.get_node(node.id).status == NodeStatus.IN_PROGRESS

    out = await execute_mcp_tool(
        agent, "blackboard_reject_intent", {"node_id": node.id, "reason": "filter blocks ../"}
    )
    assert "rejected" in out
    assert bb.get_node(node.id).status == NodeStatus.REJECTED

    # A rejected intent must feed dead-end detection, else the model can declare
    # the same route again and never be warned.
    same = await execute_mcp_tool(
        agent, "blackboard_add_intent", {"description": "intent: try LFI"}
    )
    assert "WARNING" in same and "dead end" in same


@pytest.mark.asyncio
async def test_intent_tools_reject_non_intent_nodes():
    agent = _make_agent()
    fact = agent.runtime.blackboard.create_fact("a fact")
    out = await execute_mcp_tool(agent, "blackboard_start_intent", {"node_id": fact.id})
    assert "is not an intent" in out
    out = await execute_mcp_tool(agent, "blackboard_start_intent", {"node_id": ""})
    assert "requires 'node_id'" in out
