"""提交证据门（``vulnclaw/agent/submit_gate.py``）契约。

2026-10-14 CTF2 自主解题巡航实测：``ctf2_submit_flag`` 此前只过角色/约束门 +
危险工具门 + 运维总开关，然后直接让给平台 MCP —— 没有任何证据检查（证据门
``_completion_gate`` 只在模型喊 FINAL 时跑，而提交发生在解题中途）。代价是
86 次尝试里 9 次白花，被拒候选签名一致：附件里只观察到 ``flag{``（无 ``}``），
body 与闭括号是模型自己补出来的，补完形态合法 → 连 FINAL 的 shape 检查也看不出。

这里钉住门的两端：
  * 补全型 / 占位符 / 花括号不闭合 → 本地拒绝（不消耗平台尝试）；
  * 真实观测（整串 / 花括号语境 / 已观测片段）→ 放行；
  * 自证（模型自己的黑板笔记）→ 不算证据；
  * 有界拒绝：同一候选被拒超过上限即放行，真 flag 不会被永久关在门外。
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.agent.submit_gate import (
    MAX_REFUSALS,
    assess,
    flag_body,
    submission_refusal,
)

OBSERVED = "flag{syn7h3t1c_0bs3rv3d}"          # 附件里真实观测到的完整 flag
PADDED = "flag{ch4ll3ng3_n4m3}"                   # run21：只有 `flag{`，body 按题名补的


def item(tool: str, content: str) -> SimpleNamespace:
    return SimpleNamespace(tool=tool, content=content)


def make_state(evidence, goal: str = "solve the ctf2 practice challenges") -> AgentState:
    state = AgentState(origin="https://ctf2.dasctf.com", goal=goal)
    state.evidence = list(evidence)  # 赋值不过 pydantic 校验：门只读 tool/content
    return state


def make_agent(state: AgentState | None):
    return SimpleNamespace(context=SimpleNamespace(state=state), active_role=None)


# ── assess：放行侧 ────────────────────────────────────────────────────────────


def test_whole_flag_grounds():
    verdict = assess(OBSERVED, evidence=[item("shell_command", f"strings out.png -> {OBSERVED}")])
    assert verdict.grounded and verdict.reason == "whole-flag"


def test_brace_context_body_grounds():
    verdict = assess(OBSERVED, evidence=[item("python_execute", "extracted flag{syn7h3t1c_0bs3rv3d} from png")])
    assert verdict.grounded


def test_fragment_overlap_grounds():
    """合法拼接：片段在观测里、整串不在 —— 不能因为"整串没出现"就拒。"""
    flag = "flag{" + "b" * 20 + "}"
    verdict = assess(flag, evidence=[item("python_execute", "part2 = {" + "b" * 14 + " (bit-shifted)")])
    assert verdict.grounded and verdict.reason == "fragment"


def test_flag_body_helper():
    assert flag_body("flag{abc}") == "abc"
    assert flag_body("no-braces") == "no-braces"


# ── assess：拒绝侧（run21 真实签名）──────────────────────────────────────────


def test_padded_candidate_from_bare_word_is_not_grounded():
    """附件只给了 `flag{` 与题名同族的裸词 → body 出现但不在花括号语境里。"""
    evidence = [item("shell_command", "snake.jpg: ... data ... flag{ ... Anaconda ...")]
    verdict = assess(PADDED, evidence=evidence)
    assert not verdict.grounded and verdict.reason == "none"


def test_no_evidence_at_all_is_not_grounded():
    assert not assess(PADDED, evidence=[]).grounded


def test_self_witness_note_does_not_ground():
    """模型把自己的猜测写进黑板笔记 → 那条笔记是自证，不能当观测。"""
    evidence = [
        item("blackboard_add_fact", f"fact: the flag is {PADDED}"),
        item("ctf2_agent_log_note", f"plan: submit {PADDED}"),
        item("ctf2_submit_flag", f'{{"flag": "{PADDED}", "accepted": false}}'),
    ]
    assert not assess(PADDED, evidence=evidence).grounded


def test_operator_supplied_flag_grounds_from_goal():
    verdict = assess(PADDED, evidence=[], goal_text=f"submit {PADDED} please")
    assert verdict.grounded and verdict.reason == "operator"


# ── submission_refusal：闸门行为 ─────────────────────────────────────────────


def test_grounded_submission_is_allowed():
    agent = make_agent(make_state([item("shell_command", OBSERVED)]))
    assert submission_refusal(agent, {"flag": OBSERVED, "confirmation": True}) is None


def test_padded_submission_is_refused_once_then_allowed():
    agent = make_agent(make_state([item("shell_command", "flag{ ... Anaconda")]))
    first = submission_refusal(agent, {"flag": PADDED})
    assert first is not None
    assert "没有交出去" in first and "没有消耗" in first  # 本地拒绝不清尝试
    # 有界拒绝：第 MAX_REFUSALS+1 次放行，真 flag 不会被永久关在门外
    for _ in range(MAX_REFUSALS - 1):
        assert submission_refusal(agent, {"flag": PADDED}) is not None
    assert submission_refusal(agent, {"flag": PADDED}) is None


def test_unbalanced_candidate_refused_without_counting_attempts():
    agent = make_agent(make_state([item("shell_command", "flag{Anaconda")]))
    for _ in range(MAX_REFUSALS + 2):  # 形态门永远拒（补壳不可能被平台接受）
        msg = submission_refusal(agent, {"flag": "flag{Anaconda"})
        assert msg is not None and "花括号不闭合" in msg


def test_empty_body_refused():
    agent = make_agent(make_state([item("shell_command", "flag{}")]))
    msg = submission_refusal(agent, {"flag": "flag{}"})
    assert msg is not None and "body 为空" in msg


def test_placeholder_refused():
    agent = make_agent(make_state([item("shell_command", "flag{...}")]))
    msg = submission_refusal(agent, {"flag": "flag{xxxx}"})
    assert msg is not None


def test_missing_flag_argument_is_left_to_the_platform():
    agent = make_agent(make_state([]))
    assert submission_refusal(agent, {"confirmation": True}) is None


def test_no_state_fails_open():
    """拿不到 AgentState（测试/程序化调用）时不拦 —— 没有观测面就不下判断。"""
    assert submission_refusal(make_agent(None), {"flag": PADDED}) is None


def test_refusal_counts_persist_on_state():
    agent = make_agent(make_state([item("shell_command", "flag{")]))
    submission_refusal(agent, {"flag": PADDED})
    assert agent.context.state.submit_gate_refusals.get(PADDED) == 1


# ── 集成：dispatch 层真的拦下 ────────────────────────────────────────────────


class _Registry:
    def get_server_for_tool(self, name):
        return "ctf2-mcp" if name == "ctf2_submit_flag" else None


class _Manager:
    """假 MCP manager：registry 认得 ctf2_submit_flag，call_tool 记录调用。"""

    def __init__(self):
        self.registry = _Registry()
        self.calls = []

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        return "MCP-SENTINEL"


def _yield_agent(state):
    """内置 face 隐藏 + MCP registry 拥有该名字 → 走"让给 MCP"那条路。"""
    return SimpleNamespace(
        context=SimpleNamespace(state=state),
        active_role=None,
        config=None,
        session_state=None,
        mcp_manager=_Manager(),
    )


def test_execute_mcp_tool_refuses_unseen_submission(monkeypatch):
    from vulnclaw.agent import builtin_tools as bt

    monkeypatch.setattr(bt, "_flag_submission_enabled", lambda: True)
    monkeypatch.setattr(bt, "ctf2_tools_enabled", lambda _cfg: False)  # 内置 face 隐藏
    agent = _yield_agent(make_state([item("shell_command", "no flag here")]))

    result = asyncio.run(
        bt.execute_mcp_tool(agent, "ctf2_submit_flag", {"flag": PADDED, "confirmation": True})
    )
    assert result.startswith("[submit-gate]")
    assert agent.mcp_manager.calls == []  # 平台从未收到这次提交 → 不消耗尝试


def test_execute_mcp_tool_lets_a_grounded_submission_reach_the_platform(monkeypatch):
    from vulnclaw.agent import builtin_tools as bt

    monkeypatch.setattr(bt, "_flag_submission_enabled", lambda: True)
    monkeypatch.setattr(bt, "ctf2_tools_enabled", lambda _cfg: False)
    agent = _yield_agent(make_state([item("shell_command", f"found {OBSERVED} in out.png")]))
    args = {"flag": OBSERVED, "confirmation": True}

    result = asyncio.run(bt.execute_mcp_tool(agent, "ctf2_submit_flag", args))
    assert result == "MCP-SENTINEL"
    assert agent.mcp_manager.calls == [("ctf2_submit_flag", args)]
