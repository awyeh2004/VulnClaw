"""主 solve 提示词必须说明"同一回合的多个工具调用会并发执行"。

实测依据（12 次真实 CTF2 运行，216 步 / 2060 秒）：

* 墙钟时间 ≈ 步数 × 每步延迟（实测 9.5 秒/步，一次模型往返）；
* 每步平均只有 1.1 次工具调用 —— 而循环本身会把同一条消息里的多个调用**并发**执行
  （tool_call_manager._execute_parallel），实测也出现过一步 7 连发。

也就是说并发能力一直是有的、只是主提示词没告诉模型，于是它默认一回合一发。
subagent 的提示词早就写了"在同一回合发起一波 agent_run"，主 solve 提示词此前没有
等价表述——这个不对称就是本条要钉住的东西。
"""

from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.agent import solver
from vulnclaw.agent.blackboard import Blackboard


def _agent():
    return SimpleNamespace(
        context=SimpleNamespace(state=SimpleNamespace(target="http://example.com")),
        runtime=SimpleNamespace(blackboard=Blackboard(), prior_playbook_brief=""),
        session_state=SimpleNamespace(task_constraints=None, target="http://example.com"),
        config=SimpleNamespace(safety=SimpleNamespace(python_execute_enabled=True)),
        active_role=None,
    )


def _state():
    return SimpleNamespace(
        goal="capture the flag", origin="http://example.com", correction_hints=[],
        compact_summary="", steps=[], evidence=[],
    )


def test_prompt_documents_concurrent_tool_calls():
    prompt = solver._system_prompt(_agent(), _state())
    assert "SAME message run CONCURRENTLY" in prompt
    assert "issue them together in one turn" in prompt


def test_the_guidance_explains_why_turns_are_the_cost():
    """Without the reason it reads as stylistic advice and gets ignored."""
    prompt = solver._system_prompt(_agent(), _state())
    assert "each turn costs a full model round trip" in prompt


def test_guidance_survives_the_reasoning_graph_being_off(monkeypatch):
    """The batching hint is prompt-weight guidance, not part of the reasoning graph."""
    from vulnclaw.config import settings as settings_module

    monkeypatch.setattr(
        settings_module,
        "load_config",
        lambda: SimpleNamespace(
            session=SimpleNamespace(reasoning_graph_enabled=False, tool_card_enabled=True)
        ),
    )
    prompt = solver._system_prompt(_agent(), _state())
    assert "SAME message run CONCURRENTLY" in prompt
    assert "# Blackboard" not in prompt
