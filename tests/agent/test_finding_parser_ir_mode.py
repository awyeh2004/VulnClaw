"""IR answer rounds keep the findings list as a pure answer sheet (mock exam 6).

Layer-2 natural-language auto-detection produced [Auto] entries (弱口令, 版本暴露)
next to the Q<n> answer cards; in task_mode=ir those are noise the grader would
see alongside the real answers, so they are suppressed. Layers 1/3 stay on.
"""

from types import SimpleNamespace

from vulnclaw.agent.blackboard import Blackboard
from vulnclaw.agent.context import ContextManager
from vulnclaw.agent.finding_parser import FindingParser
from vulnclaw.agent.runtime_state import RuntimeState


def _ir_runtime(task_mode="ir"):
    return SimpleNamespace(task_mode=task_mode)


def test_ir_mode_suppresses_layer2_auto_findings():
    context = ContextManager()
    parser = FindingParser(context, _ir_runtime())
    parser.parse(
        "服务器存在 弱口令 问题，且 curl -s http://x 版本信息暴露：nginx/1.14 泄露。"
        "访问 https://example.com/search?id=1 返回 SQL 错误，差异: 155"
    )
    auto = [f for f in context.state.findings if str(f.title).startswith("[Auto]")]
    assert auto == [], f"layer-2 auto findings leaked in ir mode: {[f.title for f in auto]}"


def test_default_mode_still_produces_layer2_auto_findings(i18n_language):
    i18n_language("en")
    context = ContextManager()
    parser = FindingParser(context, _ir_runtime(task_mode="pentest"))
    parser.parse(
        "发现 SQL注入 漏洞，访问 https://example.com/search?id=1 后返回 SQL 错误，差异: 155"
    )
    auto = [f for f in context.state.findings if str(f.title).startswith("[Auto]")]
    assert auto, "pentest mode must keep layer-2 auto detection"


def test_record_answer_is_idempotent_per_question():
    """Mock exam 6: the self-check re-record produced 20 cards for 10 questions."""
    import asyncio

    from vulnclaw.agent.blackboard import dispatch_blackboard_tool

    findings = []
    state = SimpleNamespace(
        add_finding=lambda f, skip_dedup=False: findings.append(f) or True,
        findings=findings,
    )
    agent = SimpleNamespace(
        runtime=SimpleNamespace(blackboard=Blackboard()),
        context=SimpleNamespace(state=state),
        session_state=SimpleNamespace(target="127.0.0.1:2224"),
    )
    args = {
        "question": "Q3: 首次入侵时间是什么？",
        "answer": "2026-09-19 03:41",
        "evidence": "Failed password for admin from 203.0.113.77 port 51022",
    }
    first = asyncio.run(dispatch_blackboard_tool(agent, "blackboard_record_answer", args))
    second = asyncio.run(dispatch_blackboard_tool(agent, "blackboard_record_answer", args))

    assert "finding recorded" in first
    assert "already recorded" in second
    assert len(findings) == 1, f"duplicate card recorded: {len(findings)}"

    # new evidence on a re-record merges into the existing card
    asyncio.run(
        dispatch_blackboard_tool(
            agent,
            "blackboard_record_answer",
            {**args, "evidence": "wtmp begins Fri Sep 18 2026"},
        )
    )
    assert len(findings) == 1
    assert "wtmp begins" in findings[0].evidence
