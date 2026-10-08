"""Round-9 (2026-10-07) postmortem — flag-demand detection must be WORD-BOUNDED.

``_goal_wants_flag`` used a substring test over
``("flag", "ctf", "getshell", "shell")``. A substring test on ``"shell"`` matches
``webSHELL``, so an 应急响应答题制 drill whose goal read
"…攻击者IP、webshell文件路径、首次入侵时间…" declared itself flag-wanting, and
``_completion_gate`` then demanded a ``word{...}`` token in FINAL from a task whose
answers are IPs, filesystem paths and timestamps and can never produce one. The run
took 8 consecutive rejections and ended
``completed=False, "stalled with no untried path remaining"``
(session ``20260927_214554_127.0.0.1_2222.json``).

Measured over the 361 stored sessions: 87 (24 %) hit at least one completion
rejection, 33 of them carrying this exact reason. The same over-match marked every
ctf2 practice run flag-wanting through ``ctf`` ⊂ ``ctf2`` (the platform's own goal
boilerplate is "用 ctf2 工具解练习场 <pid> 的题目 <cid>：<name>").

The fix is a lookaround predicate rather than ``\\b``: ``\\w`` is Unicode-aware, so
CJK is a word character and ``\\bflag\\b`` fails on "拿flag"/"获取flag" — those goals
must keep demanding a flag.
"""

import pytest

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.agent.solver import _completion_gate, _goal_wants_flag

# Verbatim from the session named in the docstring.
FORENSICS_GOAL = (
    "完成应急响应答题制排查：攻击者IP、webshell文件路径、首次入侵时间、利用的漏洞、"
    "持久化机制、其他恶意文件、清除与加固方案——每题独立作答并附证据"
)
FORENSICS_EVIDENCE = (
    "攻击者IP: 198.51.100.44; webshell: /var/www/html/uploads/avatar_cache.php; "
    "首次入侵时间: 2026-03-14T02:11:07Z"
)

FLAG_WANTING = [
    "capture the flag",
    "拿到flag后提交",
    "获取FLAG",
    "submitted  flag{...}  as the answer",
    "get a shell",
    "获取shell",
    "反弹shell",
    "getshell 之后读 flag",
    "玩一下 ctf 比赛",
]

NOT_FLAG_WANTING = [
    FORENSICS_GOAL,
    "webshell 文件路径排查",
    "分析 shellcode 行为",
    "用 ctf2 工具解练习场 123 的题目 abc：应急响应",
    "排查 webshell 并给出加固方案",
]


@pytest.mark.parametrize("goal", FLAG_WANTING)
def test_flag_wanting_goals_still_demand_a_flag(goal):
    assert _goal_wants_flag(goal)


@pytest.mark.parametrize("goal", NOT_FLAG_WANTING)
def test_compound_goal_words_do_not_demand_a_flag(goal):
    """webshell / shellcode must not match `shell`; ctf2 must not match `ctf`."""
    assert not _goal_wants_flag(goal)


def _state(goal: str, evidence_text: str) -> AgentState:
    st = AgentState(goal=goal)
    st.evidence = [
        type("Ev", (), {"content": evidence_text, "id": "e001", "evidence_id": "e001"})()
    ]
    return st


def test_forensics_goal_completes_on_quoted_evidence_without_any_flag():
    """The reported failure: a non-flag goal was forced to produce a flag."""
    st = _state(FORENSICS_GOAL, FORENSICS_EVIDENCE)
    ok, reason, _ = _completion_gate(
        st,
        "FINAL: 攻击者IP 198.51.100.44，webshell 路径 "
        "/var/www/html/uploads/avatar_cache.php，首次入侵时间 2026-03-14T02:11:07Z",
    )
    assert ok, reason
    assert "did not include a flag" not in reason


def test_flag_goal_still_requires_a_flag_after_the_fix():
    """No regression: a genuinely flag-wanting goal is unchanged."""
    st = _state("capture the flag and submit it", "port 80 open, nothing else")
    ok, reason, _ = _completion_gate(st, "FINAL: the port is open")
    assert not ok
    assert "did not include a flag" in reason


def test_cjk_adjacent_flag_goal_still_requires_a_flag():
    """`\\b` would have broken this; the lookaround form must not."""
    st = _state("拿到flag并提交", "port 80 open")
    ok, reason, _ = _completion_gate(st, "FINAL: the port is open")
    assert not ok
    assert "did not include a flag" in reason


# ── 有意收窄的爆炸半径，钉住它（round-9 审查） ────────────────────────────────

#: 平台主机型 goal：整句里唯一的「flag 线索」是主机名 ``*.http-ctf2.dasctf.com`` 里的
#: ``ctf2``。旧子串谓词靠 ``ctf ⊂ ctf2`` 把这类 run 全判成「要 flag」——实测 362 条
#: 会话首目标里 72 条翻转，其中 **69 条**是这个形态（19.9%）。收窄是**有意**的：目标句
#: 里的主机构不成「要 flag」的证据，身份由平台元数据（``_platform_identity_hint``）补。
#: 这里把该决定写死：谁要是把它当 bug 改回子串匹配，这些用例会失败并指回本段说明。
HOST_ONLY_GOALS = [
    "http://a89868f8bafcf0bc067615cc.http-ctf2.dasctf.com:80",
    "http://4bff34c3e4c334533985433e.http-ctf2.dasctf.com:80，新靶机",
    "http://f14b0e1534bbb7708dde487e.http-ctf2.dasctf.com:80",
]


@pytest.mark.parametrize("goal", HOST_ONLY_GOALS)
def test_a_platform_host_goal_is_no_longer_a_flag_demand(goal):
    assert not _goal_wants_flag(goal)


def test_the_token_that_used_to_trigger_those_goals_was_the_hostname():
    """把「当时为什么命中」也钉住：命中的是主机名，不是任务里说了 flag。"""
    goal = HOST_ONLY_GOALS[0]
    assert "flag" not in goal.lower()
    assert "ctf2" in goal.lower()
    # 显式提到 ctf（作为一个词）的目标仍然算要 flag，收窄只针对 ctf2 这种复合词。
    assert _goal_wants_flag("玩一下 ctf 比赛，拿到 flag 再说")


# ── round-9 第二处：quiz 分支的旧子串谓词 ─────────────────────────────────────

QUIZ_WEBSHELL_GOAL = "知识竞赛答题：webshell 文件路径排查，答案写在 FINAL 里"


def test_a_quiz_goal_mentioning_webshell_keeps_the_quiz_path():
    """``_completion_gate`` 的 quiz 分支曾自己内联 ``flag|getshell|shell`` 子串匹配。

    ``shell ⊂ webshell`` 于是让这类 quiz 目标跳过 quiz 路径、落到 flag 检查，最后被
    "FINAL did not cite evidence ids or quote recorded evidence" 拒掉——而 quiz 路径
    本来就允许「按知识作答」。现在它与 ``_implicit_flag_completion`` 共用词边界谓词。
    """
    st = _state(QUIZ_WEBSHELL_GOAL, FORENSICS_EVIDENCE)
    ok, reason, _ = _completion_gate(st, "FINAL: 已按问题作答")
    assert ok, reason
    assert "cite evidence ids" not in reason
