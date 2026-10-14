"""Evidence gate in front of every flag submission.

Why this module exists (2026-10-14 CTF2 自主解题巡航，24 轮实测)
-------------------------------------------------------------

`_completion_gate`（``vulnclaw/agent/solver.py``）确实把声明的 flag 与已记录证据
比对过 —— 但它只在模型喊 **FINAL** 的那一刻跑。平台的提交是**解题中途**发生的：
``ctf2_submit_flag`` 走 ``builtin_tools.execute_mcp_tool``，那条路此前只有三道闸
（角色/约束门、危险工具门、运维总开关），然后 ``yield to the MCP manager`` ——
**没有任何证据检查**。门在终点等着，提交在半路发生，两不相遇。

实测代价：账号 86 次尝试 / 77 次正确，9 次白花；其中被拒候选的签名高度一致 ——
附件里只观察到 ``flag{``（无 ``}``），模型**自己把 body 和闭括号补了出来**，
补完的串形态完全合法，所以连 FINAL 的 shape 检查也看不出破绽
（``ctf_mode.flag_completeness_issues`` 只在"没有完整 flag 且存在未闭合 token"时
才报，补过壳的候选绕过了它）。

因此本模块把**同一套证据标准前移到花掉尝试的那一刻**，并且**在本地拒绝**：
被拒的提交永远不会到达平台，所以**不消耗平台尝试数**（这是"边界拒绝"与
"事后告警"的本质区别）。拒绝是**有界**的（``MAX_REFUSALS``）：同一候选被拒
若干次后放行并记档，保证"证据读不到但确为真"的 flag 仍能交出去。

证据口径：已记录的工具证据，**扣除自证工具**（黑板书 / 笔记 / 提交动词自身）。
``_completion_gate`` 的注释已写明原因："grounding can be satisfied by the model's
own note (the evidence face includes tool results that merely echo model text)"。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any, Iterable, Optional

# ── 自证工具：它们的内容来自模型自己的话，不能当作"观测" ─────────────────────
SELF_WITNESS_TOOL_PREFIXES: tuple[str, ...] = ("blackboard_",)
SELF_WITNESS_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "ctf2_submit_flag",
        "gcs_submit_flag",
        "ctf2_agent_log_note",
        "save_playbook",
        "lookup_playbook",
        "report_finding",
    }
)

# ── 阈值：由 2026-10-14 全天 30 次真实提交标定 ──────────────────────────────
# 真实通过的提交，其 body 要么整串出现在观测里、要么出现在花括号语境里、要么与
# 已观测的 flag 形片段重合 ≥12 字符；补全型猜测（附件里只有 `flag{`）最长重合
# 0~2。取 8 留出余量，同时把"裸词恰好命中"（8 字符的单词，如题名）排除在外。
MIN_FRAGMENT_OVERLAP = 12

#: 同一候选被拒次数上限；超过则放行（有界拒绝，避免把真 flag 永久关在门外）。
MAX_REFUSALS = 2

_BODY_CHARS = r"A-Za-z0-9_\-=+/!@#$%^&*"
_BRACE_BODY_RE = re.compile(r"\{(?P<body>[" + _BODY_CHARS + r"]{3,})")
_STRIP_RE = re.compile(r"[\s'\"`+]+")


@dataclass(frozen=True)
class GroundingVerdict:
    """判定结果。``reason`` 为 ``none`` 时代表示证据里找不到这个候选。"""

    grounded: bool
    reason: str
    detail: str = ""


def _strip(text: str) -> str:
    return _STRIP_RE.sub("", text or "")


def flag_body(flag: str) -> str:
    """``flag{body}`` → ``body``；无花括号时返回原串（保持宽松，不误判）。"""
    text = (flag or "").strip()
    if "{" in text and text.endswith("}"):
        return text.split("{", 1)[1].rstrip("}")
    return text


def _lcs_len(a: str, b: str) -> int:
    if not a or not b:
        return 0
    match = SequenceMatcher(None, a, b, autojunk=False).find_longest_match(0, len(a), 0, len(b))
    return match.size


def observation_texts(evidence: Iterable[Any]) -> list[str]:
    """证据里属于"观测"的文本（剔除自证工具与空的/重复的条目）。"""
    texts: list[str] = []
    for item in evidence or []:
        tool = (getattr(item, "tool", "") or "").strip()
        if tool in SELF_WITNESS_TOOL_NAMES:
            continue
        if any(tool.startswith(prefix) for prefix in SELF_WITNESS_TOOL_PREFIXES):
            continue
        content = getattr(item, "content", "") or ""
        if content:
            texts.append(content)
    return texts


def assess(flag: str, *, evidence: Iterable[Any], goal_text: str = "") -> GroundingVerdict:
    """候选 flag 是否能在**观测证据**里成形。

    通过条件（任一）：
      * 整串在观测文本里逐字出现（去掉空白/引号/加号后比较，容忍 markdown 折断）；
      * body 出现在花括号语境里（``{flag{body}`` 或 ``{body`` 之一）；
      * 与某个已观测的"花括号后 body 片段"最长公共子串 ≥ :data:`MIN_FRAGMENT_OVERLAP`
        （覆盖"多个片段拼起来"的合法情形）。
    """
    normalized = _strip(flag)
    body = flag_body(flag)
    stripped_body = _strip(body)
    texts = observation_texts(evidence)

    if normalized and any(normalized in _strip(text) for text in texts):
        return GroundingVerdict(True, "whole-flag", "整串出现在工具观测里")

    brace_bodies: list[str] = []
    for text in texts:
        for match in _BRACE_BODY_RE.finditer(text or ""):
            brace_bodies.append(match.group("body"))
        if body and ("{" + body) in (text or ""):
            return GroundingVerdict(True, "brace-context", "body 出现在花括号语境里")

    if stripped_body:
        for fragment in brace_bodies:
            if stripped_body in _strip(fragment):
                return GroundingVerdict(True, "brace-context", "body 出现在花括号语境里")
            if _lcs_len(stripped_body, _strip(fragment)) >= MIN_FRAGMENT_OVERLAP:
                return GroundingVerdict(
                    True,
                    "fragment",
                    f"与已观测片段重合 ≥{MIN_FRAGMENT_OVERLAP} 字符",
                )

    if normalized and goal_text and normalized in _strip(goal_text):
        # 运维/用户直接给出的 flag：任务文本本身就是来源。
        return GroundingVerdict(True, "operator", "候选出现在任务文本里")

    return GroundingVerdict(False, "none", "")


def _candidate_key(flag: str) -> str:
    return _strip(flag) or flag


def _refusal_counts(state: Any) -> dict[str, int]:
    counts = getattr(state, "submit_gate_refusals", None)
    if counts is None:
        counts = {}
        try:
            setattr(state, "submit_gate_refusals", counts)
        except Exception:  # pragma: no cover - 只影响计数，不影响判定
            return {}
    return counts


def submission_refusal(agent: Any, args: dict[str, Any]) -> Optional[str]:
    """提交前置校验。返回 ``None`` 表示放行，否则返回给模型的拒绝说明。

    只在能拿到 AgentState 时介入；拿不到（测试、程序化调用）时不拦，保持
    "没有观测面就不下判断"的失败方向。
    """
    flag = (args or {}).get("flag")
    if not isinstance(flag, str) or not flag.strip():
        return None  # 参数问题交给平台自己的 schema 报错

    state = getattr(getattr(agent, "context", None), "state", None)
    if state is None:
        return None

    from vulnclaw.agent.agent_state import is_placeholder_flag
    from vulnclaw.agent.ctf_mode import flag_completeness_issues

    # ── 形态门：永远拒绝，不需要计数（补壳/占位符不可能被平台接受）──────────
    if flag.count("{") != flag.count("}") or not flag.rstrip().endswith("}"):
        return (
            "[submit-gate] 候选 flag 的花括号不闭合，**没有交出去**（没有消耗尝试）。"
            "闭括号没观察到就是还没解出：回去把尾段找出来，不要自己补 `}`。"
        )
    if not flag_body(flag).strip():
        return "[submit-gate] 候选 flag 的 body 为空，**没有交出去**（没有消耗尝试）。" 

    evidence = getattr(state, "evidence", None) or []
    verdict = assess(flag, evidence=evidence, goal_text=getattr(state, "goal", "") or "")

    if verdict.grounded:
        return None

    counts = _refusal_counts(state)
    key = _candidate_key(flag)
    counts[key] = counts.get(key, 0) + 1
    if counts[key] > MAX_REFUSALS:
        # 有界拒绝：模型反复坚持同一候选 → 放行（真 flag 不能被永久关在门外），
        # 但把这件事记在 state 里，运行摘要与后续复盘都看得见。
        return None

    shape_note = flag_completeness_issues("", [flag])
    note = f"；形态提示：{shape_note[0]}" if shape_note else ""
    if is_placeholder_flag(flag):
        return (
            "[submit-gate] 候选是占位符/模板形，**没有交出去**（没有消耗尝试）。"
            f"占位符不是真 flag{note}—— 回到目标把真 flag 读出来。"
        )
    return (
        "[submit-gate] 证据里找不到这个候选，**没有交出去**（没有消耗一次尝试）："
        f"`{_mask(flag)}` 的 body 在任何工具观测里都没有出现过（整串、花括号语境、"
        "已观测片段三类都没有）。这通常意味着 body 是按题名/类别补出来的。"
        f"回去把 flag 从目标里真正读出来再提交{note}。"
    )


def _mask(flag: str) -> str:
    """给模型看的候选展示：保留形态、不外扩 flag 值。"""
    text = (flag or "").strip()
    if len(text) <= 12:
        return text
    return f"{text[:6]}…{text[-4:]}"
