"""Render an IR deliverable (WP) from the session's recorded answer cards.

Why this exists
---------------
``blackboard_record_answer`` writes every graded answer twice: a blackboard fact
and a *finding* with ``vuln_type="ir-answer"`` (title = the question, description
= the answer, evidence = the verbatim command output). The report, SARIF and
verify-pending consumers deliberately skip those cards -- an answer card is not a
vulnerability, and rendering them as findings promoted a question that merely
names a class ("漏洞名称") into a verified vulnerability (round-10 finding #1).

Skipping is right for the *vulnerability* report and wrong for the *deliverable*:
at the end of an IR engagement the WP has to carry those conclusions and their
evidence, and the only way to get them out was to hand-copy each card from the
session inside the competition's 20-minute write-up window. This module renders
that half mechanically.

Scope, stated plainly: this produces the **answer-sheet half** of the WP. It does
not invent a one-line conclusion, an attack-chain timeline, IOCs or remediation
advice -- those need a human, and the checklist it emits says so.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from vulnclaw.config.domain_models import is_answer_card

#: Stable heading for the machine-written block, so a reviewer can always tell
#: auto-exported content from the operator's own prose.
ANSWER_SECTION_HEADING = "## 答案卡（自动导出 · 含证据原文）"

#: What the machine deliberately did NOT write. Kept next to the renderer so the
#: gap is stated where the WP is produced, not only in a runbook.
HANDOFF_CHECKLIST = """## 人工待补（机器写不了的部分）

- [ ] 一句话失陷结论（这台机器被怎么了）＋ 影响范围
- [ ] 攻击链时间线（初始访问 → 执行 → 持久化 → 横向），**标注时区**
- [ ] IOC 清单（IP / 域名 / 文件哈希 / 账号）
- [ ] 处置与加固建议（顺序：阻断 → **先拆持久化** → 清文件 → 修漏洞 → 加固）
- [ ] flag 是否已提交 ＋ 平台回报
"""


def collect_answer_cards(session: Any) -> list[Any]:
    """The session's answer cards, in recording order.

    Order is deliberately the session's own finding order: that is the order the
    agent answered in, and a sheet that reshuffles between runs is useless as a
    cross-check against the task's questions.
    """
    return [f for f in (getattr(session, "findings", None) or []) if is_answer_card(f)]


def render_answer_cards(cards: Iterable[Any]) -> str:
    """One ``### <question>`` block per card: the answer, then the raw evidence."""
    blocks: list[str] = []
    for index, card in enumerate(cards, 1):
        question = str(getattr(card, "title", "") or "").strip() or f"Q{index}"
        answer = str(getattr(card, "description", "") or "").strip()
        evidence = str(getattr(card, "evidence", "") or "").strip()
        lines = [f"### {index}. {question}", "", f"- **答案**：{answer or '（未记录）'}"]
        if evidence:
            lines += ["", "- **证据（原文）**：", "", "```", evidence, "```"]
        blocks.append("\n".join(lines))
    if not blocks:
        return "_（本次会话没有记录任何答案卡 —— 检查 agent 是否用了 `blackboard_record_answer`）_"
    return "\n\n".join(blocks)


def build_ir_wp(
    session: Any,
    *,
    generated_at: str | None = None,
    template_text: str | None = None,
) -> str:
    """Markdown WP: auto-filled answer cards, plus the template skeleton if given.

    ``template_text`` is appended **verbatim** rather than parsed. The delivery
    templates are prose inside tables, and filling them mechanically would
    silently drop whichever section the parser did not understand -- worse than
    making the operator copy what they need into it.
    """
    target = str(getattr(session, "target", "") or "unknown")
    run_id = str(getattr(session, "run_id", "") or "")
    stamp = generated_at or datetime.now().isoformat(timespec="seconds")
    cards = collect_answer_cards(session)

    parts = [
        "# 应急响应演练报告（WP）",
        "",
        f"> 目标：`{target}`　｜　会话 run_id：`{run_id or '未记录'}`　｜　自动导出时间：{stamp}",
        f"> 由 `vulnclaw wp` 生成：**答案卡（结论 + 证据原文）{len(cards)} 条已自动填入**；",
        "> 叙述性段落（影响 / 时间线 / 建议）仍需人工补全，见文末清单。",
        "",
        ANSWER_SECTION_HEADING,
        "",
        render_answer_cards(cards),
        "",
        HANDOFF_CHECKLIST,
    ]
    if template_text:
        parts += [
            "",
            "---",
            "",
            "## 附：交付模板骨架（原文，按平台要求填写）",
            "",
            template_text.rstrip(),
            "",
        ]
    return "\n".join(parts).rstrip() + "\n"


def default_template_path() -> Any:
    """The WP skeleton shipped with the repo, if this install can see it.

    Optional on purpose: the template lives at the repository root and is not
    part of the installed package, so a wheel install legitimately has none --
    callers then render the answer-card block alone instead of failing.
    """
    from pathlib import Path

    candidates = [
        Path.cwd() / "IR-WP-TEMPLATE.md",
        Path(__file__).resolve().parents[2] / "IR-WP-TEMPLATE.md",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None
