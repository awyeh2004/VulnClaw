"""Competition writeup generation from a solved AgentState.

The West Lake Sword Competition (西湖论剑) requires a WRITEUP for every solved
challenge; a missing or overly terse one invalidates the team score.  The
official template asks for the reasoning chain, the scripts the team wrote,
and the flag — with the caveat that key steps must not be skipped.

This module renders a single-challenge writeup directly from ``AgentState`` so
the report is grounded in what the model actually did: the step chain
(reason / observation / tool calls), the code blocks extracted from executed
scripts, and line-numbered evidence excerpts standing in for screenshots.  It
also renders a popup-ready evidence text with explicit line numbers so the
operator can cross-check a claim against the exact saved evidence line.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from vulnclaw.agent.agent_state import AgentState, extract_flags, one_line

SCRIPT_TOOLS = {"python_execute", "shell_command", "http_probe_batch"}

_EVIDENCE_LINE_RE = re.compile(r"(?P<lines>\d+)(?:-\d+)?\s*\|\s*(?P<text>.*)", re.MULTILINE)


@dataclass
class WriteupMeta:
    """Team/run metadata for the writeup header."""

    team_name: str = ""
    rank: str = ""
    solved_count: str = ""
    total_tokens: int = 0
    model_name: str = ""
    exercise_name: str = ""
    category: str = ""
    difficulty: str = ""
    score: str = ""


@dataclass
class EvidenceExcerpt:
    """A line-numbered slice of saved evidence, usable as a screenshot stand-in."""

    evidence_id: str
    tool: str
    first_line: int
    last_line: int
    text: str


@dataclass
class CodeBlock:
    """A script the agent wrote, for the writeup's code section."""

    tool: str
    purpose: str
    code: str
    evidence_id: str = ""


def default_writeup_dir() -> Path:
    """Resolve the directory for generated competition writeups.

    Priority: ``VULNCLAW_WRITEUP_DIR`` env var, else the configured sessions dir.
    """
    import os

    if env_dir := os.environ.get("VULNCLAW_WRITEUP_DIR", "").strip():
        return Path(env_dir)
    try:
        from vulnclaw.config.settings import SESSIONS_DIR

        return SESSIONS_DIR
    except Exception:
        return Path("./vulnclaw-output/writeups")


def generate_writeup(
    state: AgentState,
    *,
    meta: WriteupMeta | None = None,
    output_path: str | Path | None = None,
) -> Path:
    """Write a single-challenge writeup and return its path.

    When ``output_path`` points to an existing directory (or has no filename
    extension), a timestamped filename is generated inside it.
    """
    meta = meta or WriteupMeta()
    if output_path is None:
        safe = _safe_filename(meta.exercise_name or state.origin or "challenge")
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = default_writeup_dir() / f"writeup_{stamp}_{safe}.md"
    output = Path(output_path)
    if output.suffix == "" or (output.exists() and output.is_dir()):
        safe = _safe_filename(meta.exercise_name or state.origin or "challenge")
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = output / f"writeup_{stamp}_{safe}.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_writeup(state, meta=meta), encoding="utf-8")
    return output


def render_writeup(state: AgentState, *, meta: WriteupMeta | None = None) -> str:
    """Render a single-challenge writeup Markdown document."""
    meta = meta or WriteupMeta()
    flags = extract_flags((state.final_answer or "") + "\n" + state.evidence_text())
    flag = flags[0] if flags else (state.final_answer or "").strip()[:200]
    excerpts = extract_key_excerpts(state)
    scripts = extract_scripts(state)

    lines: list[str] = [
        f"# {meta.exercise_name or '未命名题目'}",
        "",
        "## 一、团队信息",
        "",
        f"- 名称：{meta.team_name or '（待填写）'}",
        f"- 排名：{meta.rank or '（待填写）'}",
        f"- 解题数量：{meta.solved_count or '（待填写）'}",
        f"- 消耗 token 数：{meta.total_tokens or '（待填写）'}",
        f"- 模型名称：{meta.model_name or '（待填写）'}",
        "",
        "## 二、解题过程",
        "",
    ]
    if meta.category or meta.difficulty or meta.score:
        header_bits = [b for b in (meta.category, meta.difficulty, meta.score) if b]
        lines.append(f"> 题目类型：{' | '.join(header_bits)}")
        lines.append("")

    # Step chain — the reasoning backbone of the writeup.
    lines.extend(["### 解题步骤", ""])
    if state.steps:
        for step in state.steps:
            reason = (step.reason or "(未记录理由)").strip()
            tools = ", ".join(step.tool_calls) or "无"
            observation = (step.observation or "").strip()
            lines.append(f"{step.index}. {reason}")
            lines.append(f"   - 工具调用：{tools}")
            if observation:
                lines.append(f"   - 观测：{observation}")
            lines.append("")
    else:
        lines.append("- 未记录到模型步骤。")
        lines.append("")

    # Evidence excerpts as screenshot stand-ins, each with exact line numbers.
    if excerpts:
        lines.extend(["### 关键证据（替代截图）", ""])
        lines.append(
            "> 下列证据来自解题过程保存的原始工具输出。每条都标注了证据 ID 与"
            "行号，可在生成 writeup 时弹出的证据文本中按行号核对。"
        )
        lines.append("")
        for excerpt in excerpts:
            lines.extend(
                [
                    f"#### 证据 `{excerpt.evidence_id}`（{excerpt.tool}）",
                    "",
                    f"- 行号范围：第 {excerpt.first_line}–{excerpt.last_line} 行",
                    "",
                    "```text",
                    excerpt.text,
                    "```",
                    "",
                ]
            )
    else:
        lines.append("- 无可用证据记录。")
        lines.append("")

    # Scripts the agent wrote, as code blocks.
    if scripts:
        lines.extend(["### 使用的脚本", ""])
        for block in scripts:
            title = f"{block.tool}" + (f"（{block.purpose}）" if block.purpose else "")
            lines.extend([f"#### {title}", ""])
            lines.append("```")
            lines.append(block.code)
            lines.append("```")
            lines.append("")
    else:
        lines.append("- 本题未执行脚本（或脚本未被记录）。")
        lines.append("")

    # Flag + conclusion.
    lines.extend(["### 最终 Flag", ""])
    lines.append(f"```text")
    lines.append(flag or "（未获取到 flag）")
    lines.append("```")
    lines.append("")
    lines.extend(["### 总结", ""])
    lines.append(
        "以上步骤、证据与脚本共同构成完整的解题逻辑链条："
        "从题目描述出发，逐步利用目标信息，最终提取并提交 flag。"
    )
    lines.append("")

    return "\n".join(lines)


def extract_scripts(state: AgentState, *, max_blocks: int = 12) -> list[CodeBlock]:
    """Collect scripts the agent executed (code arguments from tool evidence)."""
    blocks: list[CodeBlock] = []
    seen: set[str] = set()
    for item in state.evidence:
        if item.tool not in SCRIPT_TOOLS:
            continue
        args = dict(item.arguments or {})
        code = ""
        if item.tool == "python_execute":
            code = str(args.get("code") or "")
            purpose = str(args.get("purpose") or "")
        elif item.tool == "shell_command":
            code = str(args.get("command") or "")
            purpose = str(args.get("description") or "")
        else:
            code = item.content or ""
            purpose = str(args.get("url") or "")
        if not code.strip():
            continue
        fingerprint = code.strip()[:120]
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        blocks.append(
            CodeBlock(
                tool=item.tool,
                purpose=purpose,
                code=clip_code(code),
                evidence_id=item.id,
            )
        )
        if len(blocks) >= max_blocks:
            break
    return blocks


def clip_code(code: str, *, max_lines: int = 200) -> str:
    """Clip a long script to a readable excerpt (key functions preserved)."""
    text = str(code or "").rstrip()
    if not text:
        return ""
    if text.count("\n") + 1 <= max_lines:
        return text
    head = text.splitlines()
    return "\n".join(head[:max_lines]) + "\n#[代码过长，已省略]"


def extract_key_excerpts(state: AgentState, *, max_excerpts: int = 8) -> list[EvidenceExcerpt]:
    """Build line-numbered evidence excerpts that stand in for screenshots.

    Picks evidence with a flag / non-trivial body; each excerpt is a bounded
    text window with its first/last line numbers, so the operator can locate it
    in the popup evidence text.
    """
    excerpts: list[EvidenceExcerpt] = []
    flags = extract_flags((state.final_answer or "") + "\n" + state.evidence_text())
    for item in state.evidence:
        if item.tool in SCRIPT_TOOLS and not item.content:
            continue
        raw = item.content or ""
        if not raw.strip():
            continue
        window = _flag_window(raw, flags) if flags else _body_window(raw)
        if not window:
            continue
        text, first_line, last_line = window
        excerpts.append(
            EvidenceExcerpt(
                evidence_id=item.id,
                tool=item.tool,
                first_line=first_line,
                last_line=last_line,
                text=text,
            )
        )
        if len(excerpts) >= max_excerpts:
            break
    return excerpts


def _flag_window(raw: str, flags: list[str]) -> tuple[str, int, int] | None:
    """Return a window around the first flag occurrence, with 1-based lines."""
    text = str(raw)
    for flag in flags:
        index = text.find(flag)
        if index < 0:
            continue
        start = max(0, index - 300)
        end = min(len(text), index + len(flag) + 200)
        snippet = text[start:end]
        prefix = text[:start]
        first_line = prefix.count("\n") + 1
        last_line = first_line + snippet.count("\n")
        return snippet.rstrip(), first_line, last_line
    return None


def _body_window(raw: str, *, max_chars: int = 800) -> tuple[str, int, int] | None:
    """Return a head excerpt for non-trivial evidence bodies."""
    text = str(raw).strip()
    if len(text) > max_chars:
        text = text[:max_chars]
    return text, 1, text.count("\n") + 1


def render_evidence_popup(state: AgentState, *, max_evidence: int = 12) -> str:
    """Render line-numbered evidence text for a terminal popup.

    Each evidence item is printed with a header ``e001 | tool | N 行`` and every
    body line is prefixed with its 1-based line number.  The writeup references
    these line numbers so the operator can verify a claim instantly.
    """
    blocks: list[str] = []
    for item in state.evidence[-max_evidence:]:
        raw = (item.content or "").rstrip()
        if not raw:
            continue
        line_count = raw.count("\n") + 1
        header = f"{item.id} | tool={item.tool} | {line_count} 行"
        body_lines = []
        for line_no, line in enumerate(raw.splitlines(), start=1):
            body_lines.append(f"{line_no:>4} | {line}")
        blocks.append(f"=== {header} ===")
        blocks.extend(body_lines)
    if not blocks:
        return "（无证据可展示）"
    return "\n".join(blocks)


def _safe_filename(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "challenge")).strip("._")
    return safe[:100] or "challenge"


def _jsonish(payload: dict | list | str) -> str:
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        return str(payload)
