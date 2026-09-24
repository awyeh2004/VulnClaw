"""Explicit task-mode switch — one coherent mode instead of keyword guessing.

Why this exists
---------------
The competition has two very different tracks (pentest: flag / shell; IR:
text answers, per-question submission), and mode-related behaviour used to be
scattered across four independent keyword guesses (skill routing, the tool
card's IR intent gate, quiz/pwn literal checks, two coexisting time
disciplines inside one skill file). An IR goal mentioning 「漏洞」 pulled
pentest methodology into the context; a CTF fail-fast discipline could cut an
IR 5-minute-per-surface sweep short. Nothing was *wrong* per guess — they just
never agreed on one mode.

Borrowed from StrikeAgent's three explicit task modes (redteam / CTF / blue
team): the mode decides the prompt discipline, the tool-card sections and the
skill-routing hint coherently.

Resolution order: ``session.task_mode`` (explicit) beats keyword detection.
``auto`` keeps the legacy behaviour and *says what it guessed* so a wrong
guess is visible in the run log instead of silent.
"""

from __future__ import annotations

from typing import Any

VALID_TASK_MODES = ("auto", "pentest", "ir", "ctf")

# Fallback detection markers (auto mode only). IR markers deliberately mirror
# the incident-response vocabulary; CTF markers mirror the platform wording.
_IR_MARKERS = (
    "应急响应",
    "应急",
    "被入侵",
    "入侵排查",
    "排查",
    "溯源",
    "webshell",
    "web shell",
    "勒索",
    "挖矿",
    "后门",
    "持久化",
    "攻击者ip",
    "attacker ip",
    "incident response",
    "dfir",
    "triage",
)
_CTF_MARKERS = (
    "flag{",
    "ctf{",
    "flag 格式",
    "夺旗",
    "ctf",
    "赛题",
    "解题",
    "d3ctf",
    "dasctf",
)


def detect_task_mode(goal: str) -> tuple[str, str]:
    """Keyword fallback for ``auto``. Returns ``(mode, reason)``.

    IR markers win over CTF markers: a goal that mentions both is almost
    always an IR round with CTF vocabulary in the description (「找出攻击者
    利用的漏洞」), not the other way round.
    """
    text = (goal or "").lower()
    if any(m in text for m in _IR_MARKERS):
        hit = next(m for m in _IR_MARKERS if m in text)
        return "ir", f"goal matched IR marker {hit!r}"
    if any(m in text for m in _CTF_MARKERS):
        hit = next(m for m in _CTF_MARKERS if m in text)
        return "ctf", f"goal matched CTF marker {hit!r}"
    return "pentest", "no track-specific marker found"


def effective_task_mode(config: Any, goal: str) -> tuple[str, str]:
    """Resolve the run's task mode: explicit session config beats detection."""
    configured = str(getattr(getattr(config, "session", None), "task_mode", "auto") or "auto")
    if configured not in VALID_TASK_MODES:
        configured = "auto"
    if configured != "auto":
        return configured, "session.task_mode"
    mode, reason = detect_task_mode(goal)
    return mode, f"auto: {reason}"


_MODE_DISCIPLINE: dict[str, str] = {
    "ir": (
        "\n\n# Task mode: INCIDENT-RESPONSE answer round\n"
        "- Answers are TEXT (attacker IP / file paths / times / vuln names / "
        "persistence / cleanup steps), NOT a flag — never hunt for `flag{}` here.\n"
        "- Classify the incident first, then sweep the six surfaces "
        "(logs → files → accounts → processes → persistence → network) with a "
        "**5-minute budget per surface**; no finding → next surface.\n"
        "- Answer each question as soon as you have one line of evidence, then "
        "keep digging — do not batch answers to the end.\n"
        "- Paths must be copied verbatim from command output, never reconstructed.\n"
        "Load skill reference `ir-competition-strategy` before sweeping.\n"
    ),
    "ctf": (
        "\n\n# Task mode: CTF flag round\n"
        "- The deliverable is a platform-formatted flag; submit via the platform "
        "submit verb.\n"
        "- Easiest first; fail-fast: if ~8 turns pass with no progress, drop the "
        "challenge and move on.\n"
        "Load skill reference `competition-strategy` for the full playbook.\n"
    ),
    "pentest": "",  # default deep-dive behaviour; the stall guard already sets its pace
}


def mode_instruction(mode: str) -> str:
    """The per-mode discipline block injected into the system prompt.

    This is the piece that used to mix: both disciplines lived side by side in
    the competition-mode skill text and the model picked whichever came to
    mind. One mode, one discipline.
    """
    return _MODE_DISCIPLINE.get(mode, "")
