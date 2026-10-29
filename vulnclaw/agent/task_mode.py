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


#: The submit line is CONDITIONAL on this run actually carrying a platform ref.
#:
#: Measured 2026-10-29 (GBU firmware console challenge, `task_mode: ctf` pinned in
#: the operator's config): the flag was recovered at tool call 12, and the
#: unconditional "submit via the platform submit verb" then sent the model to
#: hunt for a challenge ref it could never have -- `platform_submit` needs a
#: `ref` (`platforms/tools.py:_resolve` answers "missing `ref`" without one) and
#: the goal was a bare `openssl s_client -connect <host>:9999` with no
#: `ctf2:practice:<ground>:<challenge>` string anywhere. It spent 10 of 28 tool
#: calls (32 of 79 seconds) enumerating collections, the forbidden daily scope
#: (403 agent_scope_forbidden), all 26 practice challenges and two ended
#: competitions before concluding no ref existed. Saying "do not hunt for a ref"
#: is the difference between reporting the flag and reverse-engineering a
#: platform listing API to find one.
_CTF_SUBMIT_WITH_REF = (
    "- The deliverable is a platform-formatted flag; submit via the platform "
    "submit verb (`platform_submit` needs the challenge `ref` this run was given).\n"
)
_CTF_SUBMIT_WITHOUT_REF = (
    "- This run was handed the target directly, so the goal carries NO platform "
    "challenge ref. The flag value IS the deliverable: state it in FINAL with the "
    "evidence that proves it. If a ref is already in hand (it appeared in the goal, "
    "the origin, or a tool result this run), submit that; but do NOT enumerate "
    "collections to go find one — no `platform_list` / `ctf2_list_*` sweeps, no "
    "probing the platform's own endpoints. Measured cost of that hunt: 10 of 28 tool "
    "calls and 32 of 79 seconds, ending in `403 agent_scope_forbidden` and no ref.\n"
)


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
        "- **The answer sheet IS the findings list**: record every answer as a "
        "finding titled `Q<n>: <question>` carrying the one-line answer and its "
        "evidence. A blackboard fact is NOT an answer until it is recorded as a "
        "finding — the graders only see findings.\n"
        "- Composite questions (cleanup plan / hardening) are separate answers: "
        "write the step list (kill process → delete files → remove persistence → "
        "patch → harden) explicitly as its own finding, never folded into the LOCK.\n"
        "- Before declaring completion: count your answer findings and compare "
        "against the number of questions — if any question has no card, record it "
        "now. Every question gets exactly one card; adjacent questions sharing the "
        "same evidence log are STILL separate cards.\n"
        "- Paths must be copied verbatim from command output, never reconstructed.\n"
        "Load skill reference `ir-competition-strategy` before sweeping.\n"
    ),
    "ctf": "",  # built per run: see mode_instruction(), the submit line is conditional
    "pentest": "",  # default deep-dive behaviour; the stall guard already sets its pace
}


def _ctf_discipline(*, platform_ref: bool) -> str:
    return (
        "\n\n# Task mode: CTF flag round\n"
        + (_CTF_SUBMIT_WITH_REF if platform_ref else _CTF_SUBMIT_WITHOUT_REF)
        + "- Easiest first; fail-fast: if ~8 turns pass with no progress, drop the "
        "challenge and move on.\n"
        "- Exception: a security-hardening/defense challenge (安全加固/加固) is "
        "NOT an 8-turn fail-fast target; follow the hardening workflow, timebox "
        "30-40 minutes, and keep the service alive.\n"
        "Load skill reference `competition-strategy` for the full playbook.\n"
    )


def mode_instruction(mode: str, *, platform_ref: bool = True) -> str:
    """The per-mode discipline block injected into the system prompt.

    This is the piece that used to mix: both disciplines lived side by side in
    the competition-mode skill text and the model picked whichever came to
    mind. One mode, one discipline.

    ``platform_ref`` says whether THIS run was handed a platform challenge ref.
    It only affects the CTF block's submit line: with a ref the flag must be
    submitted (a competition run is graded by the platform), without one the
    flag value is the deliverable and hunting for a ref is wasted work. Default
    True keeps every caller that does not know about the distinction on the old
    "submit" wording -- the stricter of the two.
    """
    if mode == "ctf":
        return _ctf_discipline(platform_ref=platform_ref)
    return _MODE_DISCIPLINE.get(mode, "")
