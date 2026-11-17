"""Condense one finished run into a short, judgement-free brief.

The workflow this supports: VulnClaw spends a budget attacking, ZCode reviews what
happened, then either feeds a new goal back or drops the challenge. The review step
needs a compact answer to "what did this run actually establish?", and it must come
from recorded state — not from re-reading a 10k-line log by eye.

Why a separate collector instead of reading the session by hand: measured on the
2026-11-17 oldsvr run, the interesting facts were **not** in the obvious places.

* ``final_answer`` and ``compact_summary`` were both empty — the run died on
  ``token budget exhausted``, which writes neither.
* ``events/events.jsonl`` had 5 lines (run_created + checkpoints), no trajectory.
* The only real record was ``targets/<key>/state/current.json``: 148 evidence
  records, 162 tool calls, 17 steps.

So the collector reads that state file, plus whatever stdout the caller saved, and
emits counts and identifiers. It deliberately makes **no** judgement about whether
the run went the right way — that is the reviewer's job, and a tool that guesses
would just launder its guess into a conclusion.

Usage::

    python -X utf8 -I scripts/run_brief.py <run-dir> [--log solve.log] [--json]
    python -X utf8 -I scripts/run_brief.py --latest [--runs-root DIR] [--log NAME]

Read-only: it never writes into the run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Health thresholds ───────────────────────────────────────────────────────
#
# "Blackboard empty" is the signal that mattered on 2026-11-17: 162 tool calls
# produced 0 verified claims and 0 pinned facts, so nothing the run learned was
# ever written down. The run also received six ``Path stall: ... blackboard is
# still EMPTY`` diagnostics and never reacted. Counts, not interpretation.
_NO_CONCLUSION_TOOLS = 50  # above this, "no claims" is a real signal not a short run


@dataclass
class ToolStat:
    name: str
    calls: int = 0
    failures: int = 0


@dataclass
class RunBrief:
    run_dir: str
    run_name: str = ""
    target: str = ""
    goal: str = ""
    started_at: str = ""
    status: str = ""
    complete_reason: str = ""
    completed: bool = False

    evidence: int = 0
    tool_calls: int = 0
    steps: int = 0
    verified_claims: int = 0
    pinned_facts: int = 0
    findings: int = 0
    blackboard_angles: int = 0

    tools: list[ToolStat] = field(default_factory=list)
    distinct_targets_probed: list[str] = field(default_factory=list)
    #: ``[{"token": ..., "kind": "value"|"template"}]`` — labelled, never filtered.
    flag_shaped: list[dict[str, str]] = field(default_factory=list)
    final_answer: str = ""
    compact_summary: str = ""

    log_path: str = ""
    log_lines: int = 0
    log_signals: dict[str, int] = field(default_factory=dict)
    last_thinking: str = ""

    #: Derived, still non-interpretive: they describe the run's own bookkeeping.
    health: list[str] = field(default_factory=list)
    empty_blackboard: bool = False
    spent_budget: bool = False


_FLAG_SHAPE_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{1,20}\{[^{}\n]{4,120}\}")


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def _find_state_file(run_dir: Path) -> Path | None:
    """The target state file, whichever target directory holds it.

    A run can hold several targets; the reviewer only needs the one with content,
    so pick the largest state file rather than guessing at a key.
    """
    candidates = sorted(run_dir.glob("targets/*/state/current.json"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_size if p.exists() else 0)


def _tool_stats(tool_calls: list[dict[str, Any]]) -> list[ToolStat]:
    stats: dict[str, ToolStat] = {}
    for call in tool_calls:
        if not isinstance(call, dict):
            continue
        name = str(call.get("tool") or "?")
        stat = stats.setdefault(name, ToolStat(name=name))
        stat.calls += 1
        if call.get("ok") is False:
            stat.failures += 1
    return sorted(stats.values(), key=lambda s: (-s.calls, s.name))


def _targets_probed(tool_calls: list[dict[str, Any]]) -> list[str]:
    """Hosts the run actually talked to, in first-seen order.

    Uses the recorded arguments rather than tool output: this is "what did it aim
    at", which is what a reviewer needs to see when the goal was a single host and
    the run wandered to documentation sites.
    """
    seen: list[str] = []
    host_re = re.compile(r"https?://([^/\s'\"<>:]+)")
    for call in tool_calls:
        if not isinstance(call, dict):
            continue
        args = call.get("key_args") or ""
        for host in host_re.findall(str(args)):
            lowered = host.lower()
            if lowered not in seen:
                seen.append(lowered)
    return seen[:20]


#: Words that appear in a challenge's own source as a placeholder, never in a
#: recovered value. Matched as the WHOLE body: a bare `flag{body}` is a template,
#: but `flag{body_of_the_flag}` is still just a word and the classifier must not
#: guess further.
_PLACEHOLDER_BODIES = frozenset(
    "body flag answer value result placeholder xx xxx xxx... todo fill me here "
    "your_flag yourflag insert".split()
)


def _classify_flag_token(token: str) -> str:
    """``"template"`` when the body is code/prose rather than a value.

    Deliberately coarse, and biased toward "value": mislabelling a real flag as a
    template would make a reviewer skip it, while mislabelling a template costs one
    glance. An earlier version called any single-word body a template and got
    ``flag{deadbeef1234}`` and ``flag{c0ffee1234}`` wrong — hex happens to be a
    legal identifier, so "looks like a word" does not mean "is a placeholder".

    Signals used, in order:
      1. the body is a known placeholder word,
      2. the body carries code syntax (`+`, `${`, `{{`, `%s`, `<%`, a call),
      3. the body is empty.
    """
    match = _FLAG_SHAPE_RE.match(token) or _FLAG_SHAPE_RE.search(token)
    body = ""
    if match:
        start = match.group(0).find("{")
        body = match.group(0)[start + 1 : -1] if start >= 0 else ""
    stripped = body.strip().strip("\"'`").strip()
    if not stripped:
        return "template"
    if stripped.lower() in _PLACEHOLDER_BODIES:
        return "template"
    if re.search(r"[+*]|\$\{|\{\{|%[sd]|<%|\w+\s*\(", stripped):
        return "template"
    return "value"


def _flag_shaped(evidence: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Flag-shaped tokens that appear in recorded evidence, each labelled.

    Reported as-is, with no claim about whether they are real. Deduplicated and
    capped: on the 2026-10-31 CMB runs a byte dump produced eight of these and
    every one was noise, so the reviewer must be able to see them and dismiss them
    rather than have them silently filtered.

    ``kind`` separates a template read out of the challenge source from a token
    that looks like an actual value. Both are listed; only the label differs.
    """
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for record in evidence:
        if not isinstance(record, dict):
            continue
        text = str(record.get("content") or record.get("summary") or "")
        for match in _FLAG_SHAPE_RE.findall(text):
            if match in seen:
                continue
            seen.add(match)
            found.append({"token": match, "kind": _classify_flag_token(match)})
        if len(found) >= 12:
            break
    return found[:12]


def _scan_log(path: Path) -> tuple[dict[str, int], str]:
    """Count the markers a reviewer cares about, and keep the last thinking block.

    Signals are counted, never interpreted. ``thinking`` is the model's own
    narration — the only place a misread premise shows up, because it is not
    written to the blackboard. On 2026-11-17 the run concluded from a fact in the
    goal that "the operator knows the password", a reasoning error that existed
    only in this text.
    """
    signals: dict[str, int] = {}
    last_thinking = ""
    patterns = {
        "path_stall": r"Path stall:",
        "tool_error": r"\[tool:[^\]]+\] \[!\]",
        "traceback": r"Traceback \(most recent call last\)",
        "token_budget": r"token budget exhausted",
        "complete_rejected": r"complete_rejected|completion rejected",
        "ask_user": r"等待用户|waiting for user",
        "shadowing": r"COMPILER_FLAG_NAMES|no attribute 'dis'",
        # ``TeeStreamSink`` writes Chinese markers while the runner's own
        # diagnostics are English. Counting only one of the two makes the tool
        # silently under-report depending on which sink produced the log — the
        # 2026-11-17 NeuronShuffle transcript had 44 tool calls and scored zero
        # until both spellings were matched.
        "tool_call": r"→ 调用工具:|→ tool:",
        "tool_result": r"→ 工具结果:|→ result:",
    }
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return signals, last_thinking
    for name, pattern in patterns.items():
        count = len(re.findall(pattern, text))
        if count:
            signals[name] = count
    blocks = re.findall(r"<thinking>\s*(.*?)\s*</thinking>", text, re.DOTALL)
    if blocks:
        last_thinking = " ".join(blocks[-1].split())[:1200]
    return signals, last_thinking


def build_brief(run_dir: Path, log_path: Path | None = None) -> RunBrief:
    """Read one run directory and return its brief. Never raises on bad data."""
    brief = RunBrief(run_dir=str(run_dir), run_name=run_dir.name)
    run_meta = _load_json(run_dir / "run.json")
    if isinstance(run_meta, dict):
        brief.status = str(run_meta.get("status") or "")
        brief.started_at = str(run_meta.get("started_at") or "")
        targets = run_meta.get("targets") or []
        if targets and isinstance(targets[0], dict):
            brief.target = str(targets[0].get("canonical") or targets[0].get("input") or "")

    state = _load_json(_find_state_file(run_dir)) if _find_state_file(run_dir) else None
    if not isinstance(state, dict):
        brief.health.append("no target state found — nothing to review")
        _attach_log(brief, log_path)
        return brief

    agent_state = state.get("agent_state") or {}
    if isinstance(agent_state, dict):
        brief.goal = str(agent_state.get("goal") or "")
        brief.completed = bool(agent_state.get("completed"))
        brief.complete_reason = str(agent_state.get("complete_reason") or "")
        brief.verified_claims = len(agent_state.get("verified_claims") or [])
        brief.pinned_facts = len(agent_state.get("pinned_facts") or [])
        brief.final_answer = str(agent_state.get("final_answer") or "")
        brief.compact_summary = str(agent_state.get("compact_summary") or "")
        evidence = agent_state.get("evidence") or []
        tool_calls = agent_state.get("tool_calls") or []
        steps = agent_state.get("steps") or []
        brief.evidence = len(evidence)
        brief.tool_calls = len(tool_calls)
        brief.steps = len(steps)
        brief.tools = _tool_stats(tool_calls)
        brief.distinct_targets_probed = _targets_probed(tool_calls)
        brief.flag_shaped = _flag_shaped(evidence)

    brief.findings = len(state.get("findings") or [])

    blackboard = state.get("blackboard")
    if isinstance(blackboard, dict):
        nodes = blackboard.get("nodes") or []
        brief.blackboard_angles = sum(
            1 for n in nodes if isinstance(n, dict) and n.get("type") == "angle"
        )
    # The blackboard is not persisted in most runs (measured 2026-11-17: the key
    # is absent and the state subtree is empty), so "no angles" is the normal
    # shape, not a defect on its own. What IS a defect is finishing a long run
    # with no written conclusion of any kind.
    brief.empty_blackboard = (
        brief.verified_claims == 0
        and brief.pinned_facts == 0
        and brief.blackboard_angles == 0
    )

    brief.spent_budget = "token budget exhausted" in brief.complete_reason.lower()
    _attach_log(brief, log_path)

    # ── Derived health notes: describe, do not conclude ──────────────────
    if brief.empty_blackboard and brief.tool_calls >= _NO_CONCLUSION_TOOLS:
        brief.health.append(
            f"{brief.tool_calls} tool calls produced 0 verified claims and 0 pinned "
            f"facts — nothing the run learned was written down"
        )
    if brief.spent_budget:
        brief.health.append("ended on the token budget, not on a decision")
    if not brief.completed and not brief.spent_budget:
        brief.health.append(f"not completed; reason: {brief.complete_reason or '(none recorded)'}")
    if brief.log_signals.get("path_stall"):
        brief.health.append(
            f"{brief.log_signals['path_stall']} path-stall diagnostics in the log"
        )
    if brief.log_signals.get("shadowing"):
        brief.health.append(
            "log contains the stdlib-shadowing error — check whether the staging "
            "fix was active for this run"
        )
    per_call = brief.evidence / brief.tool_calls if brief.tool_calls else 0
    if brief.tool_calls and per_call > 2.5:
        brief.health.append(
            f"{per_call:.1f} evidence records per tool call — duplicate or "
            f"re-listed evidence inflates the board"
        )
    return brief


def _attach_log(brief: RunBrief, log_path: Path | None) -> None:
    if log_path is None or not log_path.is_file():
        return
    brief.log_path = str(log_path)
    try:
        brief.log_lines = sum(1 for _ in log_path.open(encoding="utf-8", errors="replace"))
    except OSError:
        brief.log_lines = 0
    brief.log_signals, brief.last_thinking = _scan_log(log_path)


def render_text(brief: RunBrief) -> str:
    lines = [
        "=" * 72,
        f"RUN  {brief.run_name}",
        "=" * 72,
        f"target      : {brief.target or '(not recorded)'}",
        # Two different facts, both easily misread: run.json's status is about the
        # *process* (it exited cleanly), agent_state.completed is about the *task*
        # (the goal was met). A run that burns its budget exits cleanly with
        # completed=False, and reporting only one of them invites the wrong reading.
        f"status      : run={brief.status or '?'}   task_completed={brief.completed}",
        f"reason      : {brief.complete_reason or '(none)'}",
        "",
        "GOAL",
        f"  {brief.goal[:600] or '(empty)'}",
        "",
        "WORK DONE",
        f"  tool calls {brief.tool_calls}   evidence {brief.evidence}   steps {brief.steps}",
        f"  verified claims {brief.verified_claims}   pinned facts {brief.pinned_facts}"
        f"   angles {brief.blackboard_angles}   findings {brief.findings}",
    ]
    if brief.tools:
        top = ", ".join(f"{t.name}×{t.calls}" for t in brief.tools[:8])
        lines.append(f"  tools: {top}")
    if brief.distinct_targets_probed:
        lines.append(f"  hosts aimed at: {', '.join(brief.distinct_targets_probed[:10])}")

    if brief.flag_shaped:
        lines += ["", "FLAG-SHAPED TOKENS IN EVIDENCE (unverified — not a claim)"]
        for item in brief.flag_shaped:
            label = "template" if item.get("kind") == "template" else "value"
            lines.append(f"  [{label:8}] {str(item.get('token', ''))[:100]}")

    if brief.log_signals:
        lines += ["", "LOG SIGNALS"]
        for name, count in sorted(brief.log_signals.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {name}: {count}")
    if brief.last_thinking:
        lines += ["", "LAST THINKING BLOCK (model's own narration, not evidence)"]
        for chunk in [brief.last_thinking[i:i + 110] for i in range(0, min(700, len(brief.last_thinking)), 110)]:
            lines.append(f"  {chunk}")

    if brief.health:
        lines += ["", "HEALTH (counts, not conclusions)"]
        for note in brief.health:
            lines.append(f"  - {note}")

    if brief.final_answer:
        lines += ["", "FINAL ANSWER", f"  {brief.final_answer[:400]}"]
    elif brief.compact_summary:
        lines += ["", "COMPACT SUMMARY", f"  {brief.compact_summary[:400]}"]
    else:
        lines += ["", "FINAL ANSWER", "  (empty — the run recorded no conclusion)"]
    return "\n".join(lines)


def brief_to_dict(brief: RunBrief) -> dict[str, Any]:
    return {
        "run_dir": brief.run_dir,
        "run_name": brief.run_name,
        "target": brief.target,
        "goal": brief.goal,
        "status": brief.status,
        "completed": brief.completed,
        "complete_reason": brief.complete_reason,
        "tool_calls": brief.tool_calls,
        "evidence": brief.evidence,
        "steps": brief.steps,
        "verified_claims": brief.verified_claims,
        "pinned_facts": brief.pinned_facts,
        "blackboard_angles": brief.blackboard_angles,
        "findings": brief.findings,
        "tools": [{"name": t.name, "calls": t.calls, "failures": t.failures} for t in brief.tools],
        "hosts": brief.distinct_targets_probed,
        "flag_shaped": brief.flag_shaped,
        "log": {"path": brief.log_path, "lines": brief.log_lines, "signals": brief.log_signals},
        "last_thinking": brief.last_thinking,
        "health": brief.health,
        "final_answer": brief.final_answer,
        "compact_summary": brief.compact_summary,
    }


def _latest_run(runs_root: Path, needle: str = "") -> Path | None:
    if not runs_root.is_dir():
        return None
    dirs = [p for p in runs_root.iterdir() if p.is_dir() and (p / "run.json").is_file()]
    if needle:
        dirs = [p for p in dirs if needle.lower() in p.name.lower()]
    if not dirs:
        return None
    # Sort by the recorded start time when available, else by directory name.
    # Directory names carry a UTC timestamp but are truncated to fit a path
    # component, so two runs of the same target on the same second can collide
    # in name space while `started_at` still orders them correctly.
    def _key(path: Path) -> tuple[str, str]:
        meta = _load_json(path / "run.json") or {}
        started = str(meta.get("started_at") or "") if isinstance(meta, dict) else ""
        return (started, path.name)

    return max(dirs, key=_key)


def _candidate_roots(explicit: str = "") -> list[Path]:
    """Every place a run directory may live, most-specific first.

    Runs do **not** live next to the config: when ``session.solve_work_root`` is
    set, ``_run_context_kwargs`` puts them under ``<solve_work_root>/runs``. On
    this machine that is ``E:\\vulnclaw\\work\\runs`` while the default root is
    ``~/.vulnclaw/runs`` — measured 2026-11-17, ``--latest`` reported
    "run directory not found" for a run that had just finished, because it only
    looked at the default. Scanning both is cheaper and more durable than
    re-implementing the config precedence here.
    """
    if explicit:
        return [Path(explicit)]
    roots: list[Path] = []
    env_runs = os.environ.get("VULNCLAW_RUNS_DIR")
    if env_runs:
        roots.append(Path(env_runs))
    config_dir = os.environ.get("VULNCLAW_CONFIG_DIR")
    base = Path(config_dir) if config_dir else Path.home() / ".vulnclaw"
    roots.append(base / "runs")
    work_root = _solve_work_root()
    if work_root is not None:
        roots.append(work_root / "runs")
    # De-duplicate while keeping order.
    seen: set[str] = set()
    unique: list[Path] = []
    for root in roots:
        key = str(root).lower()
        if key not in seen:
            seen.add(key)
            unique.append(root)
    return unique


def _solve_work_root() -> Path | None:
    """``session.solve_work_root`` from the loaded config, or None.

    Imported lazily and defensively: this script is also run with ``-I`` against
    arbitrary run directories, and a config that fails to load must not make the
    tool unusable.
    """
    try:
        from vulnclaw.config.settings import load_config

        value = getattr(load_config().session, "solve_work_root", "") or ""
        return Path(value).expanduser() if value else None
    except Exception:  # noqa: BLE001 - config is a convenience, not a requirement
        return None


def _latest_anywhere(needle: str = "", explicit_root: str = "") -> Path | None:
    """Newest run across every candidate root."""
    best: Path | None = None
    best_key: tuple[str, str] = ("", "")
    for root in _candidate_roots(explicit_root):
        candidate = _latest_run(root, needle)
        if candidate is None:
            continue
        meta = _load_json(candidate / "run.json") or {}
        started = str(meta.get("started_at") or "") if isinstance(meta, dict) else ""
        key = (started, candidate.name)
        if best is None or key > best_key:
            best, best_key = candidate, key
    return best


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", nargs="?", help="Run directory to summarise")
    parser.add_argument("--latest", action="store_true", help="Pick the newest run instead")
    parser.add_argument(
        "--match", default="", help="With --latest, only runs whose name contains this"
    )
    parser.add_argument("--runs-root", default="", help="Runs root (default: ~/.vulnclaw/runs)")
    parser.add_argument("--log", default="", help="stdout log saved beside the run")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    run_dir: Path | None
    if args.run_dir:
        run_dir = Path(args.run_dir)
    elif args.latest:
        run_dir = _latest_anywhere(args.match, args.runs_root)
    else:
        parser.error("give a run directory or --latest")
        return 2

    if run_dir is None or not run_dir.is_dir():
        searched = ", ".join(str(p) for p in _candidate_roots(args.runs_root))
        print(
            f"no run found (searched: {searched})"
            f"{f' matching {args.match!r}' if args.match else ''}",
            file=sys.stderr,
        )
        return 2

    log_path = Path(args.log) if args.log else None
    brief = build_brief(run_dir, log_path)
    if args.json:
        print(json.dumps(brief_to_dict(brief), ensure_ascii=False, indent=2))
    else:
        print(render_text(brief))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())