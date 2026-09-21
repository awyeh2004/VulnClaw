#!/usr/bin/env python3
"""Token-lean watchdog for a vulnclaw run.

Designed to be launched by an agent as a BACKGROUND job, so its output becomes
context later. That constraint decides everything below.

Why not the text-marker approach
--------------------------------
The obvious design searches the log for a marker:

    i, j = d.find('目标达成'), d.find('未达成')

Measured on a real solve log, that never fires: the marker bytes are not present
in the file at all, under UTF-8 or GBK (the visible text is double-encoded
mojibake). So the "solved"/"failed" conditions were dead and the watchdog was
silently relying on its stall timer alone.

Robust instead: read vulnclaw's own structured state.
  * ``run.json``            -> status: running | completed | failed, exit_code
  * ``python_execute_audit.jsonl`` mtime -> activity (cheap, no file read)

Token budget
------------
The old design wrote 300-800 characters of raw log into its report. The agent
does not need log prose -- it needs the state and where to look next, so the
default report is ~6 short lines. Milestones are printed as they happen (so
progress is visible without polling), and ``--verbose`` exists for the rare case
where human-readable detail is actually wanted.

Usage (agent: run this in the background)
----------------------------------------
    python scripts/run_watchdog.py --run ctf2-stack2
    python scripts/run_watchdog.py --run ctf2-stack2 --stall-secs 420 --max-minutes 55

Supervising a run that is already in flight
-------------------------------------------
Three modes, cheapest first. Pick ONE -- two watchdogs on one run duplicate every
notification, and the periodic modes are what make "check on it" cheap at all:

    --status                  one shot, ~10 lines, no polling. Use to peek mid-flight.
    --follow                  one line per CHANGE, then the final block. Use when you
                              want a running narrative (~1 line per 30s of progress).
    --follow --quiet          silent until the run ends or needs input, then ONE block.
                              This is the one to use for unattended supervision: a
                              single background call, and all N polls cost one block.

Do NOT poll `--status` yourself in a loop: N checks then cost N tool calls and N full
blocks, which is precisely the token cost these modes exist to avoid.

Exit status is always 0: the OUTCOME is written to stdout and to the report file,
and a non-zero exit would look like the watchdog itself failed.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime
from pathlib import Path

def _default_home() -> Path:
    """The config dir the run wrote into — resolved exactly like vulnclaw itself.

    Order matters, and so does having only ONE order. ``VULNCLAW_CONFIG_DIR`` is
    authoritative because it is what the run process itself honoured
    (``vulnclaw/config/settings.py:69``); otherwise the default is
    ``~/.vulnclaw``.

    Round-5 review N9: this used to insert a repo-local
    ``.test-tmp/vulnclaw-home`` step BEFORE the real default. That directory only
    ever exists on a development machine (it is a leftover of the local drills),
    and because it was consulted first, a stray copy hijacked the watchdog — which
    then silently reported on a different directory's runs, or on none at all, and
    an empty run dir is exactly what makes a watchdog call a healthy run stalled.
    The resolution is delegated to vulnclaw's own settings, so the watchdog and
    the run can no longer disagree.
    """
    try:
        from vulnclaw.config.settings import CONFIG_DIR

        return Path(CONFIG_DIR)
    except Exception:
        env = os.environ.get("VULNCLAW_CONFIG_DIR")
        if env:
            return Path(env)
        return Path.home() / ".vulnclaw"


DEFAULT_HOME = _default_home()


def _run_dir(home: str | Path, run: str) -> Path:
    """``<home>/runs/<run>``, with ``run`` confined to the runs directory.

    Round-5 review N9: ``--run ../../x`` walked out of ``runs/``, so the watchdog
    read state — and wrote its report — outside the runs tree. A run name is a
    single directory entry; anything else is a mistake worth stopping for.
    """
    name = str(run or "").strip()
    if not name or name in (".", ".."):
        raise SystemExit("[!] --run needs a run name (see --list)")
    if any(ch in name for ch in ("/", "\\", ":", "\x00")):
        raise SystemExit(f"[!] --run must be a bare run name, got {name!r}")
    root = (Path(home) / "runs").resolve()
    candidate = (root / name).resolve()
    if candidate != root and root not in candidate.parents:
        raise SystemExit(f"[!] --run escapes the runs directory: {candidate}")
    return candidate


def _safe_mtime(path: Path) -> float:
    """mtime, or -1 when the file vanished between listing and stat."""
    try:
        return path.stat().st_mtime
    except OSError:
        return -1.0


def _fmt_age(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"


def _read_json(path: Path) -> dict:
    """Tolerant read: run.json is rewritten in place, so a partial read is normal."""
    for _ in range(3):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            time.sleep(0.2)
    return {}


def _newest_mtime(run_dir: Path, log_path: Path | None) -> tuple[float | None, str]:
    """(mtime, label) of the newest sign of life, or (None, reason).

    ⚠️ SOURCE ORDERING MATTERS for the liveness signal, and getting it wrong makes
    `--status` useless exactly when it is needed. Measured on a live run:

        activity: 54s ago (events.jsonl)     <- run was healthy, first LLM turn

    ``events.jsonl`` and the state checkpoints are only written at CHECKPOINT
    boundaries (turn end), so during a turn they look frozen while the run is
    working perfectly. `python_execute_audit.jsonl` is appended mid-turn, so it is
    the finest-grained signal available -- it is therefore reported PREFERENTIALLY,
    and only when it is absent do the coarser sources get used.

    Returns None -- not 0.0 -- when nothing exists yet. An earlier version returned
    `time.time() - 0.0` ("age = 56 years", a false stall) and, in the other
    direction, made an empty directory look perpetually fresh.
    """
    # Finest-grained first: appended as tool calls happen, i.e. mid-turn.
    for p in run_dir.rglob("python_execute_audit.jsonl"):
        try:
            return p.stat().st_mtime, p.name
        except OSError:
            pass
    if log_path is not None and log_path.exists():
        try:
            return log_path.stat().st_mtime, log_path.name
        except OSError:
            pass

    candidates: list[tuple[float, str]] = []
    for p, label in (
        (run_dir / "run.json", "run.json"),
        (run_dir / "targets", "targets/"),
        (run_dir / "events", "events/"),
    ):
        if not p.exists():
            continue
        try:
            candidates.append((p.stat().st_mtime, label))
        except OSError:
            pass
    if not candidates:
        return None, "no activity files yet"
    return max(candidates)


def _activity_age(run_dir: Path, log_path: Path | None) -> tuple[float, str]:
    mtime, label = _newest_mtime(run_dir, log_path)
    if mtime is None:
        return -1.0, label  # -1 == "unknown", never treated as stale
    return time.time() - mtime, label


def _find_log(run_dir: Path) -> Path | None:
    """Audit log is the cheapest reliable liveness signal; fall back to any file."""
    for p in run_dir.rglob("python_execute_audit.jsonl"):
        return p
    files = [p for p in run_dir.rglob("*") if p.is_file()]
    return max(files, key=_safe_mtime) if files else None


def _outcome(run_dir: Path) -> dict:
    """How the run actually ENDED, read from the state checkpoint.

    ⚠️ ``run.json.status == "completed"`` does NOT mean the task finished. On a
    real run measured here:

        run.json       status = completed, exit_code = 0
        agent_state    completed = False
                       complete_reason = "waiting for user input"
                       pending_questions = ["是否需要继续读取这两个文件...?"]

    The process exited normally while the AGENT was still mid-task, blocked on a
    question for the operator. A watchdog that trusts ``run.json`` reports
    "completed" and the supervisor closes a run that is really waiting on them --
    a false success, the most expensive kind of wrong answer. So the boolean
    ``agent_state.completed`` is authoritative, and the two signals are reported
    separately when they disagree rather than being flattened into one word.

    Returns {} when no checkpoint exists yet (run still starting).
    """
    newest: tuple[float, dict] | None = None
    for cur in run_dir.rglob("current.json"):
        data = _read_json(cur)
        if not data:
            continue
        try:
            mtime = cur.stat().st_mtime
        except OSError:
            continue
        if newest is None or mtime > newest[0]:
            newest = (mtime, data)
    if newest is None:
        return {}

    state = newest[1]
    agent_state = state.get("agent_state") or {}
    # complete_reason doubles as the reason string when completed is False, so it
    # is read before final_answer for the needs-input case.
    answer = str(agent_state.get("final_answer") or "").strip()
    reason = str(agent_state.get("complete_reason") or "").strip()
    questions = [str(q).strip() for q in (agent_state.get("pending_questions") or []) if str(q).strip()]
    return {
        "completed": agent_state.get("completed"),
        "answer": (answer or reason).splitlines()[0][:200] if (answer or reason) else "",
        "reason": reason,
        "questions": questions,
    }


def _final_answer(run_dir: Path) -> str:
    """First line of the recorded final answer (or completion reason), or ''."""
    return _outcome(run_dir).get("answer", "")


def _report_path(run_dir: Path, explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    return run_dir / "watchdog.txt"


def _current_state(run_dir: Path) -> Path | None:
    """The newest per-target state file.

    It is CHECKPOINT-written, so it can lag the live state by up to one turn --
    which is exactly why `--status` also reports the audit log's mtime separately:
    "state says 6 steps but activity was 3s ago" tells you a turn is in flight.
    """
    files = list(run_dir.rglob("current.json"))
    if not files:
        return None
    return max(files, key=_safe_mtime)


def _status_lines(args: argparse.Namespace) -> tuple[list[str], str, tuple[int, int]]:
    """Build the status block. Returns (lines, status, (evidence, tool_calls)).

    ``status`` is the EFFECTIVE state, not ``run.json``'s raw word: a run whose
    checkpoint says ``completed=False`` is reported as ``needs-input`` even though
    its process already exited with status ``completed`` (see :func:`_outcome`).

    Separate from :func:`print_status` so ``--follow`` can compare successive
    snapshots without printing an unchanged block again.
    """
    run_dir = _run_dir(args.home, args.run)
    run_json = _read_json(run_dir / "run.json")
    log_path = _find_log(run_dir)
    age, source = _activity_age(run_dir, log_path)

    status = str(run_json.get("status") or "unknown")
    raw_status = status
    lines = [f"STATUS {args.run}: {status}"]
    lines.append(
        f"activity: {_fmt_age(age) + ' ago' if age >= 0 else 'none yet'} ({source})"
    )
    started_at = str(run_json.get("started_at") or "")
    if started_at:
        lines.append(f"started: {started_at[:19].replace('T', ' ')}")

    state_path = _current_state(run_dir)
    if state_path is None:
        lines.append("no state checkpoint yet (run may still be starting)")
        return lines, status, (0, 0)

    state = _read_json(state_path)
    agent_state = state.get("agent_state") or {}
    evidence = agent_state.get("evidence") or []
    calls = agent_state.get("tool_calls") or []

    lines.append(
        f"progress: phase={state.get('phase') or '?'} "
        f"evidence={len(evidence)} tool_calls={len(calls)} "
        f"findings={len(state.get('findings') or [])}"
    )

    # What it just did. Tool names are short, so a chain of them is the cheapest
    # possible "narrative" of the last few turns.
    recent = [str(e.get("tool") or e.get("name") or "?") for e in calls[-6:]]
    if recent:
        lines.append("recent tools: " + " -> ".join(recent))

    signals = agent_state.get("progress_signals") or []
    if signals:
        last = signals[-1]
        tool = str(last.get("tool") or "")
        detail = str(last.get("detail") or "")[:90]
        lines.append(f"last signal: {tool + ': ' if tool else ''}{detail}")

    outcome = _outcome(run_dir)
    # `completed is False` is also the normal state of a HEALTHY in-flight run, so
    # it only means "blocked" once the process has stopped (or is stopping). An
    # earlier version stamped "BLOCKED on a reply" onto a live `running` run during
    # a TIMEOUT -- it was still working, not waiting on anyone.
    if status.lower() != "running" or outcome.get("completed") is False:
        if outcome.get("completed") is False:
            if raw_status.lower() == "running":
                # Still alive: report the outstanding question as news, not as a block.
                for q in outcome.get("questions", [])[:3]:
                    lines.append(f"pending question: {q[:200]}")
            else:
                status = "needs-input"
                lines[0] = f"STATUS {args.run}: NEEDS INPUT (run.json says {raw_status})"
                if outcome.get("answer"):
                    lines.append(f"asking: {outcome['answer'][:160]}")
                for q in outcome.get("questions", [])[:3]:
                    lines.append(f"question: {q[:200]}")
                lines.append("^ the run is BLOCKED on a reply -- it has NOT finished the task")
        elif outcome.get("answer") and status.lower() != "running":
            lines.append(f"final: {outcome['answer']}")

    lines.append(f"state: {state_path}")
    return lines, status, (len(evidence), len(calls))


def print_status(args: argparse.Namespace) -> int:
    """One-shot progress view. No polling: one process, a few lines.

    Kept deliberately narrow. Deeper inspection already exists (`evidence_view` /
    `evidence_search` over the same run directory), so this answers only the
    supervisor's question: is it alive, how far in, and what did it just do.
    """
    lines, _status, _counts = _status_lines(args)
    print("\n".join(lines), flush=True)
    return 0


def follow_status(args: argparse.Namespace) -> int:
    """Print a status line only when something CHANGED, until the run ends.

    Why this beats "call --status repeatedly yourself": the polling loop lives in
    the process, so N checks cost N short lines of context instead of N process
    invocations plus N full blocks. Silence means "no change", which is itself the
    useful signal -- a supervisor does not need to see the same counters twice.

    ``--quiet`` drops even the per-change running lines and emits only the final
    block, i.e. it blocks until the run either finishes or needs a human. That is
    the cheapest correct supervision loop: one tool call in, one line of verdict
    out.
    """
    last: tuple[str, tuple[int, int]] | None = None
    started = time.time()
    while time.time() - started < args.max_minutes * 60:
        lines, status, counts = _status_lines(args)
        key = (status.lower(), counts)
        if key != last:
            last = key
            stamp = f"[{datetime.now():%H:%M:%S}]"
            if status.lower() == "running":
                if not args.quiet:
                    print(f"{stamp} running evidence={counts[0]} tools={counts[1]}",
                          flush=True)
            else:
                print("\n".join(lines), flush=True)
                return 0
        if status.lower() != "running" and last is not None:
            return 0
        time.sleep(args.interval)

    print(f"FOLLOW TIMEOUT after {args.max_minutes:.0f}m", flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Token-lean watchdog for a vulnclaw run")
    ap.add_argument("--run", required=True, help="run name (the runs/<name> directory)")
    ap.add_argument("--home", default=str(DEFAULT_HOME), help="VULNCLAW_CONFIG_DIR used by the run")
    ap.add_argument("--stall-secs", type=float, default=420.0,
                    help="no activity for this long => STUCK (default 420; a reasoning "
                         "model can legitimately spend 5+ minutes in one chain)")
    ap.add_argument("--max-minutes", type=float, default=55.0, help="give up after this long")
    ap.add_argument("--interval", type=float, default=30.0, help="poll interval (seconds)")
    ap.add_argument("--report", default=None, help="report path (default runs/<name>/watchdog.txt)")
    ap.add_argument("--verbose", action="store_true",
                    help="include a short log tail in the report (off by default: token cost)")
    ap.add_argument("--status", action="store_true",
                    help="print current progress once and exit (no polling) -- use this "
                         "to check on a run mid-flight without disturbing the watchdog")
    ap.add_argument("--follow", action="store_true",
                    help="print a status line only when it CHANGES, until the run ends "
                         "(cheapest way to watch progress: the loop runs in this process, "
                         "so N checks cost N short lines, not N tool calls)")
    ap.add_argument("--quiet", action="store_true",
                    help="with --follow: stay silent until the run ends or needs input, "
                         "then print the final block once (best for background supervision)")
    args = ap.parse_args()

    if args.status:
        return print_status(args)
    if args.follow:
        return follow_status(args)

    run_dir = _run_dir(args.home, args.run)
    report = _report_path(run_dir, args.report)
    started = time.time()

    def emit(outcome: str, detail: str = "") -> int:
        lines = [
            f"WATCHDOG {outcome}",
            f"run: {args.run}",
            f"waited: {_fmt_age(time.time() - started)}",
        ]
        if detail:
            lines.append(f"detail: {detail}")
        lines.append(f"run.json: {run_dir / 'run.json'}")
        lines.append(f"report:   {report}")
        text = "\n".join(lines) + "\n"
        try:
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(text, encoding="utf-8")
        except OSError:
            pass
        print(text, end="", flush=True)
        return 0

    print(f"WATCHDOG started run={args.run} stall={_fmt_age(args.stall_secs)} "
          f"max={args.max_minutes:.0f}m", flush=True)

    last_logged: str | None = None
    last_milestone = 0.0
    while time.time() - started < args.max_minutes * 60:
        run_json = _read_json(run_dir / "run.json")
        status = str(run_json.get("status") or "").lower()
        log_path = _find_log(run_dir)
        age, source = _activity_age(run_dir, log_path)
        has_run_json = (run_dir / "run.json").exists()

        # ── milestone: state CHANGED, so print once and keep going ──────
        if status and status != last_logged:
            last_logged = status
            if status == "running":
                print(f"[{datetime.now():%H:%M:%S}] status=running (watching; "
                      f"stall>{_fmt_age(args.stall_secs)})", flush=True)
            else:
                outcome = _outcome(run_dir)
                detail = f"exit_code={run_json.get('exit_code')}"
                if outcome.get("answer"):
                    detail += f" | final: {outcome['answer']}"
                if outcome.get("completed") is False:
                    # Process is gone but the agent never finished its task: it
                    # stopped to ask the operator something. Saying "ENDED:COMPLETED"
                    # here would invite the supervisor to close a run that is
                    # actually blocked on them.
                    detail += " | BLOCKED: run.json says completed but agent_state"
                    detail += " says completed=False"
                    for q in outcome.get("questions", [])[:3]:
                        detail += f"\n     question: {q[:200]}"
                    return emit("NEEDS_INPUT", detail)
                return emit(f"ENDED:{status.upper()}", detail)

        # ── no run dir yet: the run may simply not have created it. Only
        #    report after the grace period, and say so plainly rather than
        #    pretending it is a stall of a run that never started.
        if not has_run_json:
            if time.time() - started > args.stall_secs:
                return emit("NO_RUN_DIR", f"{run_dir} still has no run.json after "
                                          f"{_fmt_age(time.time() - started)}")
            time.sleep(args.interval)
            continue

        # ── stall (age == -1 means unknown, never stale) ────────────────
        if age >= 0 and age > args.stall_secs:
            detail = f"no activity for {_fmt_age(age)} (newest: {source})"
            if status:
                detail = f"status={status} but " + detail
            if args.verbose and log_path:
                try:
                    tail = log_path.read_text(encoding="utf-8", errors="replace")[-400:]
                    detail += "\n--- tail ---\n" + tail.strip()
                except OSError:
                    pass
            return emit("STUCK", detail)

        # ── reassurance every 10 minutes (2 lines, cheap) ───────────────
        now = time.time()
        if now - last_milestone > 600:
            last_milestone = now
            print(f"[{datetime.now():%H:%M:%S}] alive status={status or '?'} "
                  f"last-activity={_fmt_age(age) if age >= 0 else 'unknown'} ago", flush=True)

        time.sleep(args.interval)

    # A timeout must not be a dead end: if there IS readable state, hand it over.
    # Measured failure of the first version -- it printed
    #     detail: still unknown after 0m
    # which tells the supervisor nothing at all, while the run's own checkpoint
    # already held phase/evidence/tools. Fall back to the raw status word only
    # when no checkpoint exists.
    lines, status, counts = _status_lines(args)
    if counts != (0, 0) or "no state checkpoint" not in " ".join(lines):
        detail = " | ".join(lines[1:])[:600]
    else:
        detail = f"still {last_logged or 'unknown'} after {args.max_minutes:.0f}m"
    return emit("TIMEOUT", detail)


if __name__ == "__main__":
    raise SystemExit(main())
