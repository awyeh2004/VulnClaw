#!/usr/bin/env python
"""Replay per-turn output metrics from VULNCLAW_EVENT_LOG files (audit item B).

Reads ``*.events.ndjson`` run logs and answers ONE question per run: did the
per-turn signals (printable ratio, text size, tool activity, new evidence) move
in a shape that could distinguish "converging" from "flooded/stuck"?

Two log generations, both handled:

* 2026-10-24+: ``turn_metrics`` events carry the exact per-step numbers
  emitted by ``solver._turn_text_metrics`` (full assistant text).
* older logs: ``agent_observation`` records are a PROXY -- ``reason`` is the
  one-lined assistant text (truncated, whitespace collapsed) and ``tools`` is
  the per-step tool list, so printable_ratio is approximate. Proxy rows are
  marked ``proxy`` and must not be treated as measurements.

This tool only REPORTS. Wiring any of these signals into a stall decision
requires replay evidence first (see TECH-DEBT B); this script is how that
evidence gets produced.

Usage:
    python scripts/replay_turn_metrics.py [glob ...] [--json]
    # default glob: %TEMP%/ *.events.ndjson  (E:/vulnclaw/tmp on this host)
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path


def _iter_events(path: Path):
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
    except OSError:
        return


def _proxy_printable_ratio(text: str) -> float:
    body = str(text or "")
    if not body:
        return 0.0
    printable = sum(1 for ch in body if ch.isprintable() or ch in "\n\r\t")
    return round(printable / len(body), 4)


def replay_file(path: Path) -> dict:
    """One run's per-step table + aggregate shape flags."""
    steps: dict[int, dict] = {}
    telemetry = False
    completed = False
    for rec in _iter_events(path):
        kind = str(rec.get("kind", "") or "")
        if kind == "turn_metrics":
            telemetry = True
            step = int(rec.get("step", 0) or 0)
            steps[step] = {
                "chars": int(rec.get("chars", 0) or 0),
                "printable_ratio": float(rec.get("printable_ratio", 0.0) or 0.0),
                "nonempty_lines": int(rec.get("nonempty_lines", 0) or 0),
                "tools": int(rec.get("tools_used", 0) or 0),
                "new_evidence": int(rec.get("new_evidence", 0) or 0),
                "proxy": False,
            }
        elif kind == "agent_observation" and not telemetry:
            step = int(rec.get("step", 0) or 0)
            reason = str(rec.get("reason", "") or "")
            steps.setdefault(
                step,
                {
                    "chars": len(reason),
                    "printable_ratio": _proxy_printable_ratio(reason),
                    "nonempty_lines": 1 if reason.strip() else 0,
                    "tools": len(rec.get("tools", []) or []),
                    "new_evidence": 1 if rec.get("evidence") else 0,
                    "proxy": True,
                },
            )
        elif kind == "completed":
            completed = True

    ordered = [steps[k] for k in sorted(steps)]
    ratios = [s["printable_ratio"] for s in ordered]
    tools = [s["tools"] for s in ordered]
    return {
        "run": path.name,
        "telemetry": telemetry,
        "proxy": bool(ordered) and ordered[0]["proxy"],
        "completed": completed,
        "steps": ordered,
        "ratio_series": ratios,
        "tools_series": tools,
        "ratio_monotone_up_streak": _longest_monotone(ratios, up=True),
        "zero_tool_streak": _longest_run(tools, lambda t: t == 0),
    }


def _longest_monotone(series: list[float], *, up: bool) -> int:
    best = streak = 0
    prev = None
    for value in series:
        if prev is not None and ((up and value >= prev) or (not up and value <= prev)):
            streak += 1
        else:
            streak = 1
        best = max(best, streak)
        prev = value
    return best if len(series) > 1 else 0


def _longest_run(series: list[int], predicate) -> int:
    best = streak = 0
    for value in series:
        streak = streak + 1 if predicate(value) else 0
        best = max(best, streak)
    return best


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "globs",
        nargs="*",
        default=[os.path.join(os.environ.get("TEMP", "/tmp"), "*.events.ndjson")],
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    paths: list[Path] = []
    for pattern in args.globs:
        paths.extend(Path(p) for p in sorted(glob.glob(pattern)))
    if not paths:
        print("no event logs matched", file=sys.stderr)
        return 1

    reports = [replay_file(p) for p in paths]
    telemetry_runs = [r for r in reports if r["telemetry"]]
    proxy_runs = [r for r in reports if r["proxy"]]

    if args.json:
        print(json.dumps(reports, ensure_ascii=False, indent=2))
    else:
        for r in reports:
            tag = "telemetry" if r["telemetry"] else ("proxy" if r["proxy"] else "empty")
            flag = "completed" if r["completed"] else "unfinished"
            print(f"{r['run']}: {tag} {flag} steps={len(r['steps'])} "
                  f"ratio_series={r['ratio_series']} tools_series={r['tools_series']}")
        print(
            f"\nsummary: {len(reports)} runs, {len(telemetry_runs)} with real "
            f"turn_metrics, {len(proxy_runs)} proxy-only (agent_observation), "
            f"{len(reports) - len(telemetry_runs) - len(proxy_runs)} empty."
        )
        if not telemetry_runs:
            print(
                "VERDICT: no telemetry runs yet -- the printable-rate hypothesis "
                "cannot be evaluated from proxy rows. Re-run after solves with "
                "VULNCLAW_EVENT_LOG set (2026-10-24+ emit turn_metrics)."
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
