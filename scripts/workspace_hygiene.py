"""Workspace hygiene probe — make ignored garbage visible again.

``git status`` clean only means everything stray is gitignored, not that the
tree is clean. Solve scratch, tool downloads, and test sandboxes pile up behind
the ignore rules (one measured day: 110 stray root files + 48MB of test-tmp +
25MB of sqlmap install leftovers). This probe surfaces them:

  * root-level ignored files        -> reported as NEW STRAYS (exit 1)
  * ignored directories (by size)   -> reported with a known/unknown verdict
  * fresh strays (< STALE_HOURS)    -> flagged as likely a live session's work

Known directories carry a reason and are not strays; anything else at the repo
root that git ignores is, by convention here, garbage that should be archived
or deleted. Use --json for machine-readable output.

Usage:
    python scripts/workspace_hygiene.py [--json]
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# A stray younger than this may belong to a concurrently running solve/test
# session (parallel ZCode sessions share this checkout) — report, don't touch.
STALE_HOURS = 12

# Ignored directories that are intentional. Anything not listed here shows up
# as an UNKNOWN directory worth a look.
KNOWN_DIRS: dict[str, str] = {
    ".ir-tools": "installed toolchain (exiftool/binwalk/volatility3/D-shield) — never delete",
    ".test-tmp": "test sandbox (auto-pruned by conftest at session start)",
    ".pytest_cache": "pytest cache (auto-rebuilt)",
    ".zcode": "ZCode session plans/workflows",
    "docs": "workspace docs, gitignored by convention",
    "demo": "demo fixtures (gitignore rule is root-anchored on purpose)",
    "kernels": "pwn replay kernel/module assets",
    "tsec_bench": "TSecBench benchmark workspace (HANDOFF/c03 analysis live here)",
    "vulnclaw-output": "solve run outputs + tool download residue",
    "ir-collection": "IR drill collection artifacts (competition prep)",
    "__pycache__": "bytecode cache (auto-rebuilt)",
    "node_modules": "web UI build deps",
}


def _git_ignored_entries() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
        capture_output=True,
        cwd=REPO_ROOT,
    ).stdout
    names = [chunk.decode("utf-8", errors="replace") for chunk in out.split(b"\0") if chunk]
    # un-quote core.quotePath escapes for non-ASCII names
    return [n[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape") if n.startswith('"') else n for n in names]


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def _tracked_top_dirs() -> set[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], capture_output=True, cwd=REPO_ROOT
    ).stdout
    dirs: set[str] = set()
    for chunk in out.split(b"\0"):
        if not chunk:
            continue
        name = chunk.decode("utf-8", errors="replace")
        if "/" in name:
            dirs.add(name.split("/", 1)[0])
    return dirs


def scan() -> dict:
    entries = _git_ignored_entries()
    top_level: dict[str, dict] = {}
    root_files: list[str] = []
    for name in entries:
        first = name.split("/", 1)[0]
        top_level.setdefault(first, {"files": 0, "entries": []})["files"] += 1
        top_level[first]["entries"].append(name)
        if "/" not in name:
            root_files.append(name)

    now = _dt.datetime.now()
    strays: list[dict] = []
    for name in sorted(set(root_files)):
        path = REPO_ROOT / name
        try:
            stat = path.stat()
        except OSError:
            continue
        age_h = (now - _dt.datetime.fromtimestamp(stat.st_mtime)).total_seconds() / 3600
        strays.append(
            {
                "file": name,
                "bytes": stat.st_size,
                "mtime": _dt.datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="minutes"),
                "fresh": age_h < STALE_HOURS,
            }
        )

    tracked = _tracked_top_dirs()
    dirs: list[dict] = []
    strays_in_tracked: list[str] = []
    for name in sorted(top_level):
        path = REPO_ROOT / name
        if "/" in name or (name in root_files):
            continue  # a root-level file, not a directory
        if not path.is_dir():
            continue
        try:
            visible = any(path.iterdir())
        except OSError:
            visible = True
        if not visible:
            continue
        if name in tracked:
            # tracked code dir: ignored content should be __pycache__ only
            odd = [
                e
                for e in top_level[name]["entries"]
                if "/__pycache__/" not in f"/{e}" and "__pycache__" not in e.split("/")[1:2]
            ]
            if odd:
                strays_in_tracked.extend(odd[:20])
            reason = "bytecode caches inside a tracked code dir (auto-rebuilt)"
            known = True
        elif name in KNOWN_DIRS:
            reason = KNOWN_DIRS[name]
            known = True
        else:
            reason = "UNKNOWN — inspect, then delete or add to KNOWN_DIRS with a reason"
            known = False
        dirs.append(
            {
                "dir": name,
                "known": known,
                "reason": reason,
                "files": top_level[name]["files"],
                "bytes": _dir_size(path),
            }
        )
    dirs.sort(key=lambda d: -d["bytes"])

    return {
        "ok": not strays,
        "strays": strays,
        "strays_in_tracked_dirs": strays_in_tracked,
        "fresh_strays": [s for s in strays if s["fresh"]],
        "dirs": dirs,
        "hint": (
            "root strays: archive to E:\\vulnclaw\\work\\<topic>-scratch\\ or delete; "
            "fresh ones (<{h}h) may be a live session's work — leave them"
        ).format(h=STALE_HOURS),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    report = scan()

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ok"] else 1

    if report["ok"]:
        print("workspace-hygiene OK — no root-level strays.")
    else:
        print(f"workspace-hygiene: {len(report['strays'])} root-level stray file(s):")
        for s in report["strays"]:
            mark = "FRESH " if s["fresh"] else "stale "
            print(f"  [{mark}] {s['mtime']}  {s['bytes']:>9}  {s['file']}")
        print(f"  -> {report['hint']}")

    if report.get("strays_in_tracked_dirs"):
        print("\nignored non-pycache files inside tracked code dirs:")
        for e in report["strays_in_tracked_dirs"]:
            print(f"  {e}")

    print("\nignored directories by size:")
    for d in report["dirs"]:
        mb = d["bytes"] / 1_048_576
        tag = "known " if d["known"] else "UNKNOWN"
        print(f"  [{tag}] {mb:8.1f} MB {d['files']:>6} files  {d['dir']}"
              + ("" if d["known"] else f"  — {d['reason']}"))
        if d["known"] and mb > 200:
            print(f"          (large; prune when convenient)")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
