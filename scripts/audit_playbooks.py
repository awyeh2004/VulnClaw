#!/usr/bin/env python3
"""Audit the VulnClaw playbook store without mutating it.

Exit codes: 0 clean, 1 quality findings, 2 probable secret/flag residue.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

from vulnclaw.agent import playbook as pb

FLAG_RE = re.compile(r"(?i)(?:CTF2|DASCTF|FLAG|D0g3|SETCTF|GKCTF)\{(?![^\n}]*…)[^\n}]{5,}\}")
# A real flag is often truncated in a note (no closing brace, e.g. an ELF string
# constant copied from `strings`). FLAG_RE cannot see those, so a literal fragment
# leaked into a fingerprint went unnoticed. Informational, not blocking: the
# ``…``-masked forms and short placeholders (flag{xxxx}) are excluded on purpose.
FLAG_FRAGMENT_RE = re.compile(
    r"(?i)(?:CTF2|DASCTF|FLAG|D0g3|SETCTF|GKCTF)\{(?![^\n]*…)[^\s}…\n]{6,}"
)
REQUIRED_FIELDS = ("name", "fingerprint", "status", "source", "updated_at")
# The store's real write gate (vulnclaw.agent.playbook.save_playbook) only demands
# len(text) >= MIN_PLAYBOOK_CHARS (80) plus AT LEAST ONE structured heading.
# STEPS is a recommended completeness field, not a gate: treating it as required
# over-reported the gap by ~190 notes and sent a cleanup at a non-problem.
GATE_HEADINGS = ("LOCK", "CONFIRMED", "ANGLES")
FORMAT_HEADINGS = ("LOCK", "CONFIRMED", "ANGLES", "STEPS")


def audit() -> dict:
    notes = pb.list_playbooks()
    result = {
        "playbook_dir": str(pb.PLAYBOOKS_DIR),
        "count": len(notes),
        "status": dict(Counter(n.status for n in notes)),
        "source": dict(Counter(n.source for n in notes)),
        "missing_fields": [],
        "short": [],
        "missing_headings": [],
        "ungated": [],
        "duplicate_names": [],
        "duplicate_fingerprints": [],
        "raw_flag_residue": [],
        "raw_flag_fragments": [],
    }
    names = Counter(n.name for n in notes)
    fingerprints = Counter(n.fingerprint for n in notes)
    result["duplicate_names"] = sorted(k for k, v in names.items() if v > 1)
    result["duplicate_fingerprints"] = sorted(k for k, v in fingerprints.items() if v > 1)
    for note in notes:
        path = pb.PLAYBOOKS_DIR / f"{note.slug}.md"
        raw = path.read_text(encoding="utf-8")
        meta, _ = pb._parse_frontmatter(raw)
        missing = [field for field in REQUIRED_FIELDS if not str(meta.get(field, "")).strip()]
        if missing:
            result["missing_fields"].append({"slug": note.slug, "fields": missing})
        if len(note.steps.strip()) < 80:
            result["short"].append(note.slug)
        body = note.steps.upper()
        absent = [heading for heading in FORMAT_HEADINGS if heading not in body]
        if absent:
            result["missing_headings"].append({"slug": note.slug, "headings": absent})
        if not any(heading in body for heading in GATE_HEADINGS):
            result["ungated"].append(note.slug)
        if FLAG_RE.search(raw):
            result["raw_flag_residue"].append(note.slug)
        if FLAG_FRAGMENT_RE.search(raw):
            result["raw_flag_fragments"].append(note.slug)
    result["blocking_findings"] = bool(
        result["missing_fields"]
        or result["duplicate_names"]
        or result["duplicate_fingerprints"]
        or result["raw_flag_residue"]
        or result["ungated"]
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()
    result = audit()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else json.dumps(result, ensure_ascii=False))
    return 2 if result["raw_flag_residue"] else (1 if result["blocking_findings"] or result["short"] or result["missing_headings"] else 0)


if __name__ == "__main__":
    raise SystemExit(main())
