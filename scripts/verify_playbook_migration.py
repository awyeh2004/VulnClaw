#!/usr/bin/env python3
"""Verify a playbook format migration did not lose or invent content.

For every ``_archive/<slug>.orig.md`` snapshot, compare it against the live
``<slug>.md``:

* frontmatter fields ``name``/``fingerprint``/``status``/``source`` must be
  byte-identical (only ``updated_at`` may move),
* the four structured headings must be present in the body,
* every "hard token" (paths, params, payloads, credentials, CVE ids, commands,
  offsets, hex blobs) present in the original body must still be present,
* anything the body gained that the original never had is reported separately
  so invented facts can be spotted.

Read-only: never writes to the store. Exit 1 when a file fails.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from vulnclaw.agent import playbook as pb

ARCHIVE = pb.PLAYBOOKS_DIR / "_archive"
FROZEN_FIELDS = ("name", "fingerprint", "status", "source")
FORMAT_HEADINGS = ("LOCK", "CONFIRMED", "ANGLES", "STEPS")

# Tokens that carry technical meaning: host/path fragments, params, payload
# pieces, credential-ish strings, CVE ids, offsets, hex, commands.
HARD_TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./\\%#:?=&+~!@$^{}\[\]()-]{2,}")
# Purely conversational words to ignore when reporting *new* tokens.
STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "then", "than",
    "when", "must", "does", "not", "any", "all", "use", "using", "uses",
    "its", "it", "is", "are", "was", "were", "be", "been", "being", "on",
    "in", "into", "to", "of", "or", "as", "at", "by", "if", "so", "but",
    "note", "notes", "step", "steps", "stop", "lock", "confirmed", "angles",
    "preconditions", "related", "status", "draft", "validated", "curated",
    "auto", "keep", "read", "only", "re", "do", "don", "does", "still",
}


def hard_tokens(text: str) -> set[str]:
    out: set[str] = set()
    for raw in HARD_TOKEN_RE.findall(text):
        tok = raw.strip(".,;:)]}\"'-")
        if len(tok) < 3:
            continue
        out.add(tok.lower())
    return out


def split(path: Path) -> tuple[dict[str, str], str]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    meta, body = pb._parse_frontmatter(raw)
    return {k: str(v) for k, v in meta.items()}, body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--slugs-file",
        help="only check the slugs listed (one per line) in this file",
    )
    args = parser.parse_args()

    wanted: set[str] | None = None
    if args.slugs_file:
        wanted = {
            line.strip()
            for line in Path(args.slugs_file).read_text(encoding="utf-8").splitlines()
            if line.strip()
        }

    report: list[dict] = []
    for snap in sorted(ARCHIVE.glob("*.orig.md")):
        slug = snap.name[: -len(".orig.md")]
        if wanted is not None and slug not in wanted:
            continue
        live = pb.PLAYBOOKS_DIR / f"{slug}.md"
        entry: dict = {"slug": slug, "ok": True, "problems": []}
        if not live.exists():
            entry["ok"] = False
            entry["problems"].append("live file missing")
            report.append(entry)
            continue

        old_meta, old_body = split(snap)
        new_meta, new_body = split(live)

        for field in FROZEN_FIELDS:
            if old_meta.get(field, "") != new_meta.get(field, ""):
                entry["ok"] = False
                entry["problems"].append(f"frontmatter {field} changed")

        upper = new_body.upper()
        absent = [h for h in FORMAT_HEADINGS if h not in upper]
        if absent:
            entry["ok"] = False
            entry["problems"].append(f"missing headings {absent}")

        old_tok, new_tok = hard_tokens(old_body), hard_tokens(new_body)
        lost = sorted(old_tok - new_tok)
        gained = sorted(t for t in (new_tok - old_tok) if t not in STOPWORDS)
        if lost:
            entry["ok"] = False
            entry["lost_tokens"] = lost
        if gained:
            entry["gained_tokens"] = gained
        entry["old_chars"], entry["new_chars"] = len(old_body), len(new_body)
        report.append(entry)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        bad = [e for e in report if not e["ok"]]
        print(f"checked {len(report)} migrated notes; failures: {len(bad)}")
        for e in report:
            flag = "OK  " if e["ok"] else "FAIL"
            gained = len(e.get("gained_tokens", []))
            lost = len(e.get("lost_tokens", []))
            print(f"{flag} {e['slug']:<58} {e['old_chars']:>5}->{e['new_chars']:<5} lost={lost} gained={gained}")
            for p in e["problems"]:
                print(f"       ! {p}")
            for tok in e.get("lost_tokens", [])[:25]:
                print(f"       - lost: {tok}")
    return 1 if any(not e["ok"] for e in report) else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
