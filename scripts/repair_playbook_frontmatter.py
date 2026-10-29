#!/usr/bin/env python3
"""Repair playbook notes whose frontmatter was corrupted by a multi-line value.

``save_playbook`` writes ``key: value`` one per line, but it used to write
``name`` / ``fingerprint`` verbatim. A captured CTF2 goal carries the whole
challenge prompt -- description, attachment paths, platform policy text -- so
the stored ``fingerprint:`` became a dozen physical lines. Any line of dashes
inside that text (a Chinese book's 勘误表 separator is ``----``; a Markdown
horizontal rule is ``---``) then terminated the YAML-ish block early:
``_parse_frontmatter`` used a non-greedy ``\\n---`` match, so everything after
the first ``---`` prefix was read as BODY. The note still said
``status: validated`` on disk and still had ``target_ref``, but the loader saw
a draft with no structured identity -- invisible to the validated-only
auto-inject path in ``solver.py``.

Both ends are fixed in ``vulnclaw/agent/playbook.py`` now (whole-line
delimiter; single-line values on write), so this script only exists to
straighten the notes written BEFORE the fix. It rewrites each affected file
into the canonical shape, collapsing the multi-line value back to the single
line the writer intended. Whitespace is the only thing removed from a value,
so the fingerprint's token set is unchanged.

Usage::

    # dry-run: report what would change, touch nothing
    python scripts/repair_playbook_frontmatter.py

    # write (backs the originals up first, outside the package: E: on this box)
    python scripts/repair_playbook_frontmatter.py --apply --backup-to E:/vulnclaw/playbook-frontmatter-backup

Re-running is safe: a repaired note parses cleanly and is skipped.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

from vulnclaw.agent import playbook as pb
from vulnclaw.utils.atomic_write import atomic_write_text

#: Keys ``save_playbook`` writes after the (possibly multi-line) fingerprint.
_TAIL_KEYS = ("status", "source", "updated_at", "identity_version", "target_ref", "target_hash")
_STATUS_RE = re.compile(r"^status:[ \t]*(validated|draft)[ \t]*$")


def _split_corrupted(text: str) -> tuple[dict[str, str], str] | None:
    """Return (canonical meta, body) for a note with a multi-line frontmatter value.

    The value region is everything between ``fingerprint:`` and the ``status:``
    line; the block ends at the first delimiter line AFTER that status line.
    Every key of the tail block is copied verbatim (they are all single-line by
    construction), so nothing but the value's newlines is discarded.

    The tail block is recognised by SHAPE -- ``status`` followed within a few
    lines by ``source`` and ``updated_at`` -- and the LAST such candidate wins,
    because the captured goal text a note carries can itself contain a line
    that looks like ``status: validated``.
    """
    lines = text.splitlines()
    if not lines or not pb._FM_DELIM.match(lines[0]):
        return None
    tail_at = None
    for i in range(1, len(lines)):
        if not _STATUS_RE.match(lines[i]):
            continue
        window = lines[i + 1:i + 7]
        keys = {line.partition(":")[0].strip() for line in window}
        if {"source", "updated_at"} <= keys and any(pb._FM_DELIM.match(w) for w in window):
            tail_at = i
    if tail_at is None:
        return None
    close_at = next(
        (i for i in range(tail_at + 1, len(lines)) if pb._FM_DELIM.match(lines[i])), None
    )
    if close_at is None:
        return None

    name_at = next((i for i in range(1, tail_at) if lines[i].startswith("name:")), None)
    if name_at is None:
        return None
    # The LAST `fingerprint:` before the tail block: earlier occurrences are
    # goal text, not keys (a note's description can quote the word).
    fp_at = next(
        (i for i in range(tail_at - 1, name_at, -1) if lines[i].startswith("fingerprint:")),
        None,
    )
    if fp_at is None or tail_at - fp_at < 2:
        return None

    meta: dict[str, str] = {
        "name": lines[name_at][len("name:"):].strip(),
    }
    value_parts = [lines[fp_at][len("fingerprint:"):]] + lines[fp_at + 1:tail_at]
    meta["fingerprint"] = pb._single_line(" ".join(value_parts))

    for line in lines[tail_at:close_at]:
        key, _, val = line.partition(":")
        key = key.strip()
        if key in _TAIL_KEYS:
            meta[key] = val.strip()

    body = "\n".join(lines[close_at + 1:]).lstrip("\n")
    return meta, body


def _render(meta: dict[str, str], body: str) -> str:
    out = ["---", f"name: {meta['name']}", f"fingerprint: {meta['fingerprint']}"]
    for key in _TAIL_KEYS:
        if meta.get(key):
            out.append(f"{key}: {meta[key]}")
    out += ["---", "", body, ""]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--dir", default=None, help="playbook dir (default: the configured store)")
    ap.add_argument("--apply", action="store_true", help="write the repaired notes")
    ap.add_argument(
        "--backup-to",
        default=None,
        help="directory to copy each original into before --apply rewrites it",
    )
    args = ap.parse_args(argv)

    root = Path(args.dir) if args.dir else pb.PLAYBOOKS_DIR
    if not root.is_dir():
        print(f"no playbook directory: {root}")
        return 2
    if args.apply and not args.backup_to:
        print("--apply needs --backup-to (the store is shared and not under git)")
        return 2
    backup = Path(args.backup_to) if args.backup_to else None
    if args.apply and backup:
        backup.mkdir(parents=True, exist_ok=True)

    broken = fixed = lost_status = 0
    for path in sorted(root.glob("*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        meta, body = pb._parse_frontmatter(text)
        if "status" not in meta:
            lost_status += 1
        broken += 1
        parts = _split_corrupted(text)
        if parts is None:
            broken -= 1
            continue
        new_meta, new_body = parts
        if not new_meta.get("fingerprint"):
            broken -= 1
            print(f"SKIP  {path.name}: no fingerprint recovered")
            continue
        rendered = _render(new_meta, new_body)
        check_meta, check_body = pb._parse_frontmatter(rendered)
        if check_meta.get("status") != new_meta.get("status") or \
                check_meta.get("fingerprint") != new_meta["fingerprint"] or \
                check_body.strip() != new_body.strip():
            broken -= 1
            print(f"SKIP  {path.name}: round-trip check failed")
            continue
        fixed += 1
        old_tokens = len(pb.Playbook(slug=path.stem, name=meta.get("name", ""),
                                     fingerprint=meta.get("fingerprint", "")).tokens())
        new_tokens = len(pb.Playbook(slug=path.stem, name=new_meta["name"],
                                     fingerprint=new_meta["fingerprint"]).tokens())
        status = new_meta.get("status")
        note = "" if old_tokens == new_tokens else f"  TOKENS {old_tokens}->{new_tokens}"
        print(f"{'FIXED' if args.apply else 'WOULD'}  {path.name}  status={status}"
              f" ref={'yes' if new_meta.get('target_ref') else 'no'}{note}")
        if args.apply:
            if backup:
                shutil.copy2(path, backup / path.name)
            atomic_write_text(path, rendered)

    print(f"\n{broken} notes with a multi-line frontmatter value, {fixed} repairable; "
          f"{lost_status} of them currently load as status-less "
          f"({'written' if args.apply else 'dry-run, pass --apply to write'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
