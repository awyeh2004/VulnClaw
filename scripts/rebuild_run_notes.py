#!/usr/bin/env python3
"""Rebuild draft playbook notes from saved VulnClaw session files.

The live blackboard is memory-only -- ``AgentCore.reset_context()`` (the REPL's
``target <t>`` / ``clear`` / natural-language target switch) builds a fresh empty
one, and a session file keeps no board nodes -- so a run that died before the
solve loop's own capture (every 20 steps, and at termination) used to lose its
conclusions. What a session file DOES keep is every tool call with its arguments
and result text, which is enough to walk the board back.

Usage::

    # dry-run: print what could be rebuilt
    python scripts/rebuild_run_notes.py ~/.vulnclaw/sessions/20261006_154352_*.json

    # write draft notes into ~/.vulnclaw/playbooks/
    python scripts/rebuild_run_notes.py --save ~/.vulnclaw/sessions/*.json

    # every session in the store
    python scripts/rebuild_run_notes.py --all --save
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("sessions", nargs="*", help="session JSON file(s)")
    parser.add_argument(
        "--all",
        action="store_true",
        help="also scan the sessions directory (~/.vulnclaw/sessions)",
    )
    parser.add_argument(
        "--dir",
        default=None,
        help="sessions directory used by --all (default: the configured one)",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="write the rebuilt note into the playbook store (default: print only)",
    )
    args = parser.parse_args(argv)

    from vulnclaw.agent.playbook import (
        PLAYBOOKS_DIR,
        capture_run_notes_from_session,
        rebuild_run_notes,
    )
    from vulnclaw.config.settings import SESSIONS_DIR

    paths = [Path(p).expanduser() for p in args.sessions]
    if args.all:
        root = Path(args.dir).expanduser() if args.dir else SESSIONS_DIR
        paths += sorted(root.glob("*.json"))
    if not paths:
        print("[!] no session files given (pass paths or --all)", file=sys.stderr)
        return 2

    written = 0
    for path in paths:
        if not path.exists():
            print(f"[!] not found: {path}", file=sys.stderr)
            continue
        if args.save:
            reasons: list[str] = []
            ack = capture_run_notes_from_session(path, out_reason=reasons)
            if ack is None:
                print(f"[-] {path.name}: nothing written ({reasons[0] if reasons else 'unknown'})")
                continue
            written += 1
            print(f"[+] {path.name} -> {ack.get('slug')} [{ack.get('status')}]")
            continue
        try:
            state = json.loads(path.read_text(encoding="utf-8")).get("agent_state") or {}
        except (OSError, ValueError) as exc:
            print(f"[!] {path.name}: unreadable ({exc})", file=sys.stderr)
            continue
        reasons = []
        text = rebuild_run_notes(state, out_reason=reasons)
        if text is None:
            print(f"[-] {path.name}: nothing to rebuild ({reasons[0] if reasons else 'unknown'})")
            continue
        print("=" * 78)
        print(f"# {path.name}")
        print(text)

    if args.save:
        print(f"[=] {written} note(s) written into {PLAYBOOKS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
