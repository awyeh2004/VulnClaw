"""Read-only detector for "the run concluded X is impossible, then proved X works".

This is the failure that cost the two challenges examined on 2026-11-16:

* **ezphp** — a candidate fact said the Redis session was "tamper-protected, so
  session forging is not viable without config secret", while a *later* fact in
  the same run recorded ``encrypted_session_data|O:8:"stdClass"` returning HTTP
  500 — hard proof that the second `key|value` slot *is* deserialised. The
  solution needed only `stdClass` replaced by the known gadget class.
* **NeuronShuffle** — the LOCK said "model_B.bin is unrelated noise", and no
  later evidence ever revisited that; the run spent 530k candidate permutations
  proving a path the premise had already closed.

Neither run was blocked by a guard, and neither lacked evidence. The gap is
that a negative conclusion was written down once and then treated as settled.

This script only *counts* that shape across recorded sessions so the decision to
add a gate is made from data rather than from two anecdotes. It changes nothing.

Usage::

    python -X utf8 -I scripts/detect_negated_hypotheses.py [--sessions DIR] [-v]

Reads session JSON files (``~/.vulnclaw/sessions`` by default) and prints, per
session, every negative-conclusion statement together with any later evidence
that contradicts it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

#: Phrases that assert a path is closed. Deliberately narrow: "not viable",
#: "noise", "cannot", "rules out". A detector that fires on every hedge would
#: report noise and bury the real hits.
_NEGATIVE_PATTERNS = (
    r"\bnot viable\b",
    r"\bnot possible\b",
    r"\bimpossible\b",
    r"\bcannot be\b",
    r"\bcan't be\b",
    r"\bruled out\b",
    r"\brules out\b",
    r"\bdead end\b",
    r"\bno (?:recoverable|usable|exploitable)\b",
    r"\bis unrelated noise\b",
    r"\bnot (?:recoverable|exploitable|forgeable)\b",
    r"\bfails? closed\b",
    r"\btamper-protected\b",
)

#: Phrases that assert a capability was *demonstrated*. A negative statement
#: produced before one of these, about the same subject, is the shape we want.
_POSITIVE_PATTERNS = (
    r"\bconfirms?\b",
    r"\bconfirmed\b",
    r"\bproves?\b",
    r"\bproven\b",
    r"\byields?\s+HTTP\s+\d{3}\b",
    r"\btriggers?\b",
    r"\bsucceeded\b",
    r"\bworks\b",
    r"\backnowledged\b",
)

_NEGATIVE_RE = re.compile("|".join(_NEGATIVE_PATTERNS), re.IGNORECASE)
_POSITIVE_RE = re.compile("|".join(_POSITIVE_PATTERNS), re.IGNORECASE)

#: Words the blackboard stamp itself contributes. Two statements about entirely
#: different subjects still share them, so counting them as subject overlap
#: manufactures conflicts: an ELFStudy note "XOR keys are ruled out" appeared to
#: conflict with a later "challenge brief is {...}" purely because both said
#: "fact" and "challenge".
_BOARD_META = frozenset(
    "blackboard fact facts set confirmed candidate blackboard node lock angle "
    "tension intent hint proposed in_progress challenged rejected superseded "
    "description evidence challenge target".split()
)

#: Stop words dropped before comparing a negative claim with later evidence, so
#: "session forging is not viable" shares tokens with "session forgery confirmed".
_STOP = frozenset(
    "the a an is are was were be been being of to in on at for with without "
    "and or but if then than that this these those it its as by from into "
    "not no cannot can't only also very more most such so any all some".split()
) | _BOARD_META


def _tokens(text: str) -> set[str]:
    words = re.findall(r"[A-Za-z][A-Za-z0-9_]{2,}", str(text or "").lower())
    return {w for w in words if w not in _STOP}


@dataclass
class Finding:
    session: str
    negative_at: str
    negative_text: str
    positive_at: str
    positive_text: str
    overlap: int


#: What a blackboard tool result actually starts with. A *substring* test is not
#: enough: one NeuronShuffle run piped a knowledge file through PowerShell, and
#: that file's own text contains "[blackboard]", so the command output passed a
#: ``in`` check and became a phantom "positive".
_BLACKBOARD_PREFIXES = ("[blackboard]", "[blackboard ")


def _is_blackboard_write(text: str) -> bool:
    head = str(text or "").lstrip()[:40].lower()
    return head.startswith(_BLACKBOARD_PREFIXES)


def _texts_in_order(payload: dict) -> list[tuple[str, str]]:
    """Blackboard writes, oldest first, recovered from what the run recorded.

    The blackboard itself is **not persisted** — it lives in memory for the run's
    duration, and a finished session JSON has neither a ``blackboard`` key nor a
    populated ``run_state.blackboard``. What survives is the *tool result* of
    every ``blackboard_*`` call: the events ndjson carries those, and a session
    JSON carries them inside ``agent_state.evidence`` as ``[blackboard] fact n7
    CONFIRMED: ...`` lines.

    Restricting the scan to these (rather than every tool result) is what makes
    the detector usable: an earlier version scanned all evidence and 6 of 6
    sampled hits were shell output that merely contained a negative word, while
    the one real case lived entirely in blackboard writes.
    """
    rows: list[tuple[str, str]] = []

    for node in (payload.get("blackboard") or {}).get("nodes") or []:
        if isinstance(node, dict):
            rows.append(
                (
                    str(node.get("created_at") or ""),
                    f"[{node.get('type')}/{node.get('status')}] {node.get('description') or ''}",
                )
            )

    state = payload.get("agent_state") or {}
    for evidence in state.get("evidence") or []:
        if not isinstance(evidence, dict):
            continue
        body = str(evidence.get("content") or "")
        if not _is_blackboard_write(body):
            continue
        rows.append((str(evidence.get("created_at") or ""), body))

    rows = [row for row in rows if row[1].strip()]
    rows.sort(key=lambda row: row[0])
    return rows


def scan_session(path: Path) -> list[Finding]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []

    rows = _texts_in_order(payload)
    findings: list[Finding] = []

    for index, (stamp, text) in enumerate(rows):
        if not _NEGATIVE_RE.search(text):
            continue
        claim = _tokens(text)
        if len(claim) < 3:
            continue
        for later_stamp, later_text in rows[index + 1 :]:
            # The later statement must ALSO be a blackboard write. Letting raw
            # tool output serve as the "positive" is what produced the false
            # hits: `Command: $ErrorActionPreference...` contains "works" in
            # unrelated prose. Both sides of a conflict are beliefs the run
            # recorded, so both must come from the board.
            if not _is_blackboard_write(later_text):
                continue
            if not _POSITIVE_RE.search(later_text):
                continue
            shared = claim & _tokens(later_text)
            # Two shared content words is the floor: one is coincidence (both
            # mention "target"), three misses a real conflict whose wording
            # drifted ("session forging not viable" vs "object injection works").
            if len(shared) >= 2:
                findings.append(
                    Finding(
                        session=path.name,
                        negative_at=stamp,
                        negative_text=" ".join(text.split())[:220],
                        positive_at=later_stamp,
                        positive_text=" ".join(later_text.split())[:220],
                        overlap=len(shared),
                    )
                )
                break
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sessions",
        default=str(Path.home() / ".vulnclaw" / "sessions"),
        help="Session directory to scan (default: ~/.vulnclaw/sessions)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Print each hit")
    parser.add_argument(
        "--min-overlap", type=int, default=2, help="Shared content words required (default 2)"
    )
    args = parser.parse_args(argv)

    root = Path(args.sessions)
    if not root.is_dir():
        print(f"no such sessions dir: {root}", file=sys.stderr)
        return 2

    files = sorted(root.glob("*.json"))
    total = 0
    sessions_with_hits = 0
    for path in files:
        findings = scan_session(path)
        findings = [f for f in findings if f.overlap >= args.min_overlap]
        if not findings:
            continue
        sessions_with_hits += 1
        total += len(findings)
        if args.verbose:
            print(f"\n=== {path.name}")
            for hit in findings:
                print(f"  NEGATIVE @ {hit.negative_at}  (overlap={hit.overlap})")
                print(f"    {hit.negative_text}")
                print(f"  POSITIVE @ {hit.positive_at}")
                print(f"    {hit.positive_text}")

    print(
        f"\nscanned {len(files)} session(s): "
        f"{sessions_with_hits} with conflicts, {total} conflict(s) total"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())