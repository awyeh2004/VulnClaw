"""The handoff record between one solve round and the next.

Why a file instead of a conversation: the review step's output has to survive
being handed to a *different* reviewer. Measured 2026-11-17 on oldsvr, the whole
value of the review was one direction change — "stop dictionary-searching the md5
prefix, enumerate the 24-bit constraint instead" — and the next round improved
from 162 tool calls with 0 conclusions to ~90 calls with 7. That instruction
travelled through a chat message, which means it was lost the moment a different
process or a different day picked up the challenge.

Design constraints, each from something that already bit:

* **Reviewers differ; the schema does not.** Nothing here assumes the writer was
  this repo's tooling. Any process that can write JSON can review a run.
* **Read-only toward the run.** ``case_state.json`` lives beside the challenge, not
  inside a run directory. A reviewer that edited run state would destroy the
  evidence it was asked to weigh.
* **Never auto-resume on a stale file.** ``rounds`` grows; a consumer must check
  the last round's target against the one it is about to run, because reusing a
  verdict for a different target is worse than having no verdict.
* **Judgement never enters the blackboard.** Hints reach the model as operator
  hints — text the model may weigh — not as confirmed facts. The evidence gate
  stays intact.

Usage::

    # reviewer writes (any language, plain JSON)
    python -X utf8 -I scripts/case_state.py add-round <dir> \\
        --run-name <run> --verdict stalled --blocked-at auth \\
        --ruled-out "dictionary attack on md5 prefix" \\
        --next-hint "24-bit prefix constraint: enumerate, do not use a wordlist"

    # runner reads
    python -X utf8 -I scripts/case_state.py hints <dir>     # one hint per line
    python -X utf8 -I scripts/case_state.py show <dir>      # human summary
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
STATE_FILENAME = "case_state.json"

#: What a reviewer is allowed to conclude. Kept closed so a new reviewer cannot
#: invent a verdict the runner does not understand; anything else is rejected at
#: write time rather than silently carried into the next round.
VERDICT_CONTINUE = "continue"
VERDICT_STALLED = "stalled"
VERDICT_SOLVED = "solved"
VERDICT_SWITCH = "switch"
VERDICTS = frozenset({VERDICT_CONTINUE, VERDICT_STALLED, VERDICT_SOLVED, VERDICT_SWITCH})

#: Hard cap, so a loop that keeps rewriting its own hints cannot grow the file
#: without bound. Older rounds are dropped first; the latest is always kept.
MAX_ROUNDS = 50


class CaseStateError(ValueError):
    """Malformed or inconsistent case state."""


@dataclass
class Round:
    round: int
    run_name: str = ""
    verdict: str = VERDICT_STALLED
    blocked_at: str = ""
    #: Approaches the reviewer concluded are dead. Carried forward so the next
    #: round does not re-derive them — on oldsvr, re-deriving "rockyou doesn't
    #: contain the password" would have cost another dictionary run.
    ruled_out: list[str] = field(default_factory=list)
    #: Free-text direction for the next round. This is the payload: the one thing
    #: a reviewer contributes that the runner cannot compute.
    next_hint: str = ""
    target: str = ""
    recorded_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "round": self.round,
            "run_name": self.run_name,
            "verdict": self.verdict,
            "blocked_at": self.blocked_at,
            "ruled_out": list(self.ruled_out),
            "next_hint": self.next_hint,
            "target": self.target,
            "recorded_at": self.recorded_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Round":
        verdict = str(data.get("verdict") or VERDICT_STALLED)
        if verdict not in VERDICTS:
            raise CaseStateError(
                f"unknown verdict {verdict!r}; expected one of {sorted(VERDICTS)}"
            )
        return cls(
            round=int(data.get("round") or 0),
            run_name=str(data.get("run_name") or ""),
            verdict=verdict,
            blocked_at=str(data.get("blocked_at") or ""),
            ruled_out=[str(x) for x in (data.get("ruled_out") or []) if str(x).strip()],
            next_hint=str(data.get("next_hint") or ""),
            target=str(data.get("target") or ""),
            recorded_at=str(data.get("recorded_at") or ""),
        )


@dataclass
class CaseState:
    target: str = ""
    rounds: list[Round] = field(default_factory=list)

    @property
    def last(self) -> Round | None:
        return self.rounds[-1] if self.rounds else None

    def hints_for(self, target: str) -> list[str]:
        """Hints safe to hand a new round on ``target``.

        Empty when the last round was recorded against a different target: a
        verdict about challenge A is not a hint about challenge B, and reusing it
        would be worse than starting cold. Also empty after a ``solved`` verdict —
        there is nothing left to steer.
        """
        last = self.last
        if last is None:
            return []
        if last.verdict == VERDICT_SOLVED:
            return []
        if last.target and target and last.target.strip().lower() != target.strip().lower():
            return []
        hints: list[str] = []
        if last.blocked_at:
            hints.append(f"previous round was blocked at: {last.blocked_at}")
        if last.ruled_out:
            hints.append("already ruled out: " + "; ".join(last.ruled_out))
        if last.next_hint:
            hints.append(last.next_hint)
        return hints

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "target": self.target,
            "rounds": [r.to_dict() for r in self.rounds],
        }


def state_path(directory: str | Path) -> Path:
    return Path(directory) / STATE_FILENAME


def load(directory: str | Path) -> CaseState:
    """Read the case state, or an empty one when the file does not exist."""
    path = state_path(directory)
    if not path.is_file():
        return CaseState()
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CaseStateError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CaseStateError(f"{path} is not a JSON object")
    version = data.get("schema_version")
    if version is not None and int(version) > SCHEMA_VERSION:
        raise CaseStateError(
            f"{path} has schema_version {version}, newer than this tool "
            f"understands ({SCHEMA_VERSION}) — refusing rather than guessing"
        )
    rounds = [Round.from_dict(item) for item in (data.get("rounds") or []) if isinstance(item, dict)]
    return CaseState(target=str(data.get("target") or ""), rounds=rounds)


def save(directory: str | Path, state: CaseState) -> Path:
    """Write atomically; never leave a half-written file for the next round."""
    path = state_path(directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    if len(state.rounds) > MAX_ROUNDS:
        state.rounds = state.rounds[-MAX_ROUNDS:]
    payload = json.dumps(state.to_dict(), ensure_ascii=False, indent=2)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(path)
    return path


def add_round(
    directory: str | Path,
    *,
    run_name: str = "",
    verdict: str = VERDICT_STALLED,
    blocked_at: str = "",
    ruled_out: list[str] | None = None,
    next_hint: str = "",
    target: str = "",
) -> CaseState:
    """Append one review verdict and persist it."""
    if verdict not in VERDICTS:
        raise CaseStateError(f"unknown verdict {verdict!r}")
    state = load(directory)
    if target:
        state.target = target
    state.rounds.append(
        Round(
            round=len(state.rounds) + 1,
            run_name=run_name,
            verdict=verdict,
            blocked_at=blocked_at,
            ruled_out=list(ruled_out or []),
            next_hint=next_hint,
            target=state.target,
            recorded_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
    )
    save(directory, state)
    return state


def render(state: CaseState) -> str:
    if not state.rounds:
        return "no rounds recorded"
    lines = [f"target: {state.target or '(not set)'}", f"{len(state.rounds)} round(s):"]
    for r in state.rounds:
        lines.append(
            f"  {r.round}. [{r.verdict}] {r.run_name or '(no run)'}"
            + (f" blocked_at={r.blocked_at}" if r.blocked_at else "")
        )
        for item in r.ruled_out:
            lines.append(f"       ruled out: {item}")
        if r.next_hint:
            lines.append(f"       next hint: {r.next_hint}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add-round", help="Append a review verdict")
    add.add_argument("directory")
    add.add_argument("--run-name", default="")
    add.add_argument("--verdict", default=VERDICT_STALLED, choices=sorted(VERDICTS))
    add.add_argument("--blocked-at", default="")
    add.add_argument("--ruled-out", action="append", default=[])
    add.add_argument("--next-hint", default="")
    add.add_argument("--target", default="")

    hints = sub.add_parser("hints", help="Print hints for a new round, one per line")
    hints.add_argument("directory")
    hints.add_argument("--target", default="")

    show = sub.add_parser("show", help="Human-readable summary")
    show.add_argument("directory")

    args = parser.parse_args(argv)
    try:
        if args.command == "add-round":
            state = add_round(
                args.directory,
                run_name=args.run_name,
                verdict=args.verdict,
                blocked_at=args.blocked_at,
                ruled_out=args.ruled_out,
                next_hint=args.next_hint,
                target=args.target,
            )
            print(render(state))
            return 0
        if args.command == "hints":
            for hint in load(args.directory).hints_for(args.target):
                print(hint)
            return 0
        if args.command == "show":
            print(render(load(args.directory)))
            return 0
    except CaseStateError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())