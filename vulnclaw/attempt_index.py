"""Which targets has this machine already run?

The 2026-10-31 post-mortem turned up a scheduling gap that no guard could fix:
four challenges (babysilent, 谍影, CanonicoPWN, dreambound) were **never
started**, while the challenges that *were* attempted absorbed 1500+ tool calls.
The mirror-image loss is subtler but just as expensive — a challenge that was
attempted and abandoned gets re-attempted from scratch on the next command,
because nothing on disk answers "have we tried this one already?".

``vulnclaw solve-all`` can only see the platform's ``solved`` flag today, which
covers half the question. This module answers the other half from local runs.

Design notes:

* **Attempted ≠ solved.** A run directory existing means the target was worked
  on; it says nothing about outcome. The index therefore reports both what it
  found and *how much* effort went in, so an operator can decide per challenge
  (a 2-step run deserves another go; a 300-call run probably does not).
* **``run.json`` status is unreliable.** Measured across 13 runs from 2026-10-31:
  most still say ``"status": "running"`` because the process was killed and never
  wrote a terminal state. Presence of the directory is the honest signal, so
  that is what we key on, and the recorded status is reported as-is.
* **Keys are the repo's own.** ``target_state_key`` hashes the canonical target,
  so this index agrees with the per-target state directories. That function does
  *not* fold ``https://host:443`` and bare ``host`` together — two spellings, two
  keys — so a host-level fallback is kept for cross-spelling lookups.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from vulnclaw.targets import parse_target, target_state_key


@dataclass(frozen=True)
class Attempt:
    """One recorded run against one target."""

    run_name: str
    canonical: str
    target_type: str = ""
    status: str = ""
    command: str = ""
    started_at: str = ""
    tool_calls: int = 0
    evidence: int = 0
    #: The run's goal text — the only record of the challenge's name.
    goal: str = ""

    @property
    def effort(self) -> int:
        """Rough work spent: tool calls dominate, evidence is the fallback.

        Both are read from the run's session file when one is linkable, which is
        not always the case (a killed run may have written ``run.json`` but no
        session). 0 means "started but nothing measurable" rather than "cheap".
        """
        return self.tool_calls or self.evidence


@dataclass
class AttemptIndex:
    attempts: list[Attempt] = field(default_factory=list)
    #: state_key -> every attempt recorded under it
    by_key: dict[str, list[Attempt]] = field(default_factory=dict)
    #: bare host -> attempts, for cross-spelling lookups
    by_host: dict[str, list[Attempt]] = field(default_factory=dict)
    #: normalised challenge name -> attempts, recovered from each run's goal
    by_name: dict[str, list[Attempt]] = field(default_factory=dict)

    def for_target(self, target: str) -> list[Attempt]:
        """Attempts recorded for ``target`` under any spelling we can match.

        Three passes, most specific first: the repo's own state key (exact
        identity), then the bare host (``https://h:443`` vs ``h``), then the
        challenge name. The name pass is what makes platform refs useful at all
        — a run never records the ref, only the target it was handed, so the
        name in its goal is the sole link back to the challenge.
        """
        raw = str(target or "").strip()
        if not raw:
            return []
        try:
            key = target_state_key(parse_target(raw).canonical)
        except Exception:  # noqa: BLE001 - an unparseable target simply has no key
            key = ""
        if key and self.by_key.get(key):
            return list(self.by_key[key])
        host = _bare_host(raw)
        if host and self.by_host.get(host):
            return list(self.by_host[host])
        name_key = _name_key(raw)
        if name_key:
            # Bidirectional on purpose: a query of "oldsvr" must find a run whose
            # goal recorded "oldsvr mips64 pwn", and a query carrying a whole goal
            # must find a run recorded under the bare challenge name. Both are
            # substring tests over normalised keys.
            for known, attempts in self.by_name.items():
                if known and (known in name_key or name_key in known):
                    return list(attempts)
        return []

    def was_attempted(self, target: str) -> bool:
        return bool(self.for_target(target))

    def effort_for(self, target: str) -> int:
        return max((attempt.effort for attempt in self.for_target(target)), default=0)


def _bare_host(value: str) -> str:
    """Lower-cased host (or the path, for local-attachment targets).

    Kept deliberately dumb: this is a fallback for matching two spellings of one
    target, not a security boundary, so a wrong guess only costs a spurious
    "already tried" that the operator can override.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = parse_target(text)
        text = parsed.canonical
    except Exception:  # noqa: BLE001
        pass
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)", text)
    if m:
        return m.group(1).lower()
    m = re.match(r"^([^/:?#\s]+)(?::\d+)?$", text)
    if m:
        return m.group(1).lower()
    return text.replace("\\", "/").lower()


#: Words too generic to identify a challenge by name. A goal like "Solve the
#: authorized CTF target" would otherwise make every challenge match every run.
_NAME_STOP = frozenset(
    "solve the authorized ctf challenge obtain flag target this that and for "
    "with from into using only please find get real accepted submit game "
    "competition practice instance brief description attach files path".split()
)


def _name_key(value: str) -> str:
    """Normalised name-ish form of a goal or challenge name, for fuzzy matching.

    Only used as the last matching pass, so a false positive costs an
    unnecessary "already attempted" label that ``--include-attempted`` undoes.
    Returns "" when the text carries no distinctive token at all, so a generic
    goal cannot make everything look attempted.
    """
    tokens = [t for t in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", str(value or "").lower()) if t not in _NAME_STOP]
    return " ".join(tokens[:6])


def _runs_root(runs_dir: str | os.PathLike[str] | None = None) -> Path:
    if runs_dir:
        return Path(runs_dir)
    env = os.environ.get("VULNCLAW_RUNS_DIR")
    if env:
        return Path(env)
    config_dir = os.environ.get("VULNCLAW_CONFIG_DIR")
    base = Path(config_dir) if config_dir else Path.home() / ".vulnclaw"
    return base / "runs"


def _target_stats(run_dir: Path, state_key: str) -> tuple[int, int]:
    """``(tool_calls, evidence)`` for one target, from its recorded state.

    Read from ``targets/<state_key>/state/current.json``, not from the session
    directory. The obvious-looking alternative — matching session filenames by
    the run's timestamp — does not work: a session is named for *process start*
    and a run for *run creation*, seconds apart, so the glob silently matched
    nothing and every attempt reported zero effort. The state file lives inside
    the run and is keyed by exactly the same ``state_key``, so no guessing is
    involved. Missing or unreadable state means "started, nothing measurable".
    """
    stats = _read_target_state(run_dir, state_key)
    return stats.get("tool_calls", 0), stats.get("evidence", 0)


def _read_target_state(run_dir: Path, state_key: str) -> dict[str, Any]:
    """One parsed ``state/current.json``, with the derived fields we index on."""
    candidates: list[Path] = []
    if state_key:
        candidates.append(run_dir / "targets" / state_key / "state" / "current.json")
    # A run can hold several target dirs; fall back to any present file when the
    # key does not line up (older runs wrote legacy keys).
    target_root = run_dir / "targets"
    if target_root.is_dir():
        candidates.extend(sorted(target_root.glob("*/state/current.json")))
    for path in candidates:
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        state = payload.get("agent_state") or {}
        return {
            "tool_calls": len(state.get("tool_calls") or []),
            "evidence": len(state.get("evidence") or []),
            # A run's goal is the only place a challenge *name* survives: the
            # platform ref is never recorded, so name-based matching (what
            # `solve-all --skip-attempted` needs) has to come from here.
            "goal": str(state.get("goal") or ""),
        }
    return {"tool_calls": 0, "evidence": 0, "goal": ""}


def build_index(
    runs_dir: str | os.PathLike[str] | None = None,
    *,
    include_effort: bool = True,
    limit_runs: int = 0,
) -> AttemptIndex:
    """Scan run directories and return what was attempted.

    ``limit_runs`` caps how many (newest-first) run directories are read, for
    callers that want a fast answer on a machine with thousands of runs.
    """
    root = _runs_root(runs_dir)
    index = AttemptIndex()
    if not root.is_dir():
        return index

    run_dirs = sorted(
        (p for p in root.iterdir() if p.is_dir() and (p / "run.json").is_file()),
        key=lambda p: p.name,
        reverse=True,
    )
    if limit_runs > 0:
        run_dirs = run_dirs[:limit_runs]

    for run_dir in run_dirs:
        try:
            payload = json.loads((run_dir / "run.json").read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        calls, evidence = (0, 0)
        goal = ""
        for target in payload.get("targets") or []:
            if not isinstance(target, dict):
                continue
            canonical = str(target.get("canonical") or target.get("input") or "")
            if not canonical:
                continue
            state_key = str(target.get("state_key") or "") or target_state_key(canonical)
            if include_effort:
                stats = _read_target_state(run_dir, state_key)
                calls = stats["tool_calls"]
                evidence = stats["evidence"]
                goal = stats.get("goal") or ""
            attempt = Attempt(
                run_name=str(payload.get("run_name") or run_dir.name),
                canonical=canonical,
                target_type=str(target.get("type") or ""),
                status=str(payload.get("status") or ""),
                command=str(payload.get("command") or ""),
                started_at=str(payload.get("started_at") or payload.get("created_at") or ""),
                tool_calls=calls,
                evidence=evidence,
                goal=goal,
            )
            index.attempts.append(attempt)
            index.by_key.setdefault(state_key, []).append(attempt)
            host = _bare_host(canonical)
            if host:
                index.by_host.setdefault(host, []).append(attempt)
            name_key = _name_key(goal)
            if name_key:
                index.by_name.setdefault(name_key, []).append(attempt)

    return index


def partition_targets(
    targets: Iterable[str], index: AttemptIndex
) -> tuple[list[str], list[str], dict[str, int]]:
    """Split ``targets`` into ``(untouched, previously_attempted, effort)``.

    The caller decides what to do with each bucket; this only classifies, so
    "attempted" never silently means "skip".
    """
    untouched: list[str] = []
    attempted: list[str] = []
    effort: dict[str, int] = {}
    for target in targets:
        spent = index.effort_for(target)
        if index.was_attempted(target):
            attempted.append(target)
            effort[target] = spent
        else:
            untouched.append(target)
    return untouched, attempted, effort


def summarize(index: AttemptIndex) -> dict[str, Any]:
    """Counts for an operator-facing one-liner."""
    hosts = {_bare_host(a.canonical) for a in index.attempts if _bare_host(a.canonical)}
    return {
        "runs": len({a.run_name for a in index.attempts}),
        "attempts": len(index.attempts),
        "distinct_targets": len(hosts),
    }
