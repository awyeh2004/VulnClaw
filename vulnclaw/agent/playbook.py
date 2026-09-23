"""Solve playbooks — durable, reusable attack recipes keyed by a target's
page signature (fingerprint).

A playbook captures what a prior run *already figured out* about a challenge:
target layout, the confirmed attack structure, and the concrete steps/scripts to
reproduce it. When the same challenge reappears under a new host/instance, the
agent looks it up by the page signature and *replays* the recipe instead of
re-deriving the whole attack from scratch.

Storage: one file per challenge family under ``~/.vulnclaw/playbooks/<slug>.md``,
frontmatter holds the structured fields; the body holds free-form steps/scripts.
Each challenge family is updated in place (covering), so storage stays bounded
regardless of how many instances of the same challenge are solved.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any, Optional, Sequence

from vulnclaw.agent.ctf_mode import FLAG_PREFIX_NAMES
from vulnclaw.config.settings import CONFIG_DIR

MIN_PLAYBOOK_CHARS = 80  # minimum steps length (prevents 3-line low-effort entries)

# Built FROM the one canonical prefix list instead of keeping a local copy. This file
# used to carry `(flag|ctf)\{...\}`, a two-name copy of an eighteen-name list, which is
# the same drift that once left finding_parser on 3 of 17 prefixes. Two consequences,
# both measured on the playbooks real runs wrote on 2026-09-23:
#
#   * `CTF2{...}` -- the format of the platform this tool drives -- did not match at
#     all, so BabySQL's per-instance flag was stored in full;
#   * `DASCTF{...}`/`BUUCTF{...}` matched only from the inner "CTF{".
_FLAG_FINGERPRINT_RE = re.compile(
    "(" + "|".join(re.escape(name) for name in FLAG_PREFIX_NAMES) + r")\{([^{}]{1,80})\}",
    re.IGNORECASE,
)


def _fingerprint_flags(text: str) -> str:
    """Replace full flag values with an unsubmittable fingerprint.

    Cross-instance hygiene: flags rotate per container instance, and storing the full
    value means a future run can resubmit a stale one -- measured on BabySQL, whose flag
    is generated per instance. The fingerprint keeps the shape recognisable while
    removing the value.

    ALWAYS redacts. The previous rule was `if len(inner) > 12: fingerprint, else: return
    the match unchanged`, which left any flag body of 12 characters or fewer in
    cleartext -- including `flag{222441144222}`, the flag submitted and ACCEPTED on
    2026-09-23, which is sitting in a validated playbook offered to future runs of that
    challenge. A hygiene gate whose stated purpose is "prevent stale resubmission" cannot
    keep full values for a length range, and 12 was not even principled: the fingerprint
    form `first4…last4` is 9 characters, so a 12-character body fingerprints fine.
    """
    def _fp(m: re.Match) -> str:
        prefix, inner = m.group(1), m.group(2)
        if len(inner) > 8:
            return f"{prefix}{{{inner[:4]}…{inner[-4:]}}}"
        # Too short to keep both ends without keeping everything: keep the prefix only,
        # so the model can still tell a flag was found here.
        return f"{prefix}{{…}}"

    return _FLAG_FINGERPRINT_RE.sub(_fp, text)

PLAYBOOKS_DIR = CONFIG_DIR / "playbooks"

# Tokens that are (almost) never meaningful for challenge identity and only add
# fingerprint noise: HTML boilerplate, generic CTF wrapper text, common words.
_STOP = {
    "login", "register", "logout", "button", "form", "input", "password",
    "username", "home", "index", "the", "and", "for", "title", "page",
    "challenge", "ctf", "dasctf", "http", "https", "com", "org", "net",
}


def _slugify(text: str) -> str:
    text = unicodedata.normalize("NFKD", text or "")
    text = text.encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return text[:48] or "playbook"


def _tokenize(fingerprint: str) -> set[str]:
    """Normalize a fingerprint into a comparable token set.

    The fingerprint is free text produced by the agent from its first-round
    probe (page title, distinguishing paths, form fields). We lowercase,
    split on non-alphanumerics, drop stop words and pure-numeric/short tokens,
    and dedupe.
    """
    text = unicodedata.normalize("NFKD", (fingerprint or "").lower())
    tokens: set[str] = set()
    for tok in re.findall(r"[a-z0-9]+", text):
        if tok in _STOP:
            continue
        if len(tok) < 2:
            continue
        if tok.isdigit():
            continue
        tokens.add(tok)
    return tokens


@dataclass
class Playbook:
    slug: str
    name: str = ""
    fingerprint: str = ""
    status: str = "draft"  # validated | draft
    steps: str = ""
    scripts: str = ""
    updated_at: str = ""
    _tokens: set[str] = field(default_factory=set, repr=False)

    def tokens(self) -> set[str]:
        if not self._tokens:
            self._tokens = _tokenize(self.fingerprint)
        return self._tokens

    def score(self, query_fingerprint: str) -> float:
        q = _tokenize(query_fingerprint)
        if not q:
            return 0.0
        overlap = len(q & self.tokens())
        return overlap / len(q)

    @property
    def path(self) -> Path:
        return PLAYBOOKS_DIR / f"{self.slug}.md"

    def to_frontmatter(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "fingerprint": self.fingerprint,
            "status": self.status,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_frontmatter(cls, slug: str, meta: dict[str, Any], body: str) -> "Playbook":
        return cls(
            slug=slug,
            name=str(meta.get("name", "") or ""),
            fingerprint=str(meta.get("fingerprint", "") or ""),
            status=str(meta.get("status", "draft") or "draft"),
            steps=body or "",
            scripts="",
            updated_at=str(meta.get("updated_at", "") or ""),
        )


def ensure_dirs() -> None:
    PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)


def _parse_frontmatter(content: str) -> tuple[dict[str, Any], str]:
    """Parse an optional ``---`` YAML-ish frontmatter block into (meta, body).

    Kept dependency-free: values are parsed as plain strings / lists manually.
    """
    if not content.startswith("---"):
        return {}, content
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", content, flags=re.DOTALL)
    if not m:
        return {}, content
    raw_meta, body = m.group(1), m.group(2)
    meta: dict[str, Any] = {}
    for line in raw_meta.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        val = val.strip().strip("'\"")
        meta[key.strip()] = val
    return meta, body


def _read(path: Path) -> Optional[Playbook]:
    try:
        content = path.read_text(encoding="utf-8")
    except Exception:
        return None
    meta, body = _parse_frontmatter(content)
    return Playbook.from_frontmatter(path.stem, meta, body)


def list_playbooks() -> list[Playbook]:
    ensure_dirs()
    out: list[Playbook] = []
    for p in sorted(PLAYBOOKS_DIR.glob("*.md")):
        pb = _read(p)
        if pb is not None:
            out.append(pb)
    return out


def lookup_playbook(fingerprint: str, *, limit: int = 3, min_score: float = 0.15) -> list[dict[str, Any]]:
    """Return the most relevant playbooks for ``fingerprint`` (best first, then
    validated-before-draft within the same score).

    ``min_score`` filters out unrelated playbooks: a Jaccard-style overlap below
    this threshold (default 0.15) means the fingerprints share too little signal
    to be the same challenge, even if a few generic tokens collide.
    """
    if not (fingerprint or "").strip():
        return []
    scored: list[tuple[float, Playbook]] = []
    for pb in list_playbooks():
        s = pb.score(fingerprint)
        if s >= min_score:
            scored.append((s, pb))
    # Stable ranking: higher score first; validated ahead of draft on ties.
    scored.sort(key=lambda item: (item[0], 0 if item[1].status == "validated" else 1), reverse=True)
    result = []
    for score, pb in scored[: limit if limit and limit > 0 else 3]:
        result.append(
            {
                "name": pb.name or pb.slug,
                "slug": pb.slug,
                "status": pb.status,
                "score": round(score, 3),
                "fingerprint": pb.fingerprint,
                "steps": pb.steps,
            }
        )
    return result


# Identity of the *kind* of challenge, as opposed to one concrete instance.
_CLASS_TAG_RE = re.compile(r"\[([^\[\]]{2,40})\]")
_CLASS_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
_CLASS_LABEL_RES = (
    re.compile(r"category\s+([A-Za-z\u4e00-\u9fff][\w\u4e00-\u9fff\-]*)", re.IGNORECASE),
    re.compile(r"difficulty\s+([A-Za-z\u4e00-\u9fff][\w\u4e00-\u9fff\-]*)", re.IGNORECASE),
)
_CLASS_QUOTED_RE = re.compile(r"['\"]([^'\"]{3,60})['\"]")


def challenge_class_signature(goal: str) -> str:
    """A port-free identity of the *kind* of challenge, used as a second lookup key.

    Measured 2026-09-23: a note learned on ``[Weblogic]CVE-2017-10271`` scored only
    0.222 against ``[Weblogic]CVE-2018-2628`` (a different vulnerability entirely),
    yet it transferred exactly what mattered -- the exposed surface, the
    non-blocking-`ProcessBuilder` pitfall, and where the flag can be exfiltrated --
    and turned a 179s/19-step run into 50s/8 steps.

    The exact-target fingerprint cannot find that kind of note: it embeds the
    ephemeral endpoint, so on a platform that hands out a new ``host:port`` per
    instance every run looks like a brand-new target and nothing ever matches.
    This signature drops the endpoint and keeps the discriminators that DO carry
    across instances: the bracketed framework tag, the CVE id, the category and
    difficulty labels, and the quoted challenge title.

    Kept deliberately short: ``Playbook.score`` is the share of the QUERY's tokens
    found in the note, so padding the query with prose lowers the score. Also note
    that ``_tokenize`` drops bare numbers, so CVE ids contribute "cve" but not the
    year/number -- the framework tag and labels are what actually discriminate.
    """
    text = str(goal or "")
    bits: list[str] = [m.group(1).strip() for m in _CLASS_TAG_RE.finditer(text)]
    bits += [m.group(0).upper() for m in _CLASS_CVE_RE.finditer(text)]
    for rx in _CLASS_LABEL_RES:
        match = rx.search(text)
        if match:
            bits.append(match.group(1))
    bits += [m.group(1).strip() for m in _CLASS_QUOTED_RE.finditer(text)]
    seen: set[str] = set()
    out: list[str] = []
    for bit in bits:
        key = bit.strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(bit.strip())
    return " ".join(out)


def lookup_playbook_multi(
    queries: Sequence[tuple[str, str]], *, limit: int = 3, min_score: float = 0.15
) -> list[dict[str, Any]]:
    """Look each ``(kind, query)`` up and merge the hits, best score per slug.

    Returns the same rows as :func:`lookup_playbook` plus ``query_kind`` and
    ``query``, so a caller can report which key matched -- the hit rate per key is
    the number worth watching, and it was invisible while only the count was
    recorded.
    """
    best: dict[str, dict[str, Any]] = {}
    for kind, query in queries:
        if not str(query or "").strip():
            continue
        for row in lookup_playbook(query, limit=limit, min_score=min_score):
            current = best.get(row["slug"])
            if current is None or row["score"] > current["score"]:
                merged = dict(row)
                merged["query_kind"] = kind
                merged["query"] = query
                best[row["slug"]] = merged
    rows = list(best.values())
    rows.sort(
        key=lambda r: (r["score"], 0 if r["status"] == "validated" else 1),
        reverse=True,
    )
    return rows[: limit if limit and limit > 0 else 3]


def save_playbook(
    *,
    name: str,
    fingerprint: str,
    steps: str = "",
    status: str = "draft",
    slug: Optional[str] = None,
) -> dict[str, Any]:
    """Persist (or cover-update) a playbook. Returns a small ack dict.

    Quality validation (inspired by heimdall brief-summarizer):
    1. steps must be >= MIN_PLAYBOOK_CHARS (prevents 3-line low-effort entries)
    2. must contain at least one of LOCK/CONFIRMED/ANGLES headings (structured)
    3. full flag values are fingerprinted to flag{first4…last4} (cross-instance hygiene)
    """
    ensure_dirs()

    # ── Quality gates ─────────────────────────────────────────────────
    stripped = steps.strip()
    if len(stripped) < MIN_PLAYBOOK_CHARS:
        return {"error": f"steps too short ({len(stripped)} chars, min {MIN_PLAYBOOK_CHARS}); "
                 "write LOCK / CONFIRMED / ANGLES with real evidence"}
    low = stripped.lower()
    if "lock" not in low and "confirmed" not in low and "angles" not in low:
        return {"error": "missing structured headings (LOCK / CONFIRMED / ANGLES)"}

    # ── Flag fingerprinting ───────────────────────────────────────────
    steps = _fingerprint_flags(stripped)

    status = "validated" if status == "validated" else "draft"
    slug = slug or _slugify(name)
    from datetime import datetime, timezone

    # Cover-update: if a same-name playbook exists, keep the same slug.
    for existing in list_playbooks():
        if existing.name and existing.name.strip().lower() == (name or "").strip().lower():
            slug = existing.slug
            break
    else:
        if (PLAYBOOKS_DIR / f"{slug}.md").exists():
            slug = f"{slug}-{abs(hash(fingerprint)) % 10000}"

    updated_at = datetime.now(timezone.utc).isoformat()
    lines = [
        "---",
        f"name: {name}",
        f"fingerprint: {fingerprint}",
        f"status: {status}",
        f"updated_at: {updated_at}",
        "---",
        "",
        steps.strip(),
        "",
    ]
    (PLAYBOOKS_DIR / f"{slug}.md").write_text("\n".join(lines), encoding="utf-8")
    return {"slug": slug, "status": status, "name": name}


def target_fingerprint(origin: str, goal: str = "") -> str:
    """Build a lookup fingerprint from the run's target identity.

    Local binary targets fold in a short content hash so the same attachment
    matches exactly across runs; URL/host targets use the target string itself.
    The goal is appended as weak signal (technique keywords widen family match).
    """
    o = (origin or "").strip()
    if not o:
        return ""
    p = Path(o)
    if p.exists() and p.is_file():
        try:
            digest = sha256(p.read_bytes()).hexdigest()[:16]
            return f"{o} sha256:{digest} {goal}".strip()
        except OSError:
            pass
    return f"{o} {goal}".strip()


def _auto_notes_name(target: str) -> str:
    short = target.rstrip("/\\").replace("\\", "/").rsplit("/", 1)[-1] or target
    return f"AutoNotes {short}"[:80]


def capture_run_notes(
    *,
    target: str,
    goal: str,
    blackboard: Any,
    outcome: str = "",
    status: str = "draft",
    final_answer: str = "",
) -> Optional[dict[str, Any]]:
    """Deterministically persist confirmed run conclusions as a draft playbook.

    Unlike ``save_playbook`` (model-initiated, often skipped when a run dies on
    quota or a dead end), the solve loop calls this automatically — at intervals
    and at termination — so the next run of the same target starts from confirmed
    conclusions (LOCK / CONFIRMED facts / angle outcomes) instead of raw
    evidence. When the model never engaged the blackboard, a fallback LOCK is
    synthesized from the final answer so the notes are never empty after a
    completed run. Returns the save ack, or None when there is nothing at all.
    """
    from vulnclaw.agent.blackboard import NodeStatus, NodeType

    lines: list[str] = []
    lock = blackboard.current_lock() if blackboard is not None else None
    if lock is not None:
        lines.append(f"LOCK: {lock.description}")
    facts = blackboard.confirmed_facts() if blackboard is not None else []
    if facts:
        lines.append("CONFIRMED: " + "; ".join(f.description for f in facts[:8]))
    angle_bits: list[str] = []
    if blackboard is not None:
        mark = {
            NodeStatus.CONFIRMED: "hit",
            NodeStatus.CHALLENGED: "miss",
            NodeStatus.PROPOSED: "open",
        }
        angle_bits = [
            f"[{mark.get(n.status, '?')}] {n.description}"
            for n in blackboard.all_nodes()
            if n.type == NodeType.ANGLE
        ]
    if angle_bits:
        lines.append("ANGLES: " + "; ".join(angle_bits[:10]))
    if not lines and final_answer:
        # Blackboard-avoidant run: the completion declaration is still a real
        # conclusion — keep it, clearly labelled, so reuse is not lost.
        synth = " ".join(final_answer.split())[:300]
        lines.append(f"LOCK: (from final answer) {synth}")
    if not lines:
        return None
    lines.append(f"TARGET: {target}")
    lines.append(f"GOAL: {goal}")
    if outcome:
        lines.append(f"OUTCOME: {outcome}")
    steps = "\n".join(lines).strip()
    if len(steps) < MIN_PLAYBOOK_CHARS:
        return None
    return save_playbook(
        name=_auto_notes_name(target),
        fingerprint=target_fingerprint(target, goal),
        steps=steps,
        status=status,
    )


def format_playbook_list(items: list[dict[str, Any]]) -> str:
    if not items:
        return "[playbook] No matching playbook for this fingerprint."
    parts = [f"[playbook] {len(items)} match(es):"]
    for it in items:
        mark = "✅ validated" if it["status"] == "validated" else "📝 draft"
        parts.append(
            f"- {mark} score={it['score']} :: {it['name']} (slug={it['slug']})\n"
            f"  steps:\n{it['steps'][:2000]}"
        )
    return "\n".join(parts)


async def execute_playbook_tool(tool_name: str, args: dict[str, Any]) -> str:
    """Dispatch lookup_playbook / save_playbook (run in a thread — pure disk I/O)."""
    import asyncio

    # Both are quick local I/O; keep dispatch simple and sync.
    if tool_name == "lookup_playbook":
        fingerprint = str(args.get("fingerprint") or "").strip()
        if not fingerprint:
            return "[!] lookup_playbook requires a non-empty fingerprint"
        limit = int(args.get("limit", 3) or 3)
        items = await asyncio.to_thread(lookup_playbook, fingerprint, limit=limit)
        return format_playbook_list(items)

    if tool_name == "save_playbook":
        name = str(args.get("name") or "").strip()
        fingerprint = str(args.get("fingerprint") or "").strip()
        steps = str(args.get("steps") or "").strip()
        if not name or not fingerprint or not steps:
            return "[!] save_playbook requires name, fingerprint and steps"
        status = str(args.get("status") or "draft").strip().lower()
        ack = await asyncio.to_thread(
            save_playbook,
            name=name,
            fingerprint=fingerprint,
            steps=steps,
            status=status,
        )
        if "error" in ack:
            return f"[!] save_playbook rejected: {ack['error']}"
        return (
            f"[playbook] saved '{ack['name']}' as {ack['status']} "
            f"(slug={ack['slug']}). It will be offered to future runs of this "
            f"challenge via lookup_playbook."
        )

    return f"[!] Unknown playbook tool: {tool_name}"
