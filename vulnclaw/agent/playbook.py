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
from pathlib import Path
from typing import Any, Optional

from vulnclaw.config.settings import CONFIG_DIR

MIN_PLAYBOOK_CHARS = 80  # minimum steps length (prevents 3-line low-effort entries)
_FLAG_FINGERPRINT_RE = re.compile(r"(flag|FLAG|ctf|CTF)\{([^{}]{4,80})\}")


def _fingerprint_flags(text: str) -> str:
    """Replace full flag values with first4…last4 fingerprints.

    Cross-instance hygiene: flags rotate per container instance; storing the
    full value lets a future run mistakenly resubmit a stale flag. The
    fingerprint preserves enough structure for the model to recognise the
    pattern while preventing accidental resubmission.
    """

    def _fp(m: re.Match) -> str:
        prefix, inner = m.group(1), m.group(2)
        if len(inner) > 12:
            return f"{prefix}{{{inner[:4]}…{inner[-4:]}}}"
        return m.group(0)

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
