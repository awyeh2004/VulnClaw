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
from vulnclaw.utils.atomic_write import atomic_write_text

MIN_PLAYBOOK_CHARS = 80  # minimum steps length (prevents 3-line low-effort entries)

# Where a note came from. Two kinds exist and they are not equally valuable:
# a curated note is a technique the model chose to write down (it carries the
# transferable parts -- the exposed surface, the pitfall, the exfil path), while an
# auto note is capture_run_notes() dumping the run's LOCK/CONFIRMED lines. Auto notes
# are numerous and near-duplicates of each other, and because their fingerprint is
# built from the same goal text the query uses, they score HIGH. Without the reserve
# in lookup_playbook_multi they fill every slot and push the curated note out.
SOURCE_AUTO = "auto"
SOURCE_CURATED = "curated"
AUTO_NOTES_PREFIX = "AutoNotes"

# Built FROM the one canonical prefix list instead of keeping a local copy. This file
# used to carry `(flag|ctf)\{...\}`, a two-name copy of an eighteen-name list, which is
# the same drift that once left finding_parser on 3 of 17 prefixes. Two consequences,
# both measured on the playbooks real runs wrote on 2026-09-23:
#
#   * `CTF2{...}` -- the format of the platform this tool drives -- did not match at
#     all, so BabySQL's per-instance flag was stored in full;
#   * `DASCTF{...}`/`BUUCTF{...}` matched only from the inner "CTF{".
#
# Round-8 finding R8-6: deriving from that list fixed the DRIFT but not the CLOSURE. A
# list of platform names can never be complete -- the audit named `HGAME{}`, `GWHT{}`,
# `HTB{}`, `THM{}`, `cyberpeace{}`, `0xGame{}` and `ISCC{}` as real platforms missing
# from it -- and two shape limits sat on top: a separator spelling (`flag1{`, `flag_{`)
# did not match at all, and a body longer than 80 characters was left verbatim.
#
# The gate therefore no longer depends on knowing the platform:
#
#   1. KNOWN prefix (the canonical list, now also allowing a `1`/`_`/`9mm` style
#      separator before the brace) -> redacted whatever the body looks like;
#   2. UNKNOWN prefix of flag-ish shape (`SOMEPLATFORM{...}`, possibly digit-leading as
#      in `0xGame{}`) -> redacted when the body looks like flag material rather than
#      code. That test is what keeps a note's CSS (`body{color:red}`) or JS
#      (`else{return}`) intact: a body is treated as a flag only if it is drawn from the
#      flag charset AND carries a digit, an uppercase letter or a separator -- which
#      every real flag body does and stylesheet text does not.
#
# The body cap is 200, not 80: exceeding a length is not a reason to store a flag.
_FLAGISH_PREFIX = r"(?=[A-Za-z0-9_]*[A-Za-z])[A-Za-z0-9_]{2,24}"
_FLAG_BODY_MAX = 200
# NOTE the extra `(?:...)`: alternation binds loosest, so `known|generic\{body\}`
# without it would match a bare platform name anywhere in ordinary prose and never
# require a body -- group(2) would be None and `len(inner)` would raise.
_FLAG_FINGERPRINT_RE = re.compile(
    r"((?:" + "|".join(re.escape(name) for name in FLAG_PREFIX_NAMES) + r")(?:[0-9_]{0,3})?"
    r"|" + _FLAGISH_PREFIX + r")"
    r"\{([^{}]{1," + str(_FLAG_BODY_MAX) + r"})\}",
    re.IGNORECASE,
)
# Charset a flag body is drawn from. `:` and `.` are deliberately absent: they are what
# `color:red` and `1..10` are made of, and a real flag using them still comes through
# tier 1 above (its prefix is a known platform name).
_FLAG_BODY_CHARSET_RE = re.compile(r"^[A-Za-z0-9_\-+=/!@#$%^&*]+$")
_FLAG_BODY_SIGNAL_RE = re.compile(r"[0-9A-Z_\-+=/]")
# Identifiers that precede a `{` in ordinary code/stylesheet text. Only consulted for
# tier 2, where guessing wrong is possible.
_NON_FLAG_BRACE_WORDS = frozenset(
    {
        "body", "html", "head", "media", "font", "keyframes", "supports", "root",
        "function", "return", "class", "def", "lambda", "import", "format", "print",
        "dict", "list", "set", "tuple", "map", "filter", "regex", "pattern", "query",
    }
)

_KNOWN_PREFIX_CACHE: Optional[tuple[tuple[str, ...], "re.Pattern[str]"]] = None


def _known_flag_prefix_re() -> "re.Pattern[str]":
    """Compiled matcher for tier 1, rebuilt when the canonical list changes.

    Read through the module global rather than captured at import time: the canonical
    tuple is monkeypatched in tests and may be extended at runtime, and a cached pattern
    built from a stale tuple would silently stop covering a newly added platform.
    """
    global _KNOWN_PREFIX_CACHE
    names = tuple(FLAG_PREFIX_NAMES)
    cached = _KNOWN_PREFIX_CACHE
    if cached is None or cached[0] != names:
        cached = (
            names,
            re.compile(
                "(?:" + "|".join(re.escape(name) for name in names) + r")(?:[0-9_]{0,3})?",
                re.IGNORECASE,
            ),
        )
        _KNOWN_PREFIX_CACHE = cached
    return cached[1]


def _is_known_flag_prefix(prefix: str) -> bool:
    return _known_flag_prefix_re().fullmatch(prefix) is not None


def _looks_like_flag_body(inner: str) -> bool:
    """Whether an unknown-prefix `{...}` body is flag material rather than code.

    Deliberately shape-based, not name-based: this is the half that has to work for a
    platform nobody has heard of yet. A body qualifies when it is drawn from the flag
    charset, carries no whitespace, and either contains a digit/uppercase/separator or is
    long enough (12+) that it is not an ordinary identifier.

    `color:red` (a colon), `return` (no signal character, short), `1..10` (dots) and
    `deadbeef` (8 lowercase chars) all fail; `9f113b92-cb26-424a`, `abcdef123456` and
    `abcdefghijklmnop` pass.

    Documented limit: an unknown-prefix body that is both short and signal-free
    (`GWHT{x}`) is kept. Redacting it would mean mangling `if{ready}`-shaped code, and a
    sub-12-character lowercase body is not a submittable flag in any observed format.
    """
    body = str(inner or "").strip()
    if not body or len(body) > _FLAG_BODY_MAX:
        return False
    if not _FLAG_BODY_CHARSET_RE.match(body):
        return False
    if _FLAG_BODY_SIGNAL_RE.search(body) is not None:
        return True
    return len(body) >= 12


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

    Two tiers (round-8 R8-6, see the regex comment): a KNOWN platform prefix is redacted
    whatever its body looks like, an UNKNOWN one is redacted when the body looks like flag
    material -- so the gate no longer depends on a list of platform names being complete.

    Idempotent by construction: the fingerprint form still matches the pattern, so
    applying this twice is the same as applying it once. The read path
    (``Playbook.from_frontmatter``) relies on that to filter notes written before the
    gate covered their fields (round-8 R8-5).
    """
    def _fp(m: re.Match) -> str:
        prefix, inner = m.group(1), m.group(2)
        if not _is_known_flag_prefix(prefix) and (
            prefix.lower() in _NON_FLAG_BRACE_WORDS or not _looks_like_flag_body(inner)
        ):
            return m.group(0)
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
    source: str = SOURCE_CURATED  # "auto" for auto-captured run notes
    _tokens: set[str] = field(default_factory=set, repr=False)

    @property
    def is_auto(self) -> bool:
        return self.source == SOURCE_AUTO

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

    def identity_tokens(self) -> set[str]:
        """Everything the note DECLARES about itself: fingerprint + name + slug.

        ``tokens()`` is the fingerprint alone. That is the right surface for ``score``
        (the field the lookup key was historically built from), but the WRONG surface
        for "how much does this note overlap the query". Measured 2026-09-23 on the real
        store's curated notes: their fingerprints are target-shaped ("Weblogic 10.3.6 -
        /wls-wsat/CoordinatorPortType returns 'Web Services WSAT10Service' listing;
        /console/ redirects to login ..."), so the query ``Weblogic CVE-2017-10271``
        overlaps them on exactly ONE token -- while the note's NAME ("Weblogic
        CVE-2017-10271 (wls-wsat XMLDecoder RCE) flag exfil via bea_wls_internal
        docRoot") shares TWO. Counting only the fingerprint withheld that note on 11 of
        278 real challenge goals, every one of them its own sibling challenges, and
        withheld the ThinkPHP note on 14 -- i.e. the overlap floor would have removed
        cross-challenge reuse entirely for the notes this feature exists for.

        This is the same defect the class-agreement rule in ``lookup_playbook_multi``
        already documents and fixes: the fingerprint is often just the target string,
        while the note states what it is in its name. One rule must not read the name
        while another reads only the fingerprint of the same note.

        A slug is a lossy copy of the name, but including it costs nothing and it is the
        field a note is addressed by in the run log.
        """
        return self.tokens() | _tokenize(self.name) | _tokenize(self.slug)

    @property
    def path(self) -> Path:
        return PLAYBOOKS_DIR / f"{self.slug}.md"

    def to_frontmatter(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "fingerprint": self.fingerprint,
            "status": self.status,
            "source": self.source,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_frontmatter(cls, slug: str, meta: dict[str, Any], body: str) -> "Playbook":
        recorded = str(meta.get("source", "") or "").strip().lower()
        # Round-8 finding R8-5, read half. Redaction at the WRITE path cannot clean the
        # files already on disk, and those are exactly the ones a future run loads: the
        # measured 2026-09-23 store has notes whose `name:` line holds a full flag (the
        # only surface `_fingerprint_flags` did not cover). Everything that crosses the
        # disk boundary is therefore redacted here as well -- the function is idempotent,
        # so a note written by the fixed path is unchanged by this, and a note written
        # before it becomes inert instead of being offered to the next run verbatim.
        return cls(
            slug=slug,
            name=_fingerprint_flags(str(meta.get("name", "") or "")),
            fingerprint=_fingerprint_flags(str(meta.get("fingerprint", "") or "")),
            status=str(meta.get("status", "draft") or "draft"),
            steps=_fingerprint_flags(body or ""),
            scripts="",
            updated_at=str(meta.get("updated_at", "") or ""),
            # Notes written before `source` existed are recognised by the name
            # capture_run_notes always used, so a legacy store is not silently
            # reclassified as curated (that would defeat the reserve below).
            source=recorded or (
                SOURCE_AUTO
                if str(meta.get("name", "") or "").strip().startswith(AUTO_NOTES_PREFIX)
                else SOURCE_CURATED
            ),
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

    This is the **ungated recall primitive**: it applies no overlap floor, because
    the model calls it directly through the ``lookup_playbook`` tool and wants the
    widest net (see ``lookup_playbook_multi`` for the floor that the automatic
    injection path uses). Rows carry ``overlap_tokens`` -- the number of distinct
    query tokens the note DECLARES (fingerprint + name + slug, see
    :meth:`Playbook.identity_tokens`) -- so callers never have to infer it from
    ``score``, which is a share of the QUERY and therefore length-dependent.
    """
    if not (fingerprint or "").strip():
        return []
    query_tokens = _tokenize(fingerprint)
    scored: list[tuple[float, int, Playbook]] = []
    for pb in list_playbooks():
        s = pb.score(fingerprint)
        if s >= min_score:
            scored.append((s, len(query_tokens & pb.identity_tokens()), pb))
    # Stable ranking: higher score first; more overlap, then validated-before-draft
    # on ties.
    #
    # The third key was `0 if validated else 1` under `reverse=True`, i.e. a DRAFT
    # outranked a validated note on a tie -- the exact opposite of what this comment,
    # the docstring above and `_reserve_curated_representation` all describe (round8 L3).
    # Written as a boolean it cannot be read the wrong way round again: True sorts after
    # False, so under reverse=True the validated note comes first.
    scored.sort(
        key=lambda item: (item[0], item[1], item[2].status == "validated"),
        reverse=True,
    )
    result = []
    for score, overlap, pb in scored[: limit if limit and limit > 0 else 3]:
        result.append(
            {
                "name": pb.name or pb.slug,
                "slug": pb.slug,
                "status": pb.status,
                "source": pb.source,
                "score": round(score, 3),
                "overlap_tokens": overlap,
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
    # Vulnerability classes belong in here too. Measured on a real store: with the
    # challenge name written as "([Weblogic]SSRF)" the bracketed tag is only
    # "Weblogic", so the whole signature collapsed to one token, every Weblogic note
    # scored 1.0, and the query declared no class -- which made the class-agreement
    # rule a no-op on exactly the case it exists for.
    bits += sorted(vulnerability_classes(text))
    seen: set[str] = set()
    out: list[str] = []
    for bit in bits:
        key = bit.strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(bit.strip())
    return " ".join(out)


def _reserve_curated_representation(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Keep a curated note in the result when auto-captured notes crowd it out.

    Measured 2026-09-23 on a real store: the useful note for a Weblogic challenge
    scored 0.250 while an auto note scored 0.727, so the ranking was fine -- but the
    auto store grows one entry per run, and the moment two of them outscore the
    curated note the curated note falls off the end of a ``limit=2`` result and the
    injection silently loses the only note that had carried the technique across
    challenges (that note turned a 179s/19-step run into 50s/8 steps).

    The rule is deliberately minimal and never shrinks a result set:

    * if at least one curated note matched and the top ``limit`` rows contain none,
      the last slot is given to the best curated row;
    * if the store holds only auto notes, nothing changes -- an empty-ish store must
      not be made emptier.

    Ordering by score is preserved for every other row.
    """
    if limit <= 0 or not rows:
        return rows
    top = rows[:limit]
    if any(row.get("source") != SOURCE_AUTO for row in top):
        return top
    curated = next((row for row in rows if row.get("source") != SOURCE_AUTO), None)
    if curated is None:
        return top
    return [*top[:-1], curated]


# How many rows each key is scanned for before merging. Must exceed the caller's
# limit: capping per key truncates BEFORE the curated reserve can see a curated note
# that ranks below the auto notes, which is exactly the case the reserve exists for
# (measured: two auto notes at 1.0, the useful curated note at 0.5).
_LOOKUP_SCAN_LIMIT = 50

# Minimum number of DISTINCT tokens a note must share with a query before automatic
# injection will consider it a hit.
#
# ``Playbook.score`` is the share of the QUERY's tokens found in the note, so a
# one-token query makes every note of that framework score exactly 1.0. Measured
# 2026-09-23 on CTF2: with the goal written as "([Weblogic]SSRF)" the class
# signature collapsed to a single token, the hit rate was 4/4, and every one of
# those "perfect" hits carried no relevance information -- one of them (a Weblogic
# XMLDecoder deserialization note, injected into a Weblogic SSRF challenge) measurably
# derailed the run (mentions of "ssrf" fell 28 -> 3 while "bea_wls_internal" rose
# 2 -> 41).
#
# The floor is counted in tokens, never inferred from the score: the score is
# length-dependent, so "score >= x" would block a 12-token query whose 2-token
# overlap is real while letting a 1-token query's 1.0 through.
#
# Deliberate recall cost: it also drops genuine single-token framework hits. Every
# dropped row is reported through ``out_blocked`` so the run log can name it.
MIN_OVERLAP_TOKENS = 2


def _is_a_better_merge_candidate(candidate: dict[str, Any], current: dict[str, Any]) -> bool:
    """Which of two per-key hits for the SAME note should represent it.

    Overlap first, then score. A short class query inflates the score (share of the
    query's tokens found in the note) while sharing only the framework token, whereas
    the long probe/target query that shares eight real tokens scores far lower. Keeping
    "the highest score" therefore kept the WORSE evidence: measured on a fixture where
    the class key returned ``score=1.0 overlap=1`` and the target key
    ``score=0.5 overlap=2``, the merged row inherited the one-token hit and the
    ``MIN_OVERLAP_TOKENS`` gate then threw the note away although it did qualify.
    The overlap is also the number reported in the run log, so it must describe the
    key that actually carried the hit.
    """
    return (int(candidate.get("overlap_tokens", 0) or 0), candidate["score"]) > (
        int(current.get("overlap_tokens", 0) or 0),
        current["score"],
    )


# Vulnerability classes, so "same framework" is not mistaken for "same problem".
#
# Measured 2026-09-23: the class key matched a Weblogic XMLDecoder-deserialization
# note into a Weblogic **SSRF** challenge. With the signature reduced to a single
# token ("Weblogic") the note scored 1.0, and the run visibly abandoned the asked-for
# class (mentions of "ssrf" fell 28 -> 3 while "bea_wls_internal" rose 2 -> 41). It
# solved anyway, because the note's knowledge was environmental (which path is
# unauthenticated, where the flag can be exfiltrated) and that transferred.
#
# Hence DEMOTE, never exclude: a note whose declared class disagrees stays available
# as a fallback (it demonstrably helped), but any note that agrees outranks it.
# A note declaring no class at all is not treated as disagreeing -- silence is not
# a contradiction, and most curated notes predate this vocabulary.
_VULN_CLASS_PATTERNS: dict[str, tuple[str, ...]] = {
    "ssrf": ("ssrf", "服务端请求伪造", "server-side request forgery"),
    "deserialization": ("deserial", "反序列化", "xmldecoder", "marshalsec", "jrmp", "t3 protocol"),
    "sqli": ("sql injection", "sqli", "sql注入", "sql 注入", "注入点", "boolean-blind"),
    "rce": ("rce", "命令执行", "code execution", "远程执行", "getshell", "invokefunction"),
    "xxe": ("xxe", "xml external entity", "外部实体"),
    "file_read": ("lfi", "文件包含", "path traversal", "目录穿越", "任意文件读取", "file read"),
    "upload": ("file upload", "文件上传", "上传", "webshell"),
    "ssti": ("ssti", "template injection", "模板注入"),
    "auth_bypass": ("weak password", "弱口令", "brute force", "爆破", "未授权", "unauth", "unacc"),
    "steganography": ("steg", "隐写", "隐写术"),
    "crypto": ("rsa", "aes", "cipher", "加密", "解密", "密码学"),
    "reverse": ("reverse", "逆向", "crackme", "disassembl", "反汇编"),
    "pwn": ("pwn", "pwntools", "heap overflow", "栈溢出", "rop chain"),
}

# Needles that are deliberately the STEM of a longer word, and so must not require a
# trailing boundary: "deserial" -> deserialization, "disassembl" -> disassembly,
# "unauth" -> unauthorized, "unacc" -> unaccepted, "steg" -> steganography/stegsolve.
_VULN_CLASS_PREFIX_NEEDLES = frozenset({"deserial", "disassembl", "unauth", "unacc", "steg"})


def _class_needle_re(needle: str) -> "re.Pattern[str]":
    """Word-bounded matcher for one class needle.

    The boundaries are ASCII-only on purpose. Python's ``\\b`` uses ``\\w``, which counts
    CJK characters as word characters, so ``\\brce\\b`` would NOT match the ordinary
    Chinese spelling ``RCE漏洞`` -- a boundary test against 漏 fails. `(?![a-z0-9])`
    accepts it while still refusing to match inside "force" or "resources".

    Only the LEADING side is required for the stem needles above; a trailing boundary
    would make "deserial" stop matching "deserialization", which is the whole point of
    listing the stem.
    """
    escaped = re.escape(needle.lower())
    if needle in _VULN_CLASS_PREFIX_NEEDLES:
        return re.compile(r"(?<![a-z0-9])" + escaped)
    return re.compile(r"(?<![a-z0-9])" + escaped + r"(?![a-z0-9])")


_VULN_CLASS_RES: dict[str, tuple["re.Pattern[str]", ...]] = {
    name: tuple(_class_needle_re(needle) for needle in needles)
    for name, needles in _VULN_CLASS_PATTERNS.items()
}


def vulnerability_classes(text: str) -> frozenset[str]:
    """Vulnerability classes a text declares, from a fixed vocabulary.

    Deliberately a closed vocabulary rather than a model call: this runs on every
    lookup and must be deterministic and free. Unknown classes simply do not appear,
    which degrades to the previous behaviour instead of failing.

    Round-8 finding R8-7: the needles were matched as BARE SUBSTRINGS, so `"rce"` fired
    on "brute fo**rce**", "view-sou**rce**" and "resou**rce**s" -- measured:
    ``vulnerability_classes("brute force the login form")`` returned ``{auth_bypass, rce}``.
    Every false declaration costs twice: the class-agreement demotion stops working on the
    most common class (a note that really is about RCE compares equal), and the note class
    read from a fingerprint mislabels rows. Matching is now word-bounded (see
    ``_VULN_CLASS_RES``), which is the third instance of this same defect in this file --
    single-token signatures and read-only-fingerprint classes were the first two.
    """
    low = str(text or "").lower()
    return frozenset(
        name for name, patterns in _VULN_CLASS_RES.items()
        if any(pattern.search(low) for pattern in patterns)
    )


def lookup_playbook_multi(
    queries: Sequence[tuple[str, str]],
    *,
    limit: int = 3,
    min_score: float = 0.15,
    out_blocked: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    """Look each ``(kind, query)`` up and merge the hits, best row per slug.

    Returns the same rows as :func:`lookup_playbook` plus ``query_kind``,
    ``query``, ``overlap_tokens``, ``vuln_classes`` and ``vuln_class_agrees``, so a
    caller can report which key matched and whether the note is about the same KIND
    of problem -- the hit rate per key is the number worth watching, and it was
    invisible while only the count was recorded. When two keys find the same note,
    the row kept is the one with the larger overlap (see
    :func:`_is_a_better_merge_candidate`), not the larger score.

    Ranking puts class agreement ahead of raw score: a keyword-overlap score cannot
    separate "same framework" from "same vulnerability", and the class key is
    usually a short query (one or two tokens) where everything scores 1.0.

    Every surviving row must overlap **``MIN_OVERLAP_TOKENS`` distinct tokens** with
    at least one of the queries. The floor is what kills the degenerate case in
    which a one-token query (the real signature of ``([Weblogic]SSRF)`` is just
    ``Weblogic``) scores **1.0 against every note of that framework** -- a perfect
    score carrying no relevance information at all, because ``score`` measures
    recall (share of the query's tokens found in the note), not relevance.

    The floor applies to the merged rows, so it treats ``target`` and ``class``
    alike: a one-token ``target`` query is the same degenerate shape. A row whose
    only qualifying key is the long target fingerprint (which carries the goal
    text, so a real sibling note can reach the floor there) still passes.

    The overlap is counted against the note's DECLARED identity (fingerprint + name +
    slug, :meth:`Playbook.identity_tokens`) rather than its fingerprint alone. Measured
    on 278 real challenge goals: counting the fingerprint only withheld the store's
    curated Weblogic note on all 11 sibling goals that matched it, and the ThinkPHP note
    on all 14 -- a 100% loss of exactly the cross-challenge reuse this feature exists for,
    because those notes' fingerprints are target-shaped and their names carry the
    discriminators. Counting the name as well restores them without letting a bare
    framework token through (a query of ``Weblogic`` alone still needs a second token
    that the note actually declares).

    ``out_blocked``, when given, is filled with the rows the floor removed --
    ``slug``/``name``/``score``/``overlap_tokens``/``query_kind`` -- so the run log
    can say *which* note was withheld. A recall cost nobody can see is a recall
    loss nobody can diagnose: without this, "why was nothing injected for this
    challenge" becomes unanswerable after the fact.
    """
    effective = limit if limit and limit > 0 else 3
    query_classes = vulnerability_classes(" ".join(q for _, q in queries))
    best: dict[str, dict[str, Any]] = {}
    for kind, query in queries:
        if not str(query or "").strip():
            continue
        for row in lookup_playbook(query, limit=_LOOKUP_SCAN_LIMIT, min_score=min_score):
            current = best.get(row["slug"])
            if current is None or _is_a_better_merge_candidate(row, current):
                merged = dict(row)
                merged["query_kind"] = kind
                merged["query"] = query
                best[row["slug"]] = merged
    rows = list(best.values())
    for row in rows:
        # The note's DECLARED identity, not its prose: name and slug are where a
        # curated note says what it is ("Weblogic CVE-2017-10271 (wls-wsat XMLDecoder
        # RCE) ..."), while the fingerprint is often just the target string. Reading
        # only the fingerprint reported an empty class set for notes whose names
        # plainly state one, which silently disabled this rule on a real store.
        note_classes = vulnerability_classes(
            " ".join(
                str(row.get(field, "") or "")
                for field in ("name", "slug", "fingerprint")
            )
        )
        row["vuln_classes"] = sorted(note_classes)
        # Silence is not contradiction: a note naming no class is not demoted.
        row["vuln_class_agrees"] = (
            not query_classes or not note_classes or bool(query_classes & note_classes)
        )
    rows.sort(
        key=lambda r: (
            bool(r.get("vuln_class_agrees", True)),
            r["score"],
            # Same sign fix as in `lookup_playbook` (round8 L3): a validated note must
            # win a tie, and a boolean under reverse=True says that directly.
            r["status"] == "validated",
        ),
        reverse=True,
    )
    if out_blocked is not None:
        blocked_seen: dict[str, dict[str, Any]] = {}
        for row in rows:
            overlap = int(row.get("overlap_tokens", 0) or 0)
            if overlap >= MIN_OVERLAP_TOKENS:
                continue
            entry = dict(row)
            entry["overlap_tokens"] = overlap
            previous = blocked_seen.get(row["slug"])
            if previous is None or overlap > previous["overlap_tokens"]:
                blocked_seen[row["slug"]] = entry
        out_blocked.extend(blocked_seen.values())
    rows = [row for row in rows if int(row.get("overlap_tokens", 0) or 0) >= MIN_OVERLAP_TOKENS]
    return _reserve_curated_representation(rows, effective)


def save_playbook(
    *,
    name: str,
    fingerprint: str,
    steps: str = "",
    status: str = "draft",
    slug: Optional[str] = None,
    source: str = SOURCE_CURATED,
) -> dict[str, Any]:
    """Persist (or cover-update) a playbook. Returns a small ack dict.

    Quality validation (inspired by heimdall brief-summarizer):
    1. steps must be >= MIN_PLAYBOOK_CHARS (prevents 3-line low-effort entries)
    2. must contain at least one of LOCK/CONFIRMED/ANGLES headings (structured)
    3. full flag values are fingerprinted to flag{first4…last4} (cross-instance hygiene)
       in EVERY persisted field -- name, fingerprint, slug and steps (round-8 R8-5;
       before that only `steps` was covered)

    ``source`` records whether the note was chosen by the model (curated) or dumped
    by capture_run_notes (auto). It is persisted in the frontmatter so the
    curated-reserve rule does not have to infer it from the name forever.
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
    # Round-8 finding R8-5: this covered `steps` ONLY, while `name`, `fingerprint` and
    # the slug DERIVED from the name were written verbatim. The model holds the flag
    # exactly when it marks a note validated, so putting it in the title is ordinary
    # behaviour -- and `format_playbook_list` feeds that name back into a future run's
    # prompt, reopening the "resubmit a previous instance's flag" channel this gate
    # exists to close. `capture_run_notes` was never affected (its name is the fixed
    # AutoNotes prefix); the model-initiated path was.
    name = _fingerprint_flags(str(name or ""))
    fingerprint = _fingerprint_flags(str(fingerprint or ""))
    steps = _fingerprint_flags(stripped)

    status = "validated" if status == "validated" else "draft"
    source = SOURCE_AUTO if str(source or "").strip().lower() == SOURCE_AUTO else SOURCE_CURATED
    # A caller-supplied slug is redacted too: it is the filename, and the filename is
    # what `list_playbooks` addresses the note by in later runs.
    slug = _slugify(_fingerprint_flags(str(slug))) if slug else _slugify(name)
    from datetime import datetime, timezone

    # Cover-update: if a same-name playbook exists, keep the same slug. Both sides are
    # compared after redaction (the read path redacts `existing.name`), so a note whose
    # stored name still holds a flag is recognised instead of being duplicated.
    for existing in list_playbooks():
        if existing.name and existing.name.strip().lower() == name.strip().lower():
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
        f"source: {source}",
        f"updated_at: {updated_at}",
        "---",
        "",
        steps.strip(),
        "",
    ]
    # Through the shared atomic writer, not a bare `write_text` (round7, still open at
    # round9). `write_text` truncates first and writes through the OS cache, so two
    # sessions saving the same slug can lose an update and a concurrent `list_playbooks`
    # can read a half-written note -- the store is shared across sessions by design
    # (`~/.vulnclaw/playbooks`). `vulnclaw.utils.atomic_write` is the one implementation
    # that also knows the Windows sharing-violation retry; the sibling KB path already
    # used it (af3c4f2), and `platforms/attachments` points at it in a comment.
    atomic_write_text(PLAYBOOKS_DIR / f"{slug}.md", "\n".join(lines))
    return {"slug": slug, "status": status, "name": name, "source": source}


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


def _recallable_fingerprint(target: str, goal: str) -> Optional[str]:
    """The fingerprint to STORE for a captured note, or None if it could never be found.

    The invariant is NOT "the fingerprint has a token" -- that is too strict, and
    measurably so. ``score`` counts the QUERY's tokens found in the NOTE, so a note whose
    fingerprint is a low-token string like ``http://t/`` is still found by the URL-shaped
    queries it was captured from: that string is IN the fingerprint text. A first version of
    this gate rejected any fingerprint with an empty token set and thereby turned two
    existing capture tests red -- a recall REGRESSION on notes that were perfectly findable.
    The real question is "can anything find this note?", so that is what gets asked.

    So the guard checks the note against the identity it is about to be given. If nothing
    of its fingerprint / name / slug can match ANY query token, the note is unreachable and
    is not worth a store slot. Measured case (2026-09-24, real home store):
    ``autonotes-babyfengshui-33c3-2016`` was captured with ``target='E:'`` and its stored
    fingerprint is that same two-character string; against 4 target shapes x 3 goals
    (12 combinations, including the target it came from) it scored 0.000 and was never
    found. ``Path('E:').exists()`` is True on Windows while ``is_file()`` is False, so a
    bare drive letter is "an existing target" that is not a file: no content hash, and
    ``_tokenize`` drops it.

    Two escapes, then a refusal:

    * the target-derived fingerprint is already findable -> store it unchanged;
    * it is not, but widening it with the GOAL makes it findable -> store the widened key,
      which keeps the run's confirmed conclusions;
    * neither -> return None, and ``capture_run_notes`` declines to write. A note nobody can
      recall costs a slot and, worse, makes the store look richer than it is.
    """
    fingerprint = target_fingerprint(target, goal)
    name = _auto_notes_name(target)
    if _note_is_queryable(fingerprint, name):
        return fingerprint
    widening = " ".join(part for part in (goal, target) if str(part or "").strip()).strip()
    if widening and _note_is_queryable(widening, name):
        return widening
    return None


def _note_is_queryable(fingerprint: str, name: str) -> bool:
    """Whether SOME query could find a note with this fingerprint and name.

    The note's own identity tokens are the candidate answers, so a query made of those
    tokens is the most favourable query that can exist: if even that scores zero, no query
    can find the note.
    """
    probe = Playbook(slug=_slugify(name), name=name, fingerprint=fingerprint or "")
    identity = probe.identity_tokens()
    if not identity:
        return False
    return probe.score(" ".join(sorted(identity))) > 0.0


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
    fingerprint = _recallable_fingerprint(target, goal)
    if fingerprint is None:
        # Nothing in the target OR the goal can be tokenized, so no future query could ever
        # score this note above zero. Writing it would create a note that looks like saved
        # knowledge and is findable by nobody (see _recallable_fingerprint for the measured
        # `'E:'` case). Declining is the smaller loss.
        return None
    return save_playbook(
        name=_auto_notes_name(target),
        fingerprint=fingerprint,
        steps=steps,
        status=status,
        source=SOURCE_AUTO,
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
