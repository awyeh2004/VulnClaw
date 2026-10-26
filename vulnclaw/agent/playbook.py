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
# Stronger signal, used ONLY by the unclosed tier. `_FLAG_BODY_SIGNAL_RE` counts an
# uppercase letter, which is not evidence enough when there is no closing brace to
# anchor on: with it, `TemplateMetadata{renderer:ReportRenderer{postProcessor:...` —
# a PHP POP chain in a curated note — read as flag material and got mangled into
# `ReportRenderer{…}`. Requiring a digit or a real flag separator demands actual flag
# shape and leaves camelCase identifiers alone. (`archiver`, `postProcessor`, and
# `MyFlagIsHere` all fail it; `W0w_U_Ar3_V3ry_G00d_A7_C0unt1n9_` passes on both.)
_FLAG_BODY_STRONG_SIGNAL_RE = re.compile(r"[0-9_\-+=/]")
# Identifiers that precede a `{` in ordinary code/stylesheet text. Only consulted for
# tier 2, where guessing wrong is possible.
_NON_FLAG_BRACE_WORDS = frozenset(
    {
        "body", "html", "head", "media", "font", "keyframes", "supports", "root",
        "function", "return", "class", "def", "lambda", "import", "format", "print",
        "dict", "list", "set", "tuple", "map", "filter", "regex", "pattern", "query",
    }
)

# Tier 3 — UNTERMINATED flag literals. Round-9 (2026-10-07) postmortem: the closed-brace
# pattern above cannot see a value whose `}` never made it into the note (a `strings`
# dump cut off mid-constant, or a note pasting only the head). That is how
# `flag{W0w_U_Ar3_V3ry_G00d_A7_C0unt1n9_` — a real ELF string constant, no closing brace
# anywhere near it — sat in a `fingerprint:` in cleartext while the read-path gate
# reported the note clean, because "a flag with no `}`" was not a shape that existed.
#
# Two guards keep it from eating prose. The body is a maximal run of FLAG-CHARSET
# characters, so the match stops dead at the first quote, space, brace, comma or
# newline and can never swallow the rest of the note (an earlier draft used `[^\s}]`,
# which greedily ate the closing quote of `'flag{...}'` and then failed the charset
# check, silently redacting nothing — caught by
# tests/agent/test_playbook_unclosed_flag_redaction.py). `(?!…)` leaves an
# already-masked `flag{abcd…3456}` alone instead of collapsing it; and
# ``_looks_like_flag_body`` must still accept the body, so shape is required even for a
# known prefix. Tier 1's "a known prefix is reason enough" deliberately does NOT apply
# here: an unclosed brace is far more ambiguous than a closed one.
_FLAG_UNCLOSED_RE = re.compile(
    r"((?:" + "|".join(re.escape(name) for name in FLAG_PREFIX_NAMES) + r")(?:[0-9_]{0,3})?"
    r"|" + _FLAGISH_PREFIX + r")"
    r"\{([A-Za-z0-9_\-+=/!@#$%^&*]{1," + str(_FLAG_BODY_MAX) + r"})"
    r"(?!…)(?![A-Za-z0-9_\-+=/!@#$%^&*])",
    re.IGNORECASE,
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

    Two tiers for the closed form (round-8 R8-6, see the regex comment): a KNOWN platform
    prefix is redacted whatever its body looks like, an UNKNOWN one is redacted when the
    body looks like flag material -- so the gate no longer depends on a list of platform
    names being complete. Tier 3 (round-9) covers the UNTERMINATED form, which the
    closed-brace pattern structurally cannot match.

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

    def _fp_unclosed(m: re.Match) -> str:
        prefix, inner = m.group(1), m.group(2)
        # Shape is required even for a known prefix here (see _FLAG_UNCLOSED_RE), and
        # no part of the value is kept: without a closing brace there is no way to tell
        # where the flag body ends, so every character of it is treated as the value.
        # Two extra bars, both because an unclosed brace carries no end delimiter and is
        # therefore far weaker evidence than a closed one:
        #   * `_NON_FLAG_BRACE_WORDS` matters more here than in tier 2 — with no closing
        #     brace to anchor on, a code identifier is the likelier reading, and
        #     `function{returnvalue1234` would otherwise pass `_looks_like_flag_body`;
        #   * an 8-character floor. `_looks_like_flag_body` alone accepts a 1-character
        #     body that happens to carry a digit, which redacted the array subscript in
        #     the bash loop `for i in array{1..10}` — caught by the pre-existing
        #     "ordinary code in a note is left alone" test. Every observed flag body is
        #     well over 8 characters; a shorter fragment is not a submittable value.
        if len(inner) < 8:
            return m.group(0)
        if prefix.lower() in _NON_FLAG_BRACE_WORDS or not _looks_like_flag_body(inner):
            return m.group(0)
        # An UNKNOWN prefix needs the stronger signal as well: an unclosed brace under a
        # camelCase identifier is ordinary code far more often than it is a flag (see
        # _FLAG_BODY_STRONG_SIGNAL_RE). A known platform prefix keeps tier 2's rule.
        if not _is_known_flag_prefix(prefix) and not _FLAG_BODY_STRONG_SIGNAL_RE.search(inner):
            return m.group(0)
        # A `…`-only body also keeps this idempotent: the redacted form is too short to
        # re-match, and its `…` is outside the flag charset in any case.
        return f"{prefix}{{…}}"

    return _FLAG_UNCLOSED_RE.sub(_fp_unclosed, _FLAG_FINGERPRINT_RE.sub(_fp, text))

PLAYBOOKS_DIR = CONFIG_DIR / "playbooks"

# Tokens that are (almost) never meaningful for challenge identity and only add
# fingerprint noise: HTML boilerplate, generic CTF wrapper text, common words.
_STOP = {
    "login", "register", "logout", "button", "form", "input", "password",
    "username", "home", "index", "the", "and", "for", "title", "page",
    "challenge", "ctf", "dasctf", "http", "https", "com", "org", "net",
    # Platform-shape words (2026-10-18, measured). Every CTF2 run goal is built
    # from the same sentence -- "Solve CTF2 challenge '<name>' (category X,
    # difficulty Y) on practice <uuid>." -- so these tokens are true of EVERY
    # CTF2 note and carry no discriminating signal. Measured on a real query:
    # 14 tokens total, 13 of them platform boilerplate, leaving exactly one
    # (`rsaroll`) that identified the challenge. The consequence was that any
    # two CTF2 notes scored 0.929 against each other, so `lookup_playbook`
    # returned the right note first but filled the remaining slots with
    # unrelated challenges. Tokens that DO discriminate (the challenge name,
    # vuln classes, attack vocabulary) are untouched.
    "solve", "practice", "category", "difficulty", "easy", "medium", "hard",
    "ctf2", "gcs", "on", "the", "of", "to", "in", "is", "it",
}


#: Tokens that are pure hex and at least this long are id fragments, not words.
#: ``ctf2:practice:<uuid>`` contributes ``b9bbb32f``/``f186``/``458f``/``b90b``
#: to every query and every auto-captured fingerprint of that practice ground;
#: keeping them makes all sibling challenges match on the ground id while
#: saying nothing about the challenge itself.
#:
#: Four, not six: a UUID is ``8-4-4-4-12``, so the middle three groups are
#: exactly four characters (``f186``/``458f``/``b90b``). The digit requirement
#: below is what keeps this from eating real words -- see :func:`_is_id_fragment`.
_HEX_ID_MIN_LEN = 4
_HEX_TOKEN = re.compile(r"[0-9a-f]+")


def _is_id_fragment(tok: str) -> bool:
    """True for a UUID slice / hash fragment rather than a word.

    Requires hex-only characters AND at least one digit: ``b9bbb32f``,
    ``f186`` and ``12440c0f6aea`` are id fragments, while ``cafe``, ``face``,
    ``dead`` and ``beef`` -- real words that happen to be hex -- survive
    because they contain no digit.

    LENGTH matters, and the old code had no upper bound (measured 2026-10-19).
    Dropping short slices is right: ``ctf2:practice:<ground-uuid>`` contributes the
    SAME four-character groups to every challenge in that ground, so keeping them
    made all siblings collide. A LONG hex run is the opposite kind of token -- a
    content address:
    ``E:\\vulnclaw\\work\\0f72e624...c836e6e72.zip sha256:a6021ade3ee77547`` is a
    fingerprint whose only identifying words are the 64-character file digest and
    its 16-character prefix, and both were discarded, leaving
    ``{sha256, vulnclaw, work, zip}`` -- four words that every attachment-based
    AutoNotes entry shares. 41 of 520 real notes had no unique token at all for
    this reason. So the fragment rule applies up to ``_HEX_ID_MAX_LEN``; anything
    longer is treated as a content-address identity and kept.
    """
    return (
        _HEX_ID_MIN_LEN <= len(tok) < _HEX_ID_MAX_LEN
        and bool(_HEX_TOKEN.fullmatch(tok))
        and any(ch.isdigit() for ch in tok)
    )


#: Length at/above which a hex run is a CONTENT ADDRESS rather than a UUID slice.
#: A UUID group is at most 12 characters (``12440c0f6aea``); the digest prefix a
#: fingerprint stores is exactly 16 (``sha256:a6021ade3ee77547``) and a full
#: sha256 is 64. So 16 is the first length that must be KEPT -- the comparison in
#: ``_is_id_fragment`` is strict (``< 16``), which drops up to 15 characters and
#: keeps 16 and above.
_HEX_ID_MAX_LEN = 16


def _slugify(text: str) -> str:
    text = unicodedata.normalize("NFKD", text or "")
    text = text.encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return text[:48] or "playbook"


_CJK_RUN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]+")


def _cjk_tokens(text: str) -> set[str]:
    """Bigram tokens from runs of CJK ideographs.

    ``re.findall(r"[a-z0-9]+")`` drops every CJK character, so a Chinese
    fingerprint tokenized to an EMPTY set and a Chinese query scored 0 against
    every note — playbook recall was structurally dead for Chinese (measured
    2026-10-04: ten drill lessons stored with a Chinese fingerprint were
    unfindable by the exact checklist queries they were written for). Bigrams
    of consecutive ideographs are the dependency-free standard fix: "应急响应"
    yields {应急, 急响, 响应}, which overlaps any other text containing those
    character pairs. A lone ideograph run of length 1 is kept as a unigram.
    """
    out: set[str] = set()
    for run in _CJK_RUN.findall(text):
        if len(run) == 1:
            out.add(run)
        else:
            out.update(run[i:i + 2] for i in range(len(run) - 1))
    return out


#: CJK bigrams with store-wide template-boilerplate frequency (audit item D).
#:
#: Measured 2026-10-24 over the real store (599 notes, 445 containing CJK,
#: 12,813 distinct bigrams): these 17 bigrams appear in >=10% of all notes and
#: carry zero discriminative power — 提交 22.2%, 得到 18.0%, 题目 16.4%,
#: 证据 15.0%, 答案 13.7%, 注意 13.5%, 到的/包上/请包 ~13% (cross-word
#: fragments of the "请在提交包上包含…" template), 记录 12.4%, 文件 12.2%,
#: 用 12.0%, 字节/返回 11.2%, 数据 10.9%, 确认 10.4%, 与 10.0%. They are
#: the Chinese equivalents of English stop words ("submit/file/data/return"),
#: plus the template's cross-word splices. By contrast 69% of bigrams (8,837)
#: occur in exactly ONE note — the discriminative signal lives elsewhere, so
#: dropping these 17 costs nothing and removes the measured failure where an
#: IR checklist scored 0.231 against an unrelated router-config challenge.
#:
#: Deliberately NOT IDF weighting: IDF multiplication was tried and withdrawn
#: (2026-10-18; the 88.3%→96.9% recall gain came from the unique-identifier
#: exemption + rarest-word ordering, not IDF). A fixed stop list is the same
#: shape as the ASCII ``_STOP`` set.
_CJK_STOP: frozenset[str] = frozenset({
    "提交", "得到", "题目", "证据", "答案", "注意",
    "到的", "包上", "请包", "记录", "文件", "用",
    "字节", "返回", "数据", "确认", "与",
})


def _cjk_signal_tokens(text: str) -> set[str]:
    """CJK bigrams minus the template-boilerplate stop list.

    The rescue path in ``_tokenize`` keeps using the UNFILTERED
    :func:`_cjk_tokens` on purpose: a note whose only tokens are stopped
    bigrams is still better findable by its raw text than permanently
    unreachable (same principle as the ASCII unfiltered fallback).
    """
    return {token for token in _cjk_tokens(text) if token not in _CJK_STOP}


def _tokenize(fingerprint: str) -> set[str]:
    """Normalize a fingerprint into a comparable token set.

    The fingerprint is free text produced by the agent from its first-round
    probe (page title, distinguishing paths, form fields). We lowercase,
    split ASCII on non-alphanumerics, drop stop words, pure-numeric/short
    tokens and id fragments, and dedupe. CJK runs are additionally tokenized
    into bigrams (see :func:`_cjk_tokens`) so Chinese fingerprints and queries
    participate in recall instead of vanishing.

    Id fragments (see :func:`_is_id_fragment`) are dropped for the same reason
    stop words are: ``ctf2:practice:<uuid>`` puts the SAME four hex slices into
    every goal and every auto-captured note of that practice ground, so keeping
    them made all sibling challenges score ~0.93 against each other regardless
    of content (measured 2026-10-18).

    **Empty-result fallback (regression found by a full-store sweep).** Filtering
    can consume EVERY token: 14 of 516 stored notes have a fingerprint that is
    nothing but ``http://<20-hex>.http-ctf2.dasctf.com:80`` -- the random host
    label is an id fragment and ``http``/``com`` are stop words. Those notes hold
    real solutions (e.g. the ``[极客大挑战 2019]Knife`` webshell recipe) and became
    permanently unreachable, which is the exact recall loss
    ``_recallable_fingerprint`` warns about. So when filtering would leave
    nothing, fall back to the unfiltered token set: a note that is only findable
    by an id-shaped query is still better than a note nobody can find.
    """
    text = unicodedata.normalize("NFKD", (fingerprint or "").lower())
    tokens: set[str] = set()
    unfiltered: set[str] = set()
    for tok in re.findall(r"[a-z0-9]+", text):
        if tok in _STOP:
            continue
        if len(tok) < 2:
            continue
        if tok.isdigit():
            continue
        unfiltered.add(tok)
        if _is_id_fragment(tok):
            continue
        tokens.add(tok)
    tokens |= _cjk_signal_tokens(text)
    # A ctf2 ref is the one shape whose two halves differ in kind: the GROUND id is
    # shared by every challenge in that ground (must stay filtered, or all siblings
    # collide -- that is why ``_is_id_fragment`` exists), while the CHALLENGE id names
    # exactly one challenge and nothing else. Measured 2026-10-19: 8 stored notes read
    # ``ctf2:practice:<ground>:<challenge> capture the flag 解出附件 flag（misc
    # forensics 取证 incident response）``. Every SURVIVING token was store-wide
    # boilerplate (df 7..236 of 520) and all eight tokenized to the SAME eleven tokens,
    # so a query sharing those words picked one of them at random -- while the
    # challenge id that would have told them apart had been thrown away.
    #
    # Unconditional (not part of the empty-set fallback below): the defect is present
    # whenever the remaining tokens are all generic, not only when there are none.
    # Adding a per-challenge token cannot make siblings collide, because it is unique
    # per challenge by construction.
    tokens |= set(_CTF2_REF_CHALLENGE.findall(text))
    if tokens:
        return tokens
    # Filtering ate everything. Restore the raw tokens ONLY when the text is a URL
    # whose identity lives in its (id-shaped) host label -- that is the measured
    # case (14/516 notes: ``http://<20-hex>.http-ctf2.dasctf.com:80``) and those
    # notes carry real solutions. A bare ``ctf2:practice:<uuid>`` string is NOT
    # rescued: its slices are shared by every challenge in that ground, so keeping
    # them re-creates the cross-sibling collision this filter exists to remove.
    if "://" in text or "http" in text:
        return unfiltered | _cjk_tokens(text)
    return set()


#: ``ctf2:practice:<ground-uuid>:<challenge-uuid>`` -- captures the CHALLENGE uuid
#: only. Ground ids are per practice ground and are deliberately not captured.
_CTF2_REF_CHALLENGE = re.compile(r"ctf2:practice:[0-9a-f-]{36}:([0-9a-f-]{36})")


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
    #: Structured instance identity (audit item A, 2026-10-24). ``target_ref`` is
    #: the stable platform reference (a full ``ctf2:practice:<ground>:<challenge>``
    #: ref) when one is derivable; ``target_hash`` is its sha256[:16]. The token
    #: fingerprint above stays the recall surface -- these fields are the TIE-BREAK
    #: layer for notes whose goals share the same template sentence, which no
    #: token scoring can separate. ``identity_version`` records the schema so a
    #: future format change can migrate old notes instead of guessing.
    identity_version: int = 0
    target_ref: str = ""
    target_hash: str = ""
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
        meta = {
            "name": self.name,
            "fingerprint": self.fingerprint,
            "status": self.status,
            "source": self.source,
            "updated_at": self.updated_at,
        }
        # Identity fields only when set, so legacy notes round-trip byte-identically.
        if self.identity_version:
            meta["identity_version"] = str(self.identity_version)
        if self.target_ref:
            meta["target_ref"] = self.target_ref
        if self.target_hash:
            meta["target_hash"] = self.target_hash
        return meta

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
            # Structured identity (audit item A). Legacy notes have none of these
            # keys and load with version 0 / empty fields -- recall for them is
            # unchanged, which IS the migration story until a future version
            # bumps the schema.
            identity_version=int(meta.get("identity_version", 0) or 0),
            target_ref=str(meta.get("target_ref", "") or ""),
            target_hash=str(meta.get("target_hash", "") or ""),
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
    # Structured-identity tie-break (audit item A): when BOTH the query and a
    # note carry the same stable platform ref (``ctf2:practice:<ground>:<chal>``),
    # that is an identity statement no token overlap can express -- the exact
    # case template-shaped goals cannot win on tokens. The floor (0.6) is above
    # min_score so an exact-ref note always clears the gate, and applies BEFORE
    # the filter. Legacy notes (no target_ref) and ref-less queries are unchanged.
    query_ref = derive_target_ref(fingerprint)
    scored: list[tuple[float, int, Playbook]] = []
    for pb in list_playbooks():
        s = pb.score(fingerprint)
        if query_ref and pb.target_ref and pb.target_ref == query_ref:
            s = max(s, 0.6)
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
#: The CTF2 practice-ground task sentence carries the challenge title right after
#: the id: ``用 ctf2 工具解练习场 <pid> 的题目 <cid>：<name>。``.
#:
#: Measured 2026-10-07 over 349 stored sessions: for a title like
#: ``Quoted-printable`` this signature came back EMPTY, because `_CLASS_TAG_RE`
#: needs brackets and `_CLASS_QUOTED_RE` needs quotes -- so the platform's most
#: common launch path produced an identity-free goal (~47% of all runs) and the
#: class key could never reach the notes keyed on that title. Bracketed titles
#: (``[HDCTF2019]信号分析``) always worked, and that is exactly what hid the bug.
#: Anchored on the challenge id so prose that merely mentions 题目 cannot fire it,
#: and the id itself is never mistaken for a title (`_CLASS_BARE_ID_RE`).
_CLASS_UUID_RE = (
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_CLASS_TASK_NAME_RE = re.compile(
    rf"题目\s*[:：]?\s*{_CLASS_UUID_RE}\s*[:：]\s*([^\n。；;]{{1,60}})"
)
_CLASS_BARE_ID_RE = re.compile(r"^[0-9a-fA-F][0-9a-fA-F-]{6,}$")

#: Operator-declared labels for the **copilot** path, e.g. ``[ransomware]`` /
#: ``category incident-response`` / ``CVE-2024-36401``.
#:
#: Why a separate extractor exists (2026-10-10, measured): in copilot mode the
#: operator pastes raw terminal output back, and ``challenge_class_signature``
#: reads that whole blob. Terminal output is full of tokens the signature
#: mistakes for challenge identity --
#:
#: * ``python3 -c "import socket,subprocess,os;"`` matched ``_CLASS_QUOTED_RE``
#:   (quote-based title rule) and became the query
#:   ``'import socket,subprocess,os;...'``;
#: * ``find / -newermt '2026-03-14'`` became the query ``'2026-03-14'``;
#: * the operator-facing contract itself contains 命令执行, which
#:   :func:`vulnerability_classes` reads as class ``rce``.
#:
#: Net effect measured on a ransomware paste: the query was
#: ``'import socket,subprocess,os;... 2026-03-14 rce'`` and the top hits were
#: ``coderunner-python-sandbox-escape`` / ``pickle-deserialization`` -- RCE notes
#: for a ransomware case. Stripping quotes is not a general fix either (it fixed
#: ransomware but BROKE an upload case that was previously right), so the copilot
#: path must not derive its query from pasted output at all.
#:
#: This extractor therefore reads **only** deliberate label forms -- bracketed tag,
#: ``category``/``difficulty`` label, CVE id -- and never a quoted shell argument.
#: Empty result means "the operator declared no class", which correctly yields no
#: class query (the fingerprint still carries the target).
_OPERATOR_LABEL_TAG_RE = _CLASS_TAG_RE
_OPERATOR_LABEL_WORD_RES = _CLASS_LABEL_RES
_OPERATOR_LABEL_CVE_RE = _CLASS_CVE_RE


def operator_declared_labels(text: str) -> str:
    """Labels the operator wrote on purpose, ignoring pasted terminal output.

    Returns a space-joined label string (``""`` when nothing was declared).
    See the module comment above ``_OPERATOR_LABEL_TAG_RE`` for the measured
    reason the copilot lookup must not read pasted output.
    """
    src = str(text or "")
    bits: list[str] = [m.group(1).strip() for m in _OPERATOR_LABEL_TAG_RE.finditer(src)]
    bits += [m.group(0).upper() for m in _OPERATOR_LABEL_CVE_RE.finditer(src)]
    for rx in _OPERATOR_LABEL_WORD_RES:
        # First occurrence only: one label per form is the operator's intent;
        # repeated occurrences add no discrimination.
        for m in rx.finditer(src):
            bits.append(m.group(1))
            break
    return " ".join(bit for bit in bits if bit.strip())


#: Evidence → label rules for the copilot path. Ordered: the first rule that
#: matches wins.
#:
#: Why a closed rule table and not a fuzzy match (2026-10-10 measured): the
#: previous attempt fed the whole pasted message to the normal lookup, so a
#: ransomware dump produced the query ``'import socket,subprocess,os;... rce'``
#: and matched RCE-sandbox notes. Deriving a label from pasted text is only safe
#: when it is *evidence-gated*: each rule names artefacts only that scenario
#: emits. A rule firing on words any dump might contain would rebuild the same
#: noise.
#:
#: Each rule is ``(label, need_groups)`` where **every group must match at least
#: one token** (``("a", "b")`` = a or b; a one-token group = that token must be
#: present). An earlier version required ALL tokens of a rule to be present at
#: once -- unreachable in practice (a ransomware dump carries README_RESTORE or
#: ``.locked``, rarely both plus the encryptor name), so nothing ever matched.
_AUTO_LABEL_RULES: tuple[tuple[str, tuple[tuple[str, ...], ...]], ...] = (
    (
        "category incident-response  [ransomware]",
        (
            ("readme_restore", "restore_instructions", "ransom note", "勒索信"),
            (".locked", ".crypt3d", ".encrypted", "encrypted"),
        ),
    ),
    (
        "category incident-response  [cryptomining]",
        (
            ("minexmr", "stratum+tcp", "xmrig", "minerd", "mining pool", "矿池"),
            ("%cpu", "system_cache", "kdevtmpfsi", "kinsing", "挖矿"),
        ),
    ),
    # Checked before the webshell rule: a capture whose filename contains
    # "webshell" (e.g. webshell-plus.pcapng) is a traffic-analysis task, so the
    # more specific evidence has to win.
    (
        "category forensics          [pcap traffic]",
        (
            (".pcap", ".pcapng", "tshark", "wireshark", "tcp.stream", "follow tcp"),
        ),
    ),
    # No bare "webshell" token: every webshell capture also carries .pcap/.pcapng,
    # so a bare word would steal the traffic cases handled by the rule above.
    (
        "category incident-response  [webshell]",
        (
            ("eval($_post", "eval($_get", "eval($_request", "eval($_cookie",
             "china chopper", "菜刀", "哥斯拉", "behinder", "冰蝎"),
        ),
    ),
    (
        "category incident-response  [data exfiltration]",
        (
            ("bash_history", ".upload.log", "exfil", "外带"),
            ("tar -czf", "tar.gz", "curl -t", "scp "),
        ),
    ),
    (
        "category incident-response  [persistence audit]",
        (
            ("crontab -l", "/etc/cron.d", "cron.d/", "systemd/system",
             "authorized_keys", "profile.d", "rc.local", "systemctl"),
        ),
    ),
    (
        "category incident-response  [hidden account]",
        (
            ("uid=0", "uid 0", ":0:0:", "nologin", "/etc/shadow"),
            ("/etc/passwd", "getent passwd", "userdel", "passwd"),
        ),
    ),
)


def auto_label_from_evidence(text: str) -> str:
    """Infer a lookup label from artefacts in pasted output. ``""`` when unsure.

    Conservative by design: a rule fires only when **every one of its groups**
    matches at least one token. An empty result means "not recognisable" and the
    caller injects nothing -- silently guessing is the failure this replaced.
    """
    low = str(text or "").lower()
    if not low.strip():
        return ""
    for label, groups in _AUTO_LABEL_RULES:
        if all(any(tok.lower() in low for tok in group) for group in groups):
            return label
    return ""


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

    The platform task-sentence title (``_CLASS_TASK_NAME_RE``) is a FALLBACK, used
    only when those extractors find nothing at all -- see the comment on the branch
    below for the measured reason (adding it to an existing signature evicts
    on-point curated notes, because ``Playbook.score`` is a share of query tokens).

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
    if not [bit for bit in bits if bit.strip()]:
        # Round-9 审查 (2026-10-08). 平台任务句的题名只在**没有别的身份**时才用。
        #
        # 实测（224 条真实 goal + 真实笔记库，每个变体都跑真实 lookup_playbook_multi，
        # 查询列表与 _inject_prior_playbooks 一致 = target fingerprint + class）：
        # 把题名并进**已有**签名会让 11 条目标的查询结果集改变，其中 1 条丢掉对口笔记
        # —— ``[GeoServer] CVE-2024-36401`` 原本命中 ``geoserver-cve-2024-36401-wfs-jxpath-rce``，
        # 之后被 ``ir-triage-checklist-ten-drills`` 顶掉。原因是 ``Playbook.score`` 是
        # 「查询词被笔记命中的比例」：查询变长只会降分，而平台任务句的原文又恰好一字
        # 不差地出现在 auto 笔记里，于是 auto 笔记把 curated 笔记挤出 ``limit=2``。
        #
        # 改成"仅当签名为空时才用题名"后：那 5 条真正有价值的收益全部保留
        # （变异凯撒→mutated-caesar、Quoted-printable→quoted-printable-ctf2-crypto-easy、
        # 丢失的MD5→md5-lost-md5、传感器→sensor-manchester-ook、一眼就解密→base64），
        # 而**已有身份**的目标拿到的查询与改动前逐字相同 —— 结果集结构上不可能改变
        # （identical 208→214，churn 11→5，回归 0）。
        bits += [
            name
            for name in (m.group(1).strip() for m in _CLASS_TASK_NAME_RE.finditer(text))
            # A task sentence always ends its id with a colon, so an empty or id-shaped
            # capture means the title was not actually there -- do not let a UUID (or a
            # bare practice id) masquerade as a challenge name.
            if name and not _CLASS_BARE_ID_RE.match(name)
        ]
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

# ── Rarity weighting ────────────────────────────────────────────────────────
#
# The floor above is counted in TOKENS, which treats every token as equally
# informative. Measured 2026-10-18 against the real 516-note store, that is wrong
# in both directions at once:
#
#   * FALSE NEGATIVES. A note captured for an instance host has ONE identity token
#     (``0b45310800c50ab708fff28f``); a query for that instance shares exactly that
#     one token -- the strongest possible evidence -- and the 2-token floor threw
#     the note away. 11 of 222 stored notes were unreachable for this reason alone.
#   * NOISE. ``zip`` (df=47/516), ``flag`` (df=145), ``capture``/``forensics``/
#     ``incident``/``response`` and the platform-template pair ``agent log note``
#     let one CTF2 note reach a 1.0 score (19 shared tokens) against EVERY sibling,
#     and let an lsass.dmp/WDigest/AES-zip recipe score 0.4 against a JPEG-carving
#     challenge whose only real shared signal was ``九连``/``连环`` (df=1).
#
# So a shared token is worth more the rarer it is, and a token that only one note
# declares is by itself sufficient evidence -- WITH ONE EXCEPTION. Rarity alone
# cannot be the test, because rarity is relative to the store: in a store holding
# one note, ``weblogic`` has df=1 and would "prove" a match on the framework alone,
# which is exactly the derailment the floor exists to prevent (see the Weblogic
# SSRF note above). The exemption is therefore confined to IDENTIFIER-SHAPED
# tokens, the only kind whose uniqueness really does identify an instance:
# instance hostnames / content hashes / long id fragments. An ordinary English
# word is never exempt, however rare it happens to be in the current store.
#
# Measured over the same 222 stored notes (self-recall@3 = "is the note that
# recorded this target found by its own target/goal?"): current code scored
# 196/222 (88.3%) with 16 queries resolving to nothing at all; the two rules below
# score 208/222 (93.7%) with 1 empty, and 九连环 -- the case that started this --
# now returns the note that recorded it at rank 0 instead of an lsass.dmp recipe.
_RARITY_CACHE: dict[str, Any] = {}

#: An identifier, not a word: a long hex/base32-ish run or a dotted host. Matched
#: on the TOKEN, which ``_tokenize`` has already split on punctuation, so a
#: hostname arrives as its labels and the discriminating label is the long one.
_IDENTIFIER_TOKEN_RE = re.compile(r"^(?=[a-z0-9]*\d)[a-z0-9]{12,}$")
_UUID_TOKEN_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _is_identifier_token(token: str) -> bool:
    """Whether ``token`` looks like an instance id / hash rather than a word.

    Requires at least 12 characters, alphanumerics only, and at least one digit.
    ``0b45310800c50ab708fff28f``, ``5f3a9c2e8b1d`` and ``t4k9m2p7`` qualify;
    ``weblogic``, ``deserialization`` and ``forensics`` do not (no digit or too
    short). Standard hyphenated UUIDs are identifiers too.
    """
    return bool(_IDENTIFIER_TOKEN_RE.match(token) or _UUID_TOKEN_RE.match(token))


def _document_frequencies() -> tuple[dict[str, int], int]:
    """token -> number of stored notes declaring it, plus the note count.

    Cached on the store's file signature (name + mtime + size). A lookup already
    re-reads every note, so recomputing this per candidate would make the lookup
    quadratic; but a stale table would mis-weight exactly the note just learned.
    The per-slug token map is cached alongside it in the same generation; the
    lookup reads it out of ``_RARITY_CACHE`` once (see ``lookup_playbook_multi``).
    """
    try:
        files = sorted(PLAYBOOKS_DIR.glob("*.md"))
        signature = tuple((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in files)
    except OSError:
        return {}, 0
    if _RARITY_CACHE.get("signature") == signature:
        return _RARITY_CACHE["df"], _RARITY_CACHE["n"]
    df: dict[str, int] = {}
    tokens_by_slug: dict[str, set[str]] = {}
    count = 0
    for path in files:
        note = _read(path)
        if note is None:
            continue
        count += 1
        tokens = note.identity_tokens()
        tokens_by_slug[note.slug] = tokens
        for token in tokens:
            df[token] = df.get(token, 0) + 1
    _RARITY_CACHE.update(
        signature=signature, df=df, n=count, tokens=tokens_by_slug
    )
    return df, count


def _rarest_shared(query_tokens: set[str], note_tokens: set[str], df: dict[str, int], total: int) -> int:
    """Document frequency of the RAREST token this note shares with the query.

    ``total + 1`` when they share nothing, so a non-match sorts last.
    """
    shared = query_tokens & note_tokens
    if not shared:
        return total + 1
    return min(df.get(token, 0) for token in shared)


def _clears_overlap_floor(
    query_tokens: set[str], note_tokens: set[str], df: dict[str, int], total: int
) -> bool:
    """Whether a shared-token set is evidence enough to inject the note.

    Two distinct tokens, OR one IDENTIFIER-shaped token: an instance id / content
    hash that no other note declares. The second arm fixes the false negatives
    above (a note keyed only by its instance host shares exactly one token with the
    query for that instance -- the strongest possible evidence). It is deliberately
    restricted to identifier tokens: rarity ALONE would let ``weblogic`` through in
    a one-note store, which is the framework-only derailment the floor exists to
    stop, so a rare ordinary word still needs a second token.
    """
    shared = query_tokens & note_tokens
    if len(shared) >= MIN_OVERLAP_TOKENS:
        return True
    if len(shared) != 1:
        return False
    token = next(iter(shared))
    return _is_identifier_token(token) and df.get(token, 0) <= 1


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
    validated_only: bool = False,
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

    Every surviving row must clear the overlap floor (``_clears_overlap_floor``):
    **``MIN_OVERLAP_TOKENS`` distinct tokens (2), OR one token that no other stored
    note declares.** The two-token arm is what kills the degenerate case in
    which a one-token query (the real signature of ``([Weblogic]SSRF)`` is just
    ``Weblogic``) scores **1.0 against every note of that framework** -- a perfect
    score carrying no relevance information at all, because ``score`` measures
    recall (share of the query's tokens found in the note), not relevance.

    The one-unique-token arm is the measured fix for the opposite failure
    (2026-10-18): a note captured for an instance host has ONE identity token
    (``0b45310800c50ab708fff28f``) and a query for that instance shares exactly
    that token -- the strongest possible evidence -- yet the bare 2-token floor
    discarded it. 11 of 222 stored notes were unreachable for that reason alone.
    A token no other note declares cannot be generic: it identifies the note.

    Ranking puts class agreement first, then the rarity of the rarest shared token,
    then raw score. Rarity is what separates "shares the challenge's own name" from
    "shares the wrapper sentence" -- measured on the same store, ordering by score
    alone let a note sharing four ubiquitous tokens (``zip``/``sha256``/``work``/
    ``vulnclaw``) outrank the note sharing the one token the challenge is named
    after.

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
    df, total_notes = _document_frequencies()
    # ONE read of the per-slug token map for the whole lookup. Resolving it per
    # row ran the signature check again each time, and every hit still stats all
    # note files -- measured 2026-10-19: 61 ms on the 530-note store, 32 rows,
    # 3.0 s of pure stat calls per warm lookup.
    note_tokens = _RARITY_CACHE.get("tokens", {})
    best: dict[str, dict[str, Any]] = {}
    for kind, query in queries:
        if not str(query or "").strip():
            continue
        for row in lookup_playbook(query, limit=_LOOKUP_SCAN_LIMIT, min_score=min_score):
            if validated_only and row.get("status") != "validated":
                continue
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
        # Rarity of the rarest word this row shares with the query that found it.
        # ``score`` alone ranked a note sharing four ubiquitous tokens (zip /
        # sha256 / work / vulnclaw) above the note sharing the ONE token that names
        # the challenge -- measured 2026-10-18, that is how an lsass.dmp/WDigest
        # recipe outranked a JPEG-carving note for 九连环.
        row["_rarest"] = _rarest_shared(
            _tokenize(str(row.get("query", "") or "")),
            note_tokens.get(row["slug"], set()),
            df,
            total_notes,
        )
    rows.sort(
        key=lambda r: (
            bool(r.get("vuln_class_agrees", True)),
            # Rarest shared token first (lower df = more discriminating). This is
            # the rank that separates "shares the challenge's own name" from
            # "shares the wrapper sentence"; it moved self-recall@3 from 196/222
            # to 212/222 on the real store (see the Rarity weighting comment).
            -r.get("_rarest", total_notes + 1),
            r["score"],
            # Same sign fix as in `lookup_playbook` (round8 L3): a validated note must
            # win a tie, and a boolean under reverse=True says that directly.
            r["status"] == "validated",
        ),
        reverse=True,
    )
    surviving = [
        row
        for row in rows
        if _clears_overlap_floor(
            _tokenize(str(row.get("query", "") or "")),
            note_tokens.get(row["slug"], set()),
            df,
            total_notes,
        )
    ]
    if out_blocked is not None:
        kept = {row["slug"] for row in surviving}
        blocked_seen: dict[str, dict[str, Any]] = {}
        for row in rows:
            if row["slug"] in kept:
                continue
            entry = dict(row)
            entry.pop("_rarest", None)
            previous = blocked_seen.get(row["slug"])
            if previous is None or int(entry.get("overlap_tokens", 0) or 0) > int(
                previous.get("overlap_tokens", 0) or 0
            ):
                blocked_seen[row["slug"]] = entry
        out_blocked.extend(blocked_seen.values())
    for row in surviving:
        row.pop("_rarest", None)
    return _reserve_curated_representation(surviving, effective)


def save_playbook(
    *,
    name: str,
    fingerprint: str,
    steps: str = "",
    status: str = "draft",
    slug: Optional[str] = None,
    source: str = SOURCE_CURATED,
    target_ref: str = "",
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

    ``target_ref`` (audit item A): the stable platform reference, persisted as a
    STRUCTURED identity field (plus its hash and identity_version=1) so template-
    shaped goals get an identity tie-break instead of relying on token overlap
    alone. Empty = legacy shape, nothing extra is written.
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
            # A STABLE digest, not `hash(fingerprint)` (round7, still open at round9).
            # CPython randomises str hashing per process (PYTHONHASHSEED), so the same
            # collision produced a DIFFERENT slug in every run: the store's "one file per
            # challenge family, updated in place" rule silently became "write yet another
            # note", and the duplicate then competes with the original in every lookup.
            # The digest only has to disambiguate, not be cryptographic.
            # Round14 F-D: the 4-hex suffix is only 16 bits, and the suffixed name was
            # written with no further check — a second note whose fingerprint hashed to
            # the same prefix silently OVERWROTE the first (measured with three
            # same-shaped Chinese targets collapsing onto slug "autonotes"). Widen the
            # same digest until the name is free instead of writing over it; a full
            # 256-bit digest match means an identical fingerprint, where the timestamp
            # tail below merely trades the old silent loss for a visible extra note.
            digest = sha256(fingerprint.encode("utf-8")).hexdigest()
            candidate = f"{slug}-{digest[:4]}"
            width = 4
            while (PLAYBOOKS_DIR / f"{candidate}.md").exists() and width < len(digest):
                width += 2
                candidate = f"{slug}-{digest[:width]}"
            if (PLAYBOOKS_DIR / f"{candidate}.md").exists():
                candidate = f"{candidate}-{datetime.now(timezone.utc).strftime('%H%M%S')}"
            slug = candidate

    updated_at = datetime.now(timezone.utc).isoformat()
    lines = [
        "---",
        f"name: {name}",
        f"fingerprint: {fingerprint}",
        f"status: {status}",
        f"source: {source}",
        f"updated_at: {updated_at}",
    ]
    if target_ref:
        lines.append(f"identity_version: 1")
        lines.append(f"target_ref: {target_ref}")
        lines.append(f"target_hash: {_target_ref_hash(target_ref)}")
    lines += [
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


#: Full platform reference -- the ONE identity that is stable across instances
#: of the same challenge and unique to it (the challenge uuid). Deliberately
#: the full ref, not the challenge uuid alone: the ground uuid in the middle is
#: what keeps two same-named challenges on different grounds from colliding.
_CTF2_REF_FULL = re.compile(r"ctf2:practice:[0-9a-f-]{36}:[0-9a-f-]{36}")


def derive_target_ref(*texts: str) -> str:
    """The stable platform ref buried in any of ``texts``, or ``""``.

    Used at BOTH ends of recall (capture stores it; lookup derives it from the
    query), so an exact match is an identity statement, not a token overlap.
    """
    for text in texts:
        m = _CTF2_REF_FULL.search(str(text or ""))
        if m:
            return m.group(0)
    return ""


def _target_ref_hash(ref: str) -> str:
    if not ref:
        return ""
    return sha256(ref.encode("utf-8")).hexdigest()[:16]


def _auto_notes_name(target: str) -> str:
    short = target.rstrip("/\\").replace("\\", "/").rsplit("/", 1)[-1] or target
    return f"AutoNotes {short}"[:80]


def _note_reason(out_reason: Optional[list[str]], reason: str) -> None:
    """Record why a capture declined, when the caller asked to be told.

    Factored out so the three refusal sites cannot drift into reporting differently shaped
    messages, and so `out_reason=None` (every existing caller) stays free.
    """
    if out_reason is not None:
        out_reason.append(reason)


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
    out_reason: Optional[list[str]] = None,
) -> Optional[dict[str, Any]]:
    """Deterministically persist confirmed run conclusions as a draft playbook.

    Unlike ``save_playbook`` (model-initiated, often skipped when a run dies on
    quota or a dead end), the solve loop calls this automatically — at intervals
    and at termination — so the next run of the same target starts from confirmed
    conclusions (LOCK / CONFIRMED facts / angle outcomes) instead of raw
    evidence. When the model never engaged the blackboard, a fallback LOCK is
    synthesized from the final answer so the notes are never empty after a
    completed run. Returns the save ack, or None when there is nothing at all.

    ``out_reason`` (round7 L8): this function declines to write on three different
    grounds -- the run recorded nothing, the text is below ``MIN_PLAYBOOK_CHARS``, or the
    only fingerprint available could never be recalled -- and all three used to return a
    bare ``None``. A caller could not tell "this run had nothing to say" from "there WAS a
    conclusion and the store refused it", so a dropped conclusion looked exactly like an
    empty one in the run log. Same shape as ``lookup_playbook_multi``'s ``out_blocked``:
    the reason is reported rather than inferred.
    """
    from vulnclaw.agent.blackboard import NodeStatus, NodeType

    lines: list[str] = []
    lock = blackboard.current_lock() if blackboard is not None else None
    facts = blackboard.confirmed_facts() if blackboard is not None else []
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
    # ── Plan C: a FAILED run records environment facts, not verdicts ─────────
    #
    # Measured 2026-10-18: 5 stored notes are pure failures and carry a bare
    # ``ANGLES: [miss] <approach>`` line. The next run reading that cannot tell
    # whether the approach was REFUTED (this method cannot work here) or merely
    # TRIED without success (wrong password this time, worth retrying) -- and the
    # injector's own wording ("REPLAY its steps") pushes it to skip. Silently
    # suppressing a direction that would have worked is the worst outcome
    # available, so a failed run now records only what stayed TRUE about the
    # challenge (facts the run confirmed before dying) and a plain statement that
    # the direction was not resolved. Nothing here tells a future run to skip.
    run_failed = bool(outcome) and bool(
        re.search(r"stalled|no untried path|no viable path|gave up|budget", outcome, re.I)
    )
    facts = blackboard.confirmed_facts() if blackboard is not None else []
    if run_failed and not facts:
        # A failure with nothing proven teaches nothing worth storing. Writing
        # "we tried and stalled" only invites the next run to skip the same
        # ground, so decline instead of storing a direction-suppressing note.
        _note_reason(
            out_reason,
            "the run failed with no confirmed facts: storing it would only record "
            "'this was hard', which the next run could misread as 'skip this'",
        )
        return None
    if run_failed and facts:
        # Keep the proven part; drop the verdicts.
        lines = []
        if lock is not None:
            lines.append(f"LOCK: {lock.description}")
        lines.append("CONFIRMED: " + "; ".join(f.description for f in facts[:8]))
        lines.append(
            "UNRESOLVED: the run stopped before finishing; the angles below were "
            "attempted without a conclusion. They are NOT refuted -- re-try them "
            "with different parameters before ruling anything out."
        )
        open_bits = [b for b in angle_bits if "open" in b or "miss" in b]
        if open_bits:
            lines.append("ANGLES (attempted, undecided): " + "; ".join(open_bits[:10]))
        angle_bits = []  # already emitted above
    else:
        # Successful (or not-failed) run: the original line shape, which the next
        # run IS meant to replay.
        if lock is not None:
            lines.append(f"LOCK: {lock.description}")
        if facts:
            lines.append("CONFIRMED: " + "; ".join(f.description for f in facts[:8]))
    if angle_bits:
        lines.append("ANGLES: " + "; ".join(angle_bits[:10]))
        # Plan B: say what a [miss] MEANS, so the next run does not read it as
        # "this method cannot work here". The board has one CHALLENGED state, but
        # two different facts produce it: (a) the approach was disproved because
        # the real answer was found elsewhere in this same run -- safe to skip;
        # (b) the approach was only attempted and did not succeed -- worth
        # retrying with different parameters. Only a solved run reaches this line,
        # so a [miss] here is (a); the failed path above labels (b) as "undecided".
        if any("[miss]" in b for b in angle_bits):
            lines.append(
                "ANGLES-NOTE: [miss] here means the approach was ruled out BY this "
                "run's own successful path -- it was not merely untried. [open] "
                "entries were never reached."
            )
    if not lines and final_answer:
        # Blackboard-avoidant run: the completion declaration is still a real
        # conclusion — keep it, clearly labelled, so reuse is not lost.
        synth = " ".join(final_answer.split())[:300]
        lines.append(f"LOCK: (from final answer) {synth}")
    if not lines:
        _note_reason(out_reason, "the run recorded nothing (no LOCK, no confirmed fact, "
                                 "no angle, no final answer)")
        return None
    lines.append(f"TARGET: {target}")
    lines.append(f"GOAL: {goal}")
    if outcome:
        lines.append(f"OUTCOME: {outcome}")
    steps = "\n".join(lines).strip()
    if len(steps) < MIN_PLAYBOOK_CHARS:
        _note_reason(
            out_reason,
            f"the recorded conclusion is too short ({len(steps)} chars, "
            f"min {MIN_PLAYBOOK_CHARS})",
        )
        return None
    fingerprint = _recallable_fingerprint(target, goal)
    if fingerprint is None:
        # Nothing in the target OR the goal can be tokenized, so no future query could ever
        # score this note above zero. Writing it would create a note that looks like saved
        # knowledge and is findable by nobody (see _recallable_fingerprint for the measured
        # `'E:'` case). Declining is the smaller loss.
        _note_reason(
            out_reason,
            "no query could ever find this note (neither the target nor the goal "
            "tokenizes to anything), so it was not written",
        )
        return None
    return save_playbook(
        name=_auto_notes_name(target),
        fingerprint=fingerprint,
        steps=steps,
        status=status,
        source=SOURCE_AUTO,
        target_ref=derive_target_ref(target, goal),
    )


# ── Post-hoc rebuild: recover a run whose board died before capture ──────────
#
# The live Blackboard is memory-only (RuntimeState.blackboard); a context reset --
# the REPL's ``target <t>`` / ``clear`` / natural-language target switch -- builds
# a fresh empty one, and nothing on disk carries the nodes: the session file has
# no blackboard field, and the REPL solve path never writes a target snapshot. So
# a run killed before the solve loop's own capture (every 20 steps, and at
# termination) used to lose its conclusions for good.
#
# What the session file DOES keep is every tool call with its arguments AND its
# result text, and the blackboard tools report the node identity and status in
# that result ("LOCK set (n1)", "angle n2 registered", "fact n3 CONFIRMED"). That
# is enough to walk the board back and rebuild the exact line shape
# ``capture_run_notes`` writes.

#: Result-text shapes the blackboard tools emit (see blackboard.dispatch_*).
_BB_FACT_RE = re.compile(r"fact (n\d+)\s+(CONFIRMED|candidate|recorded)")
_BB_ANGLE_RE = re.compile(r"angle (n\d+)\s+registered")


def _parse_key_args(raw: Any) -> dict[str, Any]:
    """Best-effort decode of a saved tool call's ``key_args`` (a JSON string)."""
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(str(raw))
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def rebuild_run_notes(
    agent_state: dict[str, Any],
    *,
    out_reason: Optional[list[str]] = None,
) -> Optional[str]:
    """Reconstruct a run's LOCK / CONFIRMED / ANGLES block from a saved session.

    Counterpart to :func:`capture_run_notes` for the case where the live board is
    already gone: walks the ``blackboard_*`` calls of ``agent_state["tool_calls"]``
    back into the same note body, so a run that died before capture can still be
    distilled after the fact.

    Only conclusions the live board would have reported are emitted (LOCK, facts
    the board CONFIRMED, every angle with its hit/miss/open mark); candidates and
    intents are deliberately left out, matching what ``capture_run_notes`` reads
    off a live board.

    Returns the note body, or None with the reason appended to ``out_reason``.
    """
    target = str(agent_state.get("origin") or "")
    goal = str(agent_state.get("goal") or "")

    lock_text = ""
    fact_desc: dict[str, str] = {}
    fact_status: dict[str, str] = {}
    confirmed_unkeyed: list[str] = []
    angle_desc: dict[str, str] = {}
    angle_status: dict[str, str] = {}

    for call in agent_state.get("tool_calls") or []:
        if not isinstance(call, dict):
            continue
        tool = str(call.get("tool") or "")
        if not tool.startswith("blackboard"):
            continue
        args = _parse_key_args(call.get("key_args"))
        result = str(call.get("summary") or "")
        desc = str(args.get("description") or "").strip()
        node_id = str(args.get("node_id") or "").strip()

        if tool == "blackboard_set_lock" and desc:
            lock_text = re.sub(r"^LOCK:\s*", "", desc).strip()
        elif tool == "blackboard_add_fact" and desc:
            match = _BB_FACT_RE.search(result)
            if match:
                fact_desc[match.group(1)] = desc
                fact_status[match.group(1)] = match.group(2)
            elif "CONFIRMED" in result:
                # Round15b (2026-10-07) postmortem: the result text drifted from
                # ``_BB_FACT_RE`` (older sessions used a different phrasing) so
                # the node id is unknown while the verdict is not. Keep the
                # description as an unkeyed confirmation instead of losing a
                # proven fact. The old branch compared ``status``, which was
                # hard-coded to "candidate" on this path, so it never fired.
                confirmed_unkeyed.append(desc)
        elif tool == "blackboard_verify_fact" and node_id:
            # The call is the confirmation attempt; the RESULT says whether the
            # description was actually witnessed, so trust the result text.
            if "CONFIRMED" in result:
                fact_status[node_id] = "CONFIRMED"
        elif tool == "blackboard_challenge_fact" and node_id:
            fact_status[node_id] = "challenged"
        elif tool == "blackboard_create_angle" and desc:
            match = _BB_ANGLE_RE.search(result)
            aid = match.group(1) if match else f"angle{len(angle_desc) + 1}"
            angle_desc[aid] = desc
            angle_status.setdefault(aid, "open")
        elif tool == "blackboard_hit_angle" and node_id:
            angle_status[node_id] = "hit"
        elif tool == "blackboard_miss_angle" and node_id:
            angle_status[node_id] = "miss"

    confirmed = [
        fact_desc[fid]
        for fid, status in fact_status.items()
        if status == "CONFIRMED" and fid in fact_desc
    ] + confirmed_unkeyed

    lines: list[str] = []
    if lock_text:
        lines.append(f"LOCK: {lock_text}")
    if confirmed:
        lines.append("CONFIRMED: " + "; ".join(confirmed[:8]))
    angle_bits = []
    for aid, desc in angle_desc.items():
        mark = angle_status.get(aid, "open")
        angle_bits.append(f"[{mark if mark in ('hit', 'miss') else 'open'}] {desc}")
    if angle_bits:
        lines.append("ANGLES: " + "; ".join(angle_bits[:10]))

    final_answer = str(agent_state.get("final_answer") or "")
    if not lines and final_answer:
        lines.append("LOCK: (from final answer) " + " ".join(final_answer.split())[:300])
    if not lines:
        _note_reason(
            out_reason,
            "the session recorded nothing (no LOCK, no confirmed fact, no angle, "
            "no final answer)",
        )
        return None

    lines.append(f"TARGET: {target}")
    lines.append(f"GOAL: {goal}")
    outcome = str(agent_state.get("complete_reason") or "").strip()
    lines.append(f"OUTCOME: {outcome}" if outcome else "OUTCOME: rebuilt from the session file")
    steps = "\n".join(lines).strip()
    if len(steps) < MIN_PLAYBOOK_CHARS:
        _note_reason(
            out_reason,
            f"the rebuilt conclusion is too short ({len(steps)} chars, "
            f"min {MIN_PLAYBOOK_CHARS})",
        )
        return None
    return steps


def capture_run_notes_from_session(
    session_path: "str | Path",
    *,
    out_reason: Optional[list[str]] = None,
    status: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Rebuild a run's notes from a saved session file and store them.

    Same gates as :func:`capture_run_notes` (a short or unrecallable note is
    refused rather than stored), so a rebuild can never pollute the store with a
    note no query could find. Returns the save ack, or None with the reason in
    ``out_reason``.
    """
    path = Path(session_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    agent_state = data.get("agent_state") or data
    if not isinstance(agent_state, dict):
        _note_reason(out_reason, f"{path.name} carries no agent_state to rebuild from")
        return None

    steps = rebuild_run_notes(agent_state, out_reason=out_reason)
    if steps is None:
        return None

    target = str(agent_state.get("origin") or "")
    goal = str(agent_state.get("goal") or "")
    fingerprint = _recallable_fingerprint(target, goal)
    if fingerprint is None:
        _note_reason(
            out_reason,
            "no query could ever find this note (neither the target nor the goal "
            "tokenizes to anything), so it was not written",
        )
        return None
    return save_playbook(
        name=_auto_notes_name(target),
        fingerprint=fingerprint,
        steps=steps,
        status=status or ("validated" if agent_state.get("completed") else "draft"),
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
