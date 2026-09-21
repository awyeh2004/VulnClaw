"""Platform-agnostic addressing for CTF platforms.

A *ref token* is the single currency of the adapter layer: every tool that acts
on a challenge takes one, and the platform it names is the ONLY place the
platform identity comes from.  That is the whole point (design doc invariant I1):
with one ``platform_submit`` tool instead of ``ctf2_submit_flag`` +
``gcs_submit_flag``, an agent physically cannot submit to the wrong platform
because the tool name carries no platform at all.

Token grammar
-------------
``<platform>:<kind>[:<group>][:<id>]``

Only the ``platform:`` prefix is mandatory and generic; the tail is interpreted
by the owning adapter's ``parse_ref``.  The two shapes we know about:

    ctf2:practice:12        a corpus (the practice ground itself)
    ctf2:practice:12:345    a challenge inside practice ground 12
    ctf2:stage:7:345        a challenge inside competition stage 7
    ctf2:daily              the daily-challenge corpus
    gcs:exercise            the whole exercise tree (GCS has no sub-grouping)
    gcs:exercise:10662      one GCS challenge

Deliberately NOT uniform: forcing one arity would make the GCS form carry an
empty field (``gcs:exercise::10662``) purely for appearances.  The model never
builds a token by hand -- it echoes one produced by ``platform_list`` /
``platform_read`` -- so a per-platform tail costs nothing and buys honesty.

Validation is strict on purpose: a malformed token is an error, never a guess.
"""

from __future__ import annotations

from dataclasses import dataclass

TOKEN_SEP = ":"


class RefError(ValueError):
    """A ref token that cannot be split into (platform, tail)."""


def _check_field(value: str, what: str) -> str:
    text = str(value)
    if not text:
        raise RefError(f"{what} must not be empty")
    if TOKEN_SEP in text:
        raise RefError(f"{what} must not contain {TOKEN_SEP!r}: {text!r}")
    if text != text.strip():
        raise RefError(f"{what} must not have surrounding whitespace: {text!r}")
    if any(ch.isspace() for ch in text):
        raise RefError(f"{what} must not contain whitespace: {text!r}")
    return text


def make_token(platform: str, *fields: str) -> str:
    """Join a platform name and non-empty tail fields into a ref token."""
    platform = _check_field(platform, "platform")
    if not fields:
        raise RefError("a ref token needs at least one field after the platform")
    return TOKEN_SEP.join([platform, *(_check_field(f, "field") for f in fields)])


def split_token(token: str) -> tuple[str, str]:
    """Split a ref token into ``(platform, tail)``.

    Only the prefix is validated here -- the tail is the owning adapter's
    business.  Raises :class:`RefError` for anything that is not
    ``<platform>:<non-empty tail>``.
    """
    text = str(token or "").strip()
    if not text:
        raise RefError("empty ref token")
    if TOKEN_SEP not in text:
        raise RefError(
            f"ref token {text!r} has no platform prefix; "
            f"expected '<platform>:<...>' (call platform_list to get a valid ref)"
        )
    platform, _, tail = text.partition(TOKEN_SEP)
    if not platform:
        raise RefError(f"ref token {text!r} has an empty platform prefix")
    if not tail:
        raise RefError(f"ref token {text!r} has an empty tail")
    return platform, tail


def platform_of(token: str) -> str:
    """The platform prefix of a ref token."""
    return split_token(token)[0]


def parse_fields(tail: str) -> list[str]:
    """Split an adapter's token tail into its fields, rejecting empty segments."""
    fields = str(tail).split(TOKEN_SEP)
    for field in fields:
        _check_field(field, "field")
    return fields


@dataclass(frozen=True)
class ChallengeRef:
    """A challenge address: platform + kind + (optional group) + id.

    ``group`` is the corpus the challenge lives in when the platform has one
    (CTF2: the practice ground / competition stage id).  GCS has no such level,
    so its refs leave ``group`` empty and the token simply omits the field.
    """

    platform: str
    kind: str
    group: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        _check_field(self.platform, "platform")
        _check_field(self.kind, "kind")
        for name, value in (("group", self.group), ("id", self.id)):
            if value:
                _check_field(value, name)

    def token(self) -> str:
        """Render the canonical token for this ref."""
        fields = [self.kind]
        if self.group:
            fields.append(self.group)
        if self.id:
            fields.append(self.id)
        return make_token(self.platform, *fields)

    @property
    def key(self) -> str:
        """Stable identity used as a state key (submit guard, caches)."""
        return self.token()

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return self.token()


@dataclass(frozen=True)
class CorpusRef:
    """A collection of challenges (practice ground, stage, exercise tree)."""

    platform: str
    kind: str
    id: str = ""

    def __post_init__(self) -> None:
        _check_field(self.platform, "platform")
        _check_field(self.kind, "kind")
        if self.id:
            _check_field(self.id, "id")

    def token(self) -> str:
        fields = [self.kind]
        if self.id:
            fields.append(self.id)
        return make_token(self.platform, *fields)

    @property
    def key(self) -> str:
        return self.token()

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return self.token()
