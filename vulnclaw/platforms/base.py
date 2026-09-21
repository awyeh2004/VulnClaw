"""Platform-agnostic data model and adapter protocol.

This module imports no concrete platform: it is the *vocabulary* that
``platforms/ctf2.py`` and ``platforms/gcs.py`` normalize their raw API payloads
into.  Keeping it platform-free is what lets the tool face, the submit guard and
the renderer be written once.

Two invariants from the design doc are expressed directly in this vocabulary:

* **I2 -- a partial response must not pass for a complete one.**
  ``EnvInfo.complete`` is a required field, not a hint.  ``state`` is normalized
  so the renderer can branch on a closed set instead of pattern-matching the
  platform's own strings.

* **I3 -- transport is never assumed.**
  ``EnvEndpoint.transport`` is ``tcp`` / ``tls`` / ``unknown``, and unknown stays
  unknown.  Defaulting it to ``tcp`` is exactly the mistake that wasted 20+
  minutes on a TLS-wrapped CTF2 target (commit f278f16).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from vulnclaw.platforms.refs import ChallengeRef, CorpusRef

# ── environment states (normalized, closed set) ────────────────────────────

STATE_NONE = "none"
"""No environment exists yet for this challenge (CTF2 answers with ``data: null``)."""

STATE_STARTING = "starting"
"""An environment is being created; connection info is NOT yet available."""

STATE_RUNNING = "running"
"""An environment is up and its endpoints are authoritative."""

STATE_STOPPED = "stopped"
"""An environment that existed was released / destroyed."""

STATE_EXPIRED = "expired"
"""The environment's TTL passed.  Restart it; do not keep probing the old host."""

STATE_NOT_REQUIRED = "not_required"
"""This challenge needs no environment at all; attack the static target."""

STATE_UNKNOWN = "unknown"
"""The platform reported something we do not have a meaning for."""

ALL_STATES = frozenset(
    {
        STATE_NONE,
        STATE_STARTING,
        STATE_RUNNING,
        STATE_STOPPED,
        STATE_EXPIRED,
        STATE_NOT_REQUIRED,
        STATE_UNKNOWN,
    }
)

INCOMPLETE_STATES = frozenset(
    {
        STATE_NONE,
        STATE_STARTING,
        STATE_STOPPED,
        STATE_EXPIRED,
        STATE_UNKNOWN,
    }
)
"""States whose payload must never be used as a live target."""

USABLE_STATES = frozenset({STATE_RUNNING, STATE_NOT_REQUIRED})

# ── transports (normalized, closed set) ───────────────────────────────────

TRANSPORT_TCP = "tcp"
TRANSPORT_TLS = "tls"
TRANSPORT_UNKNOWN = "unknown"

ALL_TRANSPORTS = frozenset({TRANSPORT_TCP, TRANSPORT_TLS, TRANSPORT_UNKNOWN})

# ── capabilities (opt-in facets; a platform declares what it supports) ────

CAP_EVENT_INFO = "event_info"
CAP_NOTICES = "notices"
CAP_OVERVIEW = "overview"
CAP_SUBMISSIONS = "submissions"

ALL_CAPABILITIES = frozenset({CAP_EVENT_INFO, CAP_NOTICES, CAP_OVERVIEW, CAP_SUBMISSIONS})


# ── value objects ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Attachment:
    """One downloadable challenge file."""

    name: str
    url: str = ""
    md5: str = ""
    size: int | None = None
    note: str = ""


@dataclass(frozen=True)
class Corpus:
    """A named collection of challenges, as returned by ``list_corpora``."""

    ref: CorpusRef
    name: str = ""
    count: int | None = None
    note: str = ""


@dataclass(frozen=True)
class Challenge:
    """A challenge as read from a platform."""

    ref: ChallengeRef
    name: str
    category: str = ""
    difficulty: str = ""
    score: str = ""
    description: str = ""
    solved: bool = False
    needs_env: bool = False
    attachments: tuple[Attachment, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EnvEndpoint:
    """One way to reach a live environment.

    ``transport`` is ``tcp`` / ``tls`` / ``unknown`` (see invariant I3).  An
    adapter that cannot determine the transport MUST leave it ``unknown`` rather
    than guessing ``tcp``.
    """

    host: str = ""
    port: int | None = None
    url: str = ""
    transport: str = TRANSPORT_UNKNOWN
    user: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        if self.transport not in ALL_TRANSPORTS:
            raise ValueError(
                f"transport must be one of {sorted(ALL_TRANSPORTS)}, got {self.transport!r}"
            )

    def display(self) -> str:
        """Human/agent-readable form, preferring the platform's own URL."""
        if self.url:
            return self.url
        if self.host and self.port:
            return f"{self.host}:{self.port}"
        return self.host


@dataclass(frozen=True)
class EnvInfo:
    """Normalized state of a challenge's live environment.

    ``complete`` is the machine-readable form of "do not trust this yet": it is
    False whenever the platform's payload omits the connection details, which is
    the failure mode commit f278f16 fixed.
    """

    ref: ChallengeRef
    state: str
    complete: bool
    endpoints: tuple[EnvEndpoint, ...] = ()
    expires_at: str = ""
    guidance: tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.state not in ALL_STATES:
            raise ValueError(f"state must be one of {sorted(ALL_STATES)}, got {self.state!r}")
        if self.complete and self.state in INCOMPLETE_STATES:
            raise ValueError(
                f"state {self.state!r} cannot be marked complete: "
                "an incomplete state means the payload lacks connection details"
            )

    @property
    def usable(self) -> bool:
        return self.complete and self.state in USABLE_STATES

    def transports(self) -> frozenset[str]:
        return frozenset(ep.transport for ep in self.endpoints)


@dataclass(frozen=True)
class SubmitResult:
    """Outcome of a flag submission.

    ``judged`` separates "the platform graded this flag" from "the call failed".
    Only a judged submission consumes an attempt in the submit guard, so a
    network blip cannot burn one of the few automatic attempts.
    """

    accepted: bool
    judged: bool
    message: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Notice:
    """A competition announcement (capability: notices)."""

    id: str
    title: str = ""
    content: str = ""
    attachment: Attachment | None = None


# ── adapter protocol ──────────────────────────────────────────────────────


@runtime_checkable
class PlatformAdapter(Protocol):
    """The six verbs every platform must provide.

    ``name`` is the ref-token prefix this adapter owns.  ``capabilities`` is an
    explicit set of optional facets (see ``CAP_*``) rather than something probed
    with ``hasattr``, so the tool face and the tests read the same declaration.
    """

    name: str
    capabilities: frozenset[str]
    enabled_by_default: bool
    """Whether the tool face is exposed when config says nothing.

    True for a platform in active use (CTF2), False for a legacy integration
    that must be switched on deliberately (GCS).  An explicit
    ``platforms.<name>.enabled`` setting always wins over this.
    """

    def is_configured(self) -> bool:
        """Whether credentials for this platform are present."""

    def make_ref(self, *, kind: str, id: str, group: str = "") -> ChallengeRef:
        """Build a challenge ref in this platform's token shape."""

    async def list_corpora(self) -> list[Corpus]:
        """List the collections of challenges this platform exposes."""

    async def list_challenges(self, corpus: CorpusRef) -> list[Challenge]:
        """List the challenges inside one collection."""

    async def read_challenge(self, ref: ChallengeRef) -> Challenge:
        """Read one challenge's detail, including attachments."""

    async def start_env(self, ref: ChallengeRef) -> EnvInfo:
        """Start (or reuse) an environment.  May return an incomplete EnvInfo."""

    async def read_env(self, ref: ChallengeRef) -> EnvInfo | None:
        """Read (poll) the current environment state.

        ``None`` means this platform has no environment concept for the ref.
        """

    async def stop_env(self, ref: ChallengeRef) -> None:
        """Release the environment so the platform can reclaim the slot."""

    async def submit_flag(self, ref: ChallengeRef, flag: str) -> SubmitResult:
        """Submit a flag.  Must not raise for a merely-wrong flag."""


@runtime_checkable
class EventInfoAdapter(Protocol):
    """Optional facet: competition notes / rules / scoreboard (GCS today)."""

    async def event_info(self) -> str: ...

    async def overview(self) -> Mapping[str, Any]: ...


@runtime_checkable
class NoticesAdapter(Protocol):
    """Optional facet: competition announcements."""

    async def notices(self, notice_id: str | None = None) -> list[Notice] | Notice: ...


@runtime_checkable
class SubmissionsAdapter(Protocol):
    """Optional facet: the team's own submission history (CTF2 today)."""

    async def submissions(self, limit: int = 20) -> list[Mapping[str, Any]]: ...
