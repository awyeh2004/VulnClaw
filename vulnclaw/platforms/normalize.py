"""Normalization helpers: platform-native values -> the adapter vocabulary.

Every function here is pure and platform-free, so both adapters share one
definition of "what counts as TLS" and "what counts as not ready".  That sharing
is the point: the 20-minute CTF2 miss (commit f278f16) happened because
``nc_ssl`` was left as a raw JSON field for the caller to notice.  Normalizing at
the adapter boundary means the renderer never has to know a platform's field
names.

Accuracy rule: when a value is ambiguous or absent, the answer is
``TRANSPORT_UNKNOWN`` / ``STATE_UNKNOWN`` -- never a convenience default.  A
wrong ``tcp`` is worse than an honest ``unknown`` (invariant I3).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from vulnclaw.platforms.base import (
    STATE_EXPIRED,
    STATE_NONE,
    STATE_NOT_REQUIRED,
    STATE_RUNNING,
    STATE_STARTING,
    STATE_STOPPED,
    STATE_UNKNOWN,
    TRANSPORT_TCP,
    TRANSPORT_TLS,
    TRANSPORT_UNKNOWN,
)

# ── tolerant field lookup ─────────────────────────────────────────────────

# Field names that different platforms use for the same idea.  Ordered by how
# likely each is; the first present, non-None value wins.
TRANSPORT_KEYS: tuple[str, ...] = (
    "nc_ssl",
    "tls",
    "ssl",
    "secure",
    "use_ssl",
    "uses_ssl",
    "is_ssl",
    "scheme",
    "protocol",
)

READY_KEYS: tuple[str, ...] = ("isNeedCheck", "is_need_check", "needCheck")


def first_present(source: Mapping[str, Any] | None, keys: tuple[str, ...]) -> Any:
    """Return the first non-None value among ``keys`` in ``source``."""
    if not isinstance(source, Mapping):
        return None
    for key in keys:
        if key in source and source[key] is not None:
            return source[key]
    return None


# ── transport ─────────────────────────────────────────────────────────────

_TRUE_TLS = {"1", "true", "yes", "y", "on", "tls", "ssl", "starttls", "secure", "https", "wss"}
_TRUE_TCP = {
    "0",
    "false",
    "no",
    "n",
    "off",
    "tcp",
    "plain",
    "plaintext",
    "none",
    "http",
    "ws",
    "raw",
}

# Substring probes for compound values ("tcp-ssl", "ssl://...", "plain-tcp").
# TLS-ish markers are tested FIRST: "https" contains "http" and "wss" contains
# "ws", so the other order would classify a secure endpoint as plain.
_TLS_MARKERS = ("ssl", "tls", "https", "wss", "secure")
_TCP_MARKERS = ("tcp", "plain", "http", "ws", "raw")


def normalize_transport(value: Any) -> str:
    """Map a platform's transport flag onto ``tcp`` / ``tls`` / ``unknown``.

    Accepts booleans (CTF2's ``nc_ssl``), 0/1, and strings -- including
    ``scheme``-style values such as ``"https"`` or ``"tcp"``.  Anything not
    recognizable returns ``unknown`` so the caller probes instead of assuming.
    """
    if value is None:
        return TRANSPORT_UNKNOWN
    if isinstance(value, bool):
        return TRANSPORT_TLS if value else TRANSPORT_TCP
    if isinstance(value, (int, float)):
        if value == 1:
            return TRANSPORT_TLS
        if value == 0:
            return TRANSPORT_TCP
        return TRANSPORT_UNKNOWN

    text = str(value).strip().lower()
    if not text:
        return TRANSPORT_UNKNOWN
    if text in _TRUE_TLS:
        return TRANSPORT_TLS
    if text in _TRUE_TCP:
        return TRANSPORT_TCP
    if any(marker in text for marker in _TLS_MARKERS):
        return TRANSPORT_TLS
    if any(marker in text for marker in _TCP_MARKERS):
        return TRANSPORT_TCP
    return TRANSPORT_UNKNOWN


# ── environment state ─────────────────────────────────────────────────────

_STARTING_ALIASES = {
    "starting",
    "start",
    "pending",
    "creating",
    "create",
    "queued",
    "queue",
    "init",
    "initializing",
    "initialising",
    "building",
    "deploying",
    "provisioning",
    "waiting",
}
_RUNNING_ALIASES = {"running", "run", "ready", "started", "active", "up", "healthy"}
_STOPPED_ALIASES = {
    "stopped",
    "stop",
    "deleted",
    "destroyed",
    "released",
    "terminated",
    "closed",
    "removed",
}
_EXPIRED_ALIASES = {"expired", "expire", "timeout", "timed_out", "timedout", "overdue"}


def normalize_status(raw_status: Any) -> str:
    """Map a platform's environment status string onto a normalized state.

    NOTE: an EMPTY status maps to ``starting``, not ``unknown``.  That preserves
    the pre-refactor behavior of the CTF2 renderer, which treated a missing
    status as "not ready yet, poll again" -- the safe reading, and the one that
    gives the caller an actionable next step.
    """
    if raw_status is None:
        return STATE_STARTING
    text = str(raw_status).strip().lower()
    if not text:
        return STATE_STARTING
    if text in _STARTING_ALIASES:
        return STATE_STARTING
    if text in _RUNNING_ALIASES:
        return STATE_RUNNING
    if text in _STOPPED_ALIASES:
        return STATE_STOPPED
    if text in _EXPIRED_ALIASES:
        return STATE_EXPIRED
    return STATE_UNKNOWN


def state_from_flags(
    *,
    needs_check: Any = None,
    has_endpoints: bool = False,
    env_required: Any = None,
) -> str:
    """Derive a state from GCS-style readiness flags.

    GCS carries readiness as ``isNeedCheck`` (still initializing) plus the
    presence of endpoints, rather than a status enum.  Kept separate from
    :func:`normalize_status` so neither platform's idiom leaks into the other.
    """
    required = normalize_bool(env_required)
    if required is False:
        return STATE_NOT_REQUIRED
    check = normalize_bool(needs_check)
    if check is True:
        return STATE_STARTING
    if has_endpoints:
        return STATE_RUNNING
    if check is False:
        # Initialization finished but no endpoint is published: still not usable.
        return STATE_STARTING
    if required is None and check is None and not has_endpoints:
        return STATE_NONE
    return STATE_UNKNOWN


# ── misc tolerant coercions ───────────────────────────────────────────────


def normalize_bool(value: Any) -> bool | None:
    """Coerce a platform boolean, or ``None`` when it is absent/unrecognized."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0:
            return False
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return None


def split_host_port(text: Any) -> tuple[str, int | None]:
    """Split ``host:port`` / ``scheme://host:port/path`` into ``(host, port)``.

    Returns ``("", None)`` when nothing host-like can be found, so an
    unrecognized platform value degrades to "no endpoint" rather than a
    half-parsed host that a caller might connect to.
    """
    raw = str(text or "").strip()
    if not raw:
        return "", None
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    host, sep, port_text = raw.rpartition(":")
    if not sep:
        # No colon at all: a bare hostname.
        return raw, None
    if host and port_text.isdigit():
        port = int(port_text)
        if 0 < port <= 65535:
            return host, port
    # ":8080" (no host) or "host:notaport": keep whatever host we do have,
    # drop the unusable port rather than inventing one.
    return (host, None) if host else ("", None)
