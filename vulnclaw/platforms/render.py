"""Render normalized environment info for the agent.

This module is the single place where invariants I2 and I3 become text the model
reads.  The wording is carried over from the pre-refactor CTF2 renderer
(``vulnclaw/ctf_platform/tools.py::_render_target_state``, commit f278f16) with
only the tool names swapped for platform-neutral ones and the CTF2-only field
name ``nc_ssl`` dropped -- so the migration is provably behavior-preserving
rather than a rewrite hoping to be equivalent.

Why the wording is so insistent: on a real challenge the agent read a
``status=starting`` target payload once, mistook it for a complete description,
took the bare host:port from the create call, and spent 20+ minutes attacking a
TLS-wrapped service with a raw socket.  "TCP connects, then nothing" is
indistinguishable from a failed exploit.  So the renderer always states the
status, always labels an incomplete payload as unusable, and always names the
TLS symptom when the transport is TLS.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from vulnclaw.platforms.base import (
    STATE_EXPIRED,
    STATE_NONE,
    STATE_NOT_REQUIRED,
    STATE_RUNNING,
    STATE_STARTING,
    STATE_STOPPED,
    TRANSPORT_TCP,
    TRANSPORT_TLS,
    EnvInfo,
)

TOOL_START_ENV = "platform_start_env"
TOOL_READ_ENV = "platform_read_env"

RAW_LIMIT = 4000

# The transports say whether a TLS wrapper is needed; they do NOT say what to
# speak once connected.  For a web challenge that difference is the whole task, so
# the renderer reads the service kind off the URL scheme it already has.
_HTTP_SCHEMES = ("http", "https")


def _url_scheme(endpoint: Any) -> str:
    """The scheme of an endpoint's URL, lowercased, or ``""`` without one."""
    url = str(getattr(endpoint, "url", "") or "")
    if "://" not in url:
        return ""
    return url.split("://", 1)[0].strip().lower()


def _format_raw(raw: Mapping[str, Any] | Any, limit: int = RAW_LIMIT) -> str:
    """Pretty-print the platform payload, truncated for LLM consumption."""
    if isinstance(raw, str):
        return raw[:limit]
    try:
        rendered = json.dumps(raw, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        return str(raw)[:limit]
    return rendered[:limit]


def render_env_info(info: EnvInfo, *, raw_limit: int = RAW_LIMIT) -> str:
    """Render an :class:`EnvInfo` as agent-facing text.

    Layout: a guidance block, then the raw platform payload after a newline and
    ``{`` -- callers that only want the guidance can split on ``"\\n{"``.
    """
    platform = info.ref.platform
    lines: list[str] = [f"[{platform}] target status: {info.state}"]

    # Order matters: a state with its own explanation (expired, stopped) must be
    # handled BEFORE the generic "incomplete" branch, or an expired target would
    # be rendered as "still starting, poll again" -- advice that sends the caller
    # back to a dead address.
    if info.state == STATE_NONE:
        lines += _render_none(info)
    elif info.state == STATE_STARTING:
        lines += _render_incomplete(info)
    elif info.state in (STATE_EXPIRED, STATE_STOPPED):
        lines += _render_unusable_other(info)
    elif info.state == STATE_RUNNING:
        lines += _render_running(info) if info.complete else _render_incomplete(info)
    elif info.state == STATE_NOT_REQUIRED:
        lines += _render_not_required()
    else:
        lines += _render_unusable_other(info)

    lines += list(info.guidance)

    if info.expires_at:
        lines.append(f"expires_at: {info.expires_at}  (renew or restart the target after this)")

    return "\n".join(lines) + "\n" + _format_raw(info.raw, raw_limit)


def _render_none(info: EnvInfo) -> list[str]:
    return [
        f"⚠️ no target is running for {info.ref.token()}.",
        f"Start one with {TOOL_START_ENV}, then poll {TOOL_READ_ENV} until "
        f"status={STATE_RUNNING} before touching the service.",
    ]


def _render_incomplete(info: EnvInfo) -> list[str]:
    return [
        "⚠️ NOT READY — this response is INCOMPLETE, do not use it as the target.",
        "   While status != running the payload omits the connection details",
        "   (access url, ports, transport flags): they are simply absent, not empty.",
        f"   → Poll {TOOL_READ_ENV} again in ~10s until status={STATE_RUNNING}.",
        "   → Do NOT reuse a host:port from the create call: it can differ, and",
        "     the transport flags are unavailable until running.",
    ]


def _render_running(info: EnvInfo) -> list[str]:
    if not info.endpoints:
        return [
            "⚠️ NOT READY — status says running but no endpoint was published,",
            "   so there is nothing to connect to yet.",
            f"   → Poll {TOOL_READ_ENV} again in ~10s.",
        ]

    lines: list[str] = []
    for endpoint in info.endpoints:
        if endpoint.transport == TRANSPORT_TLS:
            lines.append(f"endpoint: {endpoint.display()}  (transport: TLS)")
            lines += [
                "⚠️ THIS TARGET IS TLS-WRAPPED.",
                "   A raw socket will complete the TCP handshake and then appear to",
                "   do nothing (payload never reaches the service), which looks",
                "   identical to a failed exploit. Wrap the connection first:",
                "       ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)",
                "       ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE",
                "       raw = socket.create_connection((host, port), timeout=8)",
                "       s = ctx.wrap_socket(raw, server_hostname=host)",
            ]
        elif endpoint.transport == TRANSPORT_TCP:
            scheme = _url_scheme(endpoint)
            if scheme in _HTTP_SCHEMES:
                # Measured: CTF2's web targets publish `http://host:80` with no
                # nc_ssl, so the transport is legitimately `tcp` -- and the old
                # wording said "plain TCP is fine", which invites a bare socket
                # against a web challenge.  `tcp` answers "no TLS wrapper needed",
                # not "raw protocol", so name the service.
                lines.append(
                    f"endpoint: {endpoint.display()}  "
                    f"(transport: tcp — HTTP service, no TLS wrapper needed)"
                )
                lines += [
                    f"   → Speak {scheme.upper()} (curl / requests / a browser). A bare",
                    f"     socket gets no banner from a web server, which looks like a",
                    f"     dead service.",
                ]
            else:
                lines.append(
                    f"endpoint: {endpoint.display()}  (transport: tcp — plain TCP is fine)"
                )
        else:
            lines.append(f"endpoint: {endpoint.display()}  (transport: not reported)")
            lines += [
                "   → Try plain TCP first; if the handshake succeeds but the service",
                "     never responds, try TLS.",
            ]
        if endpoint.user:
            lines.append(f"   user: {endpoint.user}")
        if endpoint.note:
            lines.append(f"   note: {endpoint.note}")
    return lines


def _render_not_required() -> list[str]:
    return [
        "this challenge needs no running environment — attack the static target",
        "directly (see the challenge description / attachments).",
    ]


def _render_unusable_other(info: EnvInfo) -> list[str]:
    reason = {
        STATE_EXPIRED: "the target's TTL has passed",
        STATE_STOPPED: "the target was released",
    }.get(info.state, f"status {info.state!r} is not one this tool knows how to guide on")
    return [
        f"⚠️ NOT USABLE — {reason}. Do not keep probing the old address.",
        f"   → Start a fresh one with {TOOL_START_ENV}, then poll {TOOL_READ_ENV} "
        f"until status={STATE_RUNNING}.",
    ]


__all__ = [
    "RAW_LIMIT",
    "TOOL_READ_ENV",
    "TOOL_START_ENV",
    "render_env_info",
]
