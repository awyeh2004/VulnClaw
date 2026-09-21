"""OpenAI tool schemas and dispatch for CTF2 (DASCTF) platform tools.

Handlers call the CTF2 User Open API through :mod:`vulnclaw.ctf_platform.client`.
A missing token (`VULNCLAW_CTF2_API_KEY` unset) short-circuits each tool with a
readable, actionable message rather than a connection error, so the agent knows
to record the credential instead of retrying the network call.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

from vulnclaw.ctf_platform import client as _client

CTF_TOOL_NAMES: list[str] = [
    "ctf2_list_practice",
    "ctf2_list_daily",
    "ctf2_read_challenge",
    "ctf2_start_environment",
    "ctf2_get_target",
    "ctf2_stop_environment",
    "ctf2_submit_flag",
    "ctf2_list_competitions",
    "ctf2_list_stage_challenges",
    "ctf2_list_submissions",
]

# Tools that never mutate platform state (read-only).
CTF_READ_TOOLS: set[str] = {
    "ctf2_list_practice",
    "ctf2_list_daily",
    "ctf2_read_challenge",
    "ctf2_get_target",
    "ctf2_list_competitions",
    "ctf2_list_stage_challenges",
    "ctf2_list_submissions",
}


def ctf2_tool_schemas() -> list[dict[str, Any]]:
    """OpenAI function schemas for all CTF2 platform tools."""
    return [
        {
            "type": "function",
            "function": {
                "name": "ctf2_list_practice",
                "description": (
                    "List visible public practice grounds on the CTF2 (DASCTF) "
                    "platform. Returns practice ground ids suitable for "
                    "ctf2_read_challenge / ctf2_start_environment."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results.",
                            "default": 20,
                        },
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "ctf2_list_daily",
                "description": (
                    "List visible daily challenges on the CTF2 platform."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results.",
                            "default": 20,
                        },
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "ctf2_read_challenge",
                "description": (
                    "Read a practice challenge's full description from the CTF2 "
                    "platform, including the downloadable attachment/description."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "practice_id": {
                            "type": "string",
                            "description": "Practice ground id (from ctf2_list_practice).",
                        },
                        "challenge_id": {
                            "type": "string",
                            "description": "Challenge id inside the practice ground.",
                        },
                    },
                    "required": ["practice_id", "challenge_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "ctf2_start_environment",
                "description": (
                    "Start (or reuse) a practice challenge's live environment and "
                    "return its connection info (host/port). Each start consumes "
                    "platform quota, so prefer reading the challenge first. "
                    "Pair every successful start with ctf2_stop_environment once "
                    "the flag is captured — do not leave instances running."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "practice_id": {
                            "type": "string",
                            "description": "Practice ground id.",
                        },
                        "challenge_id": {
                            "type": "string",
                            "description": "Challenge id inside the practice ground.",
                        },
                    },
                    "required": ["practice_id", "challenge_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "ctf2_get_target",
                "description": (
                    "Return the live connection info (host/port/url) of a started "
                    "practice challenge target. Requires the front-end session "
                    "token (Bearer JWT in browser localStorage); call after "
                    "ctf2_start_environment so the target is running. Response "
                    "may include access_url/access_type and expires_at."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "practice_id": {
                            "type": "string",
                            "description": "Practice ground id.",
                        },
                        "challenge_id": {
                            "type": "string",
                            "description": "Challenge id inside the practice ground.",
                        },
                    },
                    "required": ["practice_id", "challenge_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "ctf2_stop_environment",
                "description": (
                    "Release a practice challenge's live environment (frees the "
                    "platform container slot). ALWAYS call this after the flag is "
                    "captured or submitted — leaving instances running exhausts "
                    "quota and slots; instances otherwise linger until the ~1h "
                    "platform TTL. Requires the front-end session token."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "practice_id": {
                            "type": "string",
                            "description": "Practice ground id.",
                        },
                        "challenge_id": {
                            "type": "string",
                            "description": "Challenge id inside the practice ground.",
                        },
                    },
                    "required": ["practice_id", "challenge_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "ctf2_submit_flag",
                "description": (
                    "Submit a confirmed flag for a practice challenge on the CTF2 "
                    "platform. Only call after the flag value is fully known; the "
                    "API requires an explicit confirmation sentinel. After a "
                    "successful (or definitively final) submission, release the "
                    "instance with ctf2_stop_environment."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "practice_id": {
                            "type": "string",
                            "description": "Practice ground id.",
                        },
                        "challenge_id": {
                            "type": "string",
                            "description": "Challenge id inside the practice ground.",
                        },
                        "flag": {
                            "type": "string",
                            "description": "The full flag value, e.g. flag{...}.",
                        },
                    },
                    "required": ["practice_id", "challenge_id", "flag"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "ctf2_list_competitions",
                "description": (
                    "List visible competitions on the CTF2 platform (gives access "
                    "to stage-based challenge trees)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results.",
                            "default": 20,
                        },
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "ctf2_list_stage_challenges",
                "description": (
                    "List visible challenges in a competition stage on the CTF2 "
                    "platform."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "stage_id": {
                            "type": "string",
                            "description": "Stage id (from ctf2_list_competitions).",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results.",
                            "default": 50,
                        },
                    },
                    "required": ["stage_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "ctf2_list_submissions",
                "description": (
                    "List the current user's recent flag submissions on the CTF2 "
                    "platform, including whether each was accepted."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results.",
                            "default": 20,
                        },
                    },
                },
            },
        },
    ]


CTF_TOOL_NAMES_BY_SCHEMA: list[str] = [
    s["function"]["name"] for s in ctf2_tool_schemas()
]


def _format(payload: dict | list | str) -> str:
    """Compact-JSON pretty render for LLM consumption (truncate huge bodies)."""
    if isinstance(payload, str):
        return payload[:4000]
    try:
        rendered = json.dumps(payload, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        return str(payload)[:4000]
    return rendered[:4000]


async def _guard_config() -> str | None:
    """Return an error message when the CTF2 token is not configured."""
    if not _client.is_configured():
        return (
            "[ctf2_config] CTF2 personal access token not configured. Set the "
            "VULNCLAW_CTF2_API_KEY environment variable (see /dashboard/developer/"
            "open-api on ctf2.dasctf.com), then retry."
        )
    return None


async def _named(practice_id: str, challenge_id: str) -> tuple[str, str]:
    return practice_id, challenge_id


async def _handle_list_practice(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        payload = await _client.list_practice(limit=int(args.get("limit", 20) or 20))
    except Exception as exc:  # network / platform errors must not crash the loop
        return f"[ctf2_error] list practice failed: {exc}"
    return _format(payload)


async def _handle_list_daily(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        payload = await _client.list_daily(limit=int(args.get("limit", 20) or 20))
    except Exception as exc:
        return f"[ctf2_error] list daily failed: {exc}"
    return _format(payload)


async def _handle_read_challenge(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        usage, challenge = await _named(args["practice_id"], args["challenge_id"])
        payload = await _client.read_challenge(usage, challenge)
    except Exception as exc:
        return f"[ctf2_error] read challenge failed: {exc}"
    return _format(payload)


async def _handle_start_environment(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        usage, challenge = await _named(args["practice_id"], args["challenge_id"])
        payload = await _client.start_environment(usage, challenge)
    except Exception as exc:
        return f"[ctf2_error] start environment failed: {exc}"
    return _format(payload)


def _render_target_state(payload: dict[str, Any]) -> str:
    """Render a target response so the caller cannot mistake a partial one for complete.

    WHY THIS EXISTS (a real miss, not a hypothetical): the target response has two
    different shapes depending on ``status``:

      status=starting -> {id, name, status, expires_at, created_at, description}
                         NO ``access_url``, NO ``access_urls``, NO ``nc_ssl``
      status=running  -> adds ``access_url``, ``access_urls[]``, and ``nc_ssl``

    A raw dump of the ``starting`` shape looks like a complete target description,
    so a caller reads it once and assumes it has the connection info -- then never
    polls again. That is exactly what happened on a real challenge: the agent
    fetched the target while it was still ``starting``, took the bare host:port
    from the create call, and attacked a **TLS-wrapped** target with a raw socket
    for 20+ minutes. The ``nc_ssl: true`` it needed only appears once running.

    So the status is surfaced explicitly, and when the response is not yet usable
    the tool says what to do instead of leaving the caller to infer it.
    """
    import json as _json

    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return (
            "[ctf2] no target is running for this challenge.\n"
            "Start one with ctf2_start_environment, then poll ctf2_get_target "
            "until status=running before touching the service.\n"
            + _format(payload)
        )

    status = str(data.get("status") or "").strip().lower()
    url = data.get("access_url") or ""
    ssl_flag = data.get("nc_ssl")
    if ssl_flag is None:
        for entry in data.get("access_urls") or []:
            if isinstance(entry, dict) and entry.get("nc_ssl") is not None:
                ssl_flag = entry.get("nc_ssl")
                if not url:
                    url = entry.get("url") or ""
                break

    lines: list[str] = [f"[ctf2] target status: {status or 'unknown'}"]

    if status in ("starting", "pending", "creating", "queued", ""):
        lines += [
            "⚠️ NOT READY — this response is INCOMPLETE, do not use it as the target.",
            "   While status != running the payload omits access_url / access_urls /",
            "   nc_ssl, so connection details are simply absent (not empty).",
            "   → Poll ctf2_get_target again in ~10s until status=running.",
            "   → Do NOT reuse a host:port from the create call: it can differ, and",
            "     the transport flags are unavailable until running.",
        ]
    elif status == "running":
        lines.append(f"access_url: {url}")
        if ssl_flag is True:
            lines += [
                "nc_ssl: true  ⚠️ THIS TARGET IS TLS-WRAPPED.",
                "   A raw socket will complete the TCP handshake and then appear to",
                "   do nothing (payload never reaches the service), which looks",
                "   identical to a failed exploit. Wrap the connection first:",
                "       ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)",
                "       ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE",
                "       raw = socket.create_connection((host, port), timeout=8)",
                "       s = ctx.wrap_socket(raw, server_hostname=host)",
            ]
        elif ssl_flag is False:
            lines.append("nc_ssl: false  → plain TCP is fine.")
        else:
            lines.append(
                "nc_ssl: (not reported) — try plain TCP first; if the handshake "
                "succeeds but the service never responds, try TLS."
            )
    else:
        lines.append(f"(status {status!r} is not one this tool knows how to guide on)")

    exp = data.get("expires_at")
    if exp:
        lines.append(f"expires_at: {exp}  (renew or restart the target after this)")

    return "\n".join(lines) + "\n" + _format(payload)


async def _handle_get_target(args: dict[str, Any]) -> str:
    if not _client.session_token():
        return (
            "[ctf2_config] CTF2 session token not available for target lookup. "
            "Single sign-on through the browser session (VULNCLAW_CTF2_SESSION_TOKEN) "
            "is required to read live target connection info."
        )
    try:
        usage, challenge = await _named(args["practice_id"], args["challenge_id"])
        payload = await _client.get_target(usage, challenge)
    except Exception as exc:
        return f"[ctf2_error] get target failed: {exc}"
    return _render_target_state(payload)


async def _handle_stop_environment(args: dict[str, Any]) -> str:
    if not _client.session_token():
        return (
            "[ctf2_config] CTF2 session token not available for releasing the "
            "target (VULNCLAW_CTF2_SESSION_TOKEN). The instance will still be "
            "reclaimed by the platform TTL, but the slot stays busy until then."
        )
    try:
        usage, challenge = await _named(args["practice_id"], args["challenge_id"])
        payload = await _client.stop_target(usage, challenge)
    except Exception as exc:
        return f"[ctf2_error] stop environment failed: {exc}"
    return "[ctf2] environment released (target deleted).\n" + _format(payload)


def _flag_submission_enabled() -> bool:
    """Whether flag submission has been explicitly enabled by the operator.

    Submitting a flag is the one IRREVERSIBLE action against the scoring
    platform, and the competition handbook treats "非有效操作" as grounds for
    disqualification -- a guessed or exploratory submission is exactly that.
    Default is therefore OFF; everything else on the platform (listing, reading,
    starting/stopping an environment) stays available.

    Returns True when `competition.allow_flag_submission` is set (in the config
    file or via VULNCLAW_COMPETITION__ALLOW_FLAG_SUBMISSION). On any config
    error the gate fails CLOSED: not being able to read the setting is not a
    reason to allow an irreversible action.
    """
    try:
        from vulnclaw.config.settings import load_config

        return bool(getattr(load_config().competition, "allow_flag_submission", False))
    except Exception:
        return False


async def _handle_submit_flag(args: dict[str, Any]) -> str:
    """Thin delegate to the shared submit policy.

    This handler used to carry its own copy of the gate/guard/accounting logic.
    That copy differed from the same logic on the GCS side in three measured ways
    (gate present only here, guard keyed by two ids, `[ctf2_confirm]` prefix), so
    the policy now lives in one place and both entry points call it -- the tool
    name can differ, the behaviour cannot.
    """
    from vulnclaw.platforms.refs import ChallengeRef
    from vulnclaw.platforms.tools import adapter_for_platform, submit_flag_via

    ref = ChallengeRef(
        "ctf2", "practice", str(args["practice_id"]), str(args["challenge_id"])
    )
    try:
        adapter = adapter_for_platform("ctf2")
    except Exception as exc:  # noqa: BLE001
        return f"[ctf2_error] submit flag failed: {exc}"
    return await submit_flag_via(adapter, ref, args.get("flag"))


async def _handle_list_competitions(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        payload = await _client.list_competitions(limit=int(args.get("limit", 20) or 20))
    except Exception as exc:
        return f"[ctf2_error] list competitions failed: {exc}"
    return _format(payload)


async def _handle_list_stage_challenges(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        payload = await _client.list_stage_challenges(
            args["stage_id"], limit=int(args.get("limit", 50) or 50)
        )
    except Exception as exc:
        return f"[ctf2_error] list stage challenges failed: {exc}"
    return _format(payload)


async def _handle_list_submissions(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        payload = await _client.list_submissions(limit=int(args.get("limit", 20) or 20))
    except Exception as exc:
        return f"[ctf2_error] list submissions failed: {exc}"
    return _format(payload)


def _build_handlers() -> dict[str, Callable[[dict[str, Any]], Awaitable[str]]]:
    return {
        "ctf2_list_practice": _handle_list_practice,
        "ctf2_list_daily": _handle_list_daily,
        "ctf2_read_challenge": _handle_read_challenge,
        "ctf2_start_environment": _handle_start_environment,
        "ctf2_get_target": _handle_get_target,
        "ctf2_stop_environment": _handle_stop_environment,
        "ctf2_submit_flag": _handle_submit_flag,
        "ctf2_list_competitions": _handle_list_competitions,
        "ctf2_list_stage_challenges": _handle_list_stage_challenges,
        "ctf2_list_submissions": _handle_list_submissions,
    }


_HANDLERS: dict[str, Callable[[dict[str, Any]], Awaitable[str]]] = _build_handlers()


async def dispatch_ctf2_tool(tool_name: str, args: dict[str, Any]) -> str:
    """Route a CTF2 platform tool call to its handler."""
    if tool_name not in CTF_TOOL_NAMES_BY_SCHEMA:
        return f"[ctf2_error] unknown CTF2 tool: {tool_name}"
    handler = _HANDLERS[tool_name]
    return await handler(args)