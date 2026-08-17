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
                    "platform quota, so prefer reading the challenge first."
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
                "name": "ctf2_submit_flag",
                "description": (
                    "Submit a confirmed flag for a practice challenge on the CTF2 "
                    "platform. Only call after the flag value is fully known; the "
                    "API requires an explicit confirmation sentinel."
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
    return _format(payload)


async def _handle_submit_flag(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        usage, challenge = await _named(args["practice_id"], args["challenge_id"])
        payload = await _client.submit_flag(usage, challenge, args["flag"])
    except Exception as exc:
        return f"[ctf2_error] submit flag failed: {exc}"
    return _format(payload)


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