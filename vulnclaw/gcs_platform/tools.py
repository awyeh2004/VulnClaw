"""OpenAI tool schemas and dispatch for the West Lake Sword Competition agent API.

Handlers call :mod:`vulnclaw.gcs_platform.client`. Missing/malformed access
keys short-circuit to a readable `[gcs_config]`/`[gcs_error]` message instead
of crashing the agent loop.  Environment lifecycle (start -> poll ready ->
attack -> recover) is assembled here from the flat client calls.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Awaitable, Callable

from vulnclaw.gcs_platform import client as _client

GCS_TOOL_NAMES: list[str] = [
    "gcs_match_info",
    "gcs_notice_list",
    "gcs_notice_detail",
    "gcs_overview",
    "gcs_exercise_list",
    "gcs_read_exercise",
    "gcs_build_env",
    "gcs_recover_env",
    "gcs_submit_flag",
]

GCS_READ_TOOLS: set[str] = {
    "gcs_match_info",
    "gcs_notice_list",
    "gcs_notice_detail",
    "gcs_overview",
    "gcs_exercise_list",
    "gcs_read_exercise",
}


def gcs_tools_enabled() -> bool:
    """Whether the LEGACY ``gcs_*`` tool names should be exposed to the agent.

    OFF by default. The GCS integration is legacy (one online qualifier the team did
    not advance from) and an agent solving a challenge on a DIFFERENT platform
    reached for ``gcs_submit_flag`` first -- purely because the name contains
    "submit_flag" -- without ever establishing which platform the challenge was on.
    Gating the schema is what actually removes the temptation: a tool the model
    cannot see is a tool it cannot call.

    There is now ONE switch for "the legacy per-platform names"
    (``competition.expose_legacy_tool_names``, which also governs ``ctf2_*``):
    two knobs that mean the same thing is how one of them ends up contradicting the
    other. ``gcs.tools_enabled`` is still honoured so an existing config keeps
    working, and is deprecated in favour of the newer field.

    Fails CLOSED on a config error: not being able to read the setting is not a
    reason to expose a tool face that performs irreversible actions.
    """
    try:
        from vulnclaw.config.settings import load_config

        config = load_config()
    except Exception:
        return False
    unified = bool(
        getattr(getattr(config, "competition", None), "expose_legacy_tool_names", False)
    )
    legacy = bool(getattr(getattr(config, "gcs", None), "tools_enabled", False))
    return unified or legacy


def gcs_tool_schemas() -> list[dict[str, Any]]:
    """OpenAI function schemas for all GCS competition tools.

    Returns an EMPTY list when the GCS tool face is disabled (the default) --
    see :func:`gcs_tools_enabled`. Callers register whatever this returns, so an
    empty list means the tools never enter the schema at all.
    """
    if not gcs_tools_enabled():
        return []
    return [
        {
            "type": "function",
            "function": {
                "name": "gcs_match_info",
                "description": (
                    "Fetch the West Lake Sword Competition notes and rules "
                    "(competition notice + rule text). Call this first to learn "
                    "flag format, timing and submission constraints."
                ),
                "parameters": {"type": "object", "properties": {}},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "gcs_notice_list",
                "description": (
                    "List recent competition announcements (id, title, content)."
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
                "name": "gcs_notice_detail",
                "description": (
                    "Read a single competition announcement by id, including "
                    "its attached file download link when present."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "notice_id": {
                            "type": "integer",
                            "description": "Announcement id from gcs_notice_list.",
                        },
                    },
                    "required": ["notice_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "gcs_overview",
                "description": (
                    "Query the team's current score and rank on the leaderboard."
                ),
                "parameters": {"type": "object", "properties": {}},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "gcs_exercise_list",
                "description": (
                    "List available challenges grouped by category. Each leaf "
                    "entry carries a numeric id used by gcs_read_exercise / "
                    "gcs_build_env / gcs_submit_flag."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results.",
                            "default": 50,
                        },
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "gcs_read_exercise",
                "description": (
                    "Read challenge detail: description, attachment download "
                    "urls, target endpoint info (exposeIps/ports/users/proxy "
                    "mappings), score/difficulty, and environment flags "
                    "(isNeedInit / isNeedCheck)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "exercise_id": {
                            "type": "integer",
                            "description": "Numeric challenge id from gcs_exercise_list.",
                        },
                    },
                    "required": ["exercise_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "gcs_build_env",
                "description": (
                    "Start (or reuse) a challenge's live environment. This is "
                    "async: after calling it, poll gcs_read_exercise until "
                    "isNeedCheck is false and endpoints are populated before "
                    "attempting to connect."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "exercise_id": {
                            "type": "integer",
                            "description": "Numeric challenge id.",
                        },
                    },
                    "required": ["exercise_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "gcs_recover_env",
                "description": (
                    "Recover (destroy) a challenge environment once the flag "
                    "is found, releasing platform quota. Safe to call after "
                    "gcs_submit_flag succeeds."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "exercise_id": {
                            "type": "integer",
                            "description": "Numeric challenge id.",
                        },
                    },
                    "required": ["exercise_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "gcs_submit_flag",
                "description": (
                    "Submit a flag for a challenge. The competition caps "
                    "submissions per challenge and forbids brute-forcing, so "
                    "only a limited number of attempts run automatically; "
                    "further attempts escalate to human confirmation."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "exercise_id": {
                            "type": "integer",
                            "description": "Numeric challenge id.",
                        },
                        "flag": {
                            "type": "string",
                            "description": "The flag value to submit.",
                        },
                    },
                    "required": ["exercise_id", "flag"],
                },
            },
        },
    ]


# Dispatch accepts every tool the module implements, INDEPENDENT of whether the
# tool face is currently exposed to the agent.
#
# This module-level list used to be derived from `gcs_tool_schemas()`. Once the
# schema function learned to return [] when the face is disabled, that
# derivation made dispatch reject every call with "unknown GCS tool" -- coupling
# two things that must stay separate:
#   * `gcs_tool_schemas()` decides what the MODEL can see;
#   * this decides what the CODE can execute.
# Conflating them means disabling the face would also break the `vulnclaw gcs`
# command and any programmatic caller.
GCS_TOOL_NAMES_BY_SCHEMA: list[str] = list(GCS_TOOL_NAMES)


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
    """Return an error message when the GCS access key is not configured."""
    if not _client.is_configured():
        return (
            "[gcs_config] GCS agent access key not configured. Set the "
            "VULNCLAW_GCS_ACCESS_KEY environment variable (team access key "
            "issued by the competition platform), then retry."
        )
    return None


async def _handle_match_info(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        payload = await _client.match_info()
    except Exception as exc:
        return f"[gcs_error] fetch match info failed: {exc}"
    return _format(payload)


async def _handle_notice_list(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        payload = await _client.notice_list()
        return _format(payload)
    except Exception as exc:
        return f"[gcs_error] list notices failed: {exc}"


async def _handle_notice_detail(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        payload = await _client.notice_detail(int(args["notice_id"]))
    except Exception as exc:
        return f"[gcs_error] read notice failed: {exc}"
    return _format(payload)


async def _handle_overview(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        payload = await _client.overview()
    except Exception as exc:
        return f"[gcs_error] query overview failed: {exc}"
    return _format(payload)


async def _handle_exercise_list(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        payload = await _client.exercise_list()
    except Exception as exc:
        return f"[gcs_error] list exercises failed: {exc}"
    return _format(payload)


async def _handle_read_exercise(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    try:
        payload = await _client.exercise(int(args["exercise_id"]))
    except Exception as exc:
        return f"[gcs_error] read exercise failed: {exc}"
    return _format(payload)


async def _handle_build_env(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    exercise_id = int(args["exercise_id"])
    try:
        payload = await _client.build_environment(exercise_id)
    except Exception as exc:
        return f"[gcs_error] build environment failed: {exc}"
    return _format(payload)


async def _handle_recover_env(args: dict[str, Any]) -> str:
    blocking = await _guard_config()
    if blocking:
        return blocking
    exercise_id = int(args["exercise_id"])
    try:
        payload = await _client.recover_environment(exercise_id)
    except Exception as exc:
        return f"[gcs_error] recover environment failed: {exc}"
    return _format(payload)


async def _handle_submit_flag(args: dict[str, Any]) -> str:
    """Thin delegate to the shared submit policy.

    This is the security fix, not a tidy-up: the ``allow_flag_submission`` gate
    lived only on the CTF2 handler, so this path could submit a flag with the gate
    OFF -- the one irreversible action against the scoring platform, ungated. Its
    guard was also keyed with the exercise id duplicated into both slots, which is
    exactly the shape that let CTF2 and GCS counters collide.

    Both now come from :func:`vulnclaw.platforms.tools.submit_flag_via`, so the
    old tool name behaves identically to ``platform_submit``.
    """
    from vulnclaw.platforms.refs import ChallengeRef
    from vulnclaw.platforms.tools import adapter_for_platform, submit_flag_via

    exercise_id = str(args["exercise_id"])
    ref = ChallengeRef("gcs", "exercise", "", exercise_id)
    try:
        adapter = adapter_for_platform("gcs")
    except Exception as exc:  # noqa: BLE001
        return f"[gcs_error] submit flag failed: {exc}"
    return await submit_flag_via(adapter, ref, args.get("flag"))


def _build_handlers() -> dict[str, Callable[[dict[str, Any]], Awaitable[str]]]:
    return {
        "gcs_match_info": _handle_match_info,
        "gcs_notice_list": _handle_notice_list,
        "gcs_notice_detail": _handle_notice_detail,
        "gcs_overview": _handle_overview,
        "gcs_exercise_list": _handle_exercise_list,
        "gcs_read_exercise": _handle_read_exercise,
        "gcs_build_env": _handle_build_env,
        "gcs_recover_env": _handle_recover_env,
        "gcs_submit_flag": _handle_submit_flag,
    }


_HANDLERS: dict[str, Callable[[dict[str, Any]], Awaitable[str]]] = _build_handlers()


async def dispatch_gcs_tool(tool_name: str, args: dict[str, Any]) -> str:
    """Route a GCS competition tool call to its handler."""
    if tool_name not in GCS_TOOL_NAMES_BY_SCHEMA:
        return f"[gcs_error] unknown GCS tool: {tool_name}"
    handler = _HANDLERS[tool_name]
    return await handler(args)


async def exercise_ready_poll(exercise_id: int, timeout: float = 60.0) -> str:
    """Poll ``gcs_read_exercise`` until the environment is usable.

    Returns a compact JSON summary of the exercise state. Call after
    ``gcs_build_env``; the prompt tells the agent to retry until the detail
    shows ``isNeedCheck: false`` and populated endpoints.  Treats network
    errors as transient (keeps polling until the timeout).
    """
    deadline = asyncio.get_event_loop().time() + timeout
    delay = 2.0
    while True:
        try:
            payload = await _client.exercise(exercise_id)
            text = _format(payload)
            check = (
                str(payload.get("data", {}).get("isNeedCheck"))
                if isinstance(payload.get("data"), dict)
                else str(payload)
            )
            if "False" in check or "false" in check:
                return text
        except Exception:
            pass
        if asyncio.get_event_loop().time() >= deadline:
            return f"[gcs_error] environment not ready after {timeout:.0f}s"
        await asyncio.sleep(delay)
        delay = min(delay * 1.5, 10.0)