"""The platform-neutral tool face: 6 core tools instead of 19 platform-bound ones.

Before this module, the platform an action went to was decided by *which tool name
the model picked* -- ``ctf2_submit_flag`` vs ``gcs_submit_flag``. An agent solving
a CTF2 challenge reached for the GCS one purely because the name contained
"submit_flag". Here the platform rides in the ``ref`` argument, so there is no
tool name that can express the wrong platform.

Two gates are applied here rather than per platform, so they cannot be forgotten
on one of them:

* **flag submission** is OFF unless ``competition.allow_flag_submission`` is set.
  It is the one irreversible action against the scoring platform, and the
  handbook treats an invalid operation as grounds for disqualification.
  (Measured: this gate existed only on the CTF2 path, so GCS was ungated.)
* **attempt accounting** goes through one ref-keyed guard, so a CTF2 challenge and
  a GCS challenge cannot collide in a shared key space.

Errors are returned as readable text, never raised: a platform hiccup must not
kill the agent loop, and a mis-addressed ref must tell the model how to fix it.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

from vulnclaw.platforms import base, registry
from vulnclaw.platforms.refs import ChallengeRef, CorpusRef, RefError, split_token
from vulnclaw.platforms.render import render_env_info
from vulnclaw.platforms.submit_guard import get_guard, guard_reason_to_message

# The 6 verbs every configured platform supports. These are the names that must
# survive schema pruning (see `_ALWAYS_KEEP_TOOLS` in agent/builtin_tools.py):
# a goal whose text trips a task keyword used to prune every platform tool away,
# leaving the model unable to address the platform at all.
CORE_TOOL_NAMES: list[str] = [
    "platform_list",
    "platform_read",
    "platform_start_env",
    "platform_read_env",
    "platform_stop_env",
    "platform_submit",
]

# Optional tools appear only when a configured adapter declares the capability,
# so a platform's extra features are neither flattened away nor always-on.
_CAPABILITY_TOOLS: tuple[tuple[str, str], ...] = (
    ("platform_submissions", base.CAP_SUBMISSIONS),
    ("platform_event_info", base.CAP_EVENT_INFO),
    ("platform_notices", base.CAP_NOTICES),
    ("platform_overview", base.CAP_OVERVIEW),
)

_REF_HELP = (
    "Pass a `ref` string exactly as returned by platform_list / platform_read "
    "(a bare id is refused on purpose -- the platform must never be guessed)."
)


def core_tool_names() -> list[str]:
    return list(CORE_TOOL_NAMES)


def _ref_schema(description: str) -> dict:
    return {"type": "string", "description": f"{description} {_REF_HELP}"}


def platform_tool_schemas() -> list[dict[str, Any]]:
    """OpenAI schemas for the tools the currently configured platforms support.

    Returns [] when nothing is configured: exposing a tool that can only answer
    "not configured" wastes schema budget and invites the model to try it.
    """
    from vulnclaw.platforms.bootstrap import ensure_adapters

    ensure_adapters()
    if not registry.configured_adapters():
        return []

    tools: list[dict[str, Any]] = [
        {
            "type": "function",
            "function": {
                "name": "platform_list",
                "description": (
                    "List what the configured CTF platforms expose. Without `ref` "
                    "this lists the challenge collections (practice grounds, daily "
                    "set, competition stages); with a collection `ref` it lists the "
                    "challenges inside it. Always use the refs this returns -- they "
                    "carry the platform."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ref": _ref_schema("Optional collection ref."),
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "platform_read",
                "description": (
                    "Read one challenge: description, attachments, score, and "
                    "whether it needs a running environment."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {"ref": _ref_schema("Challenge ref.")},
                    "required": ["ref"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "platform_start_env",
                "description": (
                    "Start (or reuse) a challenge's live environment. Each start "
                    "consumes platform quota, so read the challenge first. The "
                    "response is often incomplete by design -- poll platform_read_env "
                    "until it reports the target as usable. Pair every successful "
                    "start with platform_stop_env once the flag is captured."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {"ref": _ref_schema("Challenge ref.")},
                    "required": ["ref"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "platform_read_env",
                "description": (
                    "Read (poll) the live environment of a challenge: state, "
                    "endpoint(s) and TRANSPORT (plain TCP vs TLS). A response that "
                    "is not yet usable says so explicitly -- keep polling instead of "
                    "attacking an address taken from an earlier response."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {"ref": _ref_schema("Challenge ref.")},
                    "required": ["ref"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "platform_stop_env",
                "description": (
                    "Release a challenge's live environment so the platform can "
                    "reclaim the slot. ALWAYS call this after the flag is captured "
                    "or submitted; instances otherwise linger until the platform TTL."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {"ref": _ref_schema("Challenge ref.")},
                    "required": ["ref"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "platform_submit",
                "description": (
                    "Submit a confirmed flag for a challenge. The platform is taken "
                    "from the ref, so there is no way to submit to the wrong one. "
                    "Only call once the flag value is fully known; submission is "
                    "irreversible and off by default. Release the instance with "
                    "platform_stop_env afterwards."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ref": _ref_schema("Challenge ref."),
                        "flag": {
                            "type": "string",
                            "description": "The full flag value, e.g. flag{...}.",
                        },
                    },
                    "required": ["ref", "flag"],
                },
            },
        },
    ]

    capabilities = registry.capabilities()
    for name, capability in _CAPABILITY_TOOLS:
        if capability in capabilities:
            tools.append(_optional_schema(name, capability))
    return tools


def _optional_schema(name: str, capability: str) -> dict[str, Any]:
    descriptions = {
        "platform_submissions": (
            "List the team's recent flag submissions on this platform, including "
            "whether each was accepted."
        ),
        "platform_event_info": (
            "Fetch the competition's notes and rules (including the flag format)."
        ),
        "platform_notices": (
            "List competition announcements, or read one by passing its id."
        ),
        "platform_overview": "Query the team's current score and rank.",
    }
    properties: dict[str, Any] = {}
    if capability in (base.CAP_SUBMISSIONS,):
        properties["limit"] = {
            "type": "integer",
            "description": "Maximum number of results.",
            "default": 20,
        }
    if capability == base.CAP_NOTICES:
        properties["notice_id"] = {
            "type": "string",
            "description": "Announcement id; omit to list all.",
        }
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": descriptions.get(name, name),
            "parameters": {"type": "object", "properties": properties},
        },
    }


# ── dispatch ──────────────────────────────────────────────────────────────


def _format(payload: Any, limit: int = 4000) -> str:
    if isinstance(payload, str):
        return payload[:limit]
    try:
        return json.dumps(payload, ensure_ascii=False, indent=2)[:limit]
    except (TypeError, ValueError):
        return str(payload)[:limit]


def _no_platforms() -> str:
    return (
        "[platform] no CTF platform is configured, so no platform tool is "
        "available. Set the platform's credential (e.g. VULNCLAW_CTF2_API_KEY) "
        "and retry.\n" + registry.describe()
    )


def _resolve(args: dict[str, Any]) -> tuple[Any, ChallengeRef] | str:
    """Resolve `ref` to (adapter, ref), or return an error message."""
    token = str(args.get("ref") or "").strip()
    if not token:
        return f"[platform] missing `ref`. {_REF_HELP}"
    try:
        adapter = registry.adapter_for(token)
        _, tail = split_token(token)
        return adapter, adapter.parse_ref(tail)
    except registry.UnknownPlatform as exc:
        return f"[platform] {exc}"
    except registry.PlatformNotConfigured as exc:
        return f"[platform] {exc}"
    except RefError as exc:
        return f"[platform] bad ref: {exc}"


def _corpus_from(adapter: Any, token: str) -> CorpusRef | str:
    try:
        parsed = adapter.parse_ref(split_token(token)[1])
    except RefError as exc:
        return f"[platform] bad collection ref: {exc}"
    return CorpusRef(parsed.platform, parsed.kind, parsed.group or parsed.id)


def render_corpora(corpora: list[base.Corpus]) -> str:
    if not corpora:
        return "[platform] no collections reported. " + registry.describe()
    lines = ["[platform] collections (pass a ref to platform_list):"]
    for corpus in corpora:
        detail = f" ({corpus.count} challenges)" if corpus.count else ""
        note = f"  -- {corpus.note}" if corpus.note else ""
        lines.append(f"  {corpus.ref.token()}  {corpus.name}{detail}{note}")
    return "\n".join(lines)


def render_challenges(challenges: list[base.Challenge]) -> str:
    if not challenges:
        return "[platform] no challenges reported in that collection."
    lines = ["[platform] challenges (pass a ref to platform_read / _start_env):"]
    for challenge in challenges:
        bits = [f"  {challenge.ref.token()}  {challenge.name}"]
        if challenge.category:
            bits.append(f"category={challenge.category}")
        if challenge.difficulty:
            bits.append(f"difficulty={challenge.difficulty}")
        if challenge.score:
            bits.append(f"score={challenge.score}")
        if challenge.solved:
            bits.append("SOLVED")
        if challenge.needs_env:
            bits.append("needs-env")
        lines.append(" | ".join(bits))
    return "\n".join(lines)


def render_challenge(challenge: base.Challenge) -> str:
    lines = [
        f"[platform] challenge {challenge.ref.token()}",
        f"name: {challenge.name}",
    ]
    for label, value in (
        ("category", challenge.category),
        ("difficulty", challenge.difficulty),
        ("score", challenge.score),
    ):
        if value:
            lines.append(f"{label}: {value}")
    lines.append(f"needs running environment: {'yes' if challenge.needs_env else 'no'}")
    if challenge.solved:
        lines.append("already solved on the platform")
    if challenge.description:
        lines.append("description:")
        lines.append(challenge.description)
    if challenge.attachments:
        lines.append("attachments:")
        for attachment in challenge.attachments:
            extra = []
            if attachment.size:
                extra.append(f"{attachment.size} bytes")
            if attachment.md5:
                extra.append(f"md5={attachment.md5}")
            suffix = f"  ({', '.join(extra)})" if extra else ""
            lines.append(f"  {attachment.name}: {attachment.url}{suffix}")
    return "\n".join(lines) + "\n" + _format(challenge.raw)


def _flag_submission_enabled() -> bool:
    """Whether flag submission is explicitly enabled. Fails CLOSED."""
    try:
        from vulnclaw.config.settings import load_config

        return bool(getattr(load_config().competition, "allow_flag_submission", False))
    except Exception:
        return False


def _submission_disabled_message() -> str:
    return (
        "[platform_submit_disabled] Flag submission is OFF by default.\n"
        "Submitting a flag is irreversible and the competition handbook treats an "
        "invalid operation (including a wrong guess) as grounds for disqualification, "
        "so it must be enabled deliberately:\n"
        "  - config.yaml:  competition:\\n                    allow_flag_submission: true\\n"
        "  - env:          VULNCLAW_COMPETITION__ALLOW_FLAG_SUBMISSION=true\n"
        "Everything else still works: list, read, start/poll/stop the environment."
    )


async def _handle_list(args: dict[str, Any]) -> str:
    configured = registry.configured_adapters()
    if not configured:
        return _no_platforms()

    token = str(args.get("ref") or "").strip()
    if not token:
        corpora: list[base.Corpus] = []
        for adapter in configured.values():
            try:
                corpora += await adapter.list_corpora()
            except Exception as exc:  # noqa: BLE001
                corpora.append(
                    base.Corpus(
                        ref=CorpusRef(adapter.name, "error", ""),
                        name=f"{adapter.name}: list failed: {type(exc).__name__}: {exc}",
                    )
                )
        return render_corpora(corpora)

    adapter = registry.adapter_for(token) if _valid_platform(token) else None
    if adapter is None:
        return _platform_error(token)
    corpus = _corpus_from(adapter, token)
    if isinstance(corpus, str):
        return corpus
    try:
        return render_challenges(await adapter.list_challenges(corpus))
    except Exception as exc:  # noqa: BLE001
        return f"[platform] listing {corpus.token()} failed: {type(exc).__name__}: {exc}"


def _valid_platform(token: str) -> bool:
    try:
        registry.adapter_for(token)
        return True
    except Exception:  # noqa: BLE001 - the message is produced by _platform_error
        return False


def _platform_error(token: str) -> str:
    try:
        registry.adapter_for(token)
    except Exception as exc:  # noqa: BLE001
        return f"[platform] {exc}"
    return "[platform] unexpected state"


async def _handle_read(args: dict[str, Any]) -> str:
    resolved = _resolve(args)
    if isinstance(resolved, str):
        return resolved
    adapter, ref = resolved
    try:
        return render_challenge(await adapter.read_challenge(ref))
    except Exception as exc:  # noqa: BLE001
        return f"[platform] reading {ref.token()} failed: {type(exc).__name__}: {exc}"


async def _handle_start_env(args: dict[str, Any]) -> str:
    resolved = _resolve(args)
    if isinstance(resolved, str):
        return resolved
    adapter, ref = resolved
    try:
        info = await adapter.start_env(ref)
    except Exception as exc:  # noqa: BLE001
        return (
            f"[platform] starting an environment for {ref.token()} failed: "
            f"{type(exc).__name__}: {exc}"
        )
    return render_env_info(info)


async def _handle_read_env(args: dict[str, Any]) -> str:
    resolved = _resolve(args)
    if isinstance(resolved, str):
        return resolved
    adapter, ref = resolved
    try:
        info = await adapter.read_env(ref)
    except Exception as exc:  # noqa: BLE001
        return (
            f"[platform] reading the environment for {ref.token()} failed: "
            f"{type(exc).__name__}: {exc}"
        )
    if info is None:
        return (
            f"[platform] {ref.token()} has no environment concept on this platform; "
            "attack the static target from the challenge description."
        )
    return render_env_info(info)


async def _handle_stop_env(args: dict[str, Any]) -> str:
    resolved = _resolve(args)
    if isinstance(resolved, str):
        return resolved
    adapter, ref = resolved
    try:
        await adapter.stop_env(ref)
    except Exception as exc:  # noqa: BLE001
        return f"[platform] releasing {ref.token()} failed: {type(exc).__name__}: {exc}"
    return f"[platform] environment released for {ref.token()}."


def adapter_for_platform(name: str) -> Any:
    """Fetch a registered adapter by name, **without** the exposure check.

    The legacy per-platform tools have their own switch (``gcs.tools_enabled``), so
    they must keep working even when the platform is not exposed to the model.
    Routing them through :func:`registry.adapter_for` would make an old tool fail
    for a reason that has nothing to do with its own switch.
    """
    from vulnclaw.platforms.bootstrap import ensure_adapters

    ensure_adapters()
    adapter = registry.all_adapters().get(name)
    if adapter is None:
        raise registry.UnknownPlatform(f"no adapter is registered for {name!r}")
    return adapter


async def submit_flag_via(adapter: Any, ref: ChallengeRef, flag: Any) -> str:
    """The single flag-submission policy, shared by EVERY submit entry point.

    Order: irreversible-action gate -> ref-keyed attempt guard -> adapter ->
    accounting. Extracted so the legacy per-platform tools cannot drift from it
    again. Measured, before this existed:

    * the ``allow_flag_submission`` gate lived **only** on the CTF2 handler, so
      ``gcs_submit_flag`` could submit with the gate off -- the one irreversible
      action against the scoring platform, ungated;
    * the guard was keyed ``f"{practice_id}/{challenge_id}"``, so a CTF2 key and a
      GCS key could collide and silently block a legitimate submit;
    * the denial text hardcoded ``[ctf2_confirm]`` even when GCS triggered it.

    All three are properties of the *policy*, not of a platform, which is why the
    policy lives here and every entry point calls it.
    """
    if not _flag_submission_enabled():
        return _submission_disabled_message()

    text = str(flag or "").strip()
    if not text:
        return "[platform] `flag` is required and must be the full flag value."

    guard = get_guard()
    allowed, reason = guard.allow(ref.key, text)
    if not allowed:
        return guard_reason_to_message(ref.key, reason)

    try:
        result = await adapter.submit_flag(ref, text)
    except Exception as exc:  # noqa: BLE001
        # The platform never judged the flag, so consume no attempt and do not
        # dedup-block a retry of the same flag.
        guard.record_error(ref.key)
        return f"[platform] submitting to {ref.token()} failed: {type(exc).__name__}: {exc}"

    guard.record(ref.key, accepted=result.accepted, flag=text)
    verdict = "ACCEPTED" if result.accepted else "not accepted"
    message = f" ({result.message})" if result.message else ""
    return f"[platform] flag {verdict} for {ref.token()}{message}\n" + _format(result.raw)


async def _handle_submit(args: dict[str, Any]) -> str:
    resolved = _resolve(args)
    if isinstance(resolved, str):
        return resolved
    adapter, ref = resolved
    return await submit_flag_via(adapter, ref, args.get("flag"))


async def _handle_submissions(args: dict[str, Any]) -> str:
    configured = registry.configured_adapters()
    for adapter in configured.values():
        if base.CAP_SUBMISSIONS in getattr(adapter, "capabilities", frozenset()):
            try:
                limit = int(args.get("limit", 20) or 20)
            except (TypeError, ValueError):
                limit = 20
            try:
                return _format(await adapter.submissions(limit=limit))
            except Exception as exc:  # noqa: BLE001
                return f"[platform] listing submissions failed: {type(exc).__name__}: {exc}"
    return "[platform] no configured platform exposes a submission history."


async def _handle_event_info(args: dict[str, Any]) -> str:
    for adapter in registry.configured_adapters().values():
        if base.CAP_EVENT_INFO in getattr(adapter, "capabilities", frozenset()):
            try:
                return str(await adapter.event_info())
            except Exception as exc:  # noqa: BLE001
                return f"[platform] fetching competition notes failed: {type(exc).__name__}: {exc}"
    return "[platform] no configured platform exposes competition notes."


async def _handle_notices(args: dict[str, Any]) -> str:
    for adapter in registry.configured_adapters().values():
        if base.CAP_NOTICES in getattr(adapter, "capabilities", frozenset()):
            notice_id = args.get("notice_id")
            try:
                payload = await adapter.notices(
                    str(notice_id) if notice_id not in (None, "") else None
                )
            except Exception as exc:  # noqa: BLE001
                return f"[platform] reading notices failed: {type(exc).__name__}: {exc}"
            return _format(payload)
    return "[platform] no configured platform exposes announcements."


async def _handle_overview(args: dict[str, Any]) -> str:
    for adapter in registry.configured_adapters().values():
        if base.CAP_OVERVIEW in getattr(adapter, "capabilities", frozenset()):
            try:
                return _format(await adapter.overview())
            except Exception as exc:  # noqa: BLE001
                return f"[platform] querying the scoreboard failed: {type(exc).__name__}: {exc}"
    return "[platform] no configured platform exposes a scoreboard."


_HANDLERS: dict[str, Callable[[dict[str, Any]], Awaitable[str]]] = {
    "platform_list": _handle_list,
    "platform_read": _handle_read,
    "platform_start_env": _handle_start_env,
    "platform_read_env": _handle_read_env,
    "platform_stop_env": _handle_stop_env,
    "platform_submit": _handle_submit,
    "platform_submissions": _handle_submissions,
    "platform_event_info": _handle_event_info,
    "platform_notices": _handle_notices,
    "platform_overview": _handle_overview,
}

PLATFORM_TOOL_NAMES: frozenset[str] = frozenset(_HANDLERS)


async def dispatch_platform_tool(tool_name: str, args: dict[str, Any]) -> str:
    """Route a platform tool call to its handler."""
    from vulnclaw.platforms.bootstrap import ensure_adapters

    ensure_adapters()
    handler = _HANDLERS.get(tool_name)
    if handler is None:
        return f"[platform] unknown platform tool: {tool_name}"
    return await handler(args)
