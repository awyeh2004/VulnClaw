"""Minimal HTTP client for the CTF2 (DASCTF) platform.

Two API surfaces share the same host:

- ``/api/open/v1/user`` 鈥?the public Open API. Authenticated with a personal
  access token via the ``X-CTF2-API-Key`` header. Covers practice listing /
  challenge reads / environment start / flag submission.
- ``/api/v1`` 鈥?the front-end session API. Authenticated with the Bearer JWT
  that the SPA keeps in localStorage. Needed for the pieces the Open API
  deliberately omits: live target connection info (host/port after start) and
  challenge attachment downloads.

Token sources, in order of precedence:
1. ``VULNCLAW_CTF2_API_KEY`` 鈥?Open API personal access token.
2. ``VULNCLAW_CTF2_SESSION_TOKEN`` 鈥?front-end Bearer JWT for the session API.
   When unset, ``session_token()`` may auto-read it from the local Edge/Chrome
   profile localStorage so a logged-in browser session can be reused.
3. ``VULNCLAW_CTF2_BASE_URL`` override for the API root (defaults to the public
   CTF2 endpoint).
"""

from __future__ import annotations

import asyncio
import json
import os

import httpx

DEFAULT_BASE_URL = "https://ctf2.dasctf.com"
API_PREFIX = "/api/open/v1/user"
SESSION_PREFIX = "/api/v1"

# Shared module-level client so connection pools are reused across calls
# instead of opening a fresh connection per endpoint (standard httpx practice).
#
# ⚠️ It is also bound to the event loop it was created on, so the loop is
# remembered beside it: reusing the client from a *different* loop raises
# "Event loop is closed" (and then 30s PoolTimeout on every later call, because
# the pool's loop is dead). That is not hypothetical -- it took the whole CTF2
# platform path offline inside the agent loop, where tool calls run on a
# different loop than an earlier asyncio.run() in the same process. Recreating
# the client when the running loop changes is what keeps the pool honest.
_client: httpx.AsyncClient | None = None
_client_loop: object | None = None

# Client default. NOTE: this is only the fallback for requests that carry no
# timeout of their own, and a longer value asked for AFTER the cached client was
# created is NOT applied (httpx fixes the default at construction). The slow
# endpoints therefore pass ``timeout=`` per request -- see SLOW_TIMEOUT below --
# which is what actually bounds them.
DEFAULT_TIMEOUT = 30.0

# Budget for the async environment/target calls: they wait on the platform's
# provisioning queue, so a 30s request timeout was cutting them off.
SLOW_TIMEOUT = 120.0
MEDIUM_TIMEOUT = 60.0


def _running_loop() -> object | None:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _discard_client(client: httpx.AsyncClient | None, loop: object | None) -> None:
    """Drop a client whose loop is gone, closing it when that is still possible.

    An AsyncClient is bound to the loop that built it and the CLI calls
    ``asyncio.run`` repeatedly, so a cached client routinely outlives its loop.
    If the old loop is still alive the close can be scheduled on it; if it is
    already closed the transports died with it and only the reference is dropped
    (prefer :func:`aclose_client` at the end of a long-lived loop).
    """
    if client is None or client.is_closed:
        return
    try:
        if loop is not None and not loop.is_closed():
            asyncio.run_coroutine_threadsafe(client.aclose(), loop)
    except Exception:
        pass


async def aclose_client() -> None:
    """Close the shared client. Call at the end of a loop that used it."""
    global _client, _client_loop
    client, loop = _client, _client_loop
    _client = None
    _client_loop = None
    _discard_client(client, loop)
    if client is not None and not client.is_closed and loop is _running_loop():
        try:
            await client.aclose()
        except Exception:
            pass


def get_client(timeout: float = DEFAULT_TIMEOUT) -> httpx.AsyncClient:
    """Return the shared AsyncClient for the CURRENT event loop, creating it lazily.

    httpx.AsyncClient is thread-safe and reuses TCP/TLS connections, so one
    instance per event loop avoids the per-call handshake overhead of the old
    ``async with httpx.AsyncClient(...)`` pattern -- while never handing a caller
    a client whose loop is gone.

    ``timeout`` only takes effect when the client is created. Pass a per-request
    ``timeout=`` (as the slow endpoints do) when a single call needs a longer
    budget, otherwise the cached client's default silently wins.
    """
    global _client, _client_loop
    loop = _running_loop()
    if _client is not None and (
        _client.is_closed
        or (_client_loop is not None and loop is not None and _client_loop is not loop)
    ):
        _discard_client(_client, _client_loop)
        _client = None
        _client_loop = None
    if _client is None:
        _client = httpx.AsyncClient(timeout=timeout)
        _client_loop = loop
    return _client


def api_token() -> str:
    """Return the configured CTF2 personal access token, or an empty string."""
    return os.environ.get("VULNCLAW_CTF2_API_KEY", "").strip()


def session_token() -> str:
    """Return the CTF2 front-end session JWT (Bearer auth).

    Prefers ``VULNCLAW_CTF2_SESSION_TOKEN``; falls back to scraping the local
    Edge/Chrome profile localStorage for a live ``awyeh``-style token when the
    variable is absent. Returns an empty string when neither is available.
    """
    direct = os.environ.get("VULNCLAW_CTF2_SESSION_TOKEN", "").strip()
    if direct:
        return direct
    try:
        from vulnclaw.ctf_platform.session import read_edge_session_token

        found = read_edge_session_token()
        if found:
            return found
    except Exception:
        pass
    return ""


def api_base_url() -> str:
    """Return the CTF2 API root, honouring an optional environment override."""
    return os.environ.get("VULNCLAW_CTF2_BASE_URL", "").strip() or DEFAULT_BASE_URL


def is_configured() -> bool:
    """Whether a CTF2 token is available for authenticated calls."""
    return bool(api_token() or session_token())


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "X-CTF2-API-Key": api_token(),
    }
    return headers


def _session_headers() -> dict[str, str]:
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {session_token()}",
    }


def _raise_for_status(response: httpx.Response) -> None:
    if response.status_code < 400:
        return
    detail = ""
    try:
        payload = response.json()
        detail = str(payload.get("error", ""))
    except Exception:
        payload_text = response.text[:300]
        detail = payload_text
    raise RuntimeError(
        f"CTF2 API {response.status_code}: {detail or response.reason_phrase}"
    )


async def _request(client: httpx.AsyncClient, method: str, path: str, **kwargs) -> dict:
    url = f"{api_base_url()}{API_PREFIX}{path}"
    response = await client.request(method, url, headers=_headers(), **kwargs)
    _raise_for_status(response)
    return response.json()


async def list_practice(limit: int = 20) -> dict:
    """List visible public practice grounds."""
    client = get_client()
    return await _request_with_fallback(client, "GET", "/practice/", params={"limit": limit})


async def list_daily(limit: int = 20) -> dict:
    """List visible daily challenges."""
    client = get_client()
    return await _request_with_fallback(client, "GET", "/daily/", params={"limit": limit})


async def read_challenge(practice_id: str, challenge_id: str) -> dict:
    """Read a practice challenge description."""
    client = get_client()
    return await _request_with_fallback(
        client,
        "GET",
        f"/practice/{practice_id}/challenges/{challenge_id}/",
    )


async def list_practice_challenges(
    practice_id: str, page: int = 1, page_size: int = 100
) -> dict:
    """List a practice ground's challenges.

    Session API only, and that asymmetry is measured, not assumed: the Open API
    route is a hard 404
    (``/api/open/v1/user/practice/<pid>/challenges/`` -> ``{"code": "NOT_FOUND",
    "key": "errors.common.not_found", "params": {"resource": "route"}}``), while
    ``/api/v1/practice/<pid>/challenges/`` returns 200 with

        {"data": {"data": [<challenge rows>], "pagination": {...},
                  "categories": [...], "knowledge_facets": ...}, "success": true}

    Note the nesting: the rows live in ``data.data``, not ``data.items`` like the
    Open API lists. Without this, a practice ground's challenges cannot be
    enumerated at all -- there is no Open API equivalent to fall back on.
    """
    client = get_client()
    return await _session_request(
        client,
        "GET",
        f"/practice/{practice_id}/challenges/",
        params={"page": page, "page_size": page_size},
        timeout=MEDIUM_TIMEOUT,
    )


async def start_environment(practice_id: str, challenge_id: str) -> dict:
    """Start (or reuse) a practice environment, returning its connection info.

    Two APIs, two DIFFERENT routes for the same action (measured):
      * Open API: `POST /practice/<p>/challenges/<c>/environment/start/`
      * session : `POST /practice/<p>/challenges/<c>/target/` -> 202 with a
        `task_id`, then poll `GET .../target/` until `data` is non-null.
    The session API has NO `/environment/start/` route (404), so the generic
    path mapping cannot be reused here -- the fallback needs its own route.
    """
    client = get_client()
    if api_token():
        try:
            return await _request(
                client,
                "POST",
                f"/practice/{practice_id}/challenges/{challenge_id}/environment/start/",
                json={},
                timeout=SLOW_TIMEOUT,
            )
        except RuntimeError as exc:
            text = str(exc)
            if not (" 401:" in text or " 403:" in text or " 404:" in text) or not session_token():
                raise
    if not session_token():
        raise RuntimeError(
            "CTF2 cannot start an environment: set VULNCLAW_CTF2_API_KEY, or log in "
            "to CTF2 in Edge/Chrome so the session token can be read from localStorage."
        )
    return await _session_request(
        client,
        "POST",
        f"/practice/{practice_id}/challenges/{challenge_id}/target/",
        json={},
        timeout=SLOW_TIMEOUT,
    )


async def _session_request(
    client: httpx.AsyncClient, method: str, path: str, **kwargs
) -> dict:
    """Hit the front-end session API (``/api/v1``) with the Bearer JWT."""
    token = session_token()
    if not token:
        raise RuntimeError("CTF2 session token not configured (VULNCLAW_CTF2_SESSION_TOKEN)")
    url = f"{api_base_url()}{SESSION_PREFIX}{path}"
    response = await client.request(
        method, url, headers=_session_headers(), **kwargs
    )
    _raise_for_status(response)
    return response.json()


# 鈹€鈹€ Open API with a session-API fallback 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
#
# WHY: the two APIs disagree about who may read the same data. The Open API
# (``/api/open/v1/user`` + ``X-CTF2-API-Key``) covers practice listing, challenge
# reads, environment start and flag submission; the front-end session API
# (``/api/v1`` + the SPA's Bearer JWT) exposes the SAME resources and also the
# pieces the Open API deliberately omits (live target address, attachments).
#
# Measured on a real account with only a browser session (no personal access
# token): every Open API call returned
#    401 {"code": "AUTH_REQUIRED", "key": "errors.auth.permission_denied"}
# while the equivalent session paths returned 200. So a perfectly usable
# logged-in account looked completely broken.
#
# The fallback is therefore: prefer the Open API (it is the documented, stable
# surface), and fall back to the session API when no API key is configured OR
# the Open API refuses with 401/403. Any other error propagates unchanged --
# silently retrying a 500 or a 404 would hide real breakage.

# Open API path -> the equivalent session API path (same resource).
_SESSION_ROUTES: dict[str, str] = {
    "/practice/": "/practice/",
    "/competitions/": "/competitions/",
}

# Open API prefixes that map onto a session path by suffix.
_SESSION_PREFIX_ROUTES: tuple[tuple[str, str], ...] = (
    ("/practice/", "/practice/"),
)


def _session_path_for(path: str) -> str | None:
    """Best-effort mapping of an Open API path to its session API twin."""
    direct = _SESSION_ROUTES.get(path)
    if direct is not None:
        return direct
    # e.g. /practice/<pid>/challenges/<cid>/environment/start/
    #   -> /api/v1/practice/<pid>/challenges/<cid>/environment/start/
    # The session API mirrors the resource path for practice sub-resources, so
    # the same string works once the prefix differs.
    if path.startswith("/practice/"):
        return path
    if path.startswith("/daily/"):
        return None  # no session twin observed; do not invent one
    return None


async def _request_with_fallback(
    client: httpx.AsyncClient, method: str, path: str, **kwargs
) -> dict:
    """Try the Open API, then the session API when auth is the only obstacle."""
    token = api_token()
    if not token:
        session_path = _session_path_for(path)
        if session_path is not None and session_token():
            return await _session_request(client, method, session_path, **kwargs)
        # No usable credential for the documented route: report the actionable
        # cause instead of a bare 401.
        if not session_token():
            raise RuntimeError(
                "CTF2 credentials missing: set VULNCLAW_CTF2_API_KEY (Open API personal "
                "access token) or log in to CTF2 in Edge/Chrome so the session token "
                "can be read from localStorage."
            )
        raise RuntimeError(
            f"CTF2 Open API needs a personal access token for {path}; the session "
            "token cannot cover this route."
        )

    try:
        # NOTE: must be the raw _request, not this function -- an earlier bulk
        # edit rewrote this line too and made it recurse forever.
        return await _request(client, method, path, **kwargs)
    except RuntimeError as exc:
        # _raise_for_status renders as "CTF2 API 401: ..." / "CTF2 API 403: ..."
        text = str(exc)
        auth_denied = " 401:" in text or " 403:" in text
        session_path = _session_path_for(path)
        if not (auth_denied and session_path is not None and session_token()):
            raise
        return await _session_request(client, method, session_path, **kwargs)



async def get_target(practice_id: str, challenge_id: str) -> dict:
    """Return live target connection info (host/port/url) for a started challenge.

    Requires the front-end session token (Bearer JWT) — the Open API cannot see
    target addresses. May return ``{"data": null}`` until a target is running.
    """
    client = get_client()
    return await _session_request(
        client,
        "GET",
        f"/practice/{practice_id}/challenges/{challenge_id}/target/",
        timeout=MEDIUM_TIMEOUT,
    )


async def create_target(practice_id: str, challenge_id: str) -> dict:
    """Queue creation of a practice target (moves the challenge to running)."""
    client = get_client()
    return await _session_request(
        client,
        "POST",
        f"/practice/{practice_id}/challenges/{challenge_id}/target/",
        json={},
        timeout=SLOW_TIMEOUT,
    )


async def stop_target(practice_id: str, challenge_id: str) -> dict:
    """Release a practice target (DELETE the session target resource).

    Call after the flag is captured/submitted so the container slot is freed
    instead of lingering until the platform TTL reclaims it.
    """
    client = get_client()
    return await _session_request(
        client,
        "DELETE",
        f"/practice/{practice_id}/challenges/{challenge_id}/target/",
        timeout=MEDIUM_TIMEOUT,
    )


async def submit_flag(practice_id: str, challenge_id: str, flag: str) -> dict:
    """Submit a confirmed practice flag (requires ``confirmation: true``)."""
    client = get_client()
    return await _request_with_fallback(
        client,
        "POST",
        f"/practice/{practice_id}/challenges/{challenge_id}/submit/",
        json={"flag": flag, "confirmation": True},
    )


async def list_competitions(limit: int = 20) -> dict:
    """List visible competitions."""
    client = get_client()
    return await _request_with_fallback(client, "GET", "/competitions/", params={"limit": limit})


async def list_stage_challenges(stage_id: str, limit: int = 50) -> dict:
    """List visible challenges in a competition stage."""
    client = get_client()
    return await _request_with_fallback(
        client,
        "GET",
        f"/stages/{stage_id}/challenges/",
        params={"limit": limit},
    )


async def list_submissions(limit: int = 20) -> dict:
    """List current user submissions (recent flag attempts)."""
    client = get_client()
    return await _request_with_fallback(
        client,
        "GET",
        "/submissions/",
        params={"limit": limit},
    )