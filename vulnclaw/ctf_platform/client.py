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

import json
import os

import httpx

DEFAULT_BASE_URL = "https://ctf2.dasctf.com"
API_PREFIX = "/api/open/v1/user"
SESSION_PREFIX = "/api/v1"

# Shared module-level client so connection pools are reused across calls
# instead of opening a fresh connection per endpoint (standard httpx practice).
_client: httpx.AsyncClient | None = None


def get_client(timeout: float = 30.0) -> httpx.AsyncClient:
    """Return the module-level shared AsyncClient, creating it lazily.

    httpx.AsyncClient is thread-safe and reuses TCP/TLS connections, so a single
    instance for all endpoint calls avoids the per-call handshake overhead of the
    old ``async with httpx.AsyncClient(...)`` pattern.
    """
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(timeout=timeout)
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


async def start_environment(practice_id: str, challenge_id: str) -> dict:
    """Start (or reuse) a practice environment, returning its connection info."""
    client = get_client(timeout=120.0)
    return await _request_with_fallback(
        client,
        "POST",
        f"/practice/{practice_id}/challenges/{challenge_id}/environment/start/",
        json={},
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

    Requires the front-end session token (Bearer JWT) 鈥?the Open API cannot see
    target addresses. May return ``{"data": null}`` until a target is running.
    """
    client = get_client(timeout=60.0)
    return await _session_request(
        client,
        "GET",
        f"/practice/{practice_id}/challenges/{challenge_id}/target/",
    )


async def create_target(practice_id: str, challenge_id: str) -> dict:
    """Queue creation of a practice target (moves the challenge to running)."""
    client = get_client(timeout=60.0)
    return await _session_request(
        client,
        "POST",
        f"/practice/{practice_id}/challenges/{challenge_id}/target/",
        json={},
    )


async def stop_target(practice_id: str, challenge_id: str) -> dict:
    """Release a practice target (DELETE the session target resource).

    Call after the flag is captured/submitted so the container slot is freed
    instead of lingering until the platform TTL reclaims it.
    """
    client = get_client(timeout=60.0)
    return await _session_request(
        client,
        "DELETE",
        f"/practice/{practice_id}/challenges/{challenge_id}/target/",
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