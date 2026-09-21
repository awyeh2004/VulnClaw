"""HTTP client for the West Lake Sword Competition (西湖论剑) agent API.

The competition exposes a dedicated agent-facing API under
``/slab-match/api/v1`` on the gcis.(DASCTF) platform host, authenticated with
a per-team ``X-Agent-AccessKey`` header (no browser JWT, no PAT).  Every reply
uses the unified envelope ``{"code": "00000", "message": "", "data": ...}``
where ``code == "00000"`` signals success.

Endpoints give the agent the full lifecycle for a challenge:

- list / read exercises and download attachments,
- start a challenge environment (async) and poll until it is ready,
- read live target endpoints (ip / ports / users / proxy mappings),
- submit answer flags,
- recover (destroy) the environment when done.

Configuration (environment variables):

- ``VULNCLAW_GCS_ACCESS_KEY`` (required) — team agent AccessKey.
- ``VULNCLAW_GCS_BASE_URL`` (optional) — API host override, defaults to the
  public competition host.
"""

from __future__ import annotations

import asyncio
import os

import httpx
from urllib.parse import urlparse

DEFAULT_BASE_URL = "https://gcsis.dasctf.com"
AGENT_PREFIX = "/slab-match/api/v1/agent"

_SUCCESS_CODE = "00000"

# Shared module-level client so connection pools are reused across calls.
#
# ⚠️ Same event-loop caveat as the CTF2 client: an AsyncClient is bound to the
# loop it was built on, so reusing it from another loop raises
# "Event loop is closed" and then times out on every later call. The CLI calls
# asyncio.run() repeatedly (e.g. once per challenge while batch-downloading), which
# is exactly how a cached client outlives its loop.
_client: httpx.AsyncClient | None = None
_client_loop: object | None = None

# Client default: the fallback for requests that carry no timeout of their own.
# A longer value requested AFTER the cached client exists is not applied (httpx
# fixes the default at construction), so the slow endpoints pass ``timeout=``
# per request instead -- that is what actually bounds them.
DEFAULT_TIMEOUT = 30.0

# Starting an environment waits on the platform's provisioning queue.
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


def _gcs_config():
    """Best-effort read of the ``gcs`` section from the loaded config."""
    try:
        from vulnclaw.config.settings import load_config

        return getattr(load_config(), "gcs", None)
    except Exception:
        return None


def access_key() -> str:
    """Return the GCS agent AccessKey.

    A value explicitly persisted in the config ``gcs.access_key`` takes
    precedence so a stale ``VULNCLAW_GCS_ACCESS_KEY`` lingering in the current
    process tree (e.g. set during an earlier test round) cannot silently use
    the wrong credentials. The env var remains a fallback / override when the
    config field is empty.
    """
    gcs = _gcs_config()
    configured = str(getattr(gcs, "access_key", "") or "").strip()
    if configured:
        return configured
    return os.environ.get("VULNCLAW_GCS_ACCESS_KEY", "").strip()


def api_base_url() -> str:
    """Return the GCS API host.

    Precedence: config ``gcs.base_url`` (if set), then env override, then the
    default host. The config field is the persisted source; the env var is a
    fallback / override for hosts without a config file.
    """
    gcs = _gcs_config()
    configured = str(getattr(gcs, "base_url", "") or "").strip()
    if configured:
        return configured
    env = os.environ.get("VULNCLAW_GCS_BASE_URL", "").strip()
    return env or DEFAULT_BASE_URL


def is_configured() -> bool:
    """Whether an agent AccessKey is available for authenticated calls."""
    return bool(access_key())


def _headers() -> dict[str, str]:
    host = urlparse(api_base_url()).hostname or ""
    headers = {
        "Accept": "application/json",
        "X-Agent-AccessKey": access_key(),
    }
    # pro.dasctf.com sits behind a WAF that returns 403 for requests without
    # browser-like headers (UA/Origin/Referer). Present them so agent calls
    # are not blocked. Safe defaults; harmless on hosts that ignore them.
    if host == "pro.dasctf.com":
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        headers["Origin"] = f"https://{host}"
        headers["Referer"] = f"https://{host}/"
    return headers


class GCSError(RuntimeError):
    """Raised when the platform replies with a non-success code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"GCS API {code}: {message}")
        self.code = code
        self.message = message


def _unwrap(payload: dict) -> dict:
    """Validate the unified envelope and return the data part."""
    code = str(payload.get("code", ""))
    if code != _SUCCESS_CODE:
        raise GCSError(code, str(payload.get("message", "")))
    return payload.get("data") or {}


async def _request(
    client: httpx.AsyncClient, method: str, path: str, **kwargs
) -> dict:
    if not access_key():
        raise RuntimeError(
            "GCS agent access key not configured (VULNCLAW_GCS_ACCESS_KEY)"
        )
    url = f"{api_base_url()}{AGENT_PREFIX}{path}"
    response = await client.request(method, url, headers=_headers(), **kwargs)
    if response.status_code >= 500:
        raise GCSError(str(response.status_code), response.text[:300])
    if response.status_code >= 400:
        # The API may still return the unified envelope on 4xx; try to parse it.
        try:
            return _unwrap(response.json())
        except (ValueError, GCSError):
            raise GCSError(str(response.status_code), response.text[:300])
    try:
        payload = response.json()
    except ValueError:
        raise GCSError(str(response.status_code), response.text[:300])
    return _unwrap(payload)


# --- match / notices ------------------------------------------------------

async def match_info() -> dict:
    """Return competition notes and rules (``data: {note, rule}``)."""
    client = get_client()
    return await _request(client, "GET", "/match/notice/match-info")


async def notice_list() -> dict:
    """Return the list of recent competition announcements."""
    client = get_client()
    return await _request(client, "GET", "/match/notice/now-list")


async def notice_detail(notice_id: int) -> dict:
    """Return a single announcement, including any attached file."""
    client = get_client()
    return await _request(
        client, "GET", "/match/notice/detail", params={"id": notice_id}
    )


# --- scoreboard -----------------------------------------------------------

async def overview() -> dict:
    """Return the team's current score and rank (``data: {stagePoint, stageRank}``)."""
    client = get_client()
    return await _request(client, "GET", "/answer-panel/overview")


# --- exercises ------------------------------------------------------------

async def exercise_list() -> dict:
    """Return the challenge tree (``data: [{id, name, corpus: [...]}]``)."""
    client = get_client()
    return await _request(client, "GET", "/ctf/exercise-list")


async def exercise(exercise_id: int) -> dict:
    """Return challenge detail: description, attachments, endpoints, env flags."""
    client = get_client()
    return await _request(
        client, "GET", "/ctf/exercise", params={"exerciseId": exercise_id}
    )


# --- environment lifecycle --------------------------------------------------

async def build_environment(exercise_id: int) -> dict:
    """Start a challenge environment (async; poll ``exercise()`` until ready)."""
    client = get_client()
    return await _request(
        client,
        "POST",
        "/ctf/build-exercise-env",
        json={"exerciseId": exercise_id},
        timeout=SLOW_TIMEOUT,
    )


async def recover_environment(exercise_id: int) -> dict:
    """Recover (destroy) a challenge environment, releasing quota."""
    client = get_client()
    return await _request(
        client,
        "POST",
        "/ctf/recover-exercise-env",
        json={"exerciseId": exercise_id},
        timeout=MEDIUM_TIMEOUT,
    )


# --- submission ------------------------------------------------------------

async def submit_answer(exercise_id: int, flag: str) -> dict:
    """Submit an answer flag. ``data: {isCorrect: bool}`` when accepted for grading."""
    client = get_client()
    return await _request(
        client,
        "POST",
        "/answer-panel/answer",
        json={"exerciseId": exercise_id, "flag": flag},
    )