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

import os

import httpx
from urllib.parse import urlparse

DEFAULT_BASE_URL = "https://gcsis.dasctf.com"
AGENT_PREFIX = "/slab-match/api/v1/agent"

_SUCCESS_CODE = "00000"


def _gcs_config():
    """Best-effort read of the ``gcs`` section from the loaded config."""
    try:
        from vulnclaw.config.settings import load_config

        return getattr(load_config(), "gcs", None)
    except Exception:
        return None


def access_key() -> str:
    """Return the configured GCS agent AccessKey, or an empty string."""
    env = os.environ.get("VULNCLAW_GCS_ACCESS_KEY", "").strip()
    if env:
        return env
    gcs = _gcs_config()
    return str(getattr(gcs, "access_key", "") or "").strip()


def api_base_url() -> str:
    """Return the GCS API host, honouring env override then config fallback."""
    env = os.environ.get("VULNCLAW_GCS_BASE_URL", "").strip()
    if env:
        return env
    gcs = _gcs_config()
    configured = str(getattr(gcs, "base_url", "") or "").strip()
    return configured or DEFAULT_BASE_URL


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
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await _request(client, "GET", "/match/notice/match-info")


async def notice_list() -> dict:
    """Return the list of recent competition announcements."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await _request(client, "GET", "/match/notice/now-list")


async def notice_detail(notice_id: int) -> dict:
    """Return a single announcement, including any attached file."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await _request(
            client, "GET", "/match/notice/detail", params={"id": notice_id}
        )


# --- scoreboard -----------------------------------------------------------

async def overview() -> dict:
    """Return the team's current score and rank (``data: {stagePoint, stageRank}``)."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await _request(client, "GET", "/answer-panel/overview")


# --- exercises ------------------------------------------------------------

async def exercise_list() -> dict:
    """Return the challenge tree (``data: [{id, name, corpus: [...]}]``)."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await _request(client, "GET", "/ctf/exercise-list")


async def exercise(exercise_id: int) -> dict:
    """Return challenge detail: description, attachments, endpoints, env flags."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await _request(
            client, "GET", "/ctf/exercise", params={"exerciseId": exercise_id}
        )


# --- environment lifecycle --------------------------------------------------

async def build_environment(exercise_id: int) -> dict:
    """Start a challenge environment (async; poll ``exercise()`` until ready)."""
    async with httpx.AsyncClient(timeout=120.0) as client:
        return await _request(
            client,
            "POST",
            "/ctf/build-exercise-env",
            json={"exerciseId": exercise_id},
        )


async def recover_environment(exercise_id: int) -> dict:
    """Recover (destroy) a challenge environment, releasing quota."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        return await _request(
            client,
            "POST",
            "/ctf/recover-exercise-env",
            json={"exerciseId": exercise_id},
        )


# --- submission ------------------------------------------------------------

async def submit_answer(exercise_id: int, flag: str) -> dict:
    """Submit an answer flag. ``data: {isCorrect: bool}`` when accepted for grading."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await _request(
            client,
            "POST",
            "/answer-panel/answer",
            json={"exerciseId": exercise_id, "flag": flag},
        )