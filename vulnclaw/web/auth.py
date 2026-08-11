"""Token-based authentication for the VulnClaw Web UI.

The token is generated once and persisted to ``~/.vulnclaw/web_token``.
All ``/api/`` routes (except ``/api/health``) require a valid
``Authorization: Bearer <token>`` header, a session cookie carrying the same
token, or a loopback peer address.

The cookie exists because the shipped browser UI cannot send a bearer header:
``fetch`` here adds none and an SSE ``EventSource`` cannot attach one at all.
Opening the UI once at ``/?token=<token>`` exchanges the token for an
``HttpOnly``/``SameSite=Strict`` session cookie, which the browser then sends
on every subsequent request including the event stream.
"""

from __future__ import annotations

import hmac
import ipaddress
import secrets
from pathlib import Path

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    _HAS_STARLETTE = True
except ImportError:  # pragma: no cover
    _HAS_STARLETTE = False

TOKEN_DIR = Path.home() / ".vulnclaw"
TOKEN_FILE = TOKEN_DIR / "web_token"

#: Name of the session cookie that carries the bearer token for browser clients.
SESSION_COOKIE = "vulnclaw_session"


def _token_path() -> Path:
    """Return the token file path, ensuring the parent directory exists."""
    TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    return TOKEN_FILE


def generate_token() -> str:
    """Return a persisted bearer token.

    If a token file already exists its content is reused.  Otherwise a new
    32-byte URL-safe token is generated, written to disk and returned.
    """
    path = _token_path()
    if path.exists():
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing

    token = secrets.token_urlsafe(32)
    path.write_text(token, encoding="utf-8")
    # Restrict file permissions on POSIX (best-effort on Windows).
    try:
        import os

        os.chmod(path, 0o600)
    except OSError:
        pass
    return token


def verify_token(token: str) -> bool:
    """Return *True* if *token* matches the stored bearer token.

    Uses :func:`hmac.compare_digest` for timing-safe comparison.
    """
    path = _token_path()
    if not path.exists():
        return False
    stored = path.read_text(encoding="utf-8").strip()
    return hmac.compare_digest(stored, token)


def attach_session_cookie(response, token: str) -> None:  # type: ignore[no-untyped-def]
    """Store *token* on the browser as an HttpOnly session cookie.

    ``secure`` is deliberately left off: the UI is served over plain HTTP on
    localhost and inside Docker, where a Secure cookie would never be sent
    back. ``SameSite=Strict`` keeps the cookie off cross-site requests, which
    is what guards the state-changing ``/api/`` routes against CSRF.
    """
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        path="/",
    )


def request_has_valid_session(request) -> bool:  # type: ignore[no-untyped-def]
    """Whether *request* carries a session cookie holding a valid token."""
    cookie = request.cookies.get(SESSION_COOKIE, "")
    return bool(cookie) and verify_token(cookie)


def _client_is_loopback(client_host: str | None) -> bool:
    """Whether a request originates from a loopback (local) client.

    The ``web`` command binds to 127.0.0.1 by default and refuses non-loopback
    binds without ``--allow-remote``, so a loopback client is the trusted local
    operator. Bearer-token auth is therefore enforced only for **non-loopback**
    clients (the explicit ``--allow-remote`` case). This is what lets the
    same-origin browser UI work locally: native ``fetch`` here sends no bearer
    header and an SSE ``EventSource`` cannot attach one at all, so requiring a
    token on loopback would 401 the entire shipped frontend.

    Note: this trusts the peer address, so a reverse proxy on localhost would
    appear loopback. Defending a localhost bind against DNS-rebinding wants a
    ``Host`` header allowlist, which is a separate hardening step.
    """
    if not client_host:
        return False  # unknown origin — require auth
    try:
        return ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        return client_host == "localhost"


if _HAS_STARLETTE:

    class AuthMiddleware(BaseHTTPMiddleware):  # type: ignore[no-redef]
        """ASGI middleware that enforces bearer-token auth on ``/api/`` routes.

        ``/api/health`` is always exempt so that uptime probes work without
        credentials.
        """

        # Exact paths — not prefixes — so an added route like /api/healthcheck
        # or /api/health-secret is never accidentally left unauthenticated.
        _EXEMPT_PATHS: frozenset[str] = frozenset({"/api/health"})

        async def dispatch(self, request: Request, call_next):  # type: ignore[override]
            path = request.url.path
            client_host = request.client.host if request.client else None
            if (
                path.startswith("/api/")
                and path not in self._EXEMPT_PATHS
                and not _client_is_loopback(client_host)
                and not request_has_valid_session(request)
            ):
                auth_header = request.headers.get("Authorization", "")
                if not auth_header.startswith("Bearer "):
                    return JSONResponse(
                        {"detail": "Missing or malformed Authorization header"},
                        status_code=401,
                    )
                bearer = auth_header[len("Bearer ") :]
                if not verify_token(bearer):
                    return JSONResponse(
                        {"detail": "Invalid token"},
                        status_code=403,
                    )
            return await call_next(request)

else:  # pragma: no cover

    class AuthMiddleware:  # type: ignore[no-redef]
        """Stub raised when Starlette is not installed."""

        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError(
                "Starlette is not installed. Install the web extra: "
                "pip install vulnclaw[web]"
            )
