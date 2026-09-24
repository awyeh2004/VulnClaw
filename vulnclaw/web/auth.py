"""Token-based authentication for the VulnClaw Web UI.

The token is generated once and persisted to ``~/.vulnclaw/web_token``.
All ``/api/`` routes (except ``/api/health``) require a valid
``Authorization: Bearer <token>`` header, a session cookie carrying the same
token, or a **local UI request**: a loopback peer address *and* a loopback Host
header.

Both halves are required (round8 finding C3). Trusting the peer address alone
made the whole API reachable by DNS rebinding: a page on an attacker-controlled
domain whose DNS is re-pointed at 127.0.0.1 reaches the server from a loopback
peer -- the server cannot tell that apart from the operator's own browser --
and used to be exempted from auth on every route. The browser sends the
attacker's own ``Host``, so requiring a loopback ``Host`` is what closes it:
a rebinding request authenticates like any other remote one, and the
``SameSite=Strict`` cookie is not sent cross-site.

The cookie exists because the shipped browser UI cannot send a bearer header:
``fetch`` here adds none and an SSE ``EventSource`` cannot attach one at all.
Opening the UI once at ``/?token=<token>`` exchanges the token for an
``HttpOnly``/``SameSite=Strict`` session cookie, which the browser then sends
on every subsequent request including the event stream.
"""

from __future__ import annotations

import hmac
import ipaddress
import os
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
    appear loopback. That alone is NOT enough to authorize a request — see
    ``_request_is_from_the_local_ui``: the Host header must be loopback (or an
    operator-trusted host) as well, which is what stops DNS rebinding.
    """
    if not client_host:
        return False  # unknown origin — require auth
    try:
        return ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        return client_host == "localhost"


#: Host header values that mean "this is the operator's own local UI".
_LOOPBACK_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "::1"})

#: Escape hatch for a local reverse proxy in front of the UI (a case the loopback peer
#: test used to cover implicitly): comma-separated extra Host values treated as local,
#: e.g. ``VULNCLAW_WEB_TRUSTED_HOSTS=ui.internal,10.0.0.5:3080``. The peer must STILL be
#: loopback, so this cannot be used to exempt remote clients -- those authenticate.
TRUSTED_HOSTS_ENV = "VULNCLAW_WEB_TRUSTED_HOSTS"


def _normalise_host(host: str | None) -> str:
    """Lower-case a Host header value and drop its port (and IPv6 brackets)."""
    text = str(host or "").strip().lower()
    if not text:
        return ""
    if text.startswith("["):
        return text[1:].split("]", 1)[0].rstrip(".")
    head = text.split(":", 1)[0].rstrip(".")
    if head:
        return head
    # A non-bracketed IPv6 literal (`::1`). RFC 7230 wants the brackets, but the bare form
    # is unambiguous enough to understand -- and treating it as a foreign host would 401
    # the local UI for a reason nobody could see.
    return text.rstrip(".")


def _trusted_hosts() -> frozenset[str]:
    """Operator-declared extra local Host values (see ``TRUSTED_HOSTS_ENV``)."""
    raw = os.environ.get(TRUSTED_HOSTS_ENV, "")
    return frozenset(
        part for part in (_normalise_host(chunk) for chunk in raw.split(",")) if part
    )


def _host_is_loopback(host_header: str | None) -> bool:
    """Whether a ``Host`` header names a loopback authority.

    A missing or unparseable Host is NOT loopback: HTTP/1.1 requires the header, so its
    absence means a hand-written request rather than the operator's browser, and the
    fail-closed direction costs nothing (the shipped UI always sends one).
    """
    host = _normalise_host(host_header)
    if not host:
        return False
    if host in _LOOPBACK_HOSTNAMES:
        return True
    try:
        # 127.0.0.0/8 is all loopback, not just 127.0.0.1; anything else must not pass.
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _request_is_from_the_local_ui(request) -> bool:  # type: ignore[no-untyped-def]
    """Whether *request* is the operator's own browser talking to the local UI.

    Requires BOTH a loopback peer and a loopback (or explicitly trusted) Host. The peer
    address alone is not identity: a rebinding request is byte-identical to a local one
    on that field, and the Host header is the field the attacker cannot make loopback
    while still being pointed at their own domain.
    """
    client_host = request.client.host if request.client else None
    if not _client_is_loopback(client_host):
        return False
    headers = getattr(request, "headers", None)
    host_header = headers.get("Host", "") if headers else ""
    if _host_is_loopback(host_header):
        return True
    return _normalise_host(host_header) in _trusted_hosts()


def _missing_auth_detail(request) -> str:  # type: ignore[no-untyped-def]
    """Explain a 401 well enough that a legitimate setup is not mistaken for a bug.

    A loopback peer with a non-loopback Host is the one case that a working deployment
    can hit for a non-obvious reason (a local reverse proxy), so it says so and names the
    override instead of the generic header message.
    """
    client_host = request.client.host if request.client else None
    headers = getattr(request, "headers", None)
    host_header = headers.get("Host", "") if headers else ""
    if _client_is_loopback(client_host) and not _host_is_loopback(host_header):
        return (
            f"Host {host_header or '(none)'!r} is not a trusted local UI host. The local "
            f"exemption applies to loopback Host values only (DNS-rebinding guard); set "
            f"{TRUSTED_HOSTS_ENV} if this is your own reverse proxy, otherwise "
            f"authenticate with a bearer token or the session cookie."
        )
    return "Missing or malformed Authorization header"


if _HAS_STARLETTE:

    class AuthMiddleware(BaseHTTPMiddleware):
        """ASGI middleware that enforces bearer-token auth on ``/api/`` routes.

        ``/api/health`` is always exempt so that uptime probes work without
        credentials.
        """

        # Exact paths — not prefixes — so an added route like /api/healthcheck
        # or /api/health-secret is never accidentally left unauthenticated.
        _EXEMPT_PATHS: frozenset[str] = frozenset({"/api/health"})

        async def dispatch(self, request: Request, call_next):  # type: ignore[override]
            path = request.url.path
            if (
                path.startswith("/api/")
                and path not in self._EXEMPT_PATHS
                and not _request_is_from_the_local_ui(request)
                and not request_has_valid_session(request)
            ):
                auth_header = request.headers.get("Authorization", "")
                if not auth_header.startswith("Bearer "):
                    return JSONResponse({"detail": _missing_auth_detail(request)}, status_code=401)
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
