"""Keep the HARNESS'S OWN credentials out of evidence, state files and reports.

Found the hard way: a run's evidence held the operator's config file verbatim, so a live
`gcs.access_key` and LLM `api_key` ended up inside
``~/.vulnclaw/runs/<run>/targets/<t>/state/current.json`` as ``agent_state.evidence[*].content``
-- and evidence is the surface that feeds previews, snapshots and the written report.

SCOPE, and why it is this narrow
--------------------------------
This redacts the values of credentials **this harness owns** (its config, its environment, its
web token). It deliberately does NOT redact credential-*shaped* text in general: in a pentest or
incident-response run, a credential found in the target's data **is the deliverable** ("the
attacker used this API key"), and a blanket `sk-…` filter would eat exactly the finding the
operator asked for. An own-credential match is unambiguous, has no false positives, and covers
the leak that was actually measured.

Values are never logged: the replacement keeps a short recognisable head plus a digest, so an
operator can still tell "which of my keys leaked here" without the value being re-published.
"""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

#: Field names whose VALUE is a credential. Matched exactly, or as a `_key`/`_token`/`_secret`
#: suffix, with a small exclusion list for look-alikes that are not secrets at all
#: (`max_tokens`, `oauth_token_url`, `context_summary_max_tokens`, ...).
_CREDENTIAL_NAMES = frozenset(
    {
        "api_key", "apikey", "api_keys", "access_key", "secret_key", "client_secret",
        "password", "passwd", "token", "bearer_token", "session_token", "private_key",
        "secret", "web_token", "auth_token", "refresh_token",
    }
)
_CREDENTIAL_SUFFIXES = ("_key", "_keys", "_token", "_secret", "_password")
_NOT_SECRET_SUFFIXES = (
    "_tokens", "_token_url", "_token_count", "_token_budget", "_key_policy", "_keys_url",
)
#: Below this length a "match" is far more likely to be an ordinary word than a credential.
_MIN_SECRET_LENGTH = 8

#: Environment variables this harness reads credentials from.
_CREDENTIAL_ENV_NAMES = (
    "VULNCLAW_LLM_API_KEY",
    "VULNCLAW_LLM_API_KEYS",
    "VULNCLAW_GCS_ACCESS_KEY",
    "VULNCLAW_CTF2_API_KEY",
    "VULNCLAW_CTF2_SESSION_TOKEN",
)

_CACHE_TTL_SECONDS = 60.0
_cache: tuple[float, dict[str, str]] | None = None


def _looks_secret_name(name: str) -> bool:
    lowered = str(name or "").strip().lower()
    if not lowered:
        return False
    if lowered in _CREDENTIAL_NAMES:
        return True
    if lowered.endswith(_NOT_SECRET_SUFFIXES):
        return False
    return lowered.endswith(_CREDENTIAL_SUFFIXES)


def _walk_for_secrets(node: Any, path: str, out: dict[str, str]) -> None:
    if isinstance(node, Mapping):
        for key, value in node.items():
            _walk_for_secrets(value, f"{path}.{key}" if path else str(key), out)
        return
    if isinstance(node, (list, tuple, set)):
        for index, item in enumerate(node):
            _walk_for_secrets(item, f"{path}[{index}]", out)
        return
    if isinstance(node, str) and _looks_secret_name(path.rsplit(".", 1)[-1].split("[")[0]):
        value = node.strip()
        if len(value) >= _MIN_SECRET_LENGTH and not value.isdigit():
            out.setdefault(value, path)


def _web_token() -> str:
    """The Web UI bearer token lives in its own file, not in the config."""
    try:
        from vulnclaw.web.auth import TOKEN_FILE

        path = Path(TOKEN_FILE)
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
    except Exception:  # noqa: BLE001 - redaction must never break a run
        pass
    return ""


def local_secret_values(*, force: bool = False) -> dict[str, str]:
    """``{secret value: label}`` for every credential this harness owns.

    Cached for :data:`_CACHE_TTL_SECONDS`: this runs on the evidence path (once per tool
    result), and re-reading the config there would reintroduce the per-call config parse that
    the platform gates were just fixed to stop doing.
    """
    global _cache
    now = time.monotonic()
    if not force and _cache is not None and now - _cache[0] < _CACHE_TTL_SECONDS:
        return _cache[1]

    import os

    found: dict[str, str] = {}
    try:
        from vulnclaw.config.settings import load_config

        _walk_for_secrets(load_config().model_dump(mode="json"), "config", found)
    except Exception:  # noqa: BLE001 - never break a run over this
        pass
    for name in _CREDENTIAL_ENV_NAMES:
        value = os.environ.get(name, "").strip()
        if len(value) >= _MIN_SECRET_LENGTH:
            # A `_KEYS` variable may hold a comma/space separated pool.
            for part in re.split(r"[,\s]+", value):
                if len(part) >= _MIN_SECRET_LENGTH:
                    found.setdefault(part, f"env.{name}")
    token = _web_token()
    if len(token) >= _MIN_SECRET_LENGTH:
        found.setdefault(token, "web_token")

    _cache = (now, found)
    return found


def reset_cache() -> None:
    """Forget the cached secret set (tests, and after a config change)."""
    global _cache
    _cache = None


def _mask(value: str, label: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]
    head = value[:4] if len(value) > 8 else ""
    return f"{head}…[redacted {label} {digest}]"


def redact_credentials(text: Any, *, secrets: Optional[Mapping[str, str]] = None) -> str:
    """Replace occurrences of the harness's own credentials with a labelled mask.

    Longest value first, so a key that contains another key as a substring cannot be
    half-replaced. Idempotent: the replacement no longer contains the original value.
    """
    raw = str(text or "")
    if not raw:
        return raw
    table = local_secret_values() if secrets is None else dict(secrets)
    if not table:
        return raw
    for value in sorted(table, key=len, reverse=True):
        if value in raw:
            raw = raw.replace(value, _mask(value, table[value]))
    return raw


def redact_secrets_in_mapping(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Redact string leaves of a nested mapping (for structured state that bypasses text)."""
    out: dict[str, Any] = {}
    for key, value in (payload or {}).items():
        if isinstance(value, str):
            out[key] = redact_credentials(value)
        elif isinstance(value, Mapping):
            out[key] = redact_secrets_in_mapping(value)
        elif isinstance(value, list):
            out[key] = [
                redact_credentials(item) if isinstance(item, str)
                else redact_secrets_in_mapping(item) if isinstance(item, Mapping)
                else item
                for item in value
            ]
        else:
            out[key] = value
    return out


def known_labels() -> Iterable[str]:
    """Labels currently known -- for diagnostics, never the values."""
    return sorted(set(local_secret_values().values()))
