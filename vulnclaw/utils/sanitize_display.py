"""Mask secrets in operator-facing text WITHOUT touching the evidence.

This is the display-layer counterpart to :mod:`vulnclaw.utils.redaction`. That
module deliberately redacts only credentials *this harness owns*, because in a
pentest run "the credential found in the target's data IS the deliverable" -- a
blanket ``sk-`` filter would eat exactly the finding the operator asked for.
Its scope is evidence, state files and reports.

The approval prompt is a different surface with a different requirement: an
operator glancing at a pending ``curl -u admin:P@ssw0rd`` should be able to
judge the command, and that command must not then be pasted into a chat or a
ticket with a live credential in it. aiscan's ``exts/guardrail/sanitize.go``
solves the same problem the same way -- structure-preserving, best-effort, and
explicitly *not* a DLP engine.

So: two functions, two scopes. ``redact_credentials`` owns harness secrets
everywhere. ``mask_display_secrets`` owns credential-shaped text on the approval
view only. Evidence keeps the raw value; the operator sees the shape.
"""

from __future__ import annotations

import re
from typing import Any

#: Replacement marker. Shape-preserving enough to show WHERE the secret was.
MASK = "[redacted]"

#: Ordered: longer/more specific patterns first, so e.g. a private key block is
#: collapsed before the generic assignment rule sees its ``-----BEGIN`` line.
#: Each entry carries its own replacer because some masks keep a prefix (the
#: header name, the ``-u`` flag) and some replace the whole match.
_DISPLAY_PATTERNS: tuple[tuple["re.Pattern[str]", Any], ...] = (
    # PEM private keys -- multi-line, so this must run first.
    (
        re.compile(
            r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----"
        ),
        MASK,
    ),
    # Authorization headers, either scheme.
    (
        re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}"),
        lambda m: f"{m.group(1)} {MASK}",
    ),
    # Well-known key prefixes.
    (
        re.compile(r"(?i)\b(?:sk-|apikey_|ghp_|gho_|ghs_|xox[baprs]-|AKIA)[A-Za-z0-9_-]{8,}"),
        MASK,
    ),
    # userinfo in URLs: scheme://user:pass@host
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@"),
        lambda m: f"{m.group(1)}{MASK}@",
    ),
    # curl --user / -u CREDS and the same in wget style.
    (
        re.compile(r"(?i)((?:--user|-u)\s+)(?:\"[^\"]*\"|'[^']*'|[^\s;&|]+)"),
        lambda m: f"{m.group(1)}{MASK}",
    ),
    # Attached password flags in the mysql idiom: ``-uroot -pS3cret``. The
    # password is glued to the flag, so the assignment rule cannot see it.
    # Scoped to a command that already names a ``-u`` user: a bare
    # ``nmap -p80,443`` must NOT lose its port list to this rule.
    (
        re.compile(r"(?i)(\s-u\s*\S+\s+-p)([^\s;&|]+)"),
        lambda m: f"{m.group(1)}{MASK}",
    ),
    (
        re.compile(r"(?i)(--password[= ])(?:\"[^\"]*\"|'[^']*'|[^\s;&|]+)"),
        lambda m: f"{m.group(1)}{MASK}",
    ),
    # curl -H "Cookie: ..." / --header 'Authorization: ...'
    (
        re.compile(r"(?i)((?:-H|--header)\s+[\"']?(?:Cookie|Authorization|X-Api-Key)\s*:\s*)[^\"'\n]+"),
        lambda m: f"{m.group(1)}{MASK}",
    ),
    # key=value / key: value assignments naming a credential.
    (
        re.compile(
            r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key"
            r"|private[_-]?key|client[_-]?secret|session[_-]?id)\s*[:=]\s*)"
            r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&|]+)"
        ),
        lambda m: f"{m.group(1)}{MASK}",
    ),
    # Cookies on their own line (a raw header dump, not a -H argument).
    (
        re.compile(r"(?i)^([ \t]*cookie\s*:\s*).+$", re.MULTILINE),
        lambda m: f"{m.group(1)}{MASK}",
    ),
)


def mask_display_secrets(text: str) -> str:
    """Mask credential-shaped substrings, preserving the surrounding structure.

    ``curl -u admin:hunter2 http://x`` becomes ``curl -u [redacted] http://x``;
    a private key block becomes a single ``[redacted]``. Best-effort by design:
    it must never raise, because it runs on the approval path where an exception
    would turn a pending decision into a crash.
    """

    if not text:
        return text
    out = str(text)
    try:
        for pattern, replacer in _DISPLAY_PATTERNS:
            out = pattern.sub(replacer, out)
    except Exception:  # noqa: BLE001 - the approval path must not break here
        return MASK if out.strip() else out
    return out


def mask_for_approval(display: str, detail: str = "") -> tuple[str, str]:
    """Both view fields at once, plus the harness's own credentials.

    ``redact_credentials`` runs *after* the pattern pass: a harness key that
    happens to be short or oddly shaped may not match a credential pattern, but
    the exact-value substitution always catches it.
    """

    from vulnclaw.utils.redaction import redact_credentials

    return (
        redact_credentials(mask_display_secrets(display)),
        redact_credentials(mask_display_secrets(detail)),
    )