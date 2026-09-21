"""URL utility functions — shared across infrastructure and domain layers.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: 消除 V1 违规 — mcp/lifecycle.py 基础设施层不应反向依赖
         agent/builtin_tools.py 领域层，将纯 URL 工具函数抽取到
         基础设施层 config/ 包中。
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlparse


def is_ip_address(text: str) -> bool:
    """Whether ``text`` is a bare IPv4/IPv6 literal (not a hostname)."""
    candidate = str(text or "").strip().strip("[]")
    if not candidate:
        return False
    if ":" in candidate:  # IPv6
        return all(ch in "0123456789abcdefABCDEF:." for ch in candidate)
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def host_in_scope(host: str, patterns: Iterable[str]) -> bool:
    """Whether ``host`` falls inside any scope pattern.

    A bare domain pattern is a **domain scope**, not an exact host:
    ``dasctf.com`` covers ``dasctf.com`` and ``direct-ctf2.dasctf.com``. Measured
    need -- a competition target host is almost always a subdomain of the platform
    domain, and exact-equality matching rejected the target itself, which blocked
    ``fetch`` / ``shell_command`` / ``python_execute`` / ``http_probe_batch`` on a
    live challenge and left only the browser toolset able to reach it.

    ``*.example.com`` is accepted as an explicit wildcard. Suffix matching cannot
    be fooled by a lookalike: ``evil-dasctf.com`` does not end with
    ``.dasctf.com``, so it stays out of scope.

    An IP pattern stays exact-only: nothing may be "inside" an address.
    """
    candidate = str(host or "").strip().lower().rstrip(".")
    if not candidate:
        return False
    for raw in patterns or ():
        pattern = str(raw or "").strip().lower().rstrip(".")
        if not pattern:
            continue
        if pattern.startswith("*."):
            pattern = pattern[2:]
        if not pattern:
            continue
        if candidate == pattern:
            return True
        if is_ip_address(pattern):
            continue
        if candidate.endswith("." + pattern):
            return True
    return False


def infer_port_from_url(url: str) -> int | None:
    """Infer request port from URL.

    Returns the explicit port if present in the URL, otherwise infers
    from the scheme (443 for https, 80 for http), or None if unknown.
    Never raises on a malformed port (e.g. trailing ``~`` from a paste):
    a non-numeric port yields None instead of a crash.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    return _safe_parsed_port(parsed)


def _safe_parsed_port(parsed: Any) -> int | None:
    """Return ``parsed.port`` without raising on a malformed port substring.

    ``urlparse``/``urlsplit`` raise ``ValueError: Port could not be cast to
    integer value as '19667~'`` when the port is not an integer (e.g. a
    trailing ``~`` left over from a copy-paste). Callers that only want the
    port (with scheme fallback) should use this instead of touching
    ``parsed.port`` directly.
    """
    try:
        if parsed.port:
            return parsed.port
    except ValueError:
        return None
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None
