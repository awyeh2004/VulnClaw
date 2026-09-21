"""httpx client factory that keeps the system proxy off local and private targets.

Why this exists
---------------
httpx defaults to ``trust_env=True``, which makes it read the platform proxy
configuration. On Windows that means WinINET, so any machine with a proxy tool
running (Clash/Hiddify/v2ray/company proxy) had **every** httpx client in
vulnclaw routed through it -- including requests to loopback and to the
engagement target.

That is not a cosmetic problem:

* ``HttpProxy`` is consulted for private destinations too. httpx does read
  ``NO_PROXY``/``no_proxy``... but the Windows bypass list (``ProxyOverride``)
  is NOT ``NO_PROXY``. A user whose ``ProxyOverride`` already contains
  ``localhost;127.*;10.*;192.168.*`` still gets loopback requests sent to the
  proxy, and the proxy answers 502 or resets the connection. Measured:

      connect_tcp.started host='127.0.0.1' port=12334   <- destination was loopback
      httpcore._sync.http_proxy.py:207 handle_request(proxy_request)
      ReadError(ConnectionResetError(10054))

* A pentest target reached through a proxy has the proxy's source address, and
  internal targets are simply unreachable. The scan silently reports the target
  as down.

What this does
--------------
``http_client``/``async_http_client`` take the destination (or a list of them)
and set ``trust_env`` accordingly:

    loopback / private / link-local  -> trust_env=False  (always direct)
    public                           -> trust_env=True   (honours the proxy)

So an agent can still reach the internet through a corporate or TUN proxy while
talking directly to the target. Pass ``targets=`` when the destination is known;
when it is not (mixed or unpredictable), leave it unset and the environment is
honoured.

The bypass list deliberately mirrors the Windows default rather than inventing a
narrower one: reporting a private target as "unreachable" is the exact failure
being fixed, so erring toward direct is correct here.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable
from urllib.parse import urlsplit

import httpx

__all__ = ["bypass_proxy_for", "http_client", "async_http_client", "targets_need_direct"]


def _host_of(target: str) -> str:
    """Extract a bare host from a URL, ``host:port``, or a bare host."""
    text = str(target or "").strip()
    if not text:
        return ""
    if "//" in text:
        return (urlsplit(text).hostname or "").lower()
    # ``host:port`` / bare host. Guard IPv6 literals in brackets.
    if text.startswith("["):
        return text[1:].split("]", 1)[0].lower()
    head = text.split("/", 1)[0]
    if head.count(":") == 1:
        head = head.split(":", 1)[0]
    return head.lower()


def _host_needs_direct(host: str) -> bool:
    """True when this host must not be sent through an HTTP proxy."""
    if not host:
        return False
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # A DNS name: it may well resolve to a private address, but we cannot
        # know here. Public-name services (platform APIs, intel feeds) are the
        # common case, so let the environment decide.
        return False
    return bool(
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
    )


def targets_need_direct(targets: Iterable[str] | str | None) -> bool:
    """True when EVERY given target must bypass the proxy.

    Every, not any: a client reused across a public and a private target has to
    keep the environment proxy, otherwise the public one becomes unreachable.
    Callers that mix both should build separate clients.
    """
    if targets is None:
        return False
    if isinstance(targets, str):
        items = [targets]
    else:
        items = [t for t in targets if t]
    if not items:
        return False
    return all(_host_needs_direct(_host_of(t)) for t in items)


def bypass_proxy_for(targets: Iterable[str] | str | None) -> bool:
    """Whether ``trust_env`` should be disabled for these targets.

    Public, readable alias of :func:`targets_need_direct` for call sites where
    ``trust_env=bypass_proxy_for(target)`` reads better than a negation.
    """
    return targets_need_direct(targets)


def http_client(
    *,
    targets: Iterable[str] | str | None = None,
    trust_env: bool | None = None,
    **kwargs: Any,
) -> httpx.Client:
    """``httpx.Client`` that does not proxy local/private targets.

    ``trust_env`` may be forced explicitly; when omitted it is derived from
    ``targets``. Leaving ``targets`` unset honours the environment (previous
    behaviour), so this is a drop-in replacement.
    """
    if trust_env is None:
        trust_env = not targets_need_direct(targets)
    kwargs.setdefault("trust_env", trust_env)
    return httpx.Client(**kwargs)


def async_http_client(
    *,
    targets: Iterable[str] | str | None = None,
    trust_env: bool | None = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """``httpx.AsyncClient`` counterpart of :func:`http_client`."""
    if trust_env is None:
        trust_env = not targets_need_direct(targets)
    kwargs.setdefault("trust_env", trust_env)
    return httpx.AsyncClient(**kwargs)
