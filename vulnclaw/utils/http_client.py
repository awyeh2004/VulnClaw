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

Explicit egress proxy (pointing the agent at a tunnel)
-----------------------------------------------------
The bypass above is about the *system* proxy being unwanted. The opposite case
is an operator who deliberately wants target traffic to leave through a proxy
they built -- canonical shape: ``ssh -D 1080 jumpbox`` and then

    VULNCLAW_HTTP_PROXY=socks5://127.0.0.1:1080 vulnclaw solve ...

or ``network.http_proxy`` in the config file. ``resolve_egress_proxy()`` reads
that setting; target-facing call sites pass it as ``proxy=`` to the factories.

* An explicit proxy is honoured **even though the target is private** -- that is
  the entire point, and it is why this cannot be expressed with ``trust_env``.
* ``localhost``/``127.0.0.1``/``::1`` targets stay direct even then. Through a
  SOCKS tunnel the far end reads ``127.0.0.1`` as *itself*, so tunnelling a
  loopback target means a different machine, not the one you meant.
* The scope gate is unaffected: it runs on the URL before the request, and a
  proxy keeps the real hostname in the URL. That is the reason to prefer
  ``ssh -D`` (SOCKS) over ``ssh -L``: with a port forward the agent can only
  address ``127.0.0.1:8080``, so ``--only-host``/``blocked_hosts`` see
  ``127.0.0.1`` and stop discriminating.

Measured with httpx 0.28.1 (see tests/utils/test_http_client_egress_proxy.py):

* ``socks5://`` sends the **hostname** to the proxy (SOCKS5 ``ATYP=3``), i.e.
  DNS is resolved at the proxy end. httpcore implements no separate local-DNS
  variant, so ``socks5://`` and ``socks5h://`` do the same thing -- unlike curl,
  where the two differ. We therefore *normalise* ``socks5h://`` to
  ``socks5://``: the far end resolves either way, and ``socks5h`` is a **hard
  crash below httpcore 1.0.9** (``KeyError: b'socks5h'`` out of
  ``httpcore._models.URL.origin``, raised far from the proxy URL that caused it).
  Normalising keeps a curl habit from becoming a mystery traceback.
* An explicit ``proxy=`` wins over ``trust_env``/``NO_PROXY``/``HTTP_PROXY``: it
  is used verbatim, and ``trust_env=False`` is forced so nothing in the
  environment can re-route or silently disable it.
* ``http://`` proxies keep the real host in the request line, so the gate stays
  meaningful there too.
* SOCKS needs the ``socksio`` package (``pip install 'vulnclaw[socks]'``);
  without it httpx raises a clear ImportError when the client is built.

The bypass list deliberately mirrors the Windows default rather than inventing a
narrower one: reporting a private target as "unreachable" is the exact failure
being fixed, so erring toward direct is correct here.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import os
from typing import Any, Iterable
from urllib.parse import urlsplit

import httpx

__all__ = [
    "bypass_proxy_for",
    "egress_settings",
    "http_client",
    "async_http_client",
    "is_local_target",
    "normalise_proxy_url",
    "resolve_egress_proxy",
    "targets_need_direct",
]

#: Environment variable read by :func:`resolve_egress_proxy` when the config
#: file does not name a proxy. ``VULNCLAW_``-prefixed on purpose: a bare
#: ``HTTP_PROXY`` is the *system* proxy this module exists to keep out of the
#: way, and overloading it would make "bypass" and "use it" the same variable.
EGRESS_PROXY_ENV = "VULNCLAW_HTTP_PROXY"

# Mirrors what httpx itself accepts (httpx 0.28 ``_transports/default.py``);
# anything else is rejected here with a better message than httpx's.
_SUPPORTED_PROXY_SCHEMES = ("http", "https", "socks5", "socks5h")
_SOCKS_SCHEMES = ("socks5", "socks5h")


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


def _host_is_local_address(host: str) -> bool:
    """True for ``localhost``/loopback/unspecified -- "the box I am running on".

    Deliberately narrower than :func:`_host_needs_direct`: ``.internal`` and
    ``10.0.0.0/8`` are exactly the names/IPs an explicit tunnel exists to
    reach, so they must NOT be classified as local here.
    """
    if not host:
        return False
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(addr.is_loopback or addr.is_unspecified)


def is_local_target(target: str) -> bool:
    """True when ``target`` addresses this machine itself (loopback/unspecified).

    Public because a call site that builds **one client per group** has to peel
    loopback out itself: :func:`egress_settings` keeps an *all-local* target set
    direct, so a batch that mixes ``127.0.0.1`` with a target still hands the whole
    set to the tunnel -- and through a tunnel the far end reads ``127.0.0.1`` as
    itself.
    """
    return _host_is_local_address(_host_of(str(target or "")))


def _targets_are_local_only(targets: Iterable[str] | str | None) -> bool:
    """True when a non-empty target set addresses only this machine."""
    if targets is None:
        return False
    items = [targets] if isinstance(targets, str) else [t for t in targets if t]
    if not items:
        return False
    return all(is_local_target(t) for t in items)


def _check_proxy_url(url: str) -> None:
    """Reject a proxy URL that httpx cannot use, with an actionable message."""
    scheme = urlsplit(url).scheme.lower()
    if not scheme or scheme not in _SUPPORTED_PROXY_SCHEMES:
        supported = ", ".join(f"{s}://" for s in _SUPPORTED_PROXY_SCHEMES)
        raise ValueError(
            f"unsupported proxy scheme in {url!r} (expected one of {supported})"
        )
    if scheme in _SOCKS_SCHEMES and importlib.util.find_spec("socksio") is None:
        raise RuntimeError(
            f"SOCKS proxy {url!r} needs the 'socksio' package: "
            "pip install 'vulnclaw[socks]' (or pip install socksio)"
        )


def normalise_proxy_url(url: str) -> str:
    """Rewrite ``socks5h://`` to ``socks5://``.

    Measured: httpcore resolves the SOCKS5 destination **at the proxy** for both
    schemes (it never implements curl's local-DNS ``socks5``), so the two are
    behaviourally identical here. ``socks5h`` only entered httpcore's default-port
    table in 1.0.9; on 1.0.2 (the version installed in this dev environment --
    httpx pulls httpcore transitively, so the floor is ``httpx>=0.27``) it raises
    ``KeyError: b'socks5h'`` from deep inside httpcore, naming neither the proxy
    nor the feature. Rewriting is a no-op on new httpcore and a fix on old.
    """
    if urlsplit(url).scheme.lower() == "socks5h":
        return "socks5" + url[len("socks5h") :]
    return url


def resolve_egress_proxy(config: Any = None) -> str:
    """Effective explicit egress proxy, or ``""`` when none is configured.

    Precedence: ``config.network.http_proxy`` > ``$VULNCLAW_HTTP_PROXY`` > "".

    Returns a string (never ``None``) so call sites can pass the result straight
    to ``proxy=`` -- an empty string means "no explicit proxy, keep the
    ``trust_env`` bypass behaviour", which is the default everywhere.
    """
    configured = ""
    if config is not None:
        network = getattr(config, "network", None)
        configured = str(getattr(network, "http_proxy", "") or "").strip()
    if configured:
        return configured
    return str(os.environ.get(EGRESS_PROXY_ENV, "") or "").strip()


def egress_settings(
    targets: Iterable[str] | str | None,
    proxy: str | None = None,
) -> tuple[str | None, bool]:
    """Decide ``(proxy_url, trust_env)`` for a request set heading to ``targets``.

    ``proxy`` empty/``None``  -> legacy behaviour: no proxy, ``trust_env`` is
    ``False`` for private targets so a running system proxy stays out of the way.
    ``proxy`` set             -> that proxy is used for every non-local target
    and ``trust_env`` is forced ``False``, so the environment cannot re-route it
    or turn it off with ``NO_PROXY``. Local-only target sets stay direct (see
    the module docstring: through a tunnel, ``127.0.0.1`` means the far end).
    """
    url = str(proxy or "").strip()
    if not url:
        return None, not targets_need_direct(targets)
    _check_proxy_url(url)
    url = normalise_proxy_url(url)
    if _targets_are_local_only(targets):
        return None, False
    return url, False


def http_client(
    *,
    targets: Iterable[str] | str | None = None,
    proxy: str | None = None,
    trust_env: bool | None = None,
    **kwargs: Any,
) -> httpx.Client:
    """``httpx.Client`` that does not proxy local/private targets.

    ``trust_env`` may be forced explicitly; when omitted it is derived from
    ``targets``. Leaving ``targets`` unset honours the environment (previous
    behaviour), so this is a drop-in replacement.

    Pass ``proxy=resolve_egress_proxy(config)`` to route the request through an
    operator-supplied proxy (SOCKS or HTTP) instead -- see the module docstring.
    """
    proxy_url, derived_trust_env = egress_settings(targets, proxy)
    if trust_env is None:
        trust_env = derived_trust_env
    if proxy_url:
        kwargs["proxy"] = proxy_url
    kwargs.setdefault("trust_env", trust_env)
    return httpx.Client(**kwargs)


def async_http_client(
    *,
    targets: Iterable[str] | str | None = None,
    proxy: str | None = None,
    trust_env: bool | None = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """``httpx.AsyncClient`` counterpart of :func:`http_client`."""
    proxy_url, derived_trust_env = egress_settings(targets, proxy)
    if trust_env is None:
        trust_env = derived_trust_env
    if proxy_url:
        kwargs["proxy"] = proxy_url
    kwargs.setdefault("trust_env", trust_env)
    return httpx.AsyncClient(**kwargs)
