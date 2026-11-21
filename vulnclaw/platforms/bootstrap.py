"""Adapter bootstrap: make the built-in platforms known to the registry.

Kept separate from :mod:`vulnclaw.platforms.registry` so the registry stays a pure
mechanism (it never imports a concrete platform), and separate from
``platforms/__init__`` so importing the package does not drag in the platform HTTP
clients.

Registration is idempotent and lazy: the first call imports the adapters and
registers them; later calls are no-ops. A platform that is registered but not
configured (no credential) is still hidden from the agent -- registration is code,
exposure is configuration.
"""

from __future__ import annotations

from vulnclaw.platforms import registry
from vulnclaw.platforms.base import PlatformAdapter

_BUILTINS_REGISTERED = False


def _load_config() -> object | None:
    """Runtime config, or None when it cannot be read.

    Adapters that take connection details (CTFd) need it; the ones that read
    their own credential files (CTF2, GCS) ignore it. A failure here is not fatal:
    an adapter built without config simply reports itself as not configured.
    """
    try:
        from vulnclaw.config.settings import load_config

        return load_config()
    except Exception:  # noqa: BLE001
        return None


def ensure_adapters(force: bool = False) -> dict[str, PlatformAdapter]:
    """Register the built-in adapters once and return them all."""
    global _BUILTINS_REGISTERED
    if _BUILTINS_REGISTERED and not force:
        return registry.all_adapters()

    from vulnclaw.platforms.ctf2 import CTF2Adapter
    from vulnclaw.platforms.ctfd import build_adapter as build_ctfd
    from vulnclaw.platforms.gcs import GCSAdapter

    registry.register_adapter(CTF2Adapter())
    # Registered but not exposed by default (`enabled_by_default = False`): the
    # GCS integration is legacy, so it must be switched on deliberately. Being
    # registered is what lets `platforms.gcs.enabled = true` work later.
    registry.register_adapter(GCSAdapter())
    # CTFd reads its URL and token from `platforms.ctfd`; also off by default so
    # the tool face never offers a platform nobody configured.
    registry.register_adapter(build_ctfd(_load_config()))
    _BUILTINS_REGISTERED = True
    return registry.all_adapters()


def reset_bootstrap() -> None:
    """Forget that built-ins were registered (tests, re-configuration)."""
    global _BUILTINS_REGISTERED
    _BUILTINS_REGISTERED = False


__all__ = ["ensure_adapters", "reset_bootstrap"]
