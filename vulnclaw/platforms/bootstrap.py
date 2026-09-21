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


def ensure_adapters(force: bool = False) -> dict[str, PlatformAdapter]:
    """Register the built-in adapters once and return them all."""
    global _BUILTINS_REGISTERED
    if _BUILTINS_REGISTERED and not force:
        return registry.all_adapters()

    from vulnclaw.platforms.ctf2 import CTF2Adapter

    registry.register_adapter(CTF2Adapter())
    _BUILTINS_REGISTERED = True
    return registry.all_adapters()


def reset_bootstrap() -> None:
    """Forget that built-ins were registered (tests, re-configuration)."""
    global _BUILTINS_REGISTERED
    _BUILTINS_REGISTERED = False


__all__ = ["ensure_adapters", "reset_bootstrap"]
