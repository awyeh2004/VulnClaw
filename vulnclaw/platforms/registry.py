"""Adapter registry: which platforms exist, and which ones the agent may see.

A platform is *registered* when its adapter object has been handed to
:func:`register_adapter`, and *exposed* when it is both configured (credentials
present) and enabled.  Keeping those two ideas apart matters:

* registration is code and never fails at runtime;
* exposure depends on config, and a missing credential must produce a readable
  "not configured" message rather than an import error or a bare 401 much later.

The enable switch is ``platforms.<name>.enabled`` (design doc decision Q6).
Precedence: explicit config setting > adapter's ``enabled_by_default``.  If the
config cannot be read at all, exposure fails CLOSED -- not being able to read the
setting is not a reason to hand an irreversible action to the model.

This module deliberately imports no concrete platform: the adapters register
themselves in a later migration step, so the skeleton can land and be tested on
its own.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from vulnclaw.platforms.base import PlatformAdapter
from vulnclaw.platforms.refs import RefError, split_token

CONFIG_SECTION = "platforms"


class PlatformError(RuntimeError):
    """Base class for adapter-layer failures."""


class UnknownPlatform(PlatformError):
    """The ref token names a platform that is not registered."""


class PlatformNotConfigured(PlatformError):
    """The platform is registered but cannot be used right now."""


_ADAPTERS: dict[str, PlatformAdapter] = {}


# ── registration ──────────────────────────────────────────────────────────


def register_adapter(adapter: PlatformAdapter) -> None:
    """Register (or replace) an adapter under its own ``name``."""
    name = str(getattr(adapter, "name", "") or "").strip()
    if not name:
        raise PlatformError("adapter must declare a non-empty name")
    if ":" in name or any(ch.isspace() for ch in name):
        raise PlatformError(f"adapter name must be a bare token prefix, got {name!r}")
    _ADAPTERS[name] = adapter


def clear_adapters() -> None:
    """Drop every registered adapter (tests, and re-configuration)."""
    _ADAPTERS.clear()


def all_adapters() -> dict[str, PlatformAdapter]:
    """Every registered adapter, exposed or not."""
    return dict(_ADAPTERS)


def registered_names() -> list[str]:
    return sorted(_ADAPTERS)


# ── enable switch ─────────────────────────────────────────────────────────


def _config_enabled(name: str) -> bool | None:
    """The explicit ``platforms.<name>.enabled`` value, or None if unset.

    Returns False when the config cannot be read at all (fail closed); returns
    None when it reads fine but simply says nothing about this platform, so the
    adapter's own default can apply.

    Reads three shapes, because the section is free-form by adapter name
    (``PlatformsConfig`` uses ``extra="allow"``): a nested mapping
    (``{name: {enabled: true}}``), a model instance, and the bare
    ``{name: true}`` shorthand.
    """
    try:
        from vulnclaw.config.settings import load_config

        config = load_config()
    except Exception:
        return False

    section = getattr(config, CONFIG_SECTION, None)
    if section is None:
        return None

    entry: Any = None
    if isinstance(section, Mapping):
        entry = section.get(name)
    else:
        entry = getattr(section, name, None)
    if entry is None and not isinstance(section, Mapping):
        entry = (getattr(section, "model_extra", None) or {}).get(name)
    if entry is None:
        return None

    # `platforms.gcs: true` shorthand.
    if isinstance(entry, bool):
        return entry
    if isinstance(entry, Mapping):
        value = entry.get("enabled")
    else:
        value = getattr(entry, "enabled", None)
    if value is None:
        return None
    return bool(value)


def is_enabled(adapter: PlatformAdapter) -> bool:
    """Whether the adapter's tool face is switched on."""
    explicit = _config_enabled(str(adapter.name))
    if explicit is None:
        return bool(getattr(adapter, "enabled_by_default", False))
    return explicit


# ── exposure ──────────────────────────────────────────────────────────────


def configured_adapters() -> dict[str, PlatformAdapter]:
    """Adapters that are enabled AND have credentials: what the agent may use."""
    exposed: dict[str, PlatformAdapter] = {}
    for name, adapter in _ADAPTERS.items():
        try:
            if is_enabled(adapter) and adapter.is_configured():
                exposed[name] = adapter
        except Exception:
            # A broken adapter must not take the whole tool face down.
            continue
    return exposed


def adapter_for(token: str) -> PlatformAdapter:
    """Resolve a ref token to its adapter.

    Raises :class:`UnknownPlatform` when nothing owns the prefix (listing what
    IS available, so the caller can correct itself) and
    :class:`PlatformNotConfigured` when the platform exists but is switched off
    or lacks credentials.
    """
    try:
        platform, _ = split_token(token)
    except RefError as exc:
        raise UnknownPlatform(str(exc)) from exc

    adapter = _ADAPTERS.get(platform)
    if adapter is None:
        known = ", ".join(registered_names()) or "(none registered)"
        raise UnknownPlatform(
            f"no platform named {platform!r}; registered platforms: {known}. "
            f"Call platform_list to get a valid ref."
        )
    if not is_enabled(adapter):
        raise PlatformNotConfigured(
            f"platform {platform!r} is disabled (platforms.{platform}.enabled is false)"
        )
    if not adapter.is_configured():
        raise PlatformNotConfigured(
            f"platform {platform!r} has no credentials configured; "
            f"see the platform's setup notes before retrying"
        )
    return adapter


def capabilities() -> frozenset[str]:
    """Union of the optional capabilities the exposed platforms declare."""
    merged: set[str] = set()
    for adapter in configured_adapters().values():
        declared = getattr(adapter, "capabilities", frozenset())
        merged |= {str(item) for item in declared}
    return frozenset(merged)


def describe() -> str:
    """One-line-per-platform status, for diagnostics and the CLI."""
    if not _ADAPTERS:
        return "[platforms] no adapters registered."
    lines: list[str] = []
    for name, adapter in sorted(_ADAPTERS.items()):
        try:
            configured = adapter.is_configured()
        except Exception:
            configured = False
        state = "exposed" if (is_enabled(adapter) and configured) else "hidden"
        reason = []
        if not is_enabled(adapter):
            reason.append(f"platforms.{name}.enabled=false")
        if not configured:
            reason.append("no credentials")
        suffix = f" ({', '.join(reason)})" if reason else ""
        lines.append(f"[platforms] {name}: {state}{suffix}")
    return "\n".join(lines)


__all__ = [
    "CONFIG_SECTION",
    "PlatformError",
    "PlatformNotConfigured",
    "UnknownPlatform",
    "adapter_for",
    "all_adapters",
    "capabilities",
    "clear_adapters",
    "configured_adapters",
    "describe",
    "is_enabled",
    "register_adapter",
    "registered_names",
]
