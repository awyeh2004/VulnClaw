"""``platforms.<name>.enabled`` must actually switch a platform on and off.

Round-5 review N2: the registry read ``config.platforms.<name>.enabled``, but
``VulnClawConfig`` had no ``platforms`` field and pydantic silently ignores
unknown keys -- so the documented switch did nothing. GCS was therefore
permanently hidden (``enabled_by_default = False``) and CTF2 permanently exposed,
regardless of what the config file said.
"""

from __future__ import annotations

import pytest

from vulnclaw.config.schema import PlatformsConfig
from vulnclaw.platforms import bootstrap, registry
from vulnclaw.platforms.ctf2 import CTF2Adapter
from vulnclaw.platforms.gcs import GCSAdapter


class _StubClient:
    def is_configured(self) -> bool:
        return True

    def api_base_url(self) -> str:
        return "https://example.invalid"


@pytest.fixture(autouse=True)
def _clean_registry():
    registry.clear_adapters()
    bootstrap.reset_bootstrap()
    yield
    registry.clear_adapters()
    bootstrap.reset_bootstrap()


def _install(monkeypatch, config):
    """Point the registry at a config object without touching the real file."""
    monkeypatch.setattr(
        "vulnclaw.config.settings.load_config", lambda *a, **k: config
    )


def test_schema_keeps_the_platforms_section():
    """Regression: the section used to be dropped as an unknown key."""
    cfg = bootstrap_config({"platforms": {"gcs": {"enabled": True}}})
    assert cfg.platforms.toggle_for("gcs") is True


def bootstrap_config(raw: dict):
    from vulnclaw.config.schema import VulnClawConfig

    return VulnClawConfig.model_validate(raw)


def test_gcs_can_be_switched_on(monkeypatch):
    cfg = bootstrap_config({"platforms": {"gcs": {"enabled": True}}})
    _install(monkeypatch, cfg)
    adapter = GCSAdapter(_StubClient())
    registry.register_adapter(adapter)
    assert registry.is_enabled(adapter) is True
    assert "gcs" in registry.configured_adapters()


def test_gcs_stays_hidden_without_the_switch(monkeypatch):
    _install(monkeypatch, bootstrap_config({}))
    adapter = GCSAdapter(_StubClient())
    registry.register_adapter(adapter)
    assert registry.is_enabled(adapter) is False
    assert "gcs" not in registry.configured_adapters()


def test_ctf2_can_be_switched_off(monkeypatch):
    """The symmetric promise: the default-on platform is configurable too."""
    cfg = bootstrap_config({"platforms": {"ctf2": {"enabled": False}}})
    _install(monkeypatch, cfg)
    adapter = CTF2Adapter(_StubClient())
    registry.register_adapter(adapter)
    assert registry.is_enabled(adapter) is False
    assert "ctf2" not in registry.configured_adapters()


def test_ctf2_exposed_by_default(monkeypatch):
    _install(monkeypatch, bootstrap_config({}))
    assert registry.is_enabled(CTF2Adapter(_StubClient())) is True


def test_bare_bool_shorthand(monkeypatch):
    cfg = bootstrap_config({"platforms": {"gcs": True}})
    _install(monkeypatch, cfg)
    assert registry.is_enabled(GCSAdapter(_StubClient())) is True


def test_unknown_platform_name_is_kept(monkeypatch):
    """A newly registered adapter must be configurable without a schema change."""
    cfg = bootstrap_config({"platforms": {"brand-new": {"enabled": True}}})
    assert cfg.platforms.toggle_for("brand-new") is True


def test_unreadable_config_fails_closed(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("no config")

    monkeypatch.setattr("vulnclaw.config.settings.load_config", _boom)
    adapter = CTF2Adapter(_StubClient())
    assert registry.is_enabled(adapter) is False


def test_disabled_platform_reports_the_switch_that_turned_it_off(monkeypatch):
    cfg = bootstrap_config({"platforms": {"gcs": {"enabled": False}}})
    _install(monkeypatch, cfg)
    registry.register_adapter(GCSAdapter(_StubClient()))
    with pytest.raises(registry.PlatformNotConfigured) as exc:
        registry.adapter_for("gcs:exercise:1")
    assert "platforms.gcs.enabled" in str(exc.value)


def test_platforms_config_model_shape():
    section = PlatformsConfig.model_validate({"gcs": {"enabled": True}})
    assert section.toggle_for("gcs") is True
    assert section.toggle_for("absent") is None
