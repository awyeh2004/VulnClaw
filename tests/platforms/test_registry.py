"""Registry: which platforms exist, and which ones the agent may see.

Exposure has two independent gates -- the adapter has credentials, and the
``platforms.<name>.enabled`` switch is on -- and they must not be conflated: a
platform that is merely *switched off* needs a different message than one that is
*missing credentials*, and neither may look like a crash.
"""

from __future__ import annotations

import pytest

from vulnclaw.platforms.base import CAP_EVENT_INFO, CAP_OVERVIEW, CAP_SUBMISSIONS
from vulnclaw.platforms.registry import (
    PlatformError,
    PlatformNotConfigured,
    UnknownPlatform,
    adapter_for,
    capabilities,
    clear_adapters,
    configured_adapters,
    describe,
    is_enabled,
    register_adapter,
    registered_names,
)


class FakeAdapter:
    """Minimal stand-in: the registry only needs name/config/enable/capabilities."""

    def __init__(
        self,
        name: str,
        *,
        configured: bool = True,
        enabled_by_default: bool = True,
        caps: frozenset[str] = frozenset(),
        broken: bool = False,
    ) -> None:
        self.name = name
        self.capabilities = caps
        self.enabled_by_default = enabled_by_default
        self._configured = configured
        self._broken = broken

    def is_configured(self) -> bool:
        if self._broken:
            raise RuntimeError("credential lookup blew up")
        return self._configured


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_adapters()
    yield
    clear_adapters()


@pytest.fixture
def no_config_platforms(monkeypatch):
    """Make load_config return an object that says nothing about platforms."""

    class _Cfg:
        llm = None

    monkeypatch.setattr("vulnclaw.config.settings.load_config", lambda *a, **k: _Cfg())


class TestRegistration:
    def test_register_and_list(self, no_config_platforms):
        register_adapter(FakeAdapter("ctf2"))
        register_adapter(FakeAdapter("gcs"))
        assert registered_names() == ["ctf2", "gcs"]

    def test_reregistering_replaces(self, no_config_platforms):
        first = FakeAdapter("ctf2", configured=False)
        register_adapter(first)
        register_adapter(FakeAdapter("ctf2"))
        assert adapter_for("ctf2:practice:1") is not first

    def test_clear(self, no_config_platforms):
        register_adapter(FakeAdapter("ctf2"))
        clear_adapters()
        assert registered_names() == []

    @pytest.mark.parametrize("name", ["", "   ", "has:colon", "has space"])
    def test_bad_names_are_rejected(self, name):
        with pytest.raises(PlatformError):
            register_adapter(FakeAdapter(name))


class TestEnableSwitch:
    def test_falls_back_to_the_adapter_default_when_config_is_silent(
        self, no_config_platforms
    ):
        """CTF2 defaults on, GCS defaults off -- without either being special-cased."""
        assert is_enabled(FakeAdapter("ctf2", enabled_by_default=True)) is True
        assert is_enabled(FakeAdapter("gcs", enabled_by_default=False)) is False

    def test_explicit_setting_wins_over_the_default(self, monkeypatch):
        class _Entry:
            enabled = False

        class _Platforms:
            gcs = _Entry()

        class _Cfg:
            platforms = _Platforms()

        monkeypatch.setattr("vulnclaw.config.settings.load_config", lambda *a, **k: _Cfg())
        assert is_enabled(FakeAdapter("gcs", enabled_by_default=True)) is False

    def test_mapping_style_config_is_supported(self, monkeypatch):
        class _Cfg:
            platforms = {"gcs": {"enabled": True}}

        monkeypatch.setattr("vulnclaw.config.settings.load_config", lambda *a, **k: _Cfg())
        assert is_enabled(FakeAdapter("gcs", enabled_by_default=False)) is True

    def test_unknown_platform_in_config_does_not_affect_others(self, monkeypatch):
        class _Cfg:
            platforms = {"somethingelse": {"enabled": False}}

        monkeypatch.setattr("vulnclaw.config.settings.load_config", lambda *a, **k: _Cfg())
        assert is_enabled(FakeAdapter("ctf2", enabled_by_default=True)) is True

    def test_unreadable_config_fails_closed(self, monkeypatch):
        """Not being able to read the switch is no reason to expose the tools."""

        def _boom(*a, **k):
            raise RuntimeError("config exploded")

        monkeypatch.setattr("vulnclaw.config.settings.load_config", _boom)
        assert is_enabled(FakeAdapter("ctf2", enabled_by_default=True)) is False


class TestExposure:
    def test_enabled_and_configured_is_exposed(self, no_config_platforms):
        register_adapter(FakeAdapter("ctf2"))
        assert set(configured_adapters()) == {"ctf2"}

    def test_disabled_is_hidden(self, no_config_platforms):
        register_adapter(FakeAdapter("gcs", enabled_by_default=False))
        assert configured_adapters() == {}

    def test_unconfigured_is_hidden(self, no_config_platforms):
        register_adapter(FakeAdapter("ctf2", configured=False))
        assert configured_adapters() == {}

    def test_a_broken_adapter_does_not_take_the_face_down(self, no_config_platforms):
        register_adapter(FakeAdapter("broken", broken=True))
        register_adapter(FakeAdapter("ctf2"))
        assert set(configured_adapters()) == {"ctf2"}


class TestAdapterFor:
    def test_resolves_the_owning_adapter(self, no_config_platforms):
        register_adapter(FakeAdapter("ctf2"))
        assert adapter_for("ctf2:practice:12:345").name == "ctf2"

    def test_unknown_prefix_lists_what_is_registered(self, no_config_platforms):
        register_adapter(FakeAdapter("ctf2"))
        with pytest.raises(UnknownPlatform) as excinfo:
            adapter_for("gcs:exercise:1")
        message = str(excinfo.value)
        assert "ctf2" in message
        assert "platform_list" in message

    def test_bare_id_is_refused(self, no_config_platforms):
        """Decision Q2: a lone id is never guessed into a platform."""
        register_adapter(FakeAdapter("ctf2"))
        with pytest.raises(UnknownPlatform):
            adapter_for("345")

    def test_disabled_platform_says_so(self, no_config_platforms):
        register_adapter(FakeAdapter("gcs", enabled_by_default=False))
        with pytest.raises(PlatformNotConfigured) as excinfo:
            adapter_for("gcs:exercise:1")
        assert "disabled" in str(excinfo.value)

    def test_unconfigured_platform_says_so(self, no_config_platforms):
        register_adapter(FakeAdapter("ctf2", configured=False))
        with pytest.raises(PlatformNotConfigured) as excinfo:
            adapter_for("ctf2:practice:1")
        assert "credentials" in str(excinfo.value)

    def test_disabled_and_unconfigured_are_different_errors(self, no_config_platforms):
        """The operator's fix differs, so the messages must differ."""
        register_adapter(FakeAdapter("gcs", configured=False, enabled_by_default=False))
        with pytest.raises(PlatformNotConfigured) as excinfo:
            adapter_for("gcs:exercise:1")
        assert "disabled" in str(excinfo.value)


class TestCapabilities:
    def test_union_is_only_over_exposed_platforms(self, no_config_platforms):
        register_adapter(FakeAdapter("ctf2", caps=frozenset({CAP_SUBMISSIONS})))
        register_adapter(
            FakeAdapter(
                "gcs",
                enabled_by_default=False,
                caps=frozenset({CAP_EVENT_INFO, CAP_OVERVIEW}),
            )
        )
        assert capabilities() == frozenset({CAP_SUBMISSIONS})

    def test_hidden_platform_contributes_nothing(self, no_config_platforms):
        register_adapter(
            FakeAdapter("gcs", enabled_by_default=False, caps=frozenset({CAP_EVENT_INFO}))
        )
        assert capabilities() == frozenset()

    def test_union_across_two_exposed_platforms(self, no_config_platforms):
        register_adapter(FakeAdapter("ctf2", caps=frozenset({CAP_SUBMISSIONS})))
        register_adapter(FakeAdapter("gcs", caps=frozenset({CAP_OVERVIEW})))
        assert capabilities() == frozenset({CAP_SUBMISSIONS, CAP_OVERVIEW})


class TestDescribe:
    def test_empty_registry(self, no_config_platforms):
        assert "no adapters registered" in describe()

    def test_reports_state_and_reason(self, no_config_platforms):
        register_adapter(FakeAdapter("ctf2"))
        register_adapter(FakeAdapter("gcs", enabled_by_default=False))
        text = describe()
        assert "ctf2: exposed" in text
        assert "gcs: hidden" in text
        assert "platforms.gcs.enabled=false" in text
