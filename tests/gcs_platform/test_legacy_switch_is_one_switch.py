"""One switch means "expose the legacy per-platform tool names" -- not two.

`ctf2_*` and `gcs_*` are the same idea (legacy, platform-bound tool names that the
neutral `platform_*` face replaces). They were gated by two different fields:
`gcs.tools_enabled` for one, `competition.expose_legacy_tool_names` for the other.
Two knobs that mean the same thing is how one of them ends up contradicting the
other, so they are now one -- while the older field is still honoured, because a
rename that silently ignores an existing config is worse than the duplication.

Fail-closed behaviour is pinned too: a config error must not expose an irreversible
action's tool face.
"""

from __future__ import annotations

import pytest

from vulnclaw.gcs_platform import tools as gcs_tools


class _Cfg:
    def __init__(self, *, unified=False, legacy=False, competition=True, gcs=True):
        self.competition = type("C", (), {"expose_legacy_tool_names": unified})() if competition else None
        self.gcs = type("G", (), {"tools_enabled": legacy})() if gcs else None


@pytest.fixture
def config(monkeypatch):
    def _install(cfg):
        monkeypatch.setattr(
            "vulnclaw.config.settings.load_config", lambda *a, **k: cfg
        )

    return _install


class TestOneSwitch:
    def test_both_off_means_hidden(self, config):
        config(_Cfg())
        assert gcs_tools.gcs_tools_enabled() is False

    @pytest.mark.parametrize(
        ("unified", "legacy"),
        [(True, False), (False, True), (True, True)],
    )
    def test_either_field_turns_it_on(self, config, unified, legacy):
        """Honouring the old field is deliberate: existing configs keep working."""
        config(_Cfg(unified=unified, legacy=legacy))
        assert gcs_tools.gcs_tools_enabled() is True

    def test_the_unified_field_alone_is_enough(self, config):
        config(_Cfg(unified=True))
        assert gcs_tools.gcs_tools_enabled() is True

    def test_schemas_follow_the_switch(self, config):
        config(_Cfg())
        assert gcs_tools.gcs_tool_schemas() == []
        config(_Cfg(unified=True))
        names = {s["function"]["name"] for s in gcs_tools.gcs_tool_schemas()}
        assert names == set(gcs_tools.GCS_TOOL_NAMES)


class TestFailsClosed:
    def test_config_error_hides_the_face(self, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("config exploded")

        monkeypatch.setattr("vulnclaw.config.settings.load_config", boom)
        assert gcs_tools.gcs_tools_enabled() is False

    def test_missing_sections_hide_the_face(self, config):
        config(_Cfg(competition=False, gcs=False))
        assert gcs_tools.gcs_tools_enabled() is False

    def test_dispatch_is_unaffected_by_the_switch(self, config):
        """Same trap as the CTF2 face: hiding from the model must not break code."""
        config(_Cfg())
        assert set(gcs_tools.GCS_TOOL_NAMES_BY_SCHEMA) == set(gcs_tools.GCS_TOOL_NAMES)
