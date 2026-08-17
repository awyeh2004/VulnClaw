"""Tests for user language preference persistence and language detection.

Covers the regression introduced by the upstream bilingual merge: before the
merge the language default was zh; after it, sessions with no explicit env
var / config silently fell back to en, so a user who had chosen Chinese lost
it. The fixes persist an explicit preference and default back to zh.
"""

from __future__ import annotations

import os


def _isolated_config_dir(monkeypatch, tmp_path) -> str:
    os.environ.pop("VULNCLAW_LANG", None)
    os.environ.pop("LANG", None)
    monkeypatch.setenv("VULNCLAW_CONFIG_DIR", str(tmp_path))
    return str(tmp_path)


def test_default_language_is_zh_without_env_or_pref(monkeypatch, tmp_path):
    _isolated_config_dir(monkeypatch, tmp_path)
    from vulnclaw.i18n import I18nLoader

    assert I18nLoader.detect_language() == "zh"


def test_environment_variable_overrides_preference(monkeypatch, tmp_path):
    _isolated_config_dir(monkeypatch, tmp_path)
    from vulnclaw.i18n import I18nLoader, set_language_pref

    set_language_pref("zh")
    monkeypatch.setenv("VULNCLAW_LANG", "en")
    assert I18nLoader.detect_language() == "en"


def test_persisted_preference_survives_and_drives_detection(monkeypatch, tmp_path):
    _isolated_config_dir(monkeypatch, tmp_path)
    import importlib

    from vulnclaw.i18n import I18nLoader, set_language_pref

    set_language_pref("en")
    assert I18nLoader.detect_language() == "en"
    # Simulate a fresh process: drop globals, reload, preference file remains.
    monkeypatch.delattr(I18nLoader, "detect_language", raising=False)
    import vulnclaw.i18n as i18n_mod

    i18n_mod._translator = None
    importlib.reload(i18n_mod)
    assert i18n_mod.I18nLoader.detect_language() == "en"
    set_language_pref("zh")
    assert i18n_mod.I18nLoader.detect_language() == "zh"


def test_set_language_pref_ignores_invalid_values(monkeypatch, tmp_path):
    _isolated_config_dir(monkeypatch, tmp_path)
    from vulnclaw.i18n import get_language_pref, set_language_pref

    set_language_pref("fr")
    set_language_pref("")
    assert get_language_pref() is None