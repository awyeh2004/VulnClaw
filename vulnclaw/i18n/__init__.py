"""Internationalization support for VulnClaw."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

# User language preference is persisted across sessions so an explicit
# choice (e.g. /language zh, or "回答请用中文") survives restarts instead of
# being forgotten. The pref file lives next to the config dir; it is a tiny
# plain-text file (just "zh" or "en") that i18n can read without importing
# config.settings (avoiding a dependency cycle).
def _language_pref_file() -> Path:
    config_dir = Path(os.environ.get("VULNCLAW_CONFIG_DIR", str(Path.home() / ".vulnclaw")))
    return config_dir / "language_pref"


def get_language_pref() -> Optional[str]:
    """Return the persisted user language preference, if any."""
    try:
        pref = _language_pref_file().read_text(encoding="utf-8").strip().lower()
    except (OSError, UnicodeError):
        return None
    return pref if pref in ("zh", "en") else None


def set_language_pref(lang: str) -> None:
    """Persist the user language preference so later sessions remember it."""
    lang = str(lang or "").strip().lower()
    if lang not in ("zh", "en"):
        return
    try:
        _language_pref_file().parent.mkdir(parents=True, exist_ok=True)
        _language_pref_file().write_text(lang, encoding="utf-8")
    except OSError:
        logging.getLogger(__name__).warning("Failed to persist language preference.")


def _detect_system_locale() -> Optional[str]:
    """Detect the OS UI language on Windows (and best-effort on POSIX).

    Returns 'zh' for a Chinese UI system, 'en' for an English one, else None.
    """
    if os.name == "nt":
        try:
            import ctypes

            primary = ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0xFF
            if primary == 0x04:  # LANG_CHINESE
                return "zh"
            if primary == 0x09:  # LANG_ENGLISH
                return "en"
        except (AttributeError, OSError):
            pass
        try:
            import locale

            code, _ = locale.getdefaultlocale()
            if code:
                if code.lower().startswith("zh"):
                    return "zh"
                if code.lower().startswith("en"):
                    return "en"
        except Exception:
            pass
        return None
    return None


class I18nLoader:
    """Load and manage translations."""

    def __init__(self, lang: str = "zh") -> None:
        self.lang = lang
        self.translations: dict[str, str] = {}
        self.logger = logging.getLogger(__name__)
        self._load_translations()

    def _get_lang_dir(self) -> str:
        """Get the directory containing language files."""
        return os.path.join(os.path.dirname(__file__))

    def _load_translations(self) -> None:
        """Load translations from JSON file."""
        lang_file = os.path.join(self._get_lang_dir(), f"{self.lang}.json")
        fallback_file = os.path.join(self._get_lang_dir(), "en.json")

        try:
            with open(lang_file, "r", encoding="utf-8") as f:
                self.translations = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            try:
                with open(fallback_file, "r", encoding="utf-8") as f:
                    self.translations = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError, PermissionError, OSError) as e:
                self.logger.warning(
                    "Failed to load fallback translation file '%s': %s. "
                    "Translations will be empty.",
                    fallback_file, type(e).__name__,
                )
                self.translations = {}

    def t(self, key: str, **kwargs: Any) -> str:
        """Translate a key to current language.

        Args:
            key: Translation key
            **kwargs: Placeholder values for template strings

        Returns:
            Translated string with placeholders replaced
        """
        text = self.translations.get(key, key)
        if kwargs:
            try:
                text = text.format(**kwargs)
            except KeyError:
                pass
        return text

    @staticmethod
    def detect_language() -> str:
        """Detect language from environment, persisted preference, or the OS.

        Priority:
        1. VULNCLAW_LANG environment variable
        2. Persisted user preference (~/.vulnclaw/language_pref)
        3. LANG environment variable
        4. OS UI locale (Windows: GetUserDefaultUILanguage)
        5. Default to 'zh' (VulnClaw is a Chinese-first project).
        """
        # Check VulnClaw specific env var
        lang_env = os.environ.get("VULNCLAW_LANG", "").lower()
        if lang_env in ("zh", "en"):
            return lang_env

        # Check persisted user preference (explicit /language switch, or a
        # mid-session "用中文回答" directive recorded by the agent).
        pref = get_language_pref()
        if pref in ("zh", "en"):
            return pref

        # Check system LANG
        system_lang = os.environ.get("LANG", "").lower()
        if system_lang.startswith("zh"):
            return "zh"
        elif system_lang.startswith("en"):
            return "en"

        # Check the OS UI locale so a Chinese Windows user gets zh without
        # needing any env var or config change.
        system_locale = _detect_system_locale()
        if system_locale in ("zh", "en"):
            return system_locale

        # Default to Chinese: this is the pre-upstream-merge behavior and the
        # project's native language. Explicit env vars / config / pref file
        # all override it above.
        return "zh"


# Global translator instance
_translator: Optional[I18nLoader] = None


def init_i18n(lang: Optional[str] = None, config: Any = None) -> I18nLoader:
    """Initialize the global translator.

    Args:
        lang: Explicit language override (zh/en)
        config: VulnClaw config object with session.language setting
    """
    global _translator
    if lang is None:
        # Try config first
        if config is not None and hasattr(config, "session"):
            session_lang = getattr(config.session, "language", "auto")
            if session_lang and session_lang != "auto":
                lang = session_lang
        # Fall back to auto-detection
        if lang is None or lang == "auto":
            lang = I18nLoader.detect_language()
    _translator = I18nLoader(lang)
    return _translator


def _(key: str, **kwargs: Any) -> str:
    """Translate a key using the global translator."""
    if _translator is None:
        init_i18n()
    return _translator.t(key, **kwargs)


def current_lang() -> str:
    """Return the active UI language code ('zh' or 'en').

    Initializes the global translator via auto-detection if it has not been
    set up yet, so callers outside the CLI (report generation, prompt
    assembly) get a sensible language without an explicit init.
    """
    if _translator is None:
        init_i18n()
    return _translator.lang


def reset_i18n() -> None:
    """Drop the global translator so the next use auto-detects again.

    Test helper, mirroring ``exec_gate.reset_execution_gate`` and
    ``submit_guard.reset_guard``. The module holds process-wide mutable state
    (``_translator``) and there was no way to clear it, so a test that called
    ``init_i18n("en")`` without restoring left every later test pinned to English.
    That produced a *non-deterministic* full-suite failure -- a different handful
    of language-sensitive tests failed on each run, including the KB language
    gate, depending on which test happened to have run last.
    """
    global _translator
    _translator = None

