from __future__ import annotations

import json
from pathlib import Path
from string import Formatter


def _catalog(language: str) -> dict[str, str]:
    path = Path(__file__).resolve().parents[2] / "vulnclaw" / "i18n" / f"{language}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _placeholders(template: str) -> set[str]:
    return {
        field_name
        for _, field_name, _, _ in Formatter().parse(template)
        if field_name is not None
    }


def test_agent_translation_catalogs_have_matching_keys_and_placeholders():
    english = {key: value for key, value in _catalog("en").items() if key.startswith("agent.")}
    chinese = {key: value for key, value in _catalog("zh").items() if key.startswith("agent.")}

    assert english.keys() == chinese.keys()
    assert {
        key: (_placeholders(english[key]), _placeholders(chinese[key]))
        for key in english
        if _placeholders(english[key]) != _placeholders(chinese[key])
    } == {}
