"""Every skill's frontmatter must actually parse.

Why this exists (2026-11-26): rewriting six descriptions to the "Use when…"
trigger style silently broke all six — the new text contained a colon followed
by a space (``... inside a CTF: 有 URL ...``), which is illegal inside a YAML
plain scalar. ``yaml.safe_load`` raised ``ScannerError: mapping values are not
allowed here``, the loader caught it and fell back to defaults, so
``routing.target_types`` became ``[]`` and those skills stopped matching any
typed signal. Twelve routing tests failed, but the *cause* was invisible from
them: nothing said "this file's frontmatter is broken".

The fix was to use a block scalar (``description: >-``). This test makes the
failure mode loud at the source, for every skill, forever.
"""

from __future__ import annotations

import yaml

from vulnclaw.skills.loader import (
    list_core_skills,
    list_specialized_skills,
    load_skill_by_name,
)


def _all_skill_names() -> list[str]:
    return sorted(set(list_core_skills()) | set(list_specialized_skills()))


def test_there_are_skills_to_check():
    """A guard on the guard: an empty list would make every assertion vacuous."""
    assert len(_all_skill_names()) > 40


def test_every_frontmatter_block_parses_as_yaml():
    """A colon+space in an unquoted description breaks the whole block silently."""
    from pathlib import Path

    broken: list[str] = []
    for name in _all_skill_names():
        skill = load_skill_by_name(name)
        assert skill is not None, name
        path = Path(skill["path"]) if skill.get("path") else None
        if path is None or not path.is_file():
            continue
        raw = path.read_text(encoding="utf-8")
        if not raw.startswith("---"):
            continue
        block = raw.split("---", 2)[1]
        try:
            parsed = yaml.safe_load(block)
        except yaml.YAMLError as exc:  # noqa: PERF203 - one report per file
            broken.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        assert isinstance(parsed, dict), f"{name}: frontmatter is not a mapping"

    assert not broken, "unparseable frontmatter:\n" + "\n".join(broken)


def test_declared_routing_survives_the_round_trip():
    """A skill that declares routing must not come back with empty vocabularies.

    This is what the broken YAML actually cost: ``ctf-web`` read back as
    ``target_types=[] task_types=[]`` and silently stopped matching CTF goals.
    """
    from pathlib import Path

    lost: list[str] = []
    for name in _all_skill_names():
        skill = load_skill_by_name(name)
        path = Path(skill["path"]) if skill.get("path") else None
        if path is None or not path.is_file():
            continue
        raw = path.read_text(encoding="utf-8")
        if not raw.startswith("---"):
            continue
        try:
            declared = yaml.safe_load(raw.split("---", 2)[1]) or {}
        except yaml.YAMLError:
            continue  # the previous test owns that failure
        declared_routing = declared.get("routing") or {}
        loaded = skill.get("routing") or {}
        for field in ("target_types", "task_types"):
            want = list(declared_routing.get(field) or [])
            got = list(loaded.get(field) or [])
            if want and not got:
                lost.append(f"{name}.{field}: declared {want}, loaded {got}")

    assert not lost, "routing declared but lost in loading:\n" + "\n".join(lost)
