"""Skill reference loading must not escape the skill's references/ directory.

``load_skill_reference`` is a built-in tool whose ``reference_name`` argument is
model-supplied, so the old ``Path(references_dir) / ref_name`` join was a
path-traversal primitive (``../../../.vulnclaw/config.yaml``). Nested names such
as ``events/webshell.md`` are legitimate and must keep working; anything that
resolves outside ``references_dir`` must not.
"""

from __future__ import annotations

import pytest

from vulnclaw.skills import loader


@pytest.fixture()
def fake_skill(tmp_path, monkeypatch):
    """A skill whose references/ dir holds a top-level and a nested doc."""
    refs = tmp_path / "skills" / "fake-skill" / "references"
    (refs / "events").mkdir(parents=True)
    (refs / "top.md").write_text("TOP CONTENT", encoding="utf-8")
    (refs / "events" / "nested.md").write_text("NESTED CONTENT", encoding="utf-8")

    # A secret outside the references dir, i.e. what traversal would reach.
    (tmp_path / "secret.txt").write_text("TOP SECRET", encoding="utf-8")

    monkeypatch.setattr(
        loader,
        "load_skill_by_name",
        lambda name: {"name": name, "references_dir": str(refs)},
    )
    return refs


def test_toplevel_reference_still_loads(fake_skill):
    assert loader.load_skill_reference("fake-skill", "top.md") == "TOP CONTENT"


def test_nested_reference_still_loads(fake_skill):
    """Nested relative paths are a documented shape, not an anomaly."""
    assert loader.load_skill_reference("fake-skill", "events/nested.md") == "NESTED CONTENT"


@pytest.mark.parametrize(
    "evil",
    [
        "../secret.txt",
        "../../secret.txt",
        "events/../../secret.txt",
        "events/../secret.txt",
        "..\\secret.txt",
        "events\\..\\..\\secret.txt",
        "./../secret.txt",
        "top.md/../../secret.txt",
    ],
)
def test_relative_traversal_is_blocked(fake_skill, evil):
    assert loader.load_skill_reference("fake-skill", evil) is None


def test_absolute_path_is_blocked(fake_skill, tmp_path):
    secret = tmp_path / "secret.txt"
    assert loader.load_skill_reference("fake-skill", str(secret)) is None
    assert loader.load_skill_reference("fake-skill", "/etc/passwd") is None


def test_nul_byte_is_blocked(fake_skill):
    assert loader.load_skill_reference("fake-skill", "top.md\x00.txt") is None


def test_directory_is_not_a_reference(fake_skill):
    assert loader.load_skill_reference("fake-skill", "events") is None
    assert loader.load_skill_reference("fake-skill", ".") is None
    assert loader.load_skill_reference("fake-skill", "") is None


def test_escaping_symlink_is_blocked(fake_skill, tmp_path):
    """resolve() must follow links, so a planted symlink cannot step outside."""
    link = fake_skill / "escape.md"
    try:
        link.symlink_to(tmp_path / "secret.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available in this environment")
    assert loader.load_skill_reference("fake-skill", "escape.md") is None


def test_symlink_inside_references_still_works(fake_skill):
    link = fake_skill / "alias.md"
    try:
        link.symlink_to(fake_skill / "top.md")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available in this environment")
    assert loader.load_skill_reference("fake-skill", "alias.md") == "TOP CONTENT"


def test_missing_reference_returns_none(fake_skill):
    assert loader.load_skill_reference("fake-skill", "nope.md") is None


def test_unknown_skill_returns_none(monkeypatch):
    monkeypatch.setattr(loader, "load_skill_by_name", lambda name: None)
    assert loader.load_skill_reference("ghost", "top.md") is None


def test_real_skill_traversal_is_blocked():
    """Regression against a shipped skill: the escape must fail end-to-end."""
    assert loader.load_skill_reference("client-reverse", "../../../pyproject.toml") is None
    assert loader.load_skill_reference("client-reverse", "..\\..\\..\\pyproject.toml") is None
