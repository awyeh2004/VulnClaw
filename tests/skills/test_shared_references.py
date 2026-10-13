"""Shared-reference resolution: dedup without relaxing traversal containment.

TECH-DEBT.md #1: identical reference content was copied into each skill's
references/ (13 byte-identical groups, 4,167 wasted lines). Symlinks cannot
dedupe that — ``resolve_skill_reference`` follows symlinks and requires the
result to stay inside the skill's own references_dir, and that containment is
the control that stops a model-supplied ``ref_name`` from reading arbitrary
files. The shared mechanism therefore adds an *opt-in declaration* (frontmatter
``shared_references``, operator-authored) resolved against a fixed root with
the same containment check. These tests pin every leg of that contract.
"""

from __future__ import annotations

import pytest

from vulnclaw.skills import loader


@pytest.fixture()
def skill_env(tmp_path, monkeypatch):
    """One skill with own refs, a shared root, and a secret outside both."""
    own = tmp_path / "own" / "references"
    own.mkdir(parents=True)
    (own / "own-only.md").write_text("OWN ONLY", encoding="utf-8")
    (own / "override.md").write_text("OWN OVERRIDE", encoding="utf-8")

    shared = tmp_path / "shared-root"
    shared.mkdir()
    (shared / "shared-doc.md").write_text("SHARED CONTENT", encoding="utf-8")
    (shared / "undeclared.md").write_text("SHOULD BE UNREACHABLE", encoding="utf-8")
    (shared / "override.md").write_text("SHARED OVERRIDE", encoding="utf-8")

    (tmp_path / "secret.txt").write_text("TOP SECRET", encoding="utf-8")

    monkeypatch.setattr(loader, "_SHARED_REFERENCES_DIR", shared)

    def fake_load(name):
        return {
            "name": name,
            "references_dir": str(own),
            "shared_references": ["shared-doc.md", "override.md"],
        }

    monkeypatch.setattr(loader, "load_skill_by_name", fake_load)
    return own, shared


def test_own_reference_still_loads(skill_env):
    assert loader.load_skill_reference("sk", "own-only.md") == "OWN ONLY"


def test_declared_shared_reference_loads(skill_env):
    assert loader.load_skill_reference("sk", "shared-doc.md") == "SHARED CONTENT"


def test_own_copy_overrides_shared_same_name(skill_env):
    """The skill's own references/ wins, so a local copy can override shared."""
    assert loader.load_skill_reference("sk", "override.md") == "OWN OVERRIDE"


def test_undeclared_shared_file_is_not_reachable(skill_env):
    """A file in the shared root that the skill never declared must not load."""
    assert loader.load_skill_reference("sk", "undeclared.md") is None


@pytest.mark.parametrize(
    "evil",
    [
        "../secret.txt",
        "../../secret.txt",
        "shared-doc.md/../../secret.txt",
        "..\\secret.txt",
        "shared\\..\\..\\secret.txt",
    ],
)
def test_traversal_via_ref_name_stays_blocked(skill_env, evil):
    """Traversal must fail even for a skill that opted into shared references."""
    assert loader.load_skill_reference("sk", evil) is None


def test_skill_without_declaration_never_touches_shared(skill_env):
    """A skill dict without shared_references (e.g. legacy/flat) is unaffected."""
    own, _ = skill_env
    loader.load_skill_by_name = lambda name: {"name": name, "references_dir": str(own)}
    assert loader.load_skill_reference("sk", "shared-doc.md") is None
    assert loader.load_skill_reference("sk", "own-only.md") == "OWN ONLY"


def test_declaration_normalization_drops_unsafe_entries():
    raw = [
        "ok.md",                      # survives
        "nested/also-ok.md",          # survives
        "../evil.md",                 # parent traversal — dropped
        "/absolute.md",               # absolute — dropped
        "C:\\win.md",                 # drive — dropped
        "..\\win.md",                 # backslash traversal — dropped
        "a/./b.md",                   # '.' segments are collapsed, not unsafe
        "a/../b.md",                  # contains '..' — dropped
        "",                           # empty — dropped
        None,                         # non-string — dropped
        42,                           # non-string — dropped
    ]
    cleaned = loader._clean_shared_reference_names(raw)
    assert cleaned == ["ok.md", "nested/also-ok.md", "a/b.md"]


def test_declaration_rejects_non_list_frontmatter():
    assert loader._clean_shared_reference_names("ok.md") == []
    assert loader._clean_shared_reference_names(None) == []
    assert loader._clean_shared_reference_names({"a": 1}) == []


def test_directory_parse_advertises_existing_shared_only(tmp_path, monkeypatch):
    """The references list gains declared shared names that actually exist."""
    shared = tmp_path / "shared-root"
    shared.mkdir()
    (shared / "web-injection.md").write_text("X" * 10, encoding="utf-8")
    monkeypatch.setattr(loader, "_SHARED_REFERENCES_DIR", shared)

    skill_dir = tmp_path / "myskill"
    refs = skill_dir / "references"
    refs.mkdir(parents=True)
    (refs / "local.md").write_text("L", encoding="utf-8")
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: myskill\n"
        "description: t\n"
        "shared_references:\n"
        "  - web-injection.md\n"
        "  - missing-everywhere.md\n"
        "  - ../evil.md\n"
        "---\n"
        "body\n",
        encoding="utf-8",
    )

    parsed = loader._parse_skill_directory(skill_dir)
    assert "local.md" in parsed["references"]
    assert "web-injection.md" in parsed["references"]
    assert "missing-everywhere.md" not in parsed["references"]
    assert "../evil.md" not in parsed["shared_references"]
    assert parsed["shared_references"] == ["web-injection.md", "missing-everywhere.md"]


def test_directory_parse_without_declaration_is_unchanged(tmp_path, monkeypatch):
    """A skill that does not opt in keeps exactly its own reference list."""
    shared = tmp_path / "shared-root"
    shared.mkdir()
    (shared / "web-injection.md").write_text("X" * 10, encoding="utf-8")
    monkeypatch.setattr(loader, "_SHARED_REFERENCES_DIR", shared)

    skill_dir = tmp_path / "plain"
    refs = skill_dir / "references"
    refs.mkdir(parents=True)
    (refs / "local.md").write_text("L", encoding="utf-8")
    (skill_dir / "SKILL.md").write_text(
        "---\nname: plain\ndescription: t\n---\nbody\n", encoding="utf-8"
    )

    parsed = loader._parse_skill_directory(skill_dir)
    assert parsed["references"] == ["local.md"]
    assert parsed["shared_references"] == []


def test_shared_names_join_the_sorted_order(tmp_path, monkeypatch):
    """Shared references interleave with own files instead of trailing them.

    The prompt advertises only the first ten refs of this list
    (agent.skill_context), so appending shared names after the own files
    hides them from every skill with more own references than that window
    shows — client-reverse lost all nine android refs this way right after
    the dedup landed.
    """
    shared = tmp_path / "shared-root"
    shared.mkdir()
    (shared / "android-triage.md").write_text("S", encoding="utf-8")
    monkeypatch.setattr(loader, "_SHARED_REFERENCES_DIR", shared)

    skill_dir = tmp_path / "bigskill"
    refs = skill_dir / "references"
    refs.mkdir(parents=True)
    for i in range(10):
        (refs / f"z-own-{i:02d}.md").write_text("L", encoding="utf-8")
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: bigskill\n"
        "description: t\n"
        "shared_references:\n"
        "  - android-triage.md\n"
        "---\n"
        "body\n",
        encoding="utf-8",
    )

    parsed = loader._parse_skill_directory(skill_dir)
    assert parsed["references"].index("android-triage.md") == 0
    assert "android-triage.md" in parsed["references"][:10]
    assert parsed["references"] == sorted(
        parsed["references"], key=loader.reference_sort_key
    )


def test_real_library_reference_lists_stay_sorted():
    """Every real skill's advertised list obeys reference_sort_key.

    The sorted order is what makes the first-ten advertisement window
    deterministic across platforms (see reference_sort_key's own contract);
    any skill whose combined own+shared list breaks it regresses what the
    model gets to see.
    """
    from pathlib import Path

    pkg = Path(loader.__file__).parent
    checked = 0
    for sub in ("core", "specialized"):
        for skill_dir in sorted((pkg / sub).iterdir()):
            if not (skill_dir / "SKILL.md").is_file():
                continue
            refs = loader._parse_skill_directory(skill_dir)["references"]
            assert refs == sorted(refs, key=loader.reference_sort_key), (
                f"{skill_dir.name}: references not in reference_sort_key order"
            )
            checked += 1
    assert checked > 50, f"expected the package skills, found {checked}"
