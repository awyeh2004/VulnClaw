"""Reference ordering must be platform-independent and entry-point-first.

Round-5 review N6: the list came from ``sorted(rglob())``, and ``Path``
comparison case-folds on Windows. ``book/INDEX.md`` therefore sorted before the
``book/ch*.md`` chapters on POSIX but after all of them on Windows — and because
the prompt embeds only the first ten refs, the doc a skill tells the model to
read first reached the system prompt on Linux and silently did not on Windows.
"""

from __future__ import annotations

import pytest

from vulnclaw.skills import loader


@pytest.fixture()
def skill_with_book(tmp_path):
    """A skill whose entry-point doc competes with a dozen chapters."""
    skill_dir = tmp_path / "chapters-skill"
    refs = skill_dir / "references"
    (refs / "book").mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: chapters-skill\n---\nbody\n", encoding="utf-8"
    )
    (refs / "book" / "INDEX.md").write_text("read me first", encoding="utf-8")
    for i in range(1, 15):
        (refs / "book" / f"ch{i:02d}-topic.md").write_text(f"chapter {i}", encoding="utf-8")
    (refs / "events").mkdir()
    for i in range(1, 7):
        (refs / "events" / f"ev{i}.md").write_text("event", encoding="utf-8")
    (refs / "casebook.md").write_text("cases", encoding="utf-8")
    return skill_dir


def test_entry_point_leads_the_list(skill_with_book):
    refs = loader._parse_skill_directory(skill_with_book)["references"]
    assert refs[0] == "book/INDEX.md"
    assert refs.index("book/INDEX.md") < refs.index("book/ch01-topic.md")


def test_entry_point_survives_the_prompt_slice(skill_with_book):
    """The bug's actual symptom: the [:10] slice the prompt uses dropped it."""
    refs = loader._parse_skill_directory(skill_with_book)["references"]
    assert len(refs) > 10
    assert "book/INDEX.md" in refs[:10]


def test_order_is_plain_string_order_not_path_order(skill_with_book):
    """A case-folding comparator is what broke it; the key must be the string."""
    refs = loader._parse_skill_directory(skill_with_book)["references"]
    assert refs == sorted(refs)
    assert refs == sorted(refs, key=loader.reference_sort_key)


@pytest.mark.parametrize(
    ("rel", "expected_entry"),
    [
        ("book/INDEX.md", True),
        ("README.md", True),
        ("00-overview.md", True),
        ("overview.md", True),
        ("10-system-basics.md", False),
        ("book/ch2-file-artifacts.md", False),
        ("events/webshell.md", False),
    ],
)
def test_entry_point_detection(rel, expected_entry):
    assert (loader.reference_sort_key(rel)[0] == 0) is expected_entry


def test_ordering_matches_a_case_sensitive_comparator():
    """Sanity: uppercase sorts before lowercase, as POSIX does."""
    pairs = ["book/INDEX.md", "book/ch01.md", "events/x.md", "casebook.md"]
    assert sorted(pairs, key=loader.reference_sort_key) == [
        "book/INDEX.md",
        "book/ch01.md",
        "casebook.md",
        "events/x.md",
    ]


def test_real_skill_keeps_its_index_in_the_prompt():
    """End-to-end against a shipped multi-chapter skill (skipped if absent)."""
    skill = loader.load_skill_by_name("incident-response")
    if skill is None:
        pytest.skip("incident-response skill not present in this checkout")
    refs = skill["references"]
    if "book/INDEX.md" not in refs:
        pytest.skip("this checkout has no book/INDEX.md")
    assert "book/INDEX.md" in refs[:10]
