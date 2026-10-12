"""No byte-identical reference copies across skills (TECH-DEBT.md #1 guard).

The 13 duplicate groups (4,167 wasted lines) were deduplicated by moving each
shared file into ``skills/_shared/references/`` and declaring it in the using
skills' frontmatter (``shared_references``). Copies creep back easily — a new
skill is assembled by copying an existing one — so this test fails on ANY two
byte-identical files under the package skills' ``references/`` trees,
including a private copy of a file that already lives in ``_shared``. When it
fires, the fix is not an exception here: declare the name and delete the copy.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path

import pytest

SKILLS_PACKAGE = Path(__file__).resolve().parents[2] / "vulnclaw" / "skills"


def _reference_files() -> list[Path]:
    # Every */references/ tree inside the package skills, _shared/references
    # included — the shared root is the ONE allowed home for shared content,
    # so a duplicate of it anywhere is exactly what this test exists to catch.
    return [
        p
        for p in SKILLS_PACKAGE.rglob("*")
        if p.is_file() and p.suffix in (".md", ".yaml", ".yml") and "references" in p.parts
    ]


def test_reference_files_exist():
    files = _reference_files()
    assert len(files) > 100, f"expected the skills package's references, got {len(files)}"


def test_no_byte_identical_reference_copies():
    by_hash: dict[str, list[Path]] = defaultdict(list)
    for path in _reference_files():
        by_hash[hashlib.sha256(path.read_bytes()).hexdigest()].append(path)

    duplicates = {
        digest: paths for digest, paths in by_hash.items() if len(paths) > 1
    }
    if duplicates:
        details = "\n".join(
            f"  {len(paths)} identical copies:"
            + "".join(f"\n    - {p.relative_to(SKILLS_PACKAGE)}" for p in paths)
            for paths in duplicates.values()
        )
        pytest.fail(
            "Byte-identical reference files found. Shared content belongs in "
            "vulnclaw/skills/_shared/references/ with the using skills declaring "
            f"it via frontmatter `shared_references`:\n{details}"
        )
