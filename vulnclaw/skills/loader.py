"""VulnClaw Skill Loader — load and parse Skill definition files.

Supports two Skill formats:
- Directory format: <skill_name>/SKILL.md + <skill_name>/references/
- Flat file format: <skill_name>.md (legacy, auto-migrated)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from vulnclaw.config.settings import SKILLS_DIR

# ── Built-in skills directory ───────────────────────────────────────

_CORE_SKILLS_DIR = Path(__file__).parent / "core"
_SPECIALIZED_SKILLS_DIR = Path(__file__).parent / "specialized"

# A skill name is a single directory entry, never a path. ``skill_name`` reaches
# this module straight from the model (the ``load_skill_reference`` tool), and
# ``skills/<name>/SKILL.md`` with an unvalidated name is a path-traversal
# primitive: ``skill_name="../../../tmp/evil"`` would anchor the references
# directory to any directory on disk that happens to contain SKILL.md +
# references/, which would also defeat the containment check in
# :func:`resolve_skill_reference` (it would be checking against an
# attacker-chosen root).
_SKILL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def is_valid_skill_name(name: str) -> bool:
    """True when ``name`` is a plausible single-component skill name."""
    value = str(name or "").strip()
    return bool(value) and _SKILL_NAME_RE.match(value) is not None


def _is_directory_skill(path: Path) -> bool:
    """Check if a path is a directory-format skill (has SKILL.md)."""
    return path.is_dir() and (path / "SKILL.md").exists()


def _is_flat_skill(path: Path) -> bool:
    """Check if a path is a flat-file skill (.md file directly)."""
    return path.is_file() and path.suffix == ".md"


def load_core_skill(name: str) -> Optional[dict[str, Any]]:
    """Load a core skill by name.

    Args:
        name: Skill name, e.g. "pentest-flow"

    Returns:
        Dict with keys: name, description, content, path, references
        Or None if not found.
    """
    if not is_valid_skill_name(name):
        return None
    # Try directory format first
    skill_dir = _CORE_SKILLS_DIR / name
    if _is_directory_skill(skill_dir):
        return _parse_skill_directory(skill_dir)

    # Fall back to flat file format
    skill_file = _CORE_SKILLS_DIR / f"{name}.md"
    if _is_flat_skill(skill_file):
        return _parse_skill_file(skill_file)

    return None


def load_specialized_skill(name: str) -> Optional[dict[str, Any]]:
    """Load a specialized skill by name."""
    if not is_valid_skill_name(name):
        return None
    # Try directory format first
    skill_dir = _SPECIALIZED_SKILLS_DIR / name
    if _is_directory_skill(skill_dir):
        return _parse_skill_directory(skill_dir)

    # Fall back to flat file format
    skill_file = _SPECIALIZED_SKILLS_DIR / f"{name}.md"
    if _is_flat_skill(skill_file):
        return _parse_skill_file(skill_file)

    return None


def load_custom_skill(name: str) -> Optional[dict[str, Any]]:
    """Load a user custom skill by name."""
    if not is_valid_skill_name(name):
        return None
    # Try directory format first
    skill_dir = SKILLS_DIR / name
    if _is_directory_skill(skill_dir):
        return _parse_skill_directory(skill_dir)

    # Fall back to flat file format
    skill_file = SKILLS_DIR / f"{name}.md"
    if _is_flat_skill(skill_file):
        return _parse_skill_file(skill_file)

    return None


def list_core_skills() -> list[str]:
    """List all available core skill names."""
    if not _CORE_SKILLS_DIR.exists():
        return []
    names = set()
    for child in _CORE_SKILLS_DIR.iterdir():
        if _is_directory_skill(child):
            names.add(child.name)
        elif _is_flat_skill(child) and child.suffix == ".md":
            names.add(child.stem)
    return sorted(names)


def list_specialized_skills() -> list[str]:
    """List all available specialized skill names."""
    if not _SPECIALIZED_SKILLS_DIR.exists():
        return []
    names = set()
    for child in _SPECIALIZED_SKILLS_DIR.iterdir():
        if _is_directory_skill(child):
            names.add(child.name)
        elif _is_flat_skill(child) and child.suffix == ".md":
            names.add(child.stem)
    return sorted(names)


def list_custom_skills() -> list[str]:
    """List all available custom skill names."""
    if not SKILLS_DIR.exists():
        return []
    names = set()
    for child in SKILLS_DIR.iterdir():
        if _is_directory_skill(child):
            names.add(child.name)
        elif _is_flat_skill(child) and child.suffix == ".md":
            names.add(child.stem)
    return sorted(names)


def load_skill_by_name(name: str) -> Optional[dict[str, Any]]:
    """Load a skill by name, searching core → specialized → custom."""
    for loader in [load_core_skill, load_specialized_skill, load_custom_skill]:
        result = loader(name)
        if result:
            return result
    return None


# ── reference ordering ──────────────────────────────────────────────
#
# Two properties the prompt depends on, both from the round-5 review:
#
# 1. **Platform-independent.** The list used to come from ``sorted(rglob())``, and
#    comparing ``Path`` objects case-folds on Windows: ``book/INDEX.md`` sorted
#    AFTER every ``book/ch*.md`` there but BEFORE it on POSIX. Since the prompt
#    shows only the first ten refs, the file a skill tells the model to read first
#    ("read INDEX.md before the chapters") reached the system prompt on Linux and
#    silently did not on Windows. Sorting the POSIX relative *string* makes the
#    order identical everywhere.
# 2. **Entry points first.** Whatever the truncation, a doc named as the entry
#    point keeps a slot instead of competing with 13 chapters.
_ENTRY_POINT_RE = re.compile(r"^(index|readme|overview|contents|00[-_].*)$", re.IGNORECASE)


def reference_sort_key(rel_path: str) -> tuple[int, str]:
    """Sort key for a references/-relative POSIX path (entry points, then ASCII)."""
    name = str(rel_path or "").rsplit("/", 1)[-1]
    stem = name.rsplit(".", 1)[0] if "." in name else name
    is_entry = bool(_ENTRY_POINT_RE.match(stem))
    return (0 if is_entry else 1, str(rel_path or ""))


def _parse_skill_directory(skill_dir: Path) -> dict[str, Any]:
    """Parse a directory-format skill.

    Directory structure:
        <skill_name>/
        ├── SKILL.md          (required)
        └── references/       (optional, may contain subdirectories)
            ├── ref1.md
            ├── ref2.md
            └── events/       (nested groups, e.g. per-event-type docs)
                └── ref3.md

    Reference names are returned as POSIX-style paths relative to
    ``references/`` — a top-level file keeps its bare name (``ref1.md``)
    while a nested one is prefixed with its group (``events/ref3.md``).
    :func:`load_skill_reference` joins the name onto ``references_dir``,
    so both forms resolve.
    """
    skill_file = skill_dir / "SKILL.md"
    result = _parse_skill_file(skill_file)

    # Collect reference files (recursive so skills can group references
    # into subdirectories without renaming them).
    references_dir = skill_dir / "references"
    ref_files: list[str] = []
    if references_dir.exists() and references_dir.is_dir():
        collected = [
            ref.relative_to(references_dir).as_posix()
            for ref in references_dir.rglob("*")
            if ref.is_file() and ref.suffix in (".md", ".yaml", ".yml")
        ]
        collected.sort(key=reference_sort_key)
        ref_files.extend(collected)

    result["references"] = ref_files
    result["references_dir"] = str(references_dir)
    result["skill_dir"] = str(skill_dir)
    result["format"] = "directory"

    return result


def _parse_skill_file(path: Path) -> dict[str, Any]:
    """Parse a skill markdown file.

    Skill files use a simple format:
    - Optional YAML frontmatter (between --- markers)
    - Markdown body with skill content
    """
    content = path.read_text(encoding="utf-8")
    name = path.stem if path.name != "SKILL.md" else path.parent.name

    # Parse optional frontmatter
    description = ""
    # Whether a preset scan target is required before the skill can launch.
    # Self-discovering skills (e.g. ``hackerone``, which reads its target from a
    # scope link) set ``requires_target: false`` in frontmatter to launch
    # target-less. Defaults to True so every existing skill is unchanged.
    requires_target = True
    # Optional typed routing metadata (see vulnclaw.skills.routing). Kept as the
    # raw frontmatter mapping here; the resolver normalizes/validates it into a
    # ``SkillRouting`` model so the loader stays free of routing-schema imports.
    routing: dict[str, Any] = {}
    body = content

    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            import yaml

            try:
                frontmatter = yaml.safe_load(parts[1])
                if isinstance(frontmatter, dict):
                    description = frontmatter.get("description", "")
                    name = frontmatter.get("name", name)
                    # Only an explicit boolean ``false`` opts out of the target
                    # gate. Any other value (missing, null, 0, "false", …) keeps
                    # the safe default so malformed frontmatter can't silently
                    # bypass the authorized-target check.
                    rt = frontmatter.get("requires_target", True)
                    requires_target = rt if isinstance(rt, bool) else True
                    raw_routing = frontmatter.get("routing")
                    if isinstance(raw_routing, dict):
                        routing = raw_routing
            except yaml.YAMLError:
                pass
            body = parts[2].strip()

    return {
        "name": name,
        "description": description,
        "content": body,
        "path": str(path),
        "requires_target": requires_target,
        "routing": routing,
        "references": [],
        "references_dir": "",
        "skill_dir": str(path.parent) if path.name == "SKILL.md" else "",
        "format": "directory" if path.name == "SKILL.md" else "flat",
    }


def resolve_skill_reference(skill_name: str, ref_name: str) -> Optional[Path]:
    """Resolve ``ref_name`` to a file *inside* the skill's references directory.

    ``ref_name`` is model-supplied (``load_skill_reference`` is a built-in tool),
    so a bare ``Path(references_dir) / ref_name`` join is a path-traversal
    primitive: ``../../.vulnclaw/config.yaml`` would read any file the process
    can read, including API keys. Nested names (``events/webshell.md``) are a
    legitimate, documented shape, so the join is allowed but the *result* must
    still land under ``references_dir`` after symlink resolution.

    Returns the resolved path, or None when the name escapes the directory,
    is not a regular file, or does not exist.
    """
    skill = load_skill_by_name(skill_name)
    if not skill or not skill.get("references_dir"):
        return None

    try:
        ref_dir = Path(skill["references_dir"]).resolve()
        # resolve() also collapses ``..`` and follows symlinks, so a link
        # planted inside references/ cannot be used to step outside either.
        candidate = (ref_dir / str(ref_name)).resolve()
    except (OSError, ValueError, RuntimeError):
        # ValueError covers embedded NUL bytes; RuntimeError covers symlink loops.
        return None

    if candidate != ref_dir and ref_dir not in candidate.parents:
        return None
    if not candidate.is_file():
        return None
    return candidate


def load_skill_reference(skill_name: str, ref_name: str) -> Optional[str]:
    """Load a reference file from a skill's references directory.

    Args:
        skill_name: The skill name
        ref_name: The reference file name (e.g. "02-client-api-reverse-and-burp.md",
            or a nested relative path such as "events/webshell.md")

    Returns:
        The reference file content as string, or None if not found.
    """
    ref_path = resolve_skill_reference(skill_name, ref_name)
    if ref_path is None:
        return None
    try:
        return ref_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
