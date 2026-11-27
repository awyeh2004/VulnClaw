#!/usr/bin/env python3
"""Static lint for the shipped skill library.

The runtime loader is deliberately forgiving: an unparseable frontmatter block
falls back to an empty description, invalid ``shared_references`` entries are
dropped, and unknown routing tokens only surface through the resolver's
warnings. Forgiving at runtime is correct — a broken skill must not crash the
agent — but it is silent, and the failures are invisible in review.

This linter is the strict, batch counterpart. It runs in CI and fails on the
things that would otherwise degrade silently:

- frontmatter that YAML cannot parse (``competition-mode`` shipped this way:
  an unquoted ``CTF: ...`` killed the whole block, including routing and
  ``requires_target: false``)
- name/description shape, duplicate names, ``name`` != directory name
- oversized bodies (the prompt injects at most 48k chars)
- a directory skill with no reachable reference
- a declared shared reference that does not exist
- routing tokens outside the typed vocabulary (the resolver would only warn)
- workflow phase tables: parse warnings (duplicate ids, dangling gates,
  unknown modes) and tool names that do not exist in the builtin/declared
  external tool face (typos in a phase table used to be silent)
- high-confidence secret patterns and host-specific paths in shipped text

Usage:
    python scripts/lint_skills.py [--skills-dir PATH] [--strict]

Exit code 1 when any error is present (or any warning with ``--strict``).
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yaml

from vulnclaw.skills.loader import _clean_shared_reference_names, is_valid_skill_name
from vulnclaw.skills.routing import SkillRouting

SKILLS_DIR = REPO_ROOT / "vulnclaw" / "skills"
SHARED_REFERENCES_DIRNAME = Path("_shared") / "references"

MAX_DESCRIPTION_CHARS = 1024
MAX_BODY_CHARS = 48_000
WARN_BODY_CHARS = 20_000

# High-confidence, low-false-positive patterns. Payload docs legitimately
# contain example tokens (``evil.example``); these patterns do not match those.
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private-key-block": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "github-pat": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "stripe-live-key": re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"),
}

HOST_PATH_RE = re.compile(
    r"(?:C:[\\/]Users[\\/]([A-Za-z0-9_.<>-]+)|/home/([A-Za-z0-9_.<>-]+)/)"
)
# Example placeholders that are safe in documentation.
HOST_PATH_PLACEHOLDERS = {
    "user",
    "users",
    "me",
    "ctf",
    "you",
    "your_user",
    "username",
    "<user>",
    "ctf-user",
}

#: Tools provided by an MCP server / operator config rather than the builtin
#: schema builder. Shipped workflows may reference these names; add here when a
#: new default MCP tool becomes part of a shipped workflow.
EXTERNAL_TOOL_NAMES = frozenset({"fetch"})

_KNOWN_TOOL_NAMES: Optional[set[str]] = None


def known_tool_names() -> Optional[set[str]]:
    """Builtin + external tool names, or None when the agent import is unavailable."""
    global _KNOWN_TOOL_NAMES
    if _KNOWN_TOOL_NAMES is None:
        try:
            from vulnclaw.agent.builtin_tools import build_openai_tools
        except Exception:
            return None
        names = {tool["function"]["name"] for tool in build_openai_tools(None)}
        _KNOWN_TOOL_NAMES = names | set(EXTERNAL_TOOL_NAMES)
    return _KNOWN_TOOL_NAMES


SCANNED_SUFFIXES = {".md", ".yaml", ".yml"}


@dataclass(frozen=True)
class Issue:
    level: str  # "error" | "warning"
    rule: str
    path: Path
    line: int
    message: str

    def render(self, root: Path) -> str:
        try:
            rel = self.path.relative_to(root)
        except ValueError:
            rel = self.path
        where = f"{rel}:{self.line}" if self.line else str(rel)
        return f"{self.level.upper()} {where} [{self.rule}] {self.message}"


def _error(rule: str, path: Path, line: int, message: str) -> Issue:
    return Issue("error", rule, path, line, message)


def _warning(rule: str, path: Path, line: int, message: str) -> Issue:
    return Issue("warning", rule, path, line, message)


def _split_frontmatter(text: str) -> tuple[Optional[str], str, int]:
    """Return (frontmatter_text, body_text, body_first_line).

    ``frontmatter_text`` is None when the file has no complete ``---`` block.
    """
    if not text.startswith("---"):
        return None, text, 1
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None, text, 1
    frontmatter = parts[1]
    body = parts[2]
    body_first_line = 2 + frontmatter.count("\n") + 1
    return frontmatter, body, body_first_line


def _iter_skill_files(skills_dir: Path) -> Iterable[Path]:
    for path in sorted(skills_dir.rglob("*.md")):
        parts = path.relative_to(skills_dir).parts
        if "references" in parts or "_shared" in parts:
            continue
        if path.name == "SKILL.md" or path.parent.name == "core":
            yield path


def _own_reference_files(skill_path: Path) -> list[Path]:
    refs_dir = skill_path.parent / "references"
    if not refs_dir.is_dir():
        return []
    return [p for p in refs_dir.rglob("*") if p.is_file() and p.suffix in SCANNED_SUFFIXES]


def lint_skill(path: Path, skills_dir: Path, seen_names: dict[str, Path]) -> list[Issue]:
    issues: list[Issue] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [_error("E000", path, 1, f"cannot read file: {exc}")]

    frontmatter_text, body, body_line = _split_frontmatter(text)
    if frontmatter_text is None:
        issues.append(_error("E001", path, 1, "missing or unterminated '---' frontmatter block"))
        frontmatter: dict = {}
    else:
        try:
            loaded = yaml.safe_load(frontmatter_text)
        except yaml.YAMLError as exc:
            detail = str(exc).replace("\n", " ")
            issues.append(_error("E001", path, 2, f"frontmatter is not valid YAML: {detail}"))
            loaded = None
        if loaded is None:
            frontmatter = {}
        elif not isinstance(loaded, dict):
            issues.append(_error("E001", path, 2, "frontmatter must be a mapping"))
            frontmatter = {}
        else:
            frontmatter = loaded

    expected_name = path.parent.name if path.name == "SKILL.md" else path.stem
    raw_name = frontmatter.get("name")
    if not isinstance(raw_name, str) or not raw_name.strip():
        issues.append(_error("E002", path, 2, f"missing 'name' (expected {expected_name!r})"))
    else:
        name = raw_name.strip()
        if not is_valid_skill_name(name):
            issues.append(
                _error("E002", path, 2, f"name {name!r} does not match the skill-name grammar")
            )
        elif name != expected_name:
            issues.append(
                _error("E002", path, 2, f"name {name!r} != directory/file name {expected_name!r}")
            )
        other = seen_names.get(name)
        if other is not None and other != path:
            issues.append(
                _error("E004", path, 2, f"duplicate skill name {name!r} (also {other})")
            )
        else:
            seen_names[name] = path

    raw_description = frontmatter.get("description")
    if not isinstance(raw_description, str) or not raw_description.strip():
        issues.append(_error("E003", path, 2, "missing or empty 'description'"))
    elif len(raw_description) > MAX_DESCRIPTION_CHARS:
        issues.append(
            _error(
                "E003",
                path,
                2,
                f"description is {len(raw_description)} chars "
                f"(max {MAX_DESCRIPTION_CHARS})",
            )
        )

    if "requires_target" in frontmatter and not isinstance(
        frontmatter["requires_target"], bool
    ):
        issues.append(
            _error("E010", path, 2, "'requires_target' must be a boolean")
        )

    raw_routing = frontmatter.get("routing")
    if raw_routing is not None:
        if not isinstance(raw_routing, dict):
            issues.append(_error("E008", path, 2, "'routing' must be a mapping"))
        else:
            routing = SkillRouting.model_validate(raw_routing)
            for warning in routing.warnings:
                issues.append(_error("E008", path, 2, warning))

    raw_workflow = frontmatter.get("workflow")
    if raw_workflow is not None:
        from vulnclaw.skills.workflow import parse_workflow

        workflow = parse_workflow(raw_workflow)
        if workflow is None:
            issues.append(_error("E012", path, 2, "'workflow' must be a mapping"))
        else:
            for warning in workflow.warnings:
                issues.append(_error("E012", path, 2, f"workflow: {warning}"))
            known = known_tool_names()
            if known is not None:
                unknown = sorted(
                    {
                        tool
                        for phase in workflow.phases
                        for tool in phase.tools
                        if tool and tool not in known
                    }
                )
                if unknown:
                    issues.append(
                        _error(
                            "E011",
                            path,
                            2,
                            "workflow references unknown tool(s): "
                            + ", ".join(unknown)
                            + " (add operator/MCP tools to EXTERNAL_TOOL_NAMES)",
                        )
                    )

    raw_shared = frontmatter.get("shared_references")
    declared: list[str] = []
    if raw_shared is not None:
        if not isinstance(raw_shared, list):
            issues.append(_error("W001", path, 2, "'shared_references' must be a list"))
        else:
            declared = _clean_shared_reference_names(raw_shared)
            dropped = [
                repr(item) for item in raw_shared if not isinstance(item, str) or item not in declared
            ]
            if dropped:
                issues.append(
                    _warning(
                        "W001",
                        path,
                        2,
                        f"shared_references entries dropped as unsafe: {', '.join(dropped)}",
                    )
                )

    shared_root = skills_dir / SHARED_REFERENCES_DIRNAME
    for shared_name in declared:
        if not (shared_root / shared_name).is_file():
            issues.append(
                _error(
                    "E007",
                    path,
                    2,
                    f"declared shared reference does not exist: {shared_name}",
                )
            )

    body_length = len(body.strip())
    if body_length > MAX_BODY_CHARS:
        issues.append(
            _error(
                "E005",
                path,
                body_line,
                f"body is {body_length} chars (max {MAX_BODY_CHARS}, prompt cap)",
            )
        )
    elif body_length > WARN_BODY_CHARS:
        issues.append(
            _warning(
                "W003",
                path,
                body_line,
                f"body is {body_length} chars (> {WARN_BODY_CHARS}); consider references/",
            )
        )

    if path.name == "SKILL.md":
        own_refs = _own_reference_files(path)
        if not own_refs and not declared:
            issues.append(
                _error("E006", path, body_line, "directory skill has no reachable reference")
            )

    return issues


def lint_content(path: Path) -> list[Issue]:
    """Scan one shipped text file for secrets and host-specific paths."""
    issues: list[Issue] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return issues

    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in SECRET_PATTERNS.items():
            if pattern.search(line):
                issues.append(
                    _error("E009", path, line_number, f"high-confidence secret pattern: {rule}")
                )
        for match in HOST_PATH_RE.finditer(line):
            segment = match.group(1) or match.group(2) or ""
            if segment.lower() not in HOST_PATH_PLACEHOLDERS:
                issues.append(
                    _warning(
                        "W002",
                        path,
                        line_number,
                        f"host-specific path in shipped text: {match.group(0)}",
                    )
                )
    return issues


def lint_skills(skills_dir: Path = SKILLS_DIR) -> list[Issue]:
    skills_dir = Path(skills_dir)
    issues: list[Issue] = []
    seen_names: dict[str, Path] = {}

    skill_files = list(_iter_skill_files(skills_dir))
    for path in skill_files:
        issues.extend(lint_skill(path, skills_dir, seen_names))

    # Content scan covers shared references too; run it once per file.
    for path in sorted(skills_dir.rglob("*")):
        if path.is_file() and path.suffix in SCANNED_SUFFIXES and "__pycache__" not in path.parts:
            issues.extend(lint_content(path))

    return issues


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Lint the shipped skill library.")
    parser.add_argument(
        "--skills-dir",
        type=Path,
        default=SKILLS_DIR,
        help=f"skills package directory (default: {SKILLS_DIR})",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat warnings as errors",
    )
    args = parser.parse_args(argv)

    issues = lint_skills(args.skills_dir)
    errors = [issue for issue in issues if issue.level == "error"]
    warnings = [issue for issue in issues if issue.level == "warning"]

    skill_count = len(list(_iter_skill_files(args.skills_dir)))
    print(
        f"skill lint: {skill_count} skills, {len(errors)} error(s), {len(warnings)} warning(s)"
    )
    for issue in issues:
        print("  " + issue.render(REPO_ROOT))

    if errors or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
