"""Tests for the static skill linter (scripts/lint_skills.py)."""

from __future__ import annotations

from pathlib import Path

from scripts.lint_skills import SKILLS_DIR, lint_skills
from vulnclaw.skills.loader import _parse_skill_file


def _write_skill(
    root: Path,
    rel: str,
    frontmatter: str,
    *,
    body: str = "body\n",
    references: tuple[str, ...] = ("ref.md",),
) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\n{frontmatter}\n---\n{body}", encoding="utf-8")
    if references and path.name == "SKILL.md":
        refs = path.parent / "references"
        refs.mkdir(exist_ok=True)
        for name in references:
            (refs / name).write_text("reference\n", encoding="utf-8")
    return path


def _errors(issues):
    return [issue for issue in issues if issue.level == "error"]


def _rules(issues) -> set[str]:
    return {issue.rule for issue in issues}


def test_shipped_skills_have_no_errors():
    assert _errors(lint_skills(SKILLS_DIR)) == []


def test_competition_mode_frontmatter_survives_yaml_parsing():
    """Regression: an unquoted ``CTF: ...`` used to kill the whole block."""
    skill = _parse_skill_file(SKILLS_DIR / "specialized" / "competition-mode" / "SKILL.md")
    assert skill["description"].startswith("比赛模式策略")
    assert skill["requires_target"] is False


def test_valid_skill_has_no_issues(tmp_path):
    _write_skill(
        tmp_path,
        "specialized/ok/SKILL.md",
        'name: ok\ndescription: "Use when testing ok."',
    )
    assert _errors(lint_skills(tmp_path)) == []


def test_invalid_yaml_is_reported(tmp_path):
    _write_skill(
        tmp_path,
        "specialized/bad/SKILL.md",
        "name: bad\ndescription: 报告: 内容",
    )
    assert "E001" in _rules(lint_skills(tmp_path))


def test_name_must_match_directory(tmp_path):
    _write_skill(
        tmp_path,
        "specialized/expected/SKILL.md",
        'name: other\ndescription: "x"',
    )
    assert "E002" in _rules(lint_skills(tmp_path))


def test_empty_description_is_rejected(tmp_path):
    _write_skill(tmp_path, "specialized/nodesc/SKILL.md", "name: nodesc")
    assert "E003" in _rules(lint_skills(tmp_path))


def test_duplicate_names_across_flat_and_directory(tmp_path):
    _write_skill(tmp_path, "core/dup.md", 'name: dup\ndescription: "x"')
    _write_skill(tmp_path, "specialized/dup/SKILL.md", 'name: dup\ndescription: "x"')
    assert "E004" in _rules(lint_skills(tmp_path))


def test_directory_skill_needs_a_reference(tmp_path):
    _write_skill(
        tmp_path,
        "specialized/noref/SKILL.md",
        'name: noref\ndescription: "x"',
        references=(),
    )
    assert "E006" in _rules(lint_skills(tmp_path))


def test_missing_shared_reference_is_reported(tmp_path):
    _write_skill(
        tmp_path,
        "specialized/shared/SKILL.md",
        'name: shared\ndescription: "x"\nshared_references: [missing.md]',
    )
    assert "E007" in _rules(lint_skills(tmp_path))


def test_unknown_routing_token_is_reported(tmp_path):
    _write_skill(
        tmp_path,
        "specialized/routing/SKILL.md",
        'name: routing\ndescription: "x"\nrouting:\n  vulnerability_classes: [not_a_class]',
    )
    assert "E008" in _rules(lint_skills(tmp_path))


def test_secret_pattern_is_reported(tmp_path):
    token = "AKIA" + "A" * 16
    _write_skill(
        tmp_path,
        "specialized/secret/SKILL.md",
        'name: secret\ndescription: "x"',
        body=f"key: {token}\n",
    )
    assert "E009" in _rules(lint_skills(tmp_path))


def test_non_boolean_requires_target_is_reported(tmp_path):
    _write_skill(
        tmp_path,
        "specialized/target/SKILL.md",
        'name: target\ndescription: "x"\nrequires_target: "false"',
    )
    assert "E010" in _rules(lint_skills(tmp_path))


def test_unknown_workflow_tool_is_reported(tmp_path):
    _write_skill(
        tmp_path,
        "specialized/wf/SKILL.md",
        (
            'name: wf\ndescription: "x"\n'
            "workflow:\n"
            "  phases:\n"
            "    - id: report\n"
            "      tools: [not_a_real_tool]\n"
        ),
    )
    assert "E011" in _rules(lint_skills(tmp_path))


def test_workflow_parse_warnings_are_reported(tmp_path):
    _write_skill(
        tmp_path,
        "specialized/wfdup/SKILL.md",
        (
            'name: wfdup\ndescription: "x"\n'
            "workflow:\n"
            "  phases:\n"
            "    - id: report\n"
            "    - id: report\n"
        ),
    )
    assert "E012" in _rules(lint_skills(tmp_path))


def test_known_workflow_tools_pass(tmp_path):
    _write_skill(
        tmp_path,
        "specialized/wfok/SKILL.md",
        (
            'name: wfok\ndescription: "x"\n'
            "workflow:\n"
            "  phases:\n"
            "    - id: report\n"
            "      tools: [traffic_bind_evidence, verify_finding, report_finding, fetch]\n"
        ),
    )
    rules = _rules(lint_skills(tmp_path))
    assert "E011" not in rules
    assert "E012" not in rules
