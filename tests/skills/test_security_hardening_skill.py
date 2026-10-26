"""Loader checks for the shipped security-hardening skill."""

from vulnclaw.skills.loader import load_skill_by_name, load_skill_reference

EXPECTED_REFS = [
    "00-quick-checklist.md",
    "01-linux-baseline.md",
    "02-middleware-and-db.md",
    "03-web-remediation.md",
    "04-permissions-and-verification.md",
    "05-windows-baseline.md",
]


def test_security_hardening_skill_loads():
    skill = load_skill_by_name("security-hardening")
    assert skill is not None
    assert skill["name"] == "security-hardening"
    assert skill["requires_target"] is True
    assert "防守题" in skill["description"]
    assert "安全加固 Skill" in skill["content"]
    assert skill.get("routing", {}).get("task_types") == ["ctf", "audit"]


def test_security_hardening_references_all_load():
    skill = load_skill_by_name("security-hardening")
    assert skill is not None
    assert set(EXPECTED_REFS) <= set(skill.get("references", []))
    for ref in EXPECTED_REFS:
        content = load_skill_reference("security-hardening", ref)
        assert content, f"{ref} did not load"
        assert len(content) > 200, f"{ref} looks truncated"
