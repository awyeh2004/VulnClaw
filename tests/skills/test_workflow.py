"""Skill workflow metadata: phase table parsing and prompt rendering."""

from __future__ import annotations

from vulnclaw.agent.skill_context import format_selection_context
from vulnclaw.skills.loader import load_specialized_skill
from vulnclaw.skills.resolver import SkillSelection
from vulnclaw.skills.workflow import parse_workflow


def _raw():
    return {
        "modes": ["pentest", "audit"],
        "phases": [
            {
                "id": "surface",
                "goal": "map the surface",
                "tools": ["source_extract", "blackboard_create_angle"],
                "evidence": ["file list"],
                "exit": "every surface has an ANGLE",
            },
            {
                "id": "report",
                "goal": "bind and report",
                "tools": ["traffic_bind_evidence", "report_finding"],
                "evidence": ["bound request"],
                "exit": "finding accepted",
            },
        ],
        "gates": [{"after": "surface", "require": ["web_map_summary"]}],
    }


class TestParseWorkflow:
    def test_valid_workflow_keeps_phases_and_gate(self):
        wf = parse_workflow(_raw())
        assert wf is not None
        assert [p.id for p in wf.phases] == ["surface", "report"]
        assert wf.gates and wf.gates[0].after == "surface"
        assert wf.warnings == []

    def test_duplicate_phase_id_is_dropped_with_warning(self):
        raw = _raw()
        raw["phases"].append({"id": "surface", "goal": "duplicate"})
        wf = parse_workflow(raw)
        assert [p.id for p in wf.phases] == ["surface", "report"]
        assert any("duplicate" in w for w in wf.warnings)

    def test_gate_to_unknown_phase_is_dropped_with_warning(self):
        raw = _raw()
        raw["gates"].append({"after": "missing", "require": ["x"]})
        wf = parse_workflow(raw)
        assert all(g.after != "missing" for g in wf.gates)
        assert any("unknown phase" in w for w in wf.warnings)

    def test_unknown_mode_is_dropped_with_warning(self):
        raw = _raw()
        raw["modes"].append("bogus")
        wf = parse_workflow(raw)
        assert wf.modes == ["pentest", "audit"]
        assert any("unknown workflow mode" in w for w in wf.warnings)

    def test_missing_or_non_mapping_returns_none(self):
        assert parse_workflow(None) is None
        assert parse_workflow("not a mapping") is None
        assert parse_workflow({}) is not None  # empty mapping is a no-op workflow

    def test_prompt_lines_name_phases_and_angle_instruction(self):
        wf = parse_workflow(_raw())
        text = "\n".join(wf.to_prompt_lines())
        assert "surface" in text and "report" in text
        assert "blackboard_hit_angle" in text
        assert "Gate: after `surface`" in text
        assert "Before FINAL" in text


class TestElectronSkillWorkflow:
    def test_shipped_electron_skill_has_a_workflow(self):
        skill = load_specialized_skill("electron-desktop-audit")
        assert skill is not None
        wf = parse_workflow(skill.get("workflow"))
        assert wf is not None and len(wf.phases) >= 5
        ids = {p.id for p in wf.phases}
        assert {"surface", "ipc", "files", "mcp", "report"} <= ids

    def test_explicit_invocation_renders_the_phase_table(self):
        selection = SkillSelection(
            primary="electron-desktop-audit",
            signals=["explicit"],
            reason="explicit: test",
            confidence=1.0,
        )
        context = format_selection_context(selection)
        assert "Workflow phases" in context
        assert "| Phase | Goal | Tools | Evidence | Exit |" in context
        assert "| mcp |" in context


class TestShippedWorkflows:
    def test_web_and_ai_skills_declare_workflows(self):
        expected = {
            "web-pentest": {"recon", "auth", "injection", "logic", "report"},
            "ai-mcp-security": {"inventory", "prompt", "tool-abuse", "authz", "data", "report"},
        }
        for name, ids in expected.items():
            skill = load_specialized_skill(name)
            assert skill is not None, name
            wf = parse_workflow(skill.get("workflow"))
            assert wf is not None and wf.warnings == [], name
            assert ids <= {p.id for p in wf.phases}, name
