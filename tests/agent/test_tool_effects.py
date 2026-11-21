"""Every model-callable tool declares its side effects.

KubeTrail's ``collectors.SideEffects()`` + ``runner.CollectorPlan`` answer a
question VulnClaw's run record could not: what did this run actually do to the
target? The findings list says what was concluded; nothing said whether the run
only read a page or fired 400 auth attempts at a login form.

Three properties are pinned here:
- the table covers every registered tool (a new tool cannot silently look inert),
- unknown tools default to "touches the target", never to harmless,
- the record happens before dispatch, so a crashed call still counts.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.agent.tool_effects import (
    EFFECTS,
    UNCLASSIFIED,
    effects_for,
    registered_tool_names,
)


class TestDeclarations:
    def test_table_is_not_empty(self):
        assert len(EFFECTS) > 30

    def test_every_entry_has_at_least_one_effect(self):
        for name, declared in EFFECTS.items():
            assert declared.effects, name
            assert all(isinstance(effect, str) and effect for effect in declared.effects), name

    def test_reading_tools_do_not_claim_target_changes(self):
        for name in ("evidence_list", "evidence_view", "load_skill_reference", "memory_search"):
            declared = effects_for(name)
            assert declared.touches_target is False, name

    def test_network_tools_claim_target_changes(self):
        for name in ("http_probe_batch", "nmap_scan", "dir_enum", "brute_force_login"):
            assert effects_for(name).touches_target is True, name

    def test_report_finding_is_local_not_a_submission(self):
        # The distinction the CTF runs kept getting wrong: a local finding is
        # not a platform submission and must not look like one.
        declared = effects_for("report_finding")
        assert declared.touches_target is False
        assert "platform_submit" not in declared.effects


class TestUnknownTools:
    def test_unknown_is_unclassified_and_blamed_on_the_target(self):
        # A mis-declared tool must never render as harmless: an operator-facing
        # column that under-reports is worse than no column.
        declared = effects_for("some_operator_mcp_tool")
        assert UNCLASSIFIED in declared.effects
        assert declared.touches_target is True

    def test_platform_tools_are_at_least_submissions(self):
        declared = effects_for("ctf2_submit_flag")
        assert "platform_submit" in declared.effects
        assert declared.touches_target is True


class TestCoverage:
    """The rule that keeps the table honest as tools are added."""

    def test_every_registered_tool_is_declared(self):
        declared = set(EFFECTS)
        missing = sorted(
            name
            for name in registered_tool_names()
            if name not in declared
            # Platform verbs are declared by prefix in effects_for(); the CTF
            # and GCS tool sets are generated per config and cannot be listed
            # statically.
            and not name.startswith(("ctf2_", "gcs_", "platform_"))
        )
        assert missing == [], (
            "these registered tools have no side-effect declaration -- add them to "
            f"vulnclaw/agent/tool_effects.py EFFECTS: {missing}"
        )


class TestRecording:
    def test_repeats_collapse_into_one_row(self):
        state = AgentState()
        for _ in range(3):
            state.record_side_effect("nmap_scan")
        assert len(state.side_effects) == 1
        assert state.side_effects[0].count == 3

    def test_distinct_tools_stay_separate(self):
        state = AgentState()
        state.record_side_effect("nmap_scan")
        state.record_side_effect("http_probe_batch")
        assert {item.tool for item in state.side_effects} == {"nmap_scan", "http_probe_batch"}

    def test_target_touching_filter(self):
        state = AgentState()
        state.record_side_effect("evidence_list")
        state.record_side_effect("nmap_scan")
        touching = state.target_touching_effects()
        assert [item.tool for item in touching] == ["nmap_scan"]

    def test_summary_carries_effects(self):
        state = AgentState()
        state.record_side_effect("brute_force_login")
        payload = state.get_summary()["side_effects"]
        assert payload == [
            {"tool": "brute_force_login", "count": 1, "touches_target": True}
        ]


class TestRecordedBeforeDispatch:
    """The record happens past the refusal gates, before the tool body runs."""

    def test_dispatch_records_the_call(self):
        import asyncio

        from vulnclaw.agent import builtin_tools

        state = AgentState()

        class _Session:
            agent_state = state
            task_constraints = None

        class _Agent:
            session_state = _Session()
            active_role = None
            config = None
            runtime = None

        # The tool body will fail (no MCP manager, no real nmap); the point is
        # that the declaration is already recorded, which is what a crashed or
        # timed-out call must also leave behind.
        asyncio.run(builtin_tools.execute_mcp_tool(_Agent(), "nmap_scan", {}))
        assert [item.tool for item in state.side_effects] == ["nmap_scan"]

    def test_role_refusal_does_not_record_an_effect(self):
        import asyncio

        from vulnclaw.agent import builtin_tools

        state = AgentState()

        class _Session:
            agent_state = state
            task_constraints = None

        class _Agent:
            session_state = _Session()
            # A role that forbids shell keeps the call from ever being dispatched.
            active_role = "recon"
            config = None
            runtime = None

        asyncio.run(builtin_tools.execute_mcp_tool(_Agent(), "shell_command", {"command": "id"}))
        # Refused before dispatch => no effect recorded. Counting refused calls
        # as effects would overstate what the run did.
        assert state.side_effects == []


class TestReportRenders:
    def test_solve_report_names_target_touching_actions(self):
        from vulnclaw.report.solve_report import render_solve_report

        state = AgentState()
        state.origin = "https://target"
        state.goal = "assess"
        state.record_side_effect("nmap_scan")
        state.record_side_effect("nmap_scan")
        state.record_side_effect("evidence_list")

        text = render_solve_report(state)
        assert "本次运行的实际动作" in text
        assert "nmap_scan" in text
        assert "×2" in text