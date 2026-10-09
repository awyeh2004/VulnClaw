"""Cache-stability contract for the system prompt builders.

The system prompt is rebuilt *inside* the round loop by both
``loop_controller.run_auto_loop`` and ``solver.solve``. Providers that cache on
a longest-common-prefix basis therefore only get a hit on the bytes that are
byte-identical to the previous round's prompt. These tests lock in the ordering
contract that makes that prefix as long as possible:

* every run-invariant block (identity, core contract, target, auto-pentest loop
  instruction, hard constraints) is contiguous at the *front*;
* every block that can change mid-run (phase, skill bundle, MCP schemas, recon
  instruction, KB snippets, experience lessons, role block, and -- in the solve
  engine -- the prior-playbook brief) sits after the reported boundary.

If someone later interleaves a volatile block ahead of an invariant one, these
tests fail rather than the cache silently going cold.
"""

from types import SimpleNamespace

from vulnclaw.agent.context import ContextManager, TaskConstraints
from vulnclaw.agent.system_prompt import (
    SystemPromptParts,
    build_dynamic_system_prompt,
    build_dynamic_system_prompt_parts,
)


def _parts(**overrides) -> SystemPromptParts:
    kwargs = dict(
        target="example.com",
        phase=None,
        skill_context=None,
        mcp_tools=[],
        enable_personnel_dim=False,
        auto_mode=True,
        user_input=None,
        kb_context="",
        experience_context="",
        task_constraints=None,
        role_prompt_block="",
    )
    kwargs.update(overrides)
    return build_dynamic_system_prompt_parts(**kwargs)


# ── the boundary arithmetic ─────────────────────────────────────────────────


def test_boundary_splits_text_into_the_two_documented_pieces():
    parts = _parts(skill_context="SKILL-A", kb_context="KB-A")

    assert parts.text == f"{parts.stable}\n\n{parts.volatile}"
    # boundary points just past the stable prefix *including* the separator.
    assert parts.text[: parts.boundary] == f"{parts.stable}\n\n"
    assert parts.cacheable_prefix == f"{parts.stable}\n\n"


def test_boundary_is_exactly_the_stable_length_when_nothing_is_volatile():
    parts = _parts(auto_mode=False)

    assert parts.volatile == ""
    assert parts.text == parts.stable
    assert parts.boundary == len(parts.stable)
    assert parts.cacheable_prefix == parts.stable


# ── the cache-stability property itself ─────────────────────────────────────


def test_stable_prefix_survives_a_mid_run_skill_switch():
    """The original defect: a skill re-selection used to invalidate everything
    from the skill section onward, including the core contract and constraints."""
    before = _parts(skill_context="SKILL-OLD")
    after = _parts(skill_context="SKILL-NEW")

    assert before.stable == after.stable
    assert before.stable_hash == after.stable_hash
    assert before.cacheable_prefix == after.cacheable_prefix
    # ...and the skill text really did move into the volatile tail.
    assert "SKILL-OLD" in before.volatile
    assert "SKILL-NEW" in after.volatile


def test_stable_prefix_survives_every_mid_run_perturbation_at_once():
    baseline = _parts()

    disturbed = _parts(
        phase="recon",
        skill_context="SKILL-NEW",
        mcp_tools=[{"name": "mcp__late", "description": "attached mid-run"}],
        enable_personnel_dim=True,
        user_input="recon the target and enumerate subdomains",
        kb_context="KB-NEW",
        experience_context="EXPERIENCE-NEW",
        role_prompt_block="ROLE-NEW",
    )

    assert baseline.stable == disturbed.stable
    assert baseline.stable_hash == disturbed.stable_hash


def test_stable_prefix_hashes_differ_only_for_run_invariants():
    """A different run is allowed to have a different prefix -- that is the
    point. What must not change the prefix is round-to-round churn."""
    assert _parts(target="a.example").stable != _parts(target="b.example").stable
    assert _parts(task_constraints=TaskConstraints()).stable == _parts().stable
    assert _parts(task_constraints=TaskConstraints(allowed_ports=[443])).stable != _parts().stable


# ── volatile blocks are actually after the boundary ─────────────────────────


def test_volatile_blocks_are_all_placed_after_the_boundary():
    parts = _parts(
        phase="recon",
        skill_context="SKILL-MARKER",
        mcp_tools=[{"name": "mcp__marker", "description": "d"}],
        user_input="请做信息收集",
        kb_context="KB-MARKER",
        experience_context="EXPERIENCE-MARKER",
        role_prompt_block="ROLE-MARKER",
    )
    tail = parts.text[parts.boundary :]

    for marker in (
        "SKILL-MARKER",
        "mcp__marker",
        "KB-MARKER",
        "EXPERIENCE-MARKER",
        "ROLE-MARKER",
    ):
        assert marker in tail, f"{marker} leaked into the cacheable prefix"


# ── safety-critical blocks must be inside the cached prefix ─────────────────


def test_constraints_and_loop_instruction_stay_inside_the_cached_prefix():
    """Constraints are run-invariant, so they belong in the prefix -- and a
    mandatory block should not trail optional reference material."""
    constraints = TaskConstraints(allowed_ports=[443], blocked_hosts=["internal.example.com"])
    parts = _parts(
        auto_mode=True,
        task_constraints=constraints,
        skill_context="SKILL-MARKER",
        kb_context="KB-MARKER",
    )
    prefix = parts.cacheable_prefix

    assert constraints.to_prompt_block() in prefix
    assert "SKILL-MARKER" not in prefix
    assert "KB-MARKER" not in prefix


def test_auto_mode_loop_instruction_is_part_of_the_stable_prefix():
    with_auto = _parts(auto_mode=True)
    without_auto = _parts(auto_mode=False)

    assert with_auto.stable != without_auto.stable
    assert len(with_auto.stable) > len(without_auto.stable)


# ── the plain-string entry point stays consistent with the parts view ──────


def test_string_entry_point_equals_the_parts_text():
    kwargs = dict(
        target="example.com",
        phase="recon",
        skill_context="SKILL-A",
        mcp_tools=[{"name": "t", "description": "d"}],
        enable_personnel_dim=False,
        auto_mode=True,
        user_input="扫描",
        kb_context="KB-A",
        experience_context="EXP-A",
        task_constraints=TaskConstraints(allowed_ports=[80]),
        role_prompt_block="ROLE-A",
    )

    assert build_dynamic_system_prompt(**kwargs) == _parts(**kwargs).text


# ── the solve engine's own builder ─────────────────────────────────────────


def _solver_agent() -> SimpleNamespace:
    """Minimal stand-in for the solve-loop agent, mirroring tests/agent/test_solver.py."""
    agent = SimpleNamespace()
    agent.context = ContextManager()
    agent.session_state = agent.context.state
    agent.config = SimpleNamespace()
    agent.runtime = SimpleNamespace(blackboard=None, prior_playbook_brief="")
    return agent


_MARKER_ONE = "PRIOR-PLAYBOOK-BRIEF-MARKER-ONE"
_MARKER_TWO = "PRIOR-PLAYBOOK-BRIEF-MARKER-TWO-LONGER"


def test_solve_prompt_puts_the_playbook_brief_at_the_tail():
    """``save_playbook`` refreshes this brief mid-run. It is the only block in
    the solve prompt that can churn, so it must be last -- otherwise a single
    playbook hit would invalidate the tool card and mode block ahead of it."""
    from vulnclaw.agent.solver import _system_prompt

    agent = _solver_agent()
    state = agent.context.state.agent_state

    baseline = _system_prompt(agent, state)

    agent.runtime.prior_playbook_brief = _MARKER_ONE
    first = _system_prompt(agent, state)

    agent.runtime.prior_playbook_brief = _MARKER_TWO
    second = _system_prompt(agent, state)

    assert first.endswith(_MARKER_ONE)
    assert second.endswith(_MARKER_TWO)
    # Nothing but the brief changed: the shared prefix is the untouched prompt.
    assert first[: first.index(_MARKER_ONE)] == baseline
    assert second[: second.index(_MARKER_TWO)] == baseline
    assert first[: first.index(_MARKER_ONE)] == second[: second.index(_MARKER_TWO)]
