"""Optional workflow metadata for skills.

A skill may declare a ``workflow:`` block in its SKILL.md frontmatter. The
block is advisory: selection and routing stay with the resolver, and only an
explicit invocation injects the skill body. Its job is to turn a prose skill
into a phase table the model can execute and close on the blackboard.

Example::

    workflow:
      modes: [pentest, audit]
      phases:
        - id: surface
          goal: map the desktop attack surface
          tools: [source_extract, fetch, blackboard_create_angle]
          evidence: [ASAR listing, IPC handlers]
          exit: every surface has an ANGLE
        - id: report
          goal: bind evidence and report confirmed findings
          tools: [traffic_list, traffic_bind_evidence, report_finding]
          evidence: [bound request, repro log]
          exit: report_finding accepted
      gates:
        - after: surface
          require: [web_map_summary]

Validation is deliberately structural only: phase ids must be unique, gates
must point at a declared phase, and a workflow must have at least one phase.
Tool names are not validated against the live tool face because that face is
pruned per task; a stale name is a prompt hint, not a hard failure.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

#: Modes a workflow may opt into. Kept local so this module stays importable
#: without pulling in the agent runtime.
KNOWN_MODES = frozenset({"pentest", "audit", "ir", "ctf"})


class WorkflowPhase(BaseModel):
    id: str = ""
    goal: str = ""
    tools: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    exit: str = ""
    references: list[str] = Field(default_factory=list)


class WorkflowGate(BaseModel):
    after: str = ""
    require: list[str] = Field(default_factory=list)


class SkillWorkflow(BaseModel):
    modes: list[str] = Field(default_factory=list)
    phases: list[WorkflowPhase] = Field(default_factory=list)
    gates: list[WorkflowGate] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    def is_actionable(self) -> bool:
        return bool(self.phases)

    def to_prompt_lines(self) -> list[str]:
        """Render the phase table for an explicitly-invoked skill.

        Kept in this module (not the prompt formatter) so the exact wording is
        testable without building a whole agent.
        """
        if not self.phases:
            return []
        lines = [
            "## Workflow phases (turn each into one blackboard ANGLE)",
            "Create the ANGLE before starting a phase; close it with "
            "`blackboard_hit_angle` (confirmed) or `blackboard_miss_angle` "
            "(exhausted). Do not open the next phase while the current one is "
            "still undecided.",
            "",
            "| Phase | Goal | Tools | Evidence | Exit |",
            "| --- | --- | --- | --- | --- |",
        ]
        for phase in self.phases:
            lines.append(
                "| {id} | {goal} | {tools} | {evidence} | {exit} |".format(
                    id=phase.id or "-",
                    goal=phase.goal or "-",
                    tools=", ".join(phase.tools) or "-",
                    evidence=", ".join(phase.evidence) or "-",
                    exit=phase.exit or "-",
                )
            )
        if self.modes:
            lines.append("")
            lines.append(f"Applies to task modes: {', '.join(self.modes)}.")
        for gate in self.gates:
            if gate.after and gate.require:
                lines.append(
                    f"Gate: after `{gate.after}` verify {', '.join(gate.require)} "
                    "before moving on."
                )
        lines.append(
            "Before FINAL: every phase must be closed (HIT or MISS) and the "
            "confirmed findings bound to evidence; a phase left undecided is "
            "not a completed workflow."
        )
        return lines


def parse_workflow(raw: Any) -> SkillWorkflow | None:
    """Parse a frontmatter ``workflow`` mapping.

    Returns None when the block is absent or not a mapping. Structural issues
    (duplicate ids, dangling gates, unknown modes) are reported in
    ``warnings`` and the offending item is dropped rather than raising: a
    malformed workflow must not make the skill unloadable.
    """
    if not isinstance(raw, dict):
        return None
    try:
        workflow = SkillWorkflow.model_validate(raw)
    except Exception:
        return None

    warnings: list[str] = []

    phases: list[WorkflowPhase] = []
    seen: set[str] = set()
    for phase in workflow.phases:
        pid = (phase.id or "").strip()
        if not pid:
            warnings.append("workflow phase without id dropped")
            continue
        if pid in seen:
            warnings.append(f"duplicate workflow phase id {pid!r} dropped")
            continue
        seen.add(pid)
        phases.append(phase)
    workflow.phases = phases

    gates: list[WorkflowGate] = []
    for gate in workflow.gates:
        after = (gate.after or "").strip()
        if after not in seen:
            warnings.append(f"workflow gate references unknown phase {after!r} dropped")
            continue
        gates.append(gate)
    workflow.gates = gates

    modes: list[str] = []
    for mode in workflow.modes:
        token = str(mode or "").strip().lower()
        if token not in KNOWN_MODES:
            warnings.append(f"unknown workflow mode {token!r} dropped")
            continue
        if token not in modes:
            modes.append(token)
    workflow.modes = modes

    workflow.warnings = warnings
    return workflow
