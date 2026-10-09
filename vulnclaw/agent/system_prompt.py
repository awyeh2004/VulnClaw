"""Dynamic system prompt assembly for AgentCore.

Ordering contract
-----------------
Every block that goes into the system prompt is classified as either **stable**
or **volatile**, and the final prompt is `stable + separator + volatile`:

* *stable* -- fixed for the lifetime of a run. Identity, the core contract, the
  target section, the auto-pentest loop instruction, and the task's hard
  constraints. These must never be reordered relative to each other, and they
  must never depend on state that changes between rounds.
* *volatile* -- may change between rounds of the same run. The pentest phase
  (transitions are detected from model output), the selected skill bundle
  (re-selected as the run progresses), MCP tool schemas (servers can be
  attached at runtime), the recon instruction (the personnel dimension can
  activate mid-run), KB snippets, cross-session experience lessons, and the
  active role block.

Why the split matters: :func:`vulnclaw.agent.loop_controller.run_auto_loop` and
:func:`vulnclaw.agent.solver.solve` both rebuild the system prompt *inside*
their round loop. Providers that cache on a longest-common-prefix basis (OpenAI
automatic prompt caching, Anthropic cache breakpoints, several gateways) only
get a hit on the prefix that is byte-identical to the previous call. With
volatile blocks interleaved among invariant ones, a single skill switch used to
invalidate every byte from the skill section onward -- including the core
contract and the safety constraints. Keeping the invariants contiguous at the
front and pushing the churn to the tail preserves the cached prefix.

Use :func:`build_dynamic_system_prompt_parts` when you need the boundary (for
compaction, assertions, or cache instrumentation);
:func:`build_dynamic_system_prompt` remains the plain-string entry point.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from vulnclaw.agent.prompts import (
    build_system_prompt_parts,
    get_auto_pentest_instruction,
    get_recon_instruction,
)

if TYPE_CHECKING:
    from vulnclaw.agent.context import TaskConstraints


# Separator between blocks. Kept as a module constant so the boundary arithmetic
# in SystemPromptParts.boundary cannot drift from the actual join.
_BLOCK_SEP = "\n\n"

# Separator used *inside* the identity/contract/target group, matching the
# historical single-newline join in prompts.build_system_prompt.
_INNER_SEP = "\n"

_RECON_TRIGGERS = [
    # Chinese triggers
    "搜集",
    "收集",
    "信息收集",
    "侦察",
    "社会工程",
    "社工",
    "调查",
    "作者",
    "人物",
    "情报",
    "分析目标",
    "目标分析",
    "资产发现",
    "子域名",
    # English triggers
    "recon",
    "osint",
    "reconnaissance",
    "gather info",
    "information gathering",
    "enumerat",
    "subdomain",
    "asset discovery",
    "social engineer",
    "footprint",
]


@dataclass(frozen=True)
class SystemPromptParts:
    """A system prompt with its stable/volatile boundary made explicit.

    ``stable`` and ``volatile`` are already-rendered strings (no trailing
    separator). ``text`` is what gets sent to the model; ``boundary`` is the
    index in ``text`` just past the stable prefix, so
    ``text[:boundary]`` is exactly the cacheable part.
    """

    stable: str
    volatile: str

    @property
    def text(self) -> str:
        if not self.volatile:
            return self.stable
        return f"{self.stable}{_BLOCK_SEP}{self.volatile}"

    @property
    def boundary(self) -> int:
        """Index just past the stable prefix within :attr:`text`."""
        if not self.volatile:
            return len(self.stable)
        return len(self.stable) + len(_BLOCK_SEP)

    @property
    def stable_hash(self) -> str:
        """SHA-256 of the stable prefix, for cache-invalidation assertions."""
        return hashlib.sha256(self.stable.encode("utf-8")).hexdigest()

    @property
    def cacheable_prefix(self) -> str:
        """The bytes a longest-common-prefix cache can actually reuse."""
        return self.text[: self.boundary]


def build_dynamic_system_prompt_parts(
    *,
    target: Optional[str],
    phase: Optional[str],
    skill_context: Optional[str],
    mcp_tools: list[dict],
    enable_personnel_dim: bool,
    auto_mode: bool,
    user_input: Optional[str],
    kb_context: str,
    experience_context: str = "",
    task_constraints: Optional["TaskConstraints"] = None,
    role_prompt_block: str = "",
) -> SystemPromptParts:
    """Assemble the system prompt for one turn, split at the cache boundary.

    See the module docstring for the classification rule. Blocks are preserved
    verbatim; only their order changed relative to the pre-split builder, which
    used to interleave the skill/MCP sections ahead of the loop instruction and
    the hard constraints.
    """
    base_stable, base_volatile = build_system_prompt_parts(
        target=target,
        phase=phase,
        skill_context=skill_context,
        mcp_tools=mcp_tools,
        enable_personnel_dim=enable_personnel_dim,
    )

    # ── Stable prefix: run-invariant, and the front of the cacheable prefix ──
    stable_blocks: list[str] = [_INNER_SEP.join(base_stable)]

    if auto_mode:
        stable_blocks.append(get_auto_pentest_instruction())

    # Hard constraints are run-invariant (applied once at run start), so they
    # belong in the cached prefix -- and a mandatory instruction block should
    # precede optional reference material rather than trail it.
    if task_constraints is not None:
        constraints_block = task_constraints.to_prompt_block()
        if constraints_block:
            stable_blocks.append(constraints_block)

    # ── Volatile tail: everything that can change between rounds ────────────
    volatile_blocks: list[str] = []

    if base_volatile:
        volatile_blocks.append(_INNER_SEP.join(base_volatile))

    if user_input and any(trigger in user_input.lower() for trigger in _RECON_TRIGGERS):
        volatile_blocks.append(get_recon_instruction(enable_personnel_dim))

    if kb_context:
        volatile_blocks.append(kb_context)

    if experience_context:
        volatile_blocks.append(experience_context)

    if role_prompt_block:
        volatile_blocks.append(role_prompt_block)

    return SystemPromptParts(
        stable=_BLOCK_SEP.join(b for b in stable_blocks if b),
        volatile=_BLOCK_SEP.join(b for b in volatile_blocks if b),
    )


def build_dynamic_system_prompt(
    *,
    target: Optional[str],
    phase: Optional[str],
    skill_context: Optional[str],
    mcp_tools: list[dict],
    enable_personnel_dim: bool,
    auto_mode: bool,
    user_input: Optional[str],
    kb_context: str,
    experience_context: str = "",
    task_constraints: Optional["TaskConstraints"] = None,
    role_prompt_block: str = "",
) -> str:
    """Build the dynamic system prompt for one turn (plain string)."""
    return build_dynamic_system_prompt_parts(
        target=target,
        phase=phase,
        skill_context=skill_context,
        mcp_tools=mcp_tools,
        enable_personnel_dim=enable_personnel_dim,
        auto_mode=auto_mode,
        user_input=user_input,
        kb_context=kb_context,
        experience_context=experience_context,
        task_constraints=task_constraints,
        role_prompt_block=role_prompt_block,
    ).text
