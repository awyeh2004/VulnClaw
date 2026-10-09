"""VulnClaw system prompt builder — language-aware dispatch.

The actual prompt text lives in per-language modules (``prompts_zh`` /
``prompts_en``). This module selects the active language via the i18n
translator and assembles the final system prompt from the chosen bundle.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from vulnclaw.agent import prompts_en, prompts_zh
from vulnclaw.i18n import current_lang
from vulnclaw.i18n.phases import canonical_phase_id, localized_prompt_phase_heading


def _bundle(lang: Optional[str] = None):
    """Return the prompt-text module for the active (or given) language."""
    lang = lang or current_lang()
    return prompts_en if lang == "en" else prompts_zh


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_target(value: str) -> str:
    """Strip control characters and normalize a target string for safe prompt embedding.

    Removes newlines, tabs, carriage returns and other C0/C1 control characters
    that could be abused for prompt injection.  The result is a single-line
    printable string suitable for concatenation into the system prompt.

    Raises ``ValueError`` if the resulting value is empty.
    """
    cleaned = value.replace("\n", "").replace("\r", "").replace("\t", "")
    cleaned = _CONTROL_CHARS_RE.sub("", cleaned)
    cleaned = cleaned.strip()
    if not cleaned:
        raise ValueError("target must not be empty after sanitization")
    return cleaned


def build_system_prompt_parts(
    target: Optional[str] = None,
    phase: Optional[Any] = None,
    skill_context: Optional[str] = None,
    mcp_tools: Optional[list[dict]] = None,
    enable_personnel_dim: bool = True,
    lang: Optional[str] = None,
) -> tuple[list[str], list[str]]:
    """Split the system prompt into ``(stable_parts, volatile_parts)``.

    The split exists so an upstream caller can keep every invariant block
    contiguous at the *front* of the prompt and push everything that perturbs
    mid-run to the tail. Providers that cache on a longest-common-prefix basis
    then keep hitting the cache even when a volatile block changes -- see
    :mod:`vulnclaw.agent.system_prompt` for the full ordering contract.

    Classification rule for this module:

    * ``stable`` -- identity, the core contract, and the target section. All
      three are fixed for the lifetime of a run; the target is detected once
      and the other two are module constants.
    * ``volatile`` -- phase, skill references, and MCP tool schemas. A phase can
      transition between rounds, a skill bundle is re-selected as the run
      progresses, and MCP servers can be attached at runtime.

    Args:
        target: Current target identifier (IP/URL).
        phase: Current pentest phase enum, canonical ID, or legacy display name.
        skill_context: Optional skill reference index. Skill bodies are not
            automatically injected; the model may load references explicitly.
        mcp_tools: List of available MCP tool schemas.
        enable_personnel_dim: Kept for backward compatibility; the recon
            dimension toggle is applied by ``get_recon_instruction``.
        lang: Explicit language override ('zh'/'en'); defaults to the active
            UI language.

    Returns:
        ``(stable_parts, volatile_parts)`` -- each part already rendered, in
        the order they must appear.
    """
    resolved_lang = lang or current_lang()
    bundle = _bundle(resolved_lang)
    stable: list[str] = [bundle.BASE_IDENTITY, bundle.CORE_CONTRACT]

    if target:
        safe_target = _sanitize_target(target)
        stable.append(bundle.LABELS["target_section"].format(target=safe_target))

    volatile: list[str] = []

    phase_id = canonical_phase_id(phase)
    if phase_id in bundle.PHASE_DESCRIPTIONS:
        volatile.append(
            f"{localized_prompt_phase_heading(phase_id, lang=resolved_lang)}\n\n"
            f"{bundle.PHASE_DESCRIPTIONS[phase_id]}"
        )

    # Optional skill references
    if skill_context:
        volatile.append(bundle.LABELS["skill_section"].format(context=skill_context))

    if mcp_tools:
        tools_desc = _format_mcp_tools(mcp_tools)
        volatile.append(bundle.LABELS["mcp_section"].format(tools=tools_desc))

    return stable, volatile


def build_system_prompt(
    target: Optional[str] = None,
    phase: Optional[Any] = None,
    skill_context: Optional[str] = None,
    mcp_tools: Optional[list[dict]] = None,
    enable_personnel_dim: bool = True,
    lang: Optional[str] = None,
) -> str:
    """Dynamically assemble the full system prompt in the active language.

    Thin wrapper over :func:`build_system_prompt_parts`; see that function for
    the argument semantics and the stable/volatile classification.
    """
    stable, volatile = build_system_prompt_parts(
        target=target,
        phase=phase,
        skill_context=skill_context,
        mcp_tools=mcp_tools,
        enable_personnel_dim=enable_personnel_dim,
        lang=lang,
    )
    return "\n".join(stable + volatile)


def get_auto_pentest_instruction(lang: Optional[str] = None) -> str:
    """Return the auto-pentest loop instruction in the active language."""
    return _bundle(lang).AUTO_PENTEST_INSTRUCTION


def get_recon_instruction(
    enable_personnel_dim: bool = True, lang: Optional[str] = None
) -> str:
    """Return the recon instruction with its optional personnel dimension."""
    bundle = _bundle(lang)
    return (
        bundle.RECON_INSTRUCTION
        if enable_personnel_dim
        else bundle.RECON_INSTRUCTION_NO_PERSONNEL
    )


def _format_mcp_tools(tools: list[dict]) -> str:
    """Format MCP tool schemas into readable description for the LLM."""
    lines = []
    for tool in tools:
        name = tool.get("name", "unknown")
        desc = tool.get("description", "")
        lines.append(f"- **{name}**: {desc}")

        params = tool.get("inputSchema", {}).get("properties", {})
        if params:
            for param_name, param_info in params.items():
                param_type = param_info.get("type", "any")
                param_desc = param_info.get("description", "")
                lines.append(f"  - `{param_name}` ({param_type}): {param_desc}")

    return "\n".join(lines)
