"""One-line rendering of a finished run's termination cause.

The status line is where operators actually look, so it must show the *code*
next to the sentence. That pairing is what the 2026-10-21 lock-blocked run
lacked: the CLI printed "仍未达到完成条件" (the generic placeholder) for a run
that had been refused before its first step, because the branch set only
``SolveResult.reason`` and the CLI reads ``agent_state.complete_reason``.

The code comes from ``AgentState.stop_reason``; a run recorded before that field
existed renders the sentence alone, exactly as before, so old run JSON keeps
printing.
"""

from __future__ import annotations

from typing import Any, Mapping

from vulnclaw.i18n import _


def _field(state: Any, name: str) -> str:
    if isinstance(state, Mapping):
        return str(state.get(name) or "").strip()
    return str(getattr(state, name, "") or "").strip()


def format_stop_status(state: Any) -> str:
    """``code (sentence)`` for a finished run, or the unchanged fallback text.

    ``state`` is either an ``AgentState`` or the summary dict the CLI holds
    (``get_summary()``), because both call sites exist today.
    """

    code = _field(state, "stop_reason")
    reason = _field(state, "complete_reason") or _("cli.reason_not_complete")
    if code:
        return f"{code} ({reason})"
    return reason