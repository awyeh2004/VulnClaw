"""CLI 包入口 —— 共享 helper 的兼容 re-export 面。

历史：本文件曾直接定义这些 helper（2026-07-08 从 cli/main.py 抽出时的中间态），
后来 `_helpers.py` 成为正典超集，这里的一份副本**漂移了 8 处**（如
`_run_cli_orchestrated_task` 一边 60 行一边 41 行，同名不同行为）。2026-10-12
清除：不再定义任何实现，全部从 :mod:`vulnclaw.cli._helpers` 原样 re-export，
并把 UTF-8 BOM 去掉（它是当时唯一带 BOM 的源文件）。
"""

from __future__ import annotations

from vulnclaw import __version__  # noqa: F401 — re-export
from vulnclaw.cli._helpers import (  # noqa: F401 — canonical home, re-exported for compat
    ASCII_LOGO,
    BANNER_SUBTITLE,
    TERMINAL_TOOL_RESULT_PREVIEW_CHARS,
    TerminalStreamSink,
    _append_action_constraints,
    _append_cli_constraints,
    _append_cli_constraints_compat,
    _collapse_terminal_text,
    _extract_evidence_id,
    _generate_report_for_target,
    _make_solve_event_printer,
    _print_agent_output,
    _print_banner,
    _print_styled_plain,
    _run_cli_orchestrated_task,
    console,
    err_console,
)
from vulnclaw.config.text_utils import (  # noqa: F401 — re-export
    format_think_tags,
    strip_think_tags,
)
