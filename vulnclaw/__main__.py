"""Module entry point so ``python -m vulnclaw`` works.

The Rust ratatui TUI (``tui/``) spawns the Python core via
``python -m vulnclaw``; without this file that invocation fails with
"``No module named vulnclaw.__main__``". Keep this in sync with the
console script entry point (``vulnclaw.cli.main:app`` in pyproject.toml).
"""

from vulnclaw.cli.main import app

if __name__ == "__main__":
    app()
