"""VulnClaw MCP integration package.

Model Context Protocol (MCP) server lifecycle, transport probing, routing and
diagnostics. Import the concrete pieces from their submodules, e.g.::

    from vulnclaw.mcp.lifecycle import MCPLifecycleManager
    from vulnclaw.mcp._probe_mixin import ProbeMixin

This ``__init__`` is intentionally a thin package marker. It previously held a
byte-for-byte copy of :mod:`vulnclaw.mcp._probe_mixin` (``class ProbeMixin``),
which no code imported from the package root and which would silently drift from
the real module on any edit.
"""

from __future__ import annotations
