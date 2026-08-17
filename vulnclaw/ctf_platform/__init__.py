"""CTF2 (DASCTF) platform integration: automated challenge / environment tools.

Exposes the CTF2 User Open API to the agent as callable tools so it can list
practice grounds, read challenges, start live environments and submit flags
without manual platform interaction.
"""

from __future__ import annotations

from vulnclaw.ctf_platform.client import api_token, is_configured, session_token
from vulnclaw.ctf_platform.tools import (
    CTF_TOOL_NAMES,
    CTF_TOOL_NAMES_BY_SCHEMA,
    CTF_READ_TOOLS,
    ctf2_tool_schemas,
    dispatch_ctf2_tool,
)

__all__ = [
    "CTF_TOOL_NAMES",
    "CTF_TOOL_NAMES_BY_SCHEMA",
    "CTF_READ_TOOLS",
    "api_token",
    "ctf2_tool_schemas",
    "dispatch_ctf2_tool",
    "is_configured",
    "session_token",
]