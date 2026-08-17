"""West Lake Sword Competition (西湖论剑) agent API integration.

Exposes the competition's dedicated agent API (``X-Agent-AccessKey`` auth) as
callable tools so the agent can fetch rules, list/read challenges, start and
recover challenge environments, and submit flags against the scoreboard.
"""

from __future__ import annotations

from vulnclaw.gcs_platform.client import access_key, api_base_url, is_configured
from vulnclaw.gcs_platform.tools import (
    GCS_TOOL_NAMES,
    GCS_TOOL_NAMES_BY_SCHEMA,
    GCS_READ_TOOLS,
    dispatch_gcs_tool,
    exercise_ready_poll,
    gcs_tool_schemas,
)

__all__ = [
    "GCS_TOOL_NAMES",
    "GCS_TOOL_NAMES_BY_SCHEMA",
    "GCS_READ_TOOLS",
    "access_key",
    "api_base_url",
    "dispatch_gcs_tool",
    "exercise_ready_poll",
    "gcs_tool_schemas",
    "is_configured",
]
