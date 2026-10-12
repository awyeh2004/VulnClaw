"""Low-level helpers shared by several tool-family modules.

Split out of builtin_tools.py so the family modules (brute_force, http_probe)
can import them without a circular import back into the facade.
"""

from __future__ import annotations

from typing import Any


def _runtime_config(agent: Any) -> Any:
    """The runtime config the schema build used, so dispatch agrees with the view.

    ``build_openai_tools`` answers the exposure switches from this same object
    (round8 L4): dispatch must not re-read the config file per tool call.
    """
    return getattr(agent, "config", None)
