"""Run-profile isolation for the shared runtime workspace.

The operator's ``E:\\vulnclaw`` tree is used by BOTH the CTF workspace (this
checkout) and the production workspace, and the two must not read each other's
notes. ``VULNCLAW_CONFIG_DIR`` / ``VULNCLAW_WORK_DIR`` decide *where* the data
lives; this module decides *which* profile the process believes it is, so code
that has to make a policy choice (CTF-only reference docs, CTF-only completion
rules) can ask instead of guessing from file names.

Resolution: ``VULNCLAW_PROFILE`` is authoritative when set; anything other than
an explicit ``prod`` resolves to ``ctf`` because this checkout is the CTF
workspace. That means a production launcher **must** set ``VULNCLAW_PROFILE=prod``
(see the CTF/prod launcher scripts under ``E:\\vulnclaw\\bin``); an unset
variable is the CTF default, not a "shared" mode.

Unknown values fail closed to ``ctf`` for policy purposes only -- they never widen
filesystem access, which is governed separately by containment in the skill
loader.
"""

from __future__ import annotations

import os

CTF = "ctf"
PROD = "prod"
VALID_PROFILES = (CTF, PROD)


def current_profile() -> str:
    """The profile this process runs as: ``"ctf"`` or ``"prod"``."""
    raw = str(os.environ.get("VULNCLAW_PROFILE", "") or "").strip().lower()
    return PROD if raw == PROD else CTF


def is_prod() -> bool:
    return current_profile() == PROD


__all__ = ["CTF", "PROD", "VALID_PROFILES", "current_profile", "is_prod"]
