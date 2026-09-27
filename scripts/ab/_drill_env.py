"""Runtime credentials for the A/B drills -- kept OUT of the seeded configs.

Why this exists (found while auditing commit d72ca20): `scripts/ab/seeds/config.yaml` and
`config-round2.yaml` were committed as "verbatim copies" of a real config, and they carried
**live credentials** -- the operator's LLM `api_key` (three places per file) and a live GCS
`access_key`, both byte-identical to the values in `~/.vulnclaw/config.yaml`.

A drill seed has to be publishable, so the credentials are removed from the seeds and supplied
at RUN time instead: the child solve process gets them through the environment, where
`vulnclaw.config.settings` already lets `VULNCLAW_LLM_API_KEY` override `llm.api_key`.

One implementation rather than three copies: the three runners had already drifted once
(see `tests/scripts/test_ab_harness_hygiene.py`), which is the same lesson as the shared
`file_lock` and `replace_with_retry` in the product.
"""

from __future__ import annotations

import os

#: Environment variables forwarded to the child solve process when they are set.
FORWARDED_ENV = (
    "VULNCLAW_LLM_API_KEY",
    "VULNCLAW_LLM_API_KEYS",
    "VULNCLAW_LLM_BASE_URL",
    "VULNCLAW_LLM_MODEL",
    "VULNCLAW_LLM_PROVIDER",
    "VULNCLAW_GCS_ACCESS_KEY",
)


def runtime_llm_key() -> str:
    """The operator's current LLM key: from the environment, else their live config.

    Deliberately read at CALL time from the live config, so a drill never needs the key to
    be written down anywhere in the repository.
    """
    direct = os.environ.get("VULNCLAW_LLM_API_KEY", "").strip()
    if direct:
        return direct
    try:
        from vulnclaw.config.settings import load_config

        return str(getattr(load_config().llm, "api_key", "") or "").strip()
    except Exception:  # noqa: BLE001 - a drill must not die on a config read
        return ""


def with_runtime_credentials(env: dict[str, str]) -> dict[str, str]:
    """Add the credentials a drill needs, taken from the operator's own environment.

    ``env`` is normally ``dict(os.environ)`` (already inherited), so this only has to cover
    the case where the key lives in the operator's config FILE rather than the environment.
    """
    key = runtime_llm_key()
    if key:
        env.setdefault("VULNCLAW_LLM_API_KEY", key)
    for name in FORWARDED_ENV:
        value = os.environ.get(name, "").strip()
        if value:
            env.setdefault(name, value)
    return env


def describe(env: dict[str, str]) -> str:
    """A one-line, value-free summary of what credentials the child will see."""
    present = [name for name in FORWARDED_ENV if env.get(name)]
    return f"credentials: {', '.join(present) if present else 'NONE (the run will fail fast)'}"
