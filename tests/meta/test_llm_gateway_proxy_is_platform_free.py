"""Invariant I7: the LLM gateway proxy is not part of any platform package.

Why this exists: `vulnclaw/gcs_platform/gateway_proxy.py` sat between the openai SDK
and the competition **LLM** gateway, but lived inside the **GCS competition API**
package -- so `vulnclaw/agent/core.py` (the agent core) imported a platform
integration in order to build its chat client. Nothing failed; it just meant the
core could not be reasoned about, or tested, without dragging a CTF platform along.

That is a layering property, not a behaviour, so no functional test can catch a
regression. These tests pin it directly:

* the proxy module lives under `vulnclaw/utils/` and is importable from there;
* the old `vulnclaw.gcs_platform.gateway_proxy` path is **gone**, not shimmed --
  a shim would keep the misfiled module in the tree and quietly re-enable the
  import, which is the thing being prevented;
* `vulnclaw/agent/core.py` references no platform package at all.

The last one is a source check rather than an import check on purpose. Importing
`vulnclaw.agent.core` still pulls in `vulnclaw.ctf_platform` and
`vulnclaw.gcs_platform` *transitively* via `vulnclaw/agent/builtin_tools.py`, which
hosts the legacy per-platform tool face and is expected to know platforms until the
migration finishes. Asserting on `sys.modules` would therefore fail for a reason
this invariant is not about; asserting on the core's own imports states the rule
that actually holds today and that must not regress.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE = REPO_ROOT / "vulnclaw" / "agent" / "core.py"
AGENT_PKG = REPO_ROOT / "vulnclaw" / "agent"

PLATFORM_PACKAGES = ("gcs_platform", "ctf_platform")


class TestTheProxyIsNotInAPlatformPackage:
    def test_it_lives_under_utils(self):
        module = importlib.import_module("vulnclaw.utils.gateway_proxy")
        assert module.__name__ == "vulnclaw.utils.gateway_proxy"

    def test_it_exposes_the_two_entry_points_the_core_needs(self):
        from vulnclaw.utils.gateway_proxy import (  # noqa: F401
            ensure_gateway_proxy_running,
            is_gateway_url,
        )

    def test_the_old_gcs_path_is_gone_rather_than_shimmed(self):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("vulnclaw.gcs_platform.gateway_proxy")

    def test_no_platform_package_mentions_the_gateway_proxy_file(self):
        """A leftover re-export would defeat the move without failing anything."""
        offenders: list[str] = []
        for package in PLATFORM_PACKAGES:
            directory = REPO_ROOT / "vulnclaw" / package
            if not directory.is_dir():
                continue
            for path in directory.rglob("*.py"):
                text = path.read_text(encoding="utf-8")
                if "gateway_proxy" in text:
                    offenders.append(str(path.relative_to(REPO_ROOT)))
        assert offenders == [], f"gateway_proxy still referenced inside a platform package: {offenders}"


class TestTheAgentCoreDoesNotImportAPlatform:
    def test_core_references_no_platform_package(self):
        source = CORE.read_text(encoding="utf-8")
        for package in PLATFORM_PACKAGES:
            assert package not in source, (
                f"vulnclaw/agent/core.py must not reference {package}; the gateway "
                f"proxy now lives in vulnclaw/utils/"
            )

    def test_builtin_tools_is_the_only_platform_importer_left_in_agent(self):
        """Documents the remaining coupling instead of pretending it is gone.

        `builtin_tools.py` hosts the legacy per-platform tools, which are hidden
        from the schema by default but still routable. When that face is deleted,
        this test should start failing -- delete it then, deliberately.
        """
        importers = sorted(
            path.name
            for path in AGENT_PKG.glob("*.py")
            if any(package in path.read_text(encoding="utf-8") for package in PLATFORM_PACKAGES)
        )
        assert importers == ["builtin_tools.py"]
