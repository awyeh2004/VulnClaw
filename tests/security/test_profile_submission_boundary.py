"""The production profile must not talk to a scoring platform.

``VULNCLAW_PROFILE=prod`` marks the production workspace. Submitting a production
finding to a CTF scoring platform is never intended, and the verbs ride in through
two different routes (platform passthrough via MCP, builtin dispatch), so the
check lives on both rather than in the prompt wording.
"""

from __future__ import annotations


def test_profile_submit_boundary(monkeypatch):
    from vulnclaw.agent import builtin_tools
    from vulnclaw.mcp import lifecycle

    monkeypatch.delenv("VULNCLAW_PROFILE", raising=False)
    assert builtin_tools._profile_blocks_submission() is False
    assert lifecycle._profile_blocks_submission("ctf2_submit_flag") is False
    assert lifecycle._profile_blocks_submission("fetch") is False

    monkeypatch.setenv("VULNCLAW_PROFILE", "prod")
    assert builtin_tools._profile_blocks_submission() is True
    assert lifecycle._profile_blocks_submission("ctf2_submit_flag") is True
    assert lifecycle._profile_blocks_submission("gcs_submit_competition_flag") is True
    # Non-submission tools are untouched: prod still fetches, scans and reports.
    assert lifecycle._profile_blocks_submission("fetch") is False


def test_platform_submit_is_gated_on_the_mcp_route_too(monkeypatch):
    """``platform_submit`` does not end in ``_submit_flag``.

    The suffix rule alone let it through the MCP gate while the builtin route
    blocked it; the two routes must agree on the same verb.
    """
    from vulnclaw.agent import builtin_tools
    from vulnclaw.mcp import lifecycle

    monkeypatch.setenv("VULNCLAW_PROFILE", "prod")
    assert lifecycle._is_submission_tool("platform_submit") is True
    assert lifecycle._profile_blocks_submission("platform_submit") is True
    assert builtin_tools._profile_blocks_submission() is True


def test_an_unreadable_profile_blocks_instead_of_allowing(monkeypatch):
    """A policy read error must not become a scoring attempt."""
    from vulnclaw.agent import builtin_tools
    from vulnclaw.mcp import lifecycle

    import vulnclaw.config.profile as profile_mod

    def _boom():
        raise RuntimeError("profile policy unreadable")

    monkeypatch.setattr(profile_mod, "current_profile", _boom)
    assert lifecycle._profile_blocks_submission("ctf2_submit_flag") is True
    assert builtin_tools._profile_blocks_submission() is True


def test_a_production_call_never_revives_the_held_scheduler(monkeypatch):
    """The gate must run BEFORE ``_ensure_held_scheduler``.

    Otherwise the first prod MCP call pumps a CTF queue left by an earlier run,
    and the scheduler would fire it from a process that must never submit.
    """
    import asyncio

    from vulnclaw.mcp import lifecycle

    monkeypatch.setenv("VULNCLAW_PROFILE", "prod")
    manager = object.__new__(lifecycle.MCPLifecycleManager)
    revoked: list[str] = []
    manager.registry = type(
        "R",
        (),
        {"get_server_for_tool": lambda self, name: "ctf2"},
    )()
    manager._ensure_held_scheduler = lambda: revoked.append("scheduler")

    result = asyncio.run(manager.call_tool("ctf2_submit_flag", {"flag": "x"}))

    assert revoked == [], "scheduler was revived before the profile gate"
    assert "[profile]" in result
