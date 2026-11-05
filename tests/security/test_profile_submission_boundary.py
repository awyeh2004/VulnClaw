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
