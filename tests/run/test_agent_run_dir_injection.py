"""A run must hand the agent the run directory it is executing inside.

Without this seam the agent has no idea which run it belongs to, so every
evidence write resolves to the process-wide ``CONFIG_DIR/evidence`` root and two
concurrent runs (or a later run in the same process) see each other's captures.
This is the injection half of the writer/reader agreement; the round trip is
covered in ``tests/traffic/test_evidence_run_isolation.py``.
"""

from __future__ import annotations

import asyncio

from vulnclaw.agent.core import AgentCore
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.orchestrator import run_agent_task


def test_run_agent_task_anchors_the_agent_to_its_run_dir(tmp_path):
    agent = AgentCore(VulnClawConfig())
    seen: dict[str, str] = {}

    async def runner(a: AgentCore) -> None:
        # What the agent sees *during* the run -- this is what the evidence
        # writers read, so it is the value that matters.
        seen["run_dir"] = a.run_dir

    result = asyncio.run(
        run_agent_task(
            agent=agent,
            command="scan",
            target="http://app.test",
            run_name="t2-run",
            runs_dir=str(tmp_path / "runs"),
            resume=False,
            no_import=True,
            runner=runner,
        )
    )

    expected = str(tmp_path / "runs" / "t2-run")
    assert seen["run_dir"] == expected
    assert result.run_context is not None
    assert agent.run_dir == str(result.run_context.run_dir)
