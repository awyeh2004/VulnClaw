"""Empty Enter must not silently re-run a task the agent already finished.

Field report (2026-10-06): after a completed CTF2 solve the operator typed a NEW
challenge, the line was eaten by the Ctrl+C exit-confirm, they pressed Enter —
and the REPL re-ran the OLD challenge. To the operator that reads as "the agent
ignored me and solved the old task on its own".

Two independent guards keep that from happening, and both are pinned here:

* the launch text (``last_auto_input``) is cleared the moment a run finishes on
  its own — there is nothing left to replay;
* even if something re-populates it, the empty-Enter replay path asks
  ``_repl_last_run_finished`` first and refuses to replay a finished run.
"""

from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.cli.main import _repl_has_in_progress_run, _repl_last_run_finished


def _agent(*, completed: bool, evidence=None, nodes=None):
    state = SimpleNamespace(completed=completed, evidence=evidence or [], tool_calls=[])
    bb = SimpleNamespace(all_nodes=lambda: list(nodes or []))
    return SimpleNamespace(
        context=SimpleNamespace(state=SimpleNamespace(agent_state=state)),
        runtime=SimpleNamespace(blackboard=bb),
    )


class TestLastRunFinished:
    def test_completed_run_is_finished(self):
        assert _repl_last_run_finished(_agent(completed=True)) is True

    def test_unfinished_run_is_not_finished(self):
        assert _repl_last_run_finished(_agent(completed=False)) is False

    def test_unreadable_state_is_conservatively_not_finished(self):
        """A broken agent must fall back to the old behaviour (allow a retry),
        never to silently dropping one."""
        broken = SimpleNamespace(context=SimpleNamespace(state=SimpleNamespace()))
        assert _repl_last_run_finished(broken) is False


class TestTheTwoGuardsAgreeOnTheFailureShape:
    def test_a_finished_run_is_neither_resumable_nor_replayable(self):
        """The exact reported state: run done -> Enter must be a no-op, and the
        in-progress check must not claim there is something to resume."""
        agent = _agent(completed=True, evidence=[{"id": "e1"}])
        assert _repl_has_in_progress_run(agent) is False
        assert _repl_last_run_finished(agent) is True

    def test_an_interrupted_run_is_resumable(self):
        agent = _agent(completed=False, evidence=[{"id": "e1"}])
        assert _repl_has_in_progress_run(agent) is True
        assert _repl_last_run_finished(agent) is False

    def test_a_launch_that_never_gathered_anything_is_replayable(self):
        """Interrupted before any tool ran: in-place resume has nothing to
        resume, but replaying the launch text is the right retry."""
        agent = _agent(completed=False, evidence=[])
        assert _repl_has_in_progress_run(agent) is False
        assert _repl_last_run_finished(agent) is False
