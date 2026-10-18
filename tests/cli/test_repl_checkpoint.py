"""REPL run persistence and interrupt-noise retrieval (TECH-DEBT ## 3 ①/②b).

Measured 2026-10-15 (乐橙 ISRC session): the REPL drove ``agent.solve`` directly
and never persisted the finished run — the Solve panel said 目标达成 while
``targets/<id>/state.json`` still had ``completed=False`` / no findings, so a
later ``target X`` restored that stale snapshot. The command path persists via
``orchestrator.checkpoint`` (boundary callback + explicit calls); the REPL now
installs the same callback and checkpoints run_complete/interrupt explicitly.
"""

import json

from vulnclaw.agent.context import SessionState
from vulnclaw.cli.repl import (
    _checkpoint_repl_agent,
    _ensure_repl_checkpoint_callback,
    _retrieve_interrupted_task,
)


class _FakeAgent:
    def __init__(self, target="mall.imou.com"):
        self.session_state = SessionState(target=target)
        self.runtime = None


def _isolate(monkeypatch, tmp_path):
    import vulnclaw.target_state.store as store_mod

    monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path)
    return store_mod


class TestCheckpointReplAgent:
    def test_completed_run_is_persisted(self, monkeypatch, tmp_path):
        """Failure reproduction: panel-done ⇒ the saved state must say so."""
        _isolate(monkeypatch, tmp_path)
        agent = _FakeAgent()
        agent.session_state.agent_state.completed = True

        path = _checkpoint_repl_agent(agent, "run_complete")

        assert path is not None
        doc = json.loads(open(path, encoding="utf-8").read())
        assert doc["agent_state"]["completed"] is True
        assert doc["target"] == "mall.imou.com"

    def test_no_target_is_a_noop(self, monkeypatch, tmp_path):
        _isolate(monkeypatch, tmp_path)
        assert _checkpoint_repl_agent(_FakeAgent(target=""), "step_complete") is None

    def test_callback_persists_and_rearms_after_state_replacement(
        self, monkeypatch, tmp_path
    ):
        _isolate(monkeypatch, tmp_path)
        agent = _FakeAgent()
        _ensure_repl_checkpoint_callback(agent)
        agent.session_state._notify_checkpoint("finding_added")
        first = list(tmp_path.rglob("snapshots/*.json"))
        assert len(first) >= 1

        # apply_target_state_to_agent REPLACES the state object; a bare
        # assignment models that, and the reinstall must re-arm persistence.
        agent.session_state = SessionState(target="mall.imou.com")
        _ensure_repl_checkpoint_callback(agent)
        agent.session_state._notify_checkpoint("finding_added")
        assert len(list(tmp_path.rglob("snapshots/*.json"))) > len(first)

    def test_checkpoint_merges_and_does_not_drop_on_disk_findings(
        self, monkeypatch, tmp_path
    ):
        """The natural-language target-adoption branch does not hydrate, so the
        in-memory state can be a strict subset of what is on disk. A non-merging
        write used to replace it wholesale -- measured 2026-10-16, a stored
        finding went from ['SQLi in /login'] to [].
        """
        from vulnclaw.agent.context import VulnerabilityFinding
        from vulnclaw.target_state.store import save_target_state

        store_mod = _isolate(monkeypatch, tmp_path)
        rich = SessionState(target="victim.example")
        rich.add_finding(
            VulnerabilityFinding(
                title="SQLi in /login", vuln_type="sqli", target="victim.example"
            )
        )
        path = save_target_state("victim.example", rich, command="run")
        assert json.loads(path.read_text(encoding="utf-8"))["findings"]

        # A fresh, in-memory-only session for the SAME target (no hydration).
        agent = _FakeAgent(target="victim.example")
        assert _checkpoint_repl_agent(agent, "run_complete") is not None

        titles = [
            f.get("title")
            for f in json.loads(path.read_text(encoding="utf-8"))["findings"]
        ]
        assert "SQLi in /login" in titles, "checkpoint dropped an on-disk finding"
        assert store_mod is not None


class TestInterruptRetrieval:
    def test_done_task_exception_is_retrieved_and_ref_cleared(self):
        import asyncio

        import vulnclaw.cli.repl as repl_mod

        async def _boom():
            raise ValueError("boom")

        async def _spawn():
            task = asyncio.get_running_loop().create_task(_boom())
            await asyncio.sleep(0)  # let the task finish un-awaited
            return task

        task = asyncio.run(_spawn())
        assert task.done()

        repl_mod._REPL_INTERRUPTED_TASK = task
        _retrieve_interrupted_task()
        assert repl_mod._REPL_INTERRUPTED_TASK is None

    def test_no_recorded_task_is_a_noop(self):
        import vulnclaw.cli.repl as repl_mod

        repl_mod._REPL_INTERRUPTED_TASK = None
        _retrieve_interrupted_task()  # must not raise

    def test_cancelled_task_does_not_raise_and_is_retrieved(self):
        """``Task.exception()`` raises ``CancelledError`` — a BaseException, so a
        bare ``except Exception`` would let it escape the teardown path."""
        import asyncio

        import vulnclaw.cli.repl as repl_mod

        async def _cancel_me():
            raise asyncio.CancelledError()

        async def _spawn():
            task = asyncio.get_running_loop().create_task(_cancel_me())
            await asyncio.sleep(0)
            return task

        task = asyncio.run(_spawn())
        assert task.cancelled()

        repl_mod._REPL_INTERRUPTED_TASK = task
        _retrieve_interrupted_task()  # must not raise CancelledError
        assert repl_mod._REPL_INTERRUPTED_TASK is None

    def test_pending_task_keeps_the_reference(self):
        import asyncio

        import vulnclaw.cli.repl as repl_mod

        async def _spawn_pending():
            async def _never():
                await asyncio.sleep(10)

            task = asyncio.get_running_loop().create_task(_never())
            await asyncio.sleep(0)
            assert not task.done()
            repl_mod._REPL_INTERRUPTED_TASK = task
            _retrieve_interrupted_task()
            assert repl_mod._REPL_INTERRUPTED_TASK is task  # kept for the retry
            task.cancel()

        asyncio.run(_spawn_pending())
