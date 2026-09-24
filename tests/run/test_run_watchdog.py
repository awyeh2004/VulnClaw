"""run_watchdog helpers: config-dir resolution, run-name confinement, mtime races.

Round-5 review N9:
  * ``_default_home`` inserted a repo-local ``.test-tmp/vulnclaw-home`` step
    before the real default, so a stray drill leftover on a dev machine hijacked
    the watchdog — it then reported on a different directory's runs, or on none,
    which is exactly what makes a watchdog call a healthy run stalled;
  * ``max(files, key=lambda p: p.stat().st_mtime)`` raised OSError when a file
    vanished between listing and stat, killing the watchdog itself;
  * ``--run ../../x`` walked out of ``runs/``, so state was read and the report
    written outside the runs tree.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load_watchdog():
    spec = importlib.util.spec_from_file_location(
        "run_watchdog_under_test", ROOT / "scripts" / "run_watchdog.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def watchdog():
    return _load_watchdog()


def test_default_home_matches_the_config_dir_vulnclaw_uses(watchdog):
    from vulnclaw.config.settings import CONFIG_DIR

    assert Path(watchdog.DEFAULT_HOME) == Path(CONFIG_DIR)


def test_default_home_ignores_a_stray_drill_directory(watchdog, tmp_path, monkeypatch):
    """A leftover `.test-tmp/vulnclaw-home` must not hijack the resolution."""
    stray = ROOT / ".test-tmp" / "vulnclaw-home"
    if not stray.is_dir():
        pytest.skip("no drill leftover present to test against")
    from vulnclaw.config.settings import CONFIG_DIR

    assert Path(watchdog._default_home()) == Path(CONFIG_DIR)
    assert Path(watchdog._default_home()) != stray


def test_default_home_honours_the_env_override(watchdog, tmp_path, monkeypatch):
    """The override comes from settings, so patch what settings resolved to.

    Deliberately NOT `importlib.reload(vulnclaw.config.settings)`: a reload
    recomputes every module-level path in that module and leaves modules that
    already imported a derived constant holding stale values, which leaked into
    unrelated test files (CLI tests failed when this file happened to run first).
    """
    import vulnclaw.config.settings as settings

    monkeypatch.setattr(settings, "CONFIG_DIR", tmp_path / "home", raising=True)
    assert Path(watchdog._default_home()) == tmp_path / "home"


@pytest.mark.parametrize(
    "name",
    ["../../evil", "..\\evil", "/abs", "C:\\abs", "a/b", "..", ".", "", "x\x00y"],
)
def test_run_names_are_confined_to_the_runs_directory(watchdog, tmp_path, name):
    with pytest.raises(SystemExit):
        watchdog._run_dir(tmp_path, name)


def test_a_plain_run_name_resolves_inside_runs(watchdog, tmp_path):
    got = watchdog._run_dir(tmp_path, "ir-target1")
    assert got.parent == (tmp_path / "runs").resolve()
    assert got.name == "ir-target1"


def test_safe_mtime_reports_a_vanished_file(watchdog, tmp_path):
    missing = tmp_path / "gone"
    assert watchdog._safe_mtime(missing) == -1.0


def test_find_log_survives_a_file_vanishing(watchdog, tmp_path, monkeypatch):
    """The file must survive the listing and vanish before the sort key runs."""
    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True)
    (run_dir / "a.jsonl").write_text("x", encoding="utf-8")

    real_stat = Path.stat
    calls = {"n": 0}

    def _flaky_stat(self, *args, **kwargs):
        if self.name == "a.jsonl":
            calls["n"] += 1
            if calls["n"] > 1:  # survives is_file(), gone when max() stats it
                raise FileNotFoundError(str(self))
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", _flaky_stat)
    assert watchdog._find_log(run_dir) == run_dir / "a.jsonl"


def test_current_state_survives_a_file_vanishing(watchdog, tmp_path, monkeypatch):
    run_dir = tmp_path / "runs" / "r1"
    (run_dir / "t1").mkdir(parents=True)
    (run_dir / "t1" / "current.json").write_text("{}", encoding="utf-8")

    real_stat = Path.stat

    def _flaky_stat(self, *args, **kwargs):
        if self.name == "current.json":
            raise FileNotFoundError(str(self))
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", _flaky_stat)
    assert watchdog._current_state(run_dir) == run_dir / "t1" / "current.json"


class TestFollowWaitsForAVerdict:
    """Round-5 finding W1: `--follow` exited on the first poll with status `unknown`.

    Measured at HEAD before the fix (empty run dir, ``--stall-secs 3``, ``--quiet``)::

        returned after 0.60s (stall grace is 3.0s)
        output: STATUS r1: unknown
                activity: none yet (no activity files yet)
                no state checkpoint yet (run may still be starting)

    i.e. a *verdict* on a run that had not started, whose first line (`unknown`) is not
    even one of the outcomes the epilog tells readers to expect -- while the blocking
    mode had always waited out the same grace before saying ``NO_RUN_DIR``.
    """

    def _args(self, watchdog, home, **over):
        import argparse

        base = dict(
            run="r1",
            home=str(home),
            stall_secs=0.25,
            max_minutes=5.0,
            interval=0.02,
            report=None,
            verbose=False,
            status=False,
            follow=True,
            quiet=True,
        )
        base.update(over)
        return argparse.Namespace(**base)

    def _home(self, tmp_path, *, with_run_json=True):
        home = tmp_path / "home"
        run_dir = home / "runs" / "r1"
        run_dir.mkdir(parents=True)
        if with_run_json:
            (run_dir / "run.json").write_text('{"status": "running"}', encoding="utf-8")
        return home

    def _run(self, watchdog, args, monkeypatch=None):
        import io
        import time
        from contextlib import redirect_stdout

        buf = io.StringIO()
        started = time.time()
        with redirect_stdout(buf):
            code = watchdog.follow_status(args)
        return code, buf.getvalue(), time.time() - started

    def _final_block(self, out):
        """The final block's lines: the epilog calls its FIRST line the verdict.

        Waiting lines ("not started yet") may precede it, so the promise is about the
        block, not about the whole stream.
        """
        lines = [line for line in out.splitlines() if line.strip()]
        for index, line in enumerate(lines):
            if line.startswith("WATCHDOG "):
                return lines[index:]
        return []

    def test_a_missing_run_json_is_waited_out_then_reported_as_no_run_dir(
        self, watchdog, tmp_path
    ):
        home = self._home(tmp_path, with_run_json=False)
        code, out, elapsed = self._run(watchdog, self._args(watchdog, home))

        assert code == 0
        assert out.splitlines()[0] == "WATCHDOG NO_RUN_DIR", out
        assert elapsed >= 0.25, (
            f"follow gave up after {elapsed:.2f}s; the grace period is 0.25s in this test"
        )
    def test_the_first_poll_no_longer_ends_the_follow(self, watchdog, tmp_path, monkeypatch):
        """A scripted sequence: unknown, unknown, running, completed."""
        home = self._home(tmp_path)
        scripted = [
            (["STATUS r1: unknown"], "unknown", (0, 0)),
            (["STATUS r1: unknown"], "unknown", (0, 0)),
            (["STATUS r1: running"], "running", (1, 2)),
            (["STATUS r1: completed"], "completed", (3, 4)),
        ]
        calls = {"n": 0}

        def fake_status(_args):
            i = min(calls["n"], len(scripted) - 1)
            calls["n"] += 1
            return scripted[i]

        monkeypatch.setattr(watchdog, "_status_lines", fake_status)
        code, out, _elapsed = self._run(
            watchdog, self._args(watchdog, home, stall_secs=30.0, quiet=False)
        )

        assert code == 0
        assert calls["n"] == 4, "the unknown polls must not have ended the loop"
        assert "unknown" not in out, out
        block = self._final_block(out)
        assert block and block[0] == "WATCHDOG ENDED:COMPLETED", out

    def test_quiet_stays_silent_while_there_is_no_verdict(self, watchdog, tmp_path, monkeypatch):
        home = self._home(tmp_path)
        scripted = [([], "unknown", (0, 0))] * 3 + [([], "running", (2, 2))] * 3
        calls = {"n": 0}

        def fake_status(_args):
            i = min(calls["n"], len(scripted) - 1)
            calls["n"] += 1
            return scripted[i]

        monkeypatch.setattr(watchdog, "_status_lines", fake_status)
        _code, out, _elapsed = self._run(
            watchdog, self._args(watchdog, home, max_minutes=0.05, quiet=True)
        )

        lines = [line for line in out.splitlines() if line.strip()]
        assert lines[0] == "WATCHDOG TIMEOUT", out
        assert len(lines) == 2, (
            "quiet must print nothing per poll -- only the final block: " + out
        )

    def test_the_final_block_always_opens_with_the_documented_word(
        self, watchdog, tmp_path, monkeypatch
    ):
        """The epilog promises the verdict is the first line of the final block."""
        home = self._home(tmp_path)
        for status, expected in (
            ("completed", "ENDED:COMPLETED"),
            ("failed", "ENDED:FAILED"),
            ("needs-input", "NEEDS_INPUT"),
            ("cancelled", "ENDED:CANCELLED"),
        ):
            monkeypatch.setattr(
                watchdog, "_status_lines", lambda _a, s=status: ([f"STATUS r1: {s}"], s, (1, 1))
            )
            _code, out, _elapsed = self._run(watchdog, self._args(watchdog, home))
            block = self._final_block(out)
            assert block and block[0] == f"WATCHDOG {expected}", (status, out)

    def test_a_run_that_appears_late_is_followed_to_its_end(self, watchdog, tmp_path, monkeypatch):
        """The real shape: nothing on disk for a while, then a normal run."""
        home = self._home(tmp_path, with_run_json=False)
        run_json = home / "runs" / "r1" / "run.json"
        scripted = [([], "unknown", (0, 0))] * 4 + [([], "completed", (1, 1))]
        calls = {"n": 0}

        def fake_status(_args):
            i = min(calls["n"], len(scripted) - 1)
            calls["n"] += 1
            if calls["n"] == 3:
                run_json.write_text('{"status": "running"}', encoding="utf-8")
            return scripted[i]

        monkeypatch.setattr(watchdog, "_status_lines", fake_status)
        _code, out, _elapsed = self._run(
            watchdog, self._args(watchdog, home, stall_secs=30.0, quiet=False)
        )

        block = self._final_block(out)
        assert block and block[0] == "WATCHDOG ENDED:COMPLETED", out
        assert "NO_RUN_DIR" not in out

    def test_unknown_after_run_json_exists_is_not_no_run_dir(self, watchdog, tmp_path, monkeypatch):
        """run.json present but statusless is a wait, not a NO_RUN_DIR accusation."""
        home = self._home(tmp_path)
        (home / "runs" / "r1" / "run.json").write_text("{}", encoding="utf-8")
        monkeypatch.setattr(
            watchdog, "_status_lines", lambda _a: (["STATUS r1: unknown"], "unknown", (0, 0))
        )
        _code, out, _elapsed = self._run(
            watchdog, self._args(watchdog, home, stall_secs=0.05, max_minutes=0.05)
        )
        assert out.splitlines()[0] == "WATCHDOG TIMEOUT", out

    def test_outcome_words_cover_the_epilog_vocabulary(self, watchdog):
        assert watchdog._outcome_word("completed") == "ENDED:COMPLETED"
        assert watchdog._outcome_word("FAILED") == "ENDED:FAILED"
        assert watchdog._outcome_word("needs-input") == "NEEDS_INPUT"
        assert watchdog._outcome_word("stopped") == "ENDED:STOPPED"


class TestStallVerdictDeepWork:
    """Findings on record turn a silent stall into DEEP_WORK (c03 lesson)."""

    def _run_dir_with_state(self, tmp_path, findings):
        import json
        import time

        run_dir = tmp_path / "runs" / "r1"
        state_dir = run_dir / "targets" / "abc" / "state"
        state_dir.mkdir(parents=True)
        state = {"phase": "vuln_discovery", "findings": findings}
        p = state_dir / "current.json"
        p.write_text(json.dumps(state), encoding="utf-8")
        time.sleep(0.01)
        return run_dir

    def test_findings_turn_stall_into_deep_work(self, watchdog, tmp_path):
        run_dir = self._run_dir_with_state(
            tmp_path, [{"title": "RCE candidate (pending)", "confidence": 0.55}]
        )
        verdict, detail = watchdog._stall_verdict(run_dir, 1200.0, "state.jsonl", "running")
        assert verdict == "DEEP_WORK"
        assert "do NOT kill" in detail
        assert "RCE candidate" in detail

    def test_no_findings_stays_stuck(self, watchdog, tmp_path):
        run_dir = self._run_dir_with_state(tmp_path, [])
        verdict, detail = watchdog._stall_verdict(run_dir, 1200.0, "state.jsonl", "running")
        assert verdict == "STUCK"
        assert "do NOT kill" not in detail

    def test_string_findings_do_not_crash(self, watchdog, tmp_path):
        run_dir = self._run_dir_with_state(tmp_path, ["legacy plain-string finding"])
        verdict, detail = watchdog._stall_verdict(run_dir, 1200.0, "state.jsonl", "running")
        assert verdict == "DEEP_WORK"
        assert "legacy plain-string finding" in detail
