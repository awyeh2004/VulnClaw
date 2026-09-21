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
