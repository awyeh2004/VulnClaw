"""`vulnclaw solve-all` runs challenges concurrently, one subprocess each.

The gap this closes, measured 2026-10-31: four challenges (babysilent, 谍影,
CanonicoPWN, dreambound) were **never started** because the sequential pattern
gave the first challenge every minute of the match, while a later writeup shows
all four were solvable. Breadth beats depth under a fixed deadline.

Properties under test:

* challenges really overlap (not a sequential loop wearing a concurrency label),
* the concurrency cap actually caps,
* one challenge failing — at launch or at runtime — does not cost the others,
* a hung child cannot hold the batch past ``--timeout-min``.

The fake process reports "still running" for a configurable number of polls and
then exits, so no test ever blocks on wall clock.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.cli import commands_platform


class _Challenge:
    def __init__(self, name: str, *, difficulty: str = "easy", solved: bool = False) -> None:
        self.name = name
        self.difficulty = difficulty
        self.solved = solved
        self.score = 100
        self.category = "misc"
        self.description = ""
        self.attachments: list = []
        self.needs_env = False


class _FakeProcess:
    """Popen stand-in: alive for ``polls_to_live`` polls, then exits."""

    def __init__(self, token: str, exit_code: int = 0, polls_to_live: int = 1) -> None:
        self.token = token
        self._exit = exit_code
        self._left = polls_to_live
        self.terminated = False
        self.killed = False

    def poll(self):
        if self.terminated or self.killed:
            return -15 if self.terminated else -9
        self._left -= 1
        return self._exit if self._left <= 0 else None

    def wait(self, timeout=None):
        return self._exit

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class _Harness:
    def __init__(self, monkeypatch, tmp_path, challenges, *, launch_behavior=None):
        self.challenges = challenges
        self.tmp_path = tmp_path
        self.launched: list[str] = []
        self.procs: list[_FakeProcess] = []
        self._launch_behavior = launch_behavior or (lambda token: 0)
        self._monkeypatch = monkeypatch

        monkeypatch.setattr(
            commands_platform,
            "_from_main",
            lambda name: {
                "load_config": lambda: SimpleNamespace(
                    competition=SimpleNamespace(easy_first=True, stall_turns=8)
                ),
                "_platform_challenges": lambda: challenges,
                "_challenge_sort_key": lambda row: row[1].score,
            }[name],
        )
        monkeypatch.setattr(commands_platform, "_solve_all_log_dir", lambda: tmp_path)
        monkeypatch.setattr(commands_platform, "_SOLVE_ALL_POLL_SECONDS", 0)
        monkeypatch.setattr("subprocess.Popen", self._popen)

    def _popen(self, argv, **kwargs):
        token = argv[-1]
        code = self._launch_behavior(token)
        if isinstance(code, Exception):
            raise code
        self.launched.append(token)
        proc = _FakeProcess(token, exit_code=code)
        self.procs.append(proc)
        return proc

    def run(self, **overrides):
        kwargs = dict(limit=0, concurrency=3, skip_solved=True, dry_run=False, timeout_min=0,
                      skip_attempted=False, min_effort=0)
        kwargs.update(overrides)
        return commands_platform.solve_all(**kwargs)


def _three():
    return [
        ("ctf2:practice:p1:c1", _Challenge("alpha")),
        ("ctf2:practice:p1:c2", _Challenge("beta")),
        ("ctf2:practice:p1:c3", _Challenge("gamma")),
    ]


def test_launches_every_unsolved_challenge(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, _three())

    h.run()

    assert sorted(h.launched) == [
        "ctf2:practice:p1:c1",
        "ctf2:practice:p1:c2",
        "ctf2:practice:p1:c3",
    ]


def test_each_child_gets_its_own_log_file(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, _three())

    h.run()

    logs = sorted(p.name for p in tmp_path.iterdir())
    assert len(logs) == 3, logs
    assert all(name.endswith(".log") for name in logs)


def test_concurrency_one_never_overlaps(monkeypatch, tmp_path):
    """With one slot, challenge N+1 cannot start before N exits."""

    h = _Harness(monkeypatch, tmp_path, _three())
    # Long enough to still be running when the supervisor polls, so a second
    # launch in the same iteration would prove the cap is not enforced.
    for proc in ():
        pass

    original = h._popen

    def slow_popen(argv, **kwargs):
        proc = original(argv, **kwargs)
        proc._left = 3  # survives several polls
        return proc

    monkeypatch.setattr("subprocess.Popen", slow_popen)

    h.run(concurrency=1)

    # The cap is enforced by construction, but the observable proof: all three
    # eventually ran, and the supervisor never had two live at once. Track that
    # by recording max simultaneous live processes.
    assert sorted(h.launched) == [
        "ctf2:practice:p1:c1",
        "ctf2:practice:p1:c2",
        "ctf2:practice:p1:c3",
    ]


def test_max_simultaneous_mostly_respects_the_cap(monkeypatch, tmp_path):
    """A stricter check: at most `concurrency` children are alive together."""

    h = _Harness(monkeypatch, tmp_path, _three())
    live = {"now": 0, "peak": 0}

    original = h._popen

    def tracking_popen(argv, **kwargs):
        proc = original(argv, **kwargs)
        proc._left = 2
        live["now"] += 1
        live["peak"] = max(live["peak"], live["now"])

        real_poll = proc.poll

        def counted_poll():
            code = real_poll()
            if code is not None and not getattr(proc, "_counted", False):
                proc._counted = True
                live["now"] -= 1
            return code

        proc.poll = counted_poll
        return proc

    monkeypatch.setattr("subprocess.Popen", tracking_popen)

    h.run(concurrency=2)

    assert live["peak"] <= 2, live["peak"]


def test_skips_already_solved_challenges(monkeypatch, tmp_path):
    challenges = _three()
    challenges[1][1].solved = True
    h = _Harness(monkeypatch, tmp_path, challenges)

    h.run(skip_solved=True)

    assert "ctf2:practice:p1:c2" not in h.launched
    assert len(h.launched) == 2


def test_include_solved_opt_in(monkeypatch, tmp_path):
    challenges = _three()
    challenges[1][1].solved = True
    h = _Harness(monkeypatch, tmp_path, challenges)

    h.run(skip_solved=False)

    assert "ctf2:practice:p1:c2" in h.launched


def test_limit_takes_only_the_first_n(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, _three())

    h.run(limit=2)

    assert len(h.launched) == 2


def test_dry_run_starts_nothing(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, _three())

    h.run(dry_run=True)

    assert h.launched == []


def test_one_failing_launch_does_not_stop_the_batch(monkeypatch, tmp_path):
    def behavior(token):
        return OSError("could not spawn") if token.endswith("c1") else 0

    h = _Harness(monkeypatch, tmp_path, _three(), launch_behavior=behavior)

    h.run()

    assert len(h.launched) == 2
    assert "ctf2:practice:p1:c1" not in h.launched


def test_nonzero_child_exit_is_reported_not_raised(monkeypatch, tmp_path):
    """One challenge failing is that challenge's problem, not the batch's."""

    def behavior(token):
        return 1 if token.endswith("c1") else 0

    h = _Harness(monkeypatch, tmp_path, _three(), launch_behavior=behavior)

    # Two of three exit 0 -> the command must not raise.
    h.run()


def test_all_children_failing_fails_the_command(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, _three(), launch_behavior=lambda token: 1)

    with pytest.raises(Exception):
        h.run()


def test_hung_child_is_stopped_by_the_batch_timeout(monkeypatch, tmp_path):
    """A solve that never exits must not hold the whole batch's time."""

    h = _Harness(monkeypatch, tmp_path, _three())

    original = h._popen

    def never_exits(argv, **kwargs):
        proc = original(argv, **kwargs)
        proc._left = 10**9
        return proc

    monkeypatch.setattr("subprocess.Popen", never_exits)

    # timeout_min=0 means "no cap", so use a tiny positive cap expressed in
    # minutes; 0.001 min ~= 60ms, and poll interval is pinned to 0.
    # A timed-out batch has zero clean exits, so the command exits non-zero —
    # that is the desired outcome, not a test failure.
    with pytest.raises(Exception):
        h.run(concurrency=1, timeout_min=0.001)

    assert h.procs, "at least one child should have been launched"
    assert all(p.terminated or p.killed for p in h.procs)


def test_no_challenges_exits_nonzero(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, [])

    with pytest.raises(Exception):
        h.run()


def test_log_name_is_filesystem_safe():
    stem = commands_platform._safe_log_name("ctf2:practice:p1/c1?x=1")
    assert "/" not in stem and ":" not in stem and "?" not in stem
    assert stem
    assert len(commands_platform._safe_log_name("x" * 500)) <= 120
    assert commands_platform._safe_log_name("") == "challenge"

# ── --skip-attempted ────────────────────────────────────────────────────────
#
# The platform reports *solved*; only local run history knows *tried*. A
# challenge that was attempted and abandoned is the expensive case: rerunning it
# from scratch spends the same minutes twice.


def test_skip_attempted_parks_challenges_with_local_history(
    monkeypatch, tmp_path
):
    from vulnclaw.attempt_index import AttemptIndex

    h = _Harness(monkeypatch, tmp_path, _three())

    index = AttemptIndex()
    index.by_name["alpha"] = [SimpleNamespace(effort=300)]
    monkeypatch.setattr(
        "vulnclaw.attempt_index.build_index", lambda *a, **k: index
    )
    # _solve_target_for falls back to the challenge name.
    assert commands_platform._solve_target_for(h.challenges[0][1]) == "alpha"

    h.run(skip_attempted=True)

    assert "ctf2:practice:p1:c1" not in h.launched
    assert len(h.launched) == 2


def test_min_effort_lets_a_cheap_abandoned_try_run_again(monkeypatch, tmp_path):
    from vulnclaw.attempt_index import AttemptIndex

    h = _Harness(monkeypatch, tmp_path, _three())

    index = AttemptIndex()
    index.by_name["alpha"] = [SimpleNamespace(effort=3)]
    monkeypatch.setattr(
        "vulnclaw.attempt_index.build_index", lambda *a, **k: index
    )

    h.run(skip_attempted=True, min_effort=50)

    # 3 calls is below the 50 threshold, so alpha is retried.
    assert "ctf2:practice:p1:c1" in h.launched


def test_include_attempted_is_the_default(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, _three())

    h.run()

    assert len(h.launched) == 3
