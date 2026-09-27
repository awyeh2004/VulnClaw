"""A/B drill scripts: the three hygiene rules a leaked container depends on (round8 L9).

These scripts are not importable in a test -- each ends with a module-level
`asyncio.run(main())`, so importing one would START the drill against the live platform. The
checks below therefore parse the source instead of running it. They pin the three defects the
audit found in this family, all of which have the same shape: a failure path that leaves no
trace, and therefore no consequence, in an experiment whose results are the deliverable.

Measured before the fix, in all three files:

* a failed `start_env` (`continue`) released NOTHING -- and on the last arm nothing ever
  released that container again, so the drill silently left a target running;
* `release()` gave up after three attempts with no log and no return value, so "released"
  and "still allocated" were the same record;
* `negative_control.py` / `cold_warm_pair.py` recorded no `target_after_release` at all, and
  derived `ROOT` from a hard-coded `Path(r"D:\\GitClone\\VulnClaw")`.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = [
    REPO_ROOT / "scripts" / "ab" / "cold_warm_pair.py",
    REPO_ROOT / "scripts" / "ab" / "cold_warm_pair_round2.py",
    REPO_ROOT / "scripts" / "ab" / "negative_control.py",
]


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _func(tree: ast.Module, name: str) -> ast.AsyncFunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name}() not found")


def _module_assignment(tree: ast.Module, name: str) -> ast.expr | None:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return node.value
    return None


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
class TestTheDrillCannotLeaveAContainerBehind:
    def test_root_is_not_a_hard_coded_machine_path(self, path):
        """`Path(r"D:\\GitClone\\VulnClaw")` only exists on the author's machine."""
        value = _module_assignment(_tree(path), "ROOT")
        assert value is not None, "ROOT must be assigned at module level"
        rendered = ast.unparse(value)
        assert "__file__" in rendered or rendered.startswith("REPO"), rendered
        assert ":" not in rendered.replace("::", ""), (
            f"a drive-letter path crept back into ROOT: {rendered}"
        )

    def test_a_failed_start_releases_before_it_skips(self, path):
        """The measured defect: `continue` with the env still allocated."""
        main = _func(_tree(path), "main")
        guards = [
            node
            for node in ast.walk(main)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.UnaryOp)
            and isinstance(node.test.op, ast.Not)
            and ast.unparse(node.test.operand) == "url"
        ]
        assert guards, "the `if not url:` guard moved; update this test deliberately"
        for guard in guards:
            body = ast.unparse(ast.Module(body=guard.body, type_ignores=[]))
            assert "release(" in body, (
                "the failed-start branch must release the env before skipping: " + body
            )
            assert "save(" in body or "write_text" in body, (
                "and it must record the outcome, or the arm vanishes from the results"
            )

    def test_release_reports_its_outcome(self, path):
        """No log, no return value = "released" and "still allocated" look the same."""
        release = _func(_tree(path), "release")
        assert release.returns is not None, "release() must be annotated with a return type"
        assert ast.unparse(release.returns) == "bool", ast.unparse(release.returns)
        assert any(
            isinstance(node, ast.Return) and node.value is not None
            for node in ast.walk(release)
        ), "release() must return whether it succeeded"
        body = ast.unparse(release)
        assert "log(" in body, "giving up must be logged, not silent"

    def test_the_run_records_what_the_env_looked_like_afterwards(self, path):
        """`target_after_release`: the only record that the release actually happened."""
        source = path.read_text(encoding="utf-8")
        assert "target_after_release" in source, (
            "record the platform's view of the env after release, as the other drills do"
        )
        assert "released" in source, "and record release()'s own verdict"
