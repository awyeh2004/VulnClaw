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


def _prologue_only(tree: ast.Module) -> list[ast.stmt]:
    """The module statements that RUN at import time, with the dangerous parts removed.

    Function and class BODIES become `pass` (they only run when called), and the drill's
    entry point -- a module-level `asyncio.run(main())` -- is dropped, because main() is what
    starts the drill against the live platform. Everything else is kept, so the constant
    prologue is executed for real: that is what resolves names and catches F1.

    The entry point is matched by NAME (`asyncio.run`), not by "any module-level call". The
    first version dropped every module-level call, which was fine only while `asyncio.run`
    happened to be the only one -- adding a `sys.path.insert(...)` for a sibling helper then
    broke the prologue here while the script itself still ran correctly, i.e. the guard
    reported a failure that did not exist.
    """
    body: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            node.body = [ast.Pass()]
            body.append(node)
            continue
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and ast.unparse(node.value.func) == "asyncio.run"
        ):
            continue
        body.append(node)
    return body


def _looks_like_machine_path(text: str) -> bool:
    """A drive-letter or home-absolute literal, i.e. a path that only exists somewhere."""
    if len(text) > 2 and text[1] == ":" and text[0].isalpha() and text[2] in "\\/":
        return True
    return text.startswith(("/home/", "/Users/", "C:\\"))


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
class TestTheDrillCannotLeaveAContainerBehind:
    def test_the_module_level_prologue_actually_executes(self, path):
        """F1: `ROOT = REPO.parent` was placed ABOVE `REPO = ...` and nobody noticed.

        Both earlier checks were blind to it by construction -- and they were the only two:

        * `py_compile` (what the commit cited as "compiles") checks SYNTAX; a `NameError` is
          name resolution, which happens at execution;
        * the static checks in this file only inspect `ast.unparse`d text, and
          `test_root_is_not_a_hard_coded_machine_path` accepted anything containing "REPO".

        So this executes the module's constant prologue: imports, top-level assignments and
        the Path arithmetic between them, with every function BODY replaced by `pass` and the
        trailing `asyncio.run(main())` dropped. That resolves the real names (a genuine
        `NameError`/`AttributeError` at module scope fails here) while never reaching the
        drill -- main() is the only thing that talks to the platform, and it is not called.
        """
        tree = _tree(path)
        stripped = ast.Module(body=_prologue_only(tree), type_ignores=[])
        code = compile(ast.fix_missing_locations(stripped), str(path), "exec")
        namespace = {"__file__": str(path), "__name__": "ab_module_prologue_probe"}
        exec(code, namespace)  # noqa: S102 - executing THIS repo's own constants is the point
        assert "REPO" in namespace
        assert Path(namespace["REPO"]) == REPO_ROOT

    def test_root_is_not_a_hard_coded_machine_path(self, path):
        """`Path(r"D:\\GitClone\\VulnClaw")` only exists on the author's machine."""
        tree = _tree(path)
        literals = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        offenders = [text for text in literals if _looks_like_machine_path(text)]
        assert offenders == [], f"absolute machine path(s) in {path.name}: {offenders}"

        repo = _module_assignment(tree, "REPO")
        assert repo is not None, "REPO must be assigned at module level"
        assert "__file__" in ast.unparse(repo), ast.unparse(repo)

    def test_the_subprocess_working_directory_is_derived_not_guessed(self, path):
        """`cwd=ROOT / "VulnClaw"` only worked because this checkout is named VulnClaw."""
        source = path.read_text(encoding="utf-8")
        assert '"VulnClaw"' not in source, (
            "the repo directory must come from __file__, not from a literal name"
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
