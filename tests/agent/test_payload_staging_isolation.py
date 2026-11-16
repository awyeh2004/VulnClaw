"""A file in the work dir must not be able to shadow a stdlib module.

Measured 2026-10-31 on the oldsvr run. ``python_execute`` staged its script
*inside* the working directory, and Python puts the script's own directory at
``sys.path[0]``. The agent had written a helper called ``dis.py``; from then on
every call's preamble import failed:

    AttributeError: module 'dis' has no attribute 'COMPILER_FLAG_NAMES'

The traceback points at ``inspect.py`` and ``dataclasses.py`` — never at the work
dir or the offending file — so the run spent its remaining turns diagnosing a
supposedly broken interpreter. 235 tool calls, no flag.

Two properties are pinned here:

* staged payloads live in a dedicated subdirectory, so ``sys.path[0]`` holds only
  generated scripts, and
* the working directory is still importable (appended, not prepended), so a model
  that writes its own helper module keeps working.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from vulnclaw.agent.tools.shell_exec import PAYLOAD_SCRIPT_SUBDIR, _payload_script_dir


class _Session:
    def __init__(self, root: Path) -> None:
        self.solve_work_root = str(root)


class _Config:
    def __init__(self, root: Path) -> None:
        self.session = _Session(root)


class _Runtime:
    run_id = "run-1"


class _Agent:
    def __init__(self, root: Path) -> None:
        self.config = _Config(root)
        self.runtime = _Runtime()


def test_payload_scripts_do_not_share_the_working_directory(tmp_path):
    """The whole point: sys.path[0] must not contain model-written files."""
    work = tmp_path / "work"
    work.mkdir()

    staged = _payload_script_dir(_Agent(work))

    assert staged is not None
    assert Path(staged).name == PAYLOAD_SCRIPT_SUBDIR
    assert Path(staged).parent != work
    assert Path(staged).is_dir()


def test_payload_dir_is_created_once_and_stays_stable(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    agent = _Agent(work)

    first = _payload_script_dir(agent)
    second = _payload_script_dir(agent)

    assert first == second
    assert Path(first).is_dir()


def test_no_scratch_root_falls_back_to_system_temp(tmp_path, monkeypatch):
    """Staging must never fail a run: no configured root means "use temp"."""

    class _BareAgent:
        pass

    assert _payload_script_dir(_BareAgent()) is None


def _run(code: str, *, cwd: Path, script_dir: Path) -> subprocess.CompletedProcess:
    script = script_dir / "payload.py"
    script.write_text(code, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-X", "utf8", str(script)],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.skipif(sys.version_info < (3, 8), reason="needs subprocess text mode")
def test_a_work_dir_file_named_like_a_stdlib_module_cannot_break_imports(tmp_path):
    """The exact oldsvr failure, reproduced and then shown fixed."""
    work = tmp_path / "work"
    work.mkdir()
    # The agent's own helper. Empty is enough — the shadowing is what breaks.
    (work / "dis.py").write_text("X = 1\n", encoding="utf-8")

    staged = Path(_payload_script_dir(_Agent(work)))
    result = _run(
        textwrap.dedent(
            """
            import sys, os
            sys.path.append(os.getcwd())
            import pprint
            print("STDLIB_OK")
            """
        ),
        cwd=work,
        script_dir=staged,
    )

    assert "STDLIB_OK" in result.stdout, result.stderr
    assert "COMPILER_FLAG_NAMES" not in result.stderr


def test_a_literal_workdir_payload_would_have_failed_the_same_import(tmp_path):
    """Control: proves the test above is meaningful, not vacuous.

    Running the same code with the script *inside* the work dir reproduces the
    crash — which is exactly what the old staging layout did.
    """
    work = tmp_path / "work"
    work.mkdir()
    (work / "dis.py").write_text("X = 1\n", encoding="utf-8")

    result = _run(
        textwrap.dedent(
            """
            import sys, os
            sys.path.append(os.getcwd())
            import pprint
            print("STDLIB_OK")
            """
        ),
        cwd=work,
        script_dir=work,
    )

    assert "STDLIB_OK" not in result.stdout or "COMPILER_FLAG_NAMES" in result.stderr


def test_cwd_stays_importable_for_model_written_helpers(tmp_path):
    """Appending cwd keeps `import my_helper` working without letting it shadow."""
    work = tmp_path / "work"
    work.mkdir()
    (work / "my_helper.py").write_text("ANSWER = 42\n", encoding="utf-8")
    (work / "json.py").write_text("BROKEN = True\n", encoding="utf-8")  # would shadow

    staged = Path(_payload_script_dir(_Agent(work)))
    result = _run(
        textwrap.dedent(
            """
            import sys, os
            sys.path.append(os.getcwd())
            import json           # stdlib must win over the work-dir json.py
            import my_helper      # ...but the model's own module must still load
            print("HELPER", my_helper.ANSWER, "JSON", hasattr(json, "dumps"))
            """
        ),
        cwd=work,
        script_dir=staged,
    )

    assert "HELPER 42 JSON True" in result.stdout, result.stderr