"""One stdlib-named file in the working directory can break a whole run.

Measured 2026-10-31: eight sessions (two mains, six subagents) recorded

    AttributeError: module 'dis' has no attribute 'COMPILER_FLAG_NAMES'

because ``python_execute`` staged its payload inside the working directory and the
agent had written a helper named ``dis.py``. The traceback names ``inspect.py``
and ``dataclasses.py`` only — never the work dir or the offending file — so the
runs spent their remaining turns diagnosing a supposedly broken interpreter.

``python_execute`` is now fixed by absence (payloads stage in a private
subdirectory). ``shell_command`` cannot be: "run this in that directory" is its
whole contract. It warns instead, appended to the result so the note travels with
whatever error the run itself produced.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnclaw.agent.tools.shell_exec import shadowing_files, shadowing_warning


def _touch(path: Path, body: str = "X = 1\n") -> None:
    path.write_text(body, encoding="utf-8")


def test_finds_a_stdlib_shadowing_file(tmp_path):
    _touch(tmp_path / "dis.py")
    _touch(tmp_path / "app.py")

    assert shadowing_files(tmp_path) == ["dis.py"]


def test_ignores_ordinary_files(tmp_path):
    _touch(tmp_path / "solve.py")
    _touch(tmp_path / "notes.md")

    assert shadowing_files(tmp_path) == []


def test_ignores_subdirectories(tmp_path):
    """sys.path[0] is one directory deep; a nested file cannot be imported bare."""
    nested = tmp_path / "pkg"
    nested.mkdir()
    _touch(nested / "dis.py")

    assert shadowing_files(tmp_path) == []


def test_missing_directory_is_not_an_error(tmp_path):
    assert shadowing_files(tmp_path / "nope") == []


def test_warns_when_python_runs_in_a_shadowing_dir(tmp_path):
    _touch(tmp_path / "dis.py")

    warning = shadowing_warning("python app.py", tmp_path)

    assert warning.startswith("[!]")
    assert "dis.py" in warning
    assert "sys.path" in warning


def test_silent_for_non_python_commands(tmp_path):
    _touch(tmp_path / "dis.py")

    assert shadowing_warning("ls -la", tmp_path) == ""
    assert shadowing_warning("curl http://x/", tmp_path) == ""
    assert shadowing_warning("php probe.php", tmp_path) == ""


@pytest.mark.parametrize(
    "command",
    [
        "python app.py",
        "python3 app.py",
        "python3.12 app.py",
        "py app.py",
        "py -3 app.py",
        "cd x && python tools/run.py",
        "cat a | python script.py",
    ],
)
def test_recognises_python_invocations(tmp_path, command):
    _touch(tmp_path / "json.py")

    assert shadowing_warning(command, tmp_path), command


def test_silent_when_the_directory_is_clean(tmp_path):
    assert shadowing_warning("python app.py", tmp_path) == ""


def test_lists_several_shadowing_files(tmp_path):
    _touch(tmp_path / "dis.py")
    _touch(tmp_path / "json.py")

    warning = shadowing_warning("python app.py", tmp_path)

    assert "dis.py" in warning and "json.py" in warning


def test_warning_explains_why_the_error_is_misleading(tmp_path):
    """The point of the note: the real error blames the standard library."""
    _touch(tmp_path / "dis.py")

    warning = shadowing_warning("python app.py", tmp_path)

    assert "does not name them" in warning

# ── The stderr filter that used to hide the cause ───────────────────────────
#
# ``python_execute`` dropped every stderr line containing "ImportError" or
# "No module named", on the theory that the preamble's optional imports would
# spam each run. The preamble already wraps those in try/except, so what the
# filter actually removed was the *last line of the user's own traceback* — the
# only line naming the failure. The model then saw
# "Traceback (most recent call last): ... import foo" with no reason at all.


def test_stderr_keeping_the_import_error_line_is_the_contract():
    """Pins the shape the executor must preserve, not an internal detail.

    The old filter is reproduced here so the difference is visible: dropping
    ImportError lines leaves a traceback that explains nothing.
    """
    stderr_text = (
        "Traceback (most recent call last):\n"
        '  File "x.py", line 3, in <module>\n'
        "    import foo\n"
        "ImportError: No module named foo\n"
    )

    old_filtered = [
        line
        for line in stderr_text.splitlines()
        if "ImportError" not in line and "No module named" not in line
    ]

    assert "ImportError" not in "\n".join(old_filtered)
    assert "ImportError: No module named foo" in stderr_text


def test_shadowing_hint_names_the_file_and_the_directory(tmp_path):
    from unittest.mock import patch

    from vulnclaw.agent.tools.python_exec import _shadowing_hint_for_stderr

    _touch(tmp_path / "dis.py")
    stderr_text = (
        "Traceback (most recent call last):\n"
        r'  File "C:\Python\Lib\inspect.py", line 168, in <module>' + "\n"
        "    for k, v in dis.COMPILER_FLAG_NAMES.items():\n"
        "AttributeError: module 'dis' has no attribute 'COMPILER_FLAG_NAMES'\n"
    )

    with patch(
        "vulnclaw.agent.builtin_tools._default_workdir", return_value=tmp_path
    ), patch(
        "vulnclaw.agent.builtin_tools._resolve_workdir", return_value=tmp_path
    ):
        hint = _shadowing_hint_for_stderr(object(), stderr_text)

    assert hint.startswith("[!]")
    assert "dis.py" in hint
    assert str(tmp_path) in hint


def test_shadowing_hint_silent_when_the_traceback_blames_something_else(tmp_path):
    from unittest.mock import patch

    from vulnclaw.agent.tools.python_exec import _shadowing_hint_for_stderr

    _touch(tmp_path / "json.py")
    stderr_text = "ValueError: something unrelated\n"

    with patch(
        "vulnclaw.agent.builtin_tools._default_workdir", return_value=tmp_path
    ), patch(
        "vulnclaw.agent.builtin_tools._resolve_workdir", return_value=tmp_path
    ):
        assert _shadowing_hint_for_stderr(object(), stderr_text) == ""


def test_shadowing_hint_silent_when_directory_is_clean(tmp_path):
    from unittest.mock import patch

    from vulnclaw.agent.tools.python_exec import _shadowing_hint_for_stderr

    stderr_text = "AttributeError: module 'dis' has no attribute 'COMPILER_FLAG_NAMES'"

    with patch(
        "vulnclaw.agent.builtin_tools._default_workdir", return_value=tmp_path
    ), patch(
        "vulnclaw.agent.builtin_tools._resolve_workdir", return_value=tmp_path
    ):
        assert _shadowing_hint_for_stderr(object(), stderr_text) == ""


def test_empty_stderr_yields_no_hint(tmp_path):
    from vulnclaw.agent.tools.python_exec import _shadowing_hint_for_stderr

    assert _shadowing_hint_for_stderr(object(), "") == ""
