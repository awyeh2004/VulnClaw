"""Audit findings A2/A3: the answer-provenance guard, and its honest limits.

`_host_flag_hunt_reason` (python_execute) and `_shell_flag_hunt_reason` (shell_command)
refuse "hunt the local disk for a flag-shaped string". A3 closed the larger half of the
gap: the Python-side check had exactly ONE call site, so the same intent expressed as a
shell command was completely unguarded.

A2 is the part that cannot be fixed by adding patterns, and this file says so out loud.
A source/command-text regex is defeated by any reformulation -- the audit's example was
`["findstr", "/s", "/m", "/c:fla", "g{", "E:\\*"]`, where the flag literal is split
across two argv entries and the traversal verb is a different tool. `TestKnownBypasses`
therefore ASSERTS that these forms are NOT caught. That is deliberate: a green suite must
not be readable as "the guard is complete". The primary control is the prompt rule in
`prompts_zh.py`/`prompts_en.py`; these guards stop the naive form.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.builtin_tools import (
    _host_flag_hunt_reason,
    _shell_flag_hunt_reason,
)


class TestShellSideIsGuarded:
    """A3: forms that mirror what the Python-side guard catches."""

    @pytest.mark.parametrize(
        "command",
        [
            "grep -rn 'flag{' /",
            "grep -r --include=*.md -e 'flag{' ~",
            "rg 'flag{' C:\\",
            "findstr /s /m /c:flag{ C:\\",
            'Select-String -Path "E:\\" -Pattern "flag{" -Recurse',
            "Get-ChildItem C:\\ -Recurse | Select-String 'flag{'",
            "find / -name '*.txt' -exec grep -l 'flag{' {} ;",
            "grep -R 'CTF{' /home",
        ],
    )
    def test_a_recursive_flag_search_over_a_broad_root_is_refused(self, command):
        reason = _shell_flag_hunt_reason(command)
        assert reason is not None, command
        assert "answer must come from" in reason

    def test_the_split_token_form_is_refused_too(self):
        """The natural shell spelling of the audit's Python bypass."""
        assert _shell_flag_hunt_reason("findstr /s /m /c:fla g{ C:\\") is not None

    def test_the_refusal_says_how_to_do_it_legitimately(self):
        reason = _shell_flag_hunt_reason("grep -rn 'flag{' /")
        assert reason is not None
        assert "exact path" in reason
        assert "analysis only" in reason


class TestTheTwoSidesAgree:
    """Round-8 finding R8-2: the sides were asymmetric on exactly the measured shape.

    The accident's command was `grep -r flag{ E:\\vulnclaw` -- a drive SUBdirectory. The
    Python side has always refused the equivalent (`os.walk(r'C:\\vulnclaw')` + `flag{`)
    and has a test pinning it; the shell branch required whitespace/end/`*`/quote right
    after the drive colon, so only a bare `E:\\` counted and that command sailed through.
    The shell side is now at least as wide as the Python side, and these tests say so
    from both directions.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "grep -r flag{ E:\\vulnclaw",                       # the measured command
            "grep -rn 'flag{' E:\\vulnclaw\\work",              # deeper, quoted
            "rg 'flag{' E:\\vulnclaw",                          # ripgrep, recursive by default
            "rg -uu 'CTF{' D:\\GitClone",
            "findstr /s /i flag{ E:\\vulnclaw\\*",
            'Select-String -Path "E:\\vulnclaw" -Pattern "flag{" -Recurse',
            "grep -R 'flag{' C:/Users/me/Downloads",
        ],
    )
    def test_a_drive_subdirectory_is_as_broad_as_the_root(self, command):
        assert _shell_flag_hunt_reason(command) is not None, command

    def test_the_bare_root_still_is(self):
        assert _shell_flag_hunt_reason("grep -r flag{ E:\\") is not None

    @pytest.mark.parametrize(
        ("shell_command", "python_code"),
        [
            (
                "grep -r flag{ E:\\vulnclaw",
                "import os\nfor r, d, f in os.walk(r'E:\\vulnclaw'):\n"
                "    if 'flag{' in str(f): print(r)",
            ),
            (
                "rg 'flag{' D:\\GitClone",
                "import os\nfor r, d, f in os.walk('D:\\\\GitClone'):\n    pass\nprint('flag{')",
            ),
        ],
    )
    def test_the_same_intent_is_refused_on_both_paths(self, shell_command, python_code):
        """Neither side may be the softer way to express the same search."""
        assert _shell_flag_hunt_reason(shell_command) is not None
        assert _host_flag_hunt_reason(python_code) is not None

    @pytest.mark.parametrize(
        "command",
        [
            # A drive path with no flag-shaped token is ordinary work: still allowed.
            "findstr /s /m /c:timeout C:\\tools",
            "grep -rn 'def main' E:\\vulnclaw\\src",
            "rg 'TODO' D:\\GitClone\\proj",
        ],
    )
    def test_widening_the_root_did_not_drop_the_flag_requirement(self, command):
        """Both halves of the trigger are still required; only the root got wider."""
        assert _shell_flag_hunt_reason(command) is None


class TestOrdinaryCommandsStillWork:
    """The trigger is deliberately narrow: no recursion, or no broad root, or no flag."""

    @pytest.mark.parametrize(
        "command",
        [
            # One downloaded artifact -- exactly what RE work needs.
            "strings easyre.exe | grep flag",
            "grep -n 'flag' ./chal.txt",
            "python -c \"print(open('chal.bin','rb').read().count(b'flag{'))\"",
            # Recursion over the WORK area, not a broad root.
            "grep -rn 'TODO' ./src",
            "rg 'def main' vulnclaw/agent",
            # Broad root, but nothing flag-shaped.
            "grep -rn 'error' /var/log",
            "findstr /s /m /c:timeout C:\\tools",
            "ls -la /",
            "Get-ChildItem E:\\ -Recurse | Measure-Object",
        ],
    )
    def test_it_is_not_blocked(self, command):
        assert _shell_flag_hunt_reason(command) is None


class TestKnownBypasses:
    """A2, documented rather than papered over.

    These ARE bypasses. Asserting them keeps the limitation executable instead of
    letting a later reader infer completeness from a green suite. If someone does harden
    the guard, these tests fail and should be updated deliberately -- not deleted.
    """

    @pytest.mark.parametrize(
        "bypass",
        [
            # Split flag literal in a Python argv list (the audit's example).
            'subprocess.run(["findstr", "/s", "/m", "/c:fla", "g{", "E:\\\\*"])',
            # Traversal root supplied through a variable.
            "import os\nROOT = 'E:\\\\'\nfor r, d, f in os.walk(ROOT):\n    pass",
            # Recursion expressed by a method the pattern list does not know.
            'from pathlib import Path\nfor p in Path("E:/").iterdir():\n    pass',
            # Flag literal assembled at runtime.
            "import subprocess\nneedle = 'fla' + 'g{'\nsubprocess.run(['grep','-rn',needle,'/'])",
            # Shell: the pattern is built by the shell itself.
            "P=fla; grep -rn \"${P}g{\" /",
        ],
    )
    def test_these_are_NOT_caught_and_that_is_the_point(self, bypass):
        assert _host_flag_hunt_reason(bypass) is None
        assert _shell_flag_hunt_reason(bypass) is None

    def test_the_guard_is_documented_as_a_heuristic(self):
        """If the docstrings ever claim completeness, this fails."""
        import inspect

        for func in (_host_flag_hunt_reason, _shell_flag_hunt_reason):
            source = inspect.getsource(func)
            assert "heuristic" in source.lower() or "bypass" in source.lower()
