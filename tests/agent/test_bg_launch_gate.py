"""`bg_launch` must pass the ExecutionGate, and must not route around python_execute.

Audit finding A1. Two separate defects on the same path:

1. **No gate.** The three `gate.authorize` sites were shell / runtime_diff_probe /
   python, so a background launch ran an operator-unapproved local command. The boundary
   scanner's own contract says model-reachable spawn sites are exactly those the gate
   must cover. (`git show 25b4677^` fixes that list; the commit message and the
   `execute_bg_launch` docstring both said "shell/python/nmap", which round-8 finding
   R8-8 corrected -- nmap had no gate either, and now does.)
2. **A policy bypass, not just an ungated spawn.** The prefix allowlist accepts
   ``python``/``python3``, which makes the substring blacklist beside it decorative.
   Measured: ``python -c "import os;os.system('id')"`` was ACCEPTED here, while
   ``python_execute`` blocks ``os.system(`` outright and sits behind
   ``safety.enable_python_execute``.

The gate is faked rather than driven through the real approval machinery: these tests
are about *whether* the path is gated and what it rejects, not about the gate itself
(covered by tests/security/test_exec_gate.py).

Round-8 finding R8-1 added `TestTheGuardSurvivesRespellings`: the A1 fix matched raw
whitespace-split text, so quoting, concatenation and an interpreter version suffix all
walked past it. Those spellings are the point of that class -- each one is a bypass that
was measured live, not a hypothetical.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent import builtin_tools
from vulnclaw.agent.builtin_tools import (
    _bg_interpreter_inline_code,
    _bg_validate_command,
    execute_bg_launch,
    execute_mcp_tool,
)


class _Outcome:
    def __init__(self, approved: bool) -> None:
        self.approved = approved

    def refusal_text(self, tool_label: str) -> str:
        return f"[!] {tool_label} refused by the execution gate"


class _FakeGate:
    def __init__(self, approved: bool) -> None:
        self._approved = approved
        self.requests: list[object] = []

    async def authorize(self, request, run_id: str = ""):
        self.requests.append(request)
        return _Outcome(self._approved)


@pytest.fixture
def gate(monkeypatch):
    """Install a fake gate; never touches the real approval machinery.

    `_bg_run` is also stubbed: these tests are about whether the path is gated and what
    it refuses, and a unit test has no business spawning `hashcat`/`python` threads
    (they would fail fast, but "harmless process spawn" is not a thing this repo should
    normalise in its own suite).
    """
    import vulnclaw.agent.exec_gate as exec_gate

    holder = SimpleNamespace(current=_FakeGate(True))
    monkeypatch.setattr(exec_gate, "get_execution_gate", lambda config=None: holder.current)
    monkeypatch.setattr(builtin_tools, "_bg_run", lambda *a, **k: None)
    yield holder
    # Keep the task table clean between tests.
    with builtin_tools._bg_lock:
        builtin_tools._bg_tasks.clear()


def _agent():
    return SimpleNamespace(
        config=SimpleNamespace(safety=SimpleNamespace()),
        runtime=SimpleNamespace(run_id="run-1"),
    )


class TestItIsNowGated:
    async def test_an_approved_launch_reaches_the_gate_and_starts(self, gate):
        result = await execute_bg_launch(
            _agent(), {"command": "hashcat -m 0 hashes.txt rockyou.txt", "timeout": 10}
        )

        assert len(gate.current.requests) == 1
        request = gate.current.requests[0]
        assert request.kind == "shell"
        assert request.display == "hashcat -m 0 hashes.txt rockyou.txt"
        assert "background" in request.detail.lower()
        assert "started in background" in result

    async def test_a_refused_launch_starts_nothing(self, gate):
        gate.current = _FakeGate(False)

        result = await execute_bg_launch(_agent(), {"command": "hashcat -a 0 h.txt w.txt"})

        assert "refused" in result
        with builtin_tools._bg_lock:
            assert builtin_tools._bg_tasks == {}, "a refused command must not be launched"

    async def test_the_dispatcher_awaits_it(self, gate):
        """`execute_mcp_tool` is async; a missing `await` would return a coroutine."""
        result = await execute_mcp_tool(
            _agent(), "bg_launch", {"command": "python brute.py words.txt"}
        )

        assert isinstance(result, str)
        assert "started in background" in result, result


class TestItCannotRouteAroundPythonExecute:
    @pytest.mark.parametrize(
        "command",
        [
            'python -c "import os;os.system(\'id\')"',
            'python3 -c "import subprocess;subprocess.run([\'id\'])"',
            'cmd /c python -c "import os;os.system(\'id\')"',
            "python -m http.server 8000",
            "python -",
        ],
    )
    def test_inline_code_is_rejected(self, command):
        blocked = _bg_validate_command(command)
        assert blocked is not None, command
        assert "inline code" in blocked

    async def test_a_rejected_command_never_reaches_the_gate(self, gate):
        await execute_bg_launch(_agent(), {"command": 'python -c "import os;os.system(\'x\')"'})
        assert gate.current.requests == [], "validation must run before the gate"

    @pytest.mark.parametrize("token", ["-c", "-m", "--command", "-"])
    def test_the_offending_token_is_named(self, token):
        assert _bg_interpreter_inline_code(f"python {token} x") == token

    @pytest.mark.parametrize(
        "command",
        ["hashcat -m 0 h.txt w.txt", "john hashes.txt", "brute.py"],
    )
    def test_non_interpreters_are_untouched_by_the_inline_rule(self, command):
        assert _bg_interpreter_inline_code(command) is None


class TestTheGuardSurvivesRespellings:
    """Round-8 finding R8-1: same vector, four spellings the old check missed.

    The old check compared `lowered.split()` tokens against `("-c", "-m", "--command",
    "-")` and required a listed prefix followed by a space. Measured bypasses, all of
    which now refuse:

    * `python "-c" …` -- the quotes are part of the raw token, so `== "-c"` is False;
    * `python -c"…"` -- CPython takes an attached value, so this is ONE token;
    * `python3.13 …` / `pythonw …` -- the allowlist is prefix-based and both pass it,
      but neither equals a listed prefix plus a space.
    """

    @pytest.mark.parametrize(
        "command",
        [
            'python "-c" "import os;os.system(chr(105)+chr(100))"',
            "python '-c' 'import os'",
            'python -c"import os;os.system(\'id\')"',
            "python -c'print(1)'",
            'python3.13 -c "print(1)"',
            'pythonw -c "print(1)"',
            'cmd /c pythonw -c "print(1)"',
            'python -m"http.server" 8000',
            'python3.13 "-m" http.server',
        ],
    )
    def test_quoted_concatenated_and_versioned_forms_are_rejected(self, command):
        blocked = _bg_validate_command(command)
        assert blocked is not None, command
        assert "inline code" in blocked

    @pytest.mark.parametrize(
        ("command", "named"),
        [
            ('python "-c" "x"', "-c"),
            ('python -c"x"', "-c"),
            ("python -mhttp.server", "-m"),
            ("python3.13 -c x", "-c"),
        ],
    )
    def test_the_offending_flag_is_still_named(self, command, named):
        assert _bg_interpreter_inline_code(command) == named

    def test_an_attached_value_past_the_script_belongs_to_the_script(self):
        """`-charset` is the script's option, not the interpreter's: not inline code.

        The attached-value rule stops at the script name, which is what keeps a real
        brute-force invocation usable. The exact-token rule below is unchanged and
        deliberately stricter.
        """
        assert _bg_validate_command("python brute.py -charset abc words.txt") is None
        assert _bg_validate_command("python brute.py -c x words.txt") is not None

    @pytest.mark.parametrize("wrapper", ["python", "python3", "python3.13", "pythonw"])
    def test_every_interpreter_family_member_is_covered(self, wrapper):
        assert _bg_interpreter_inline_code(f'{wrapper} -c "x"') == "-c"

    @pytest.mark.parametrize("command", ["hashcat -c 0 h.txt w.txt", "john -c x hashes.txt"])
    def test_non_python_prefixes_are_still_untouched(self, command):
        """The rule is about interpreters; another tool's `-c` is not this tool's business."""
        assert _bg_interpreter_inline_code(command) is None


class TestTheDocumentedUseStillWorks:
    @pytest.mark.parametrize(
        "command",
        [
            "hashcat -m 0 -a 0 hashes.txt rockyou.txt",
            "john --wordlist=rockyou.txt hashes.txt",
            "python brute.py wordlist.txt",   # a script file: the documented use
            "python3 solve_local.py",
        ],
    )
    def test_it_is_allowed(self, command):
        assert _bg_validate_command(command) is None

    async def test_and_actually_launches(self, gate):
        result = await execute_bg_launch(_agent(), {"command": "python brute.py w.txt"})
        assert "started in background" in result
