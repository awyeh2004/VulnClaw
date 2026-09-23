"""The spawn-boundary scan must see through import aliases (audit finding A1).

The scan matched a dotted chain textually against `_SPAWN_CALLS`, so a spawn site was
invisible the moment its module was aliased. Measured: `builtin_tools.py` has
`import subprocess as _sp`, and `_bg_run` calls `_sp.run(...)` -- the site never entered
the scan set, so the check reported "all spawn sites inside the reviewed allowlist"
while an unreviewed one sat in the same file. An earlier attempt at this failure class
added exactly ONE bare name (`run_text`) to the set, which does not generalise.

`TestTheRealFileIsNowVisible` is the test that matters: it asserts the scanner finds the
site in the actual module, which is what would have caught A1 before it shipped.
"""

from __future__ import annotations

import ast

import pytest

from scripts.verify_execution_boundary import (
    ALLOWED_SPAWN_SITES,
    REPO_ROOT,
    _call_target,
    _import_aliases,
    scan_file,
)

BULTIN_TOOLS = REPO_ROOT / "vulnclaw" / "agent" / "builtin_tools.py"


def _sites(source: str) -> list[str]:
    """Every spawn the scanner finds in a source snippet, as 'scope:call'."""
    tree = ast.parse(source)
    aliases = _import_aliases(tree)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = _call_target(node, aliases)
            if target:
                found.append(target)
    return found


class TestAliasResolution:
    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            # The measured A1 form.
            (
                "import subprocess as _sp\n_sp.run(['id'])\n",
                "subprocess.run",
            ),
            # Plain import still works (no regression).
            ("import subprocess\nsubprocess.Popen(['id'])\n", "subprocess.Popen"),
            # from-import, bare.
            ("from subprocess import run\nrun(['id'])\n", "subprocess.run"),
            # from-import with an alias.
            ("from subprocess import run as r\nr(['id'])\n", "subprocess.run"),
            # os family through an alias.
            ("import os as _os\n_os.system('id')\n", "os.system"),
            ("from os import execv as go\ngo('/bin/sh', [])\n", "os.execv"),
            # asyncio / pty, to show it is not special-cased to subprocess.
            (
                "import asyncio as aio\naio.create_subprocess_shell('id')\n",
                "asyncio.create_subprocess_shell",
            ),
            ("import pty as p\np.spawn(['sh'])\n", "pty.spawn"),
        ],
    )
    def test_an_aliased_spawn_is_detected(self, source, expected):
        assert _sites(source) == [expected]

    @pytest.mark.parametrize(
        "source",
        [
            "import os\nos.path.join('a', 'b')\n",
            "import json\njson.dumps({})\n",
            "def f(run):\n    run()\n",  # a local parameter is not a spawn
            "import subprocess\nsubprocess.run  # attribute access, not a call\n",
        ],
    )
    def test_a_non_spawn_is_still_not_flagged(self, source):
        assert _sites(source) == []

    def test_a_relative_import_shadowing_subprocess_is_still_flagged(self):
        """The written name matches, so it is reported -- and that is the safe side.

        A local module named `subprocess` would be pathological; reporting it costs a
        review, missing a real spawn costs a boundary hole.
        """
        assert _sites("from . import subprocess\nsubprocess.run(['id'])\n") == ["subprocess.run"]

    def test_a_local_run_parameter_is_not_confused_with_subprocess(self):
        """`def f(run): run()` must not be read as a spawn just because of the name."""
        assert _sites("def f(run):\n    run()\n") == []


class TestTheAsWrittenNameWins:
    """Existing allowlist keys embed the spelling used in the file, so keep it.

    Resolving `run_text` through `from ... import run_text` rewrote the name and
    invalidated ten reviewed keys at once -- a regression this test now prevents.
    """

    def test_a_known_callable_keeps_its_written_name(self):
        source = (
            "from vulnclaw.utils.subprocess_text import run_text\n"
            "run_text(['git', 'status'])\n"
        )
        assert _sites(source) == ["run_text"]


class TestTheRealFileIsNowVisible:
    def test_bg_run_is_reported_as_a_spawn_site(self):
        """The site A1 was about: invisible before alias resolution, visible now."""
        sites = scan_file(BULTIN_TOOLS)

        bg_sites = [s for s in sites if s.scope == "_bg_run"]
        assert bg_sites, "the _bg_run spawn site must be scanned, not skipped"
        assert [s.call for s in bg_sites] == ["subprocess.run"]

    def test_that_site_is_registered_and_gated(self):
        """Visible AND reviewed: the scanner demands an allowlist key, which exists."""
        sites = [s for s in scan_file(BULTIN_TOOLS) if s.scope == "_bg_run"]
        keys = {
            f"{s.file}:{s.scope}:{s.call}:{s.invariant}"
            for s in sites
        }
        assert keys <= set(ALLOWED_SPAWN_SITES), keys - set(ALLOWED_SPAWN_SITES)
        purpose = str(ALLOWED_SPAWN_SITES[next(iter(keys))]["purpose"])
        assert "gate" in purpose.lower() or "bg_launch" in purpose.lower()
