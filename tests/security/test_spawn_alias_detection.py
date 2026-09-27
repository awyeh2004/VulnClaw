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
    _binding_map,
    _call_target,
    _import_aliases,
    scan_file,
)

BULTIN_TOOLS = REPO_ROOT / "vulnclaw" / "agent" / "builtin_tools.py"


def _sites(source: str) -> list[str]:
    """Every spawn the scanner finds in a source snippet, as 'scope:call'."""
    tree = ast.parse(source)
    # `_binding_map` is what `scan_file` uses (imports + assignments + star imports), so
    # these cases exercise the same resolution the real scan does.
    aliases = _binding_map(tree)
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


class TestRebindingAndDynamicLookupAreSeen:
    """Round8 L1: three ways to reach a spawn that the textual match could not see.

    Measured at round8: the scan resolved `import ... as` / `from ... import ...` but was
    blind to (a) `getattr(module, "name")`, (b) a plain assignment alias, (c) a star
    import. No such site existed in the tree at the time -- which is exactly why the gap
    is worth closing before one appears: it is the same class as A1, where the scanner
    reported "all spawn sites reviewed" while an unreviewed one sat in the same file.
    """

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            # (a) getattr at the call position: no dotted callee exists to match.
            (
                "import subprocess\ngetattr(subprocess, 'run')(['id'])\n",
                "subprocess.run",
            ),
            (
                "import subprocess as _sp\ngetattr(_sp, 'Popen')(['id'])\n",
                "subprocess.Popen",
            ),
            ("import os\ngetattr(os, 'system')('id')\n", "os.system"),
            ("import os\ngetattr(os, 'execv')('/bin/sh', [])\n", "os.execv"),
            # (b) assignment aliases, including a chain through a module binding.
            ("import subprocess\nPopen = subprocess.Popen\nPopen(['id'])\n", "subprocess.Popen"),
            ("import subprocess as sp\nrun = sp.run\nrun(['id'])\n", "subprocess.run"),
            (
                "import subprocess\nsp = subprocess\nr = sp.run\nr(['id'])\n",
                "subprocess.run",
            ),
            (
                "from subprocess import Popen as P\nQ = P\nQ(['id'])\n",
                "subprocess.Popen",
            ),
            ("import subprocess\nrun = getattr(subprocess, 'run')\nrun(['id'])\n", "subprocess.run"),
            # (c) star import: every public name of the module is bound.
            ("from subprocess import *\nrun(['id'])\n", "subprocess.run"),
            ("from os import *\nsystem('id')\n", "os.system"),
        ],
    )
    def test_the_spawn_is_reported(self, source, expected):
        assert _sites(source) == [expected]

    @pytest.mark.parametrize(
        "source",
        [
            # The REAL shape in cli/wizard.py: a constant lookup, not a call to it.
            "import subprocess\nk = getattr(subprocess, 'DETACHED_PROCESS', 0)\n",
            # A computed attribute name is beyond a static scan -- asserted, not glossed.
            "import subprocess\nname = 'run'\ngetattr(subprocess, name)(['id'])\n",
            # A star import does not make the module's OWN function a spawn.
            "from subprocess import *\ndef run(argv):\n    return argv\nrun(['id'])\n",
            # Rebinding to a non-spawn value.
            "import subprocess\nrun = print\nrun('id')\n",
        ],
    )
    def test_it_is_not_flagged(self, source):
        assert _sites(source) == []

    def test_the_import_only_map_is_a_subset_of_the_full_one(self):
        """The layering is additive: nothing the old map knew was lost."""
        tree = ast.parse("import subprocess as _sp\n_sp.run(['id'])\nP = _sp.Popen\n")
        imports = _import_aliases(tree)
        full = _binding_map(tree)
        assert set(imports.items()) <= set(full.items())
        assert full["_sp"] == "subprocess" and full["P"] == "subprocess.Popen"


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
