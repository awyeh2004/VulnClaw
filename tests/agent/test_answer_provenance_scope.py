"""The answer must come from the target -- not from the local disk.

Measured 2026-09-23: a stalled solve gave up on its (deliberately inert) web target
and walked the operator's drives hunting for flag-shaped strings. Its own stated
reason was "the harness must run it locally", so it treated this as legitimate --
and nothing forbade it: `task_constraints` was empty and no prompt rule covered it.
Its hits were OTHER tasks' artifacts (earlier solve reports, other runs' logs, test
fixtures), each holding some challenge's real flag.

Reporting one of those would be a fabricated result that still looks evidenced,
which is why this needs a rule AND a mechanical backstop.

The guard is deliberately narrow: it needs a broad filesystem TRAVERSAL and a
flag-SHAPED token. Analysing one downloaded attachment -- the thing RE and pwn work
depends on -- must keep working.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.builtin_tools import _host_flag_hunt_reason
from vulnclaw.agent.prompts import build_system_prompt


class TestHostFlagHuntIsRefused:
    @pytest.mark.parametrize(
        "code",
        [
            # The measured shape: walk a drive root, look for flag-shaped strings.
            "import os\nfor root, dirs, files in os.walk('E:\\\\'):\n    for f in files:\n"
            "        if 'flag{' in open(f).read(): print(f)",
            "import os\nfor root, dirs, files in os.walk(r'C:\\vulnclaw'):\n"
            "    if 'flag{' in str(files): print(root)",
            "from pathlib import Path\n"
            "for p in Path('/').rglob('*'):\n    if 'CTF{' in p.read_text(): print(p)",
            "import glob\n"
            "for p in glob.glob('C:/Users/**/*', recursive=True):\n"
            "    if 'flag{' in open(p).read(): print(p)",
            "for root, dirs, files in os.walk('/home'):\n"
            "    for f in files:\n        if 'flag{' in f: print(f)",
        ],
    )
    def test_host_wide_flag_search_is_refused(self, code):
        reason = _host_flag_hunt_reason(code)
        assert reason is not None
        assert "answer must come from" in reason.replace("\n", " ")

    def test_the_refusal_explains_how_to_do_it_legitimately(self):
        code = "import os\nfor r, d, f in os.walk('E:\\\\'):\n    pass\nprint('flag{')"
        reason = _host_flag_hunt_reason(code)
        assert reason is not None
        # A refusal that does not say what to do instead just blocks the run.
        assert "exact path" in reason
        assert "analysis only" in reason


class TestLegitimateLocalAnalysisStillWorks:
    """The narrowed scope: no traversal, or no flag-shaped token, or both absent."""

    @pytest.mark.parametrize(
        "code",
        [
            # Grepping ONE downloaded attachment -- exactly what RE work needs.
            "data = open(r'E:\\vulnclaw\\work\\manual\\easyre.exe', 'rb').read()\n"
            "print(data.count(b'flag{'))",
            "import capstone\n"
            "code = open('C:\\\\Users\\\\me\\\\chal.exe','rb').read()\n"
            "print(b'flag{' in code)",
            # Traversal but no flag token: ordinary file listing / analysis.
            "import os\nfor root, dirs, files in os.walk('E:\\\\vulnclaw'):\n"
            "    print(root, len(files))",
            "from pathlib import Path\nprint([p.name for p in Path('/tmp/chal').rglob('*')])",
            # Flag token but no traversal.
            "print('flag{' in open('out.txt').read())",
            "pattern = r'flag\\{[^}]+\\}'\nprint(pattern)",
            "",
        ],
    )
    def test_ordinary_analysis_is_not_blocked(self, code):
        assert _host_flag_hunt_reason(code) is None


class TestThePromptStatesTheRule:
    """Without the rule, the mechanical guard is the only signal -- and vice versa."""

    # The rule and its reason are written in the prompt's own language.
    RULE = {"en": "answer must come from", "zh": "答案必须来自目标"}
    REASON = {"en": "OTHER challenges", "zh": "别的题目"}
    ANALYSIS_OK = {"en": "analysis only", "zh": "只用于"}

    @pytest.mark.parametrize("lang", ["zh", "en"])
    def test_the_core_contract_forbids_hunting_the_local_disk(self, lang):
        prompt = build_system_prompt(target="http://example.com", lang=lang)
        assert self.RULE[lang] in prompt
        # The reason has to be given, not just the prohibition: those files may hold
        # OTHER challenges' flags.
        assert self.REASON[lang] in prompt

    @pytest.mark.parametrize("lang", ["zh", "en"])
    def test_the_rule_still_explicitly_allows_local_analysis(self, lang):
        """Bans that read as 'never touch local files' would break RE/pwn work."""
        prompt = build_system_prompt(target="http://example.com", lang=lang)
        assert self.ANALYSIS_OK[lang] in prompt
