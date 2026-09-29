"""No committed credentials -- the guard for the `d72ca20` leak.

Found while auditing that commit (the one the round-8 report left for the next window): it
imported a real run's config as "verbatim copies" into `scripts/ab/seeds/`, and those files
carried **live credentials**, byte-identical to the ones in the operator's own
`~/.vulnclaw/config.yaml`:

* `llm.api_key`, again as the single `api_keys:` list item, and again as
  `provider_keys.ds` -- three places per file, in both `config.yaml` and `config-round2.yaml`;
* `gcs.access_key` (an `ak_live_…` value);
* plus a `provider_keys.zhipu` credential that is not in the live config at all.

The seeds are now credential-free and the drills get their key at run time from
`scripts/ab/_drill_env.py`. The scan below is what should have run before that commit landed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Files whose SECRET-LOOKING strings are deliberate fixtures, with the reason.
#: Only REPO-TRACKED files belong here: this map is checked with `.exists()`, so an entry
#: for a local, untracked scratch file (the old `AUDIT-FINDINGS.md`) made the suite depend
#: on the author's machine. Removed with that file.
FIXTURE_ALLOWLIST = {
    "tests/test_codescan.py": "fixtures for the secret scanner under test",
    "tests/agent/test_recon_tools.py": "sample `AKIA…`/JWT strings for recon output parsing",
    "tests/skills/test_skills.py": "a sample JWT for skill-output parsing",
}

SECRET_PATTERNS = {
    "live-style api key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "gcs live access key": re.compile(r"\bak_live_[A-Za-z0-9]{8,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}"),
    "aws access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "provider key pair": re.compile(r"\b[0-9a-f]{32}\.[A-Za-z0-9]{16,}\b"),
}

#: Only what the repo PUBLISHES: skip the virtualenv-free tree's noise and the sandbox.
SKIP_DIRS = {".git", ".test-tmp", "__pycache__", ".venv", "node_modules"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".zip", ".pyc", ".whl"}


def _tracked_files() -> list[Path]:
    """Every file the repo publishes, with the noisy directories PRUNED from the walk.

    Pruned during the walk rather than filtered afterwards: the test sandbox holds tens of
    thousands of files, and visiting them all cost ~17s for a check that then skipped them.
    """
    import os

    files: list[Path] = []
    for root, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for name in filenames:
            path = Path(root) / name
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            files.append(path)
    return files


class TestTheSeededDrillConfigsCarryNoCredentials:
    """The direct regression: the two files that leaked, checked by KEY NAME.

    Name-based, not shape-based, because the first scan missed two of the three credentials --
    `ak_live_…` and the zhipu `<hex>.<secret>` form matched none of the openai-style patterns.
    """

    CREDENTIAL_KEY = re.compile(
        r"(?i)^\s*[\w.\-]*?(api[_-]?keys?|access[_-]?key|secret[_-]?key|client[_-]?secret|"
        r"password|passwd|token|provider[_-]?keys)\s*:\s*(?P<value>\S.*)$"
    )

    @pytest.mark.parametrize(
        "relative",
        ["scripts/ab/seeds/config.yaml", "scripts/ab/seeds/config-round2.yaml"],
    )
    def test_no_credential_field_has_a_value(self, relative):
        path = REPO_ROOT / relative
        offenders = []
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = self.CREDENTIAL_KEY.match(line)
            if match and match.group("value").strip().strip("'\"") not in ("", "[]", "{}"):
                offenders.append((number, line.split(":")[0].strip()))
        assert offenders == [], f"{relative} has populated credential field(s): {offenders}"

    @pytest.mark.parametrize(
        "relative",
        ["scripts/ab/seeds/config.yaml", "scripts/ab/seeds/config-round2.yaml"],
    )
    def test_no_bare_credential_looking_value_anywhere(self, relative):
        """A YAML list item or a nested map value has no key on its line."""
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        for label, pattern in SECRET_PATTERNS.items():
            found = pattern.findall(text)
            assert not found, f"{relative}: {label} value(s) present: {found!r}"

    def test_the_drill_still_gets_a_key_at_runtime(self):
        """Removing it from the seeds is only correct if the runner supplies it instead."""
        helper = (REPO_ROOT / "scripts" / "ab" / "_drill_env.py").read_text(encoding="utf-8")
        assert "VULNCLAW_LLM_API_KEY" in helper, (
            "the key must be forwarded to the child process, or every drill fails to start"
        )
        for runner in ("cold_warm_pair.py", "cold_warm_pair_round2.py", "negative_control.py"):
            source = (REPO_ROOT / "scripts" / "ab" / runner).read_text(encoding="utf-8")
            assert "with_runtime_credentials(env)" in source, (
                f"{runner} does not forward runtime credentials"
            )


class TestNoCredentialIsCommittedAnywhere:
    def test_no_secret_shaped_string_in_the_tracked_tree(self):
        offenders: list[str] = []
        for path in _tracked_files():
            relative = path.relative_to(REPO_ROOT).as_posix()
            if relative in FIXTURE_ALLOWLIST:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for label, pattern in SECRET_PATTERNS.items():
                if pattern.search(text):
                    offenders.append(f"{relative}: {label}")
        assert offenders == [], (
            "credential-shaped strings in tracked files (add to FIXTURE_ALLOWLIST only if the "
            f"string is a deliberate fixture): {offenders}"
        )

    def test_the_allowlist_entries_still_exist(self):
        """A stale allowlist entry would silently re-enable the scan for that path."""
        missing = [
            relative
            for relative in FIXTURE_ALLOWLIST
            if not (REPO_ROOT / relative).exists()
        ]
        assert missing == [], f"allowlisted paths no longer exist: {missing}"
