"""The profile report is the launcher's check that CTF and production stay apart.

The E: workspace is shared: attachments, playbooks, runs and evidence all used to
resolve to one location. This script prints what the process actually resolved and
--strict turns a shared production environment into a non-zero exit, so a launcher
cannot silently start a prod run against the CTF store.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts" / "profile_report.py"


def _run(tmp_path: Path, **env_overrides: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("VULNCLAW_PROFILE", None)
    env.pop("VULNCLAW_ATTACH_DIR", None)
    env["VULNCLAW_CONFIG_DIR"] = str(tmp_path / "cfg")
    env["VULNCLAW_WORK_DIR"] = str(tmp_path / "work")
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-X", "utf8", str(SCRIPT), "--json", "--strict"],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )


def test_ctf_profile_resolves_to_the_ctf_store(tmp_path):
    proc = _run(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    info = json.loads(proc.stdout)
    assert info["profile"] == "ctf"
    assert Path(info["playbook_dir"]).name == "playbooks"
    assert Path(info["attachment_dir"]) == tmp_path / "work" / "attachments"
    assert info["warnings"] == []


def test_prod_profile_keeps_its_own_attachment_and_playbook_store(tmp_path):
    proc = _run(tmp_path, VULNCLAW_PROFILE="prod")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    info = json.loads(proc.stdout)
    assert info["profile"] == "prod"
    assert Path(info["playbook_dir"]).name == "playbooks-prod"
    assert Path(info["attachment_dir"]) == tmp_path / "work" / "prod" / "attachments"
    assert info["warnings"] == []


def test_prod_on_the_shared_default_config_root_fails_the_strict_check(tmp_path, monkeypatch):
    proc = _run(tmp_path, VULNCLAW_PROFILE="prod", VULNCLAW_CONFIG_DIR=str(Path.home() / ".vulnclaw"))
    assert proc.returncode == 1
    info = json.loads(proc.stdout)
    assert any("shared with the CTF profile" in w for w in info["warnings"])
