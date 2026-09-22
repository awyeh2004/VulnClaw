"""workspace_hygiene: ignored strays must stay visible (git status hides them)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import workspace_hygiene as hygiene


@pytest.fixture()
def fake_repo(tmp_path, monkeypatch):
    """A throwaway git repo whose ignored strays we can shape freely."""
    (tmp_path / ".gitignore").write_text(
        "junk*\n.pytest_cache/\nfoo/\nstraynote\n__pycache__/\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True, capture_output=True)
    monkeypatch.setattr(hygiene, "REPO_ROOT", tmp_path)
    return tmp_path


def test_root_stray_files_reported_and_fail_ok(fake_repo):
    (fake_repo / "junk_probe.txt").write_text("x", encoding="utf-8")
    (fake_repo / "straynote").write_text("x", encoding="utf-8")
    report = hygiene.scan()
    assert report["ok"] is False
    assert {s["file"] for s in report["strays"]} == {"junk_probe.txt", "straynote"}


def test_just_created_stray_is_fresh(fake_repo):
    (fake_repo / "junk_probe.txt").write_text("x", encoding="utf-8")
    report = hygiene.scan()
    assert report["fresh_strays"], "a file created seconds ago must count as fresh"


def test_known_dir_is_not_a_stray(fake_repo):
    d = fake_repo / ".pytest_cache"
    d.mkdir()
    (d / "v").write_text("x", encoding="utf-8")
    report = hygiene.scan()
    assert report["ok"] is True
    entry = next(x for x in report["dirs"] if x["dir"] == ".pytest_cache")
    assert entry["known"] is True


def test_unknown_dir_is_flagged(fake_repo):
    d = fake_repo / "foo"
    d.mkdir()
    (d / "payload.bin").write_bytes(b"x" * 10)
    report = hygiene.scan()
    entry = next(x for x in report["dirs"] if x["dir"] == "foo")
    assert entry["known"] is False
    assert "UNKNOWN" in entry["reason"]


def _git_track(fake_repo, rel: str):
    p = fake_repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("tracked", encoding="utf-8")
    subprocess.run(["git", "add", "-f", rel], cwd=fake_repo, check=True, capture_output=True)


def test_tracked_dir_with_only_pycache_is_clean(fake_repo):
    _git_track(fake_repo, "tests/test_x.py")
    pyc = fake_repo / "tests" / "__pycache__"
    pyc.mkdir(parents=True)
    (pyc / "test_x.cpython-312.pyc").write_bytes(b"x")
    report = hygiene.scan()
    assert report["ok"] is True
    assert report["strays_in_tracked_dirs"] == []
    entry = next(x for x in report["dirs"] if x["dir"] == "tests")
    assert entry["known"] is True


def test_ignored_odd_file_inside_tracked_dir_is_flagged(fake_repo):
    _git_track(fake_repo, "tests/test_x.py")
    (fake_repo / "tests").mkdir(exist_ok=True)
    (fake_repo / "tests" / "junk_leak.txt").write_text("x", encoding="utf-8")
    report = hygiene.scan()
    assert "tests/junk_leak.txt" in report["strays_in_tracked_dirs"]


def test_json_output_is_parseable_and_exit_code_tracks_ok(fake_repo, capsys):
    # with a stray -> exit 1; without -> exit 0; both must emit valid JSON
    (fake_repo / "junk_probe.txt").write_text("x", encoding="utf-8")
    assert hygiene.main(["--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    (fake_repo / "junk_probe.txt").unlink()
    assert hygiene.main(["--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
