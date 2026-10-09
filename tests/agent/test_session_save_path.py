"""Where a session lands on disk, and that the name cannot become a directory.

Round-1 (2026-10-09) postmortem: ``SessionState.save()`` built its default name
from ``self.target`` with a bare ``.replace("/", "_").replace(":", "_")`` chain.
``\\`` was not in that set, so on Windows a target that is a path
(``C:\\Users\\x\\d\\a.zip`` -- 7 of the 222 distinct targets in this machine's own
session history) made the name split into a directory tree under ``SESSIONS_DIR``:
the session was written, but not where a flat listing looks, and the operator's
"where did my session go" question had no answer in the file system.

The same rule now lives in one place (``vulnclaw.utils.fs_names``) and is shared
with the report generators and the web report service.
"""

from __future__ import annotations

import vulnclaw.config.settings as settings
from vulnclaw.agent.context import SessionState


def _session(target: str) -> SessionState:
    return SessionState(target=target)


def test_default_path_is_one_component_for_a_path_target(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "SESSIONS_DIR", tmp_path)
    state = _session(r"C:\Users\伟\Downloads\a9c4fb8a551948e6981cbcfe84b17ed0.zip")

    path = state.save()

    assert path.parent == tmp_path, "the session must land in SESSIONS_DIR itself"
    assert "/" not in path.name and "\\" not in path.name
    assert path.name.endswith(".json")


def test_default_path_is_one_component_for_a_url_target(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "SESSIONS_DIR", tmp_path)
    state = _session("http://10.0.172.249:7860/admin?x=1")

    path = state.save()

    assert path.parent == tmp_path
    assert path.name.endswith(".json")


def test_a_saved_session_still_loads(monkeypatch, tmp_path):
    """Regression: the rename must not break resume."""
    monkeypatch.setattr(settings, "SESSIONS_DIR", tmp_path)
    state = _session(r"E:\vulnclaw\work\c96e7862\challenge.elf")

    path = state.save()
    reloaded = SessionState.load(path)

    assert reloaded.target == state.target


def test_an_explicit_path_is_used_verbatim(monkeypatch, tmp_path):
    """The ``path=`` branch is the caller's decision and stays untouched."""
    monkeypatch.setattr(settings, "SESSIONS_DIR", tmp_path / "sessions")
    explicit = tmp_path / "nested" / "my session.json"

    path = _session("10.0.0.1").save(explicit)

    assert path == explicit
    assert explicit.is_file()
