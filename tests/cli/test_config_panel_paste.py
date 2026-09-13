"""Clipboard + paste wiring for the classic-REPL config panel."""

from __future__ import annotations

import tempfile
from types import SimpleNamespace

from vulnclaw.cli import tui as tui_mod


def test_read_system_clipboard_windows_strips_bom_and_returns_text(monkeypatch, tmp_path):
    monkeypatch.setattr(tui_mod.sys, "platform", "win32")
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))

    def fake_run(cmd, **kwargs):
        path = tmp_path / f"vulnclaw-paste-{tui_mod.os.getpid()}.txt"
        path.write_bytes(b"\xef\xbb\xbfsk-pasted-key")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(tui_mod.subprocess, "run", fake_run)

    assert tui_mod._read_system_clipboard() == "sk-pasted-key"
    assert not (tmp_path / f"vulnclaw-paste-{tui_mod.os.getpid()}.txt").exists()


def test_read_system_clipboard_windows_returns_none_on_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(tui_mod.sys, "platform", "win32")
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(
        tui_mod.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout=b"", stderr=b"boom"),
    )

    assert tui_mod._read_system_clipboard() is None


def test_read_system_clipboard_unix_uses_first_working_helper(monkeypatch):
    monkeypatch.setattr(tui_mod.sys, "platform", "linux")
    calls: list[tuple[str, ...]] = []

    def fake_run(cmd, **kwargs):
        calls.append(tuple(cmd))
        if cmd[0] == "pbpaste":
            raise FileNotFoundError("no pbpaste")
        if cmd[0] == "wl-paste":
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"")
        if cmd[0] == "xclip":
            return SimpleNamespace(returncode=0, stdout=b"from-xclip", stderr=b"")
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"")

    monkeypatch.setattr(tui_mod.subprocess, "run", fake_run)

    assert tui_mod._read_system_clipboard() == "from-xclip"
    assert calls[0][0] == "pbpaste"
    assert any(c[0] == "xclip" for c in calls)
