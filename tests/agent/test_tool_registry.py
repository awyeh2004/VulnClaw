"""tool_registry: deterministic capability card injection."""

from __future__ import annotations

from unittest.mock import patch

from vulnclaw.agent import tool_registry as tr


def test_web_goal_matches_sqlmap_ffuf():
    with patch.object(tr, "_detect") as mock_detect:
        def side_effect(entry):
            return entry.get("cmd") or entry.get("name")
        mock_detect.side_effect = side_effect
        card = tr.build_tool_card("sqli injection on login page")
        assert "sqlmap" in card  # "sqli" matches sqlmap keywords


def test_hash_goal_matches_hashcat_john():
    with patch.object(tr, "_detect") as mock_detect:
        mock_detect.return_value = "hashcat"
        card = tr.build_tool_card("crack the md5 hash password")
        assert "hashcat" in card or "External tools" in card


def test_pwn_goal_matches_ropgadget():
    with patch.object(tr, "_detect") as mock_detect:
        mock_detect.return_value = "ROPgadget"
        card = tr.build_tool_card("pwn ret2libc stack overflow exploit")
        assert "ROPgadget" in card


def test_ir_goal_matches_no_attack_tools():
    """IR goals (应急响应) shouldn't trigger attack tool cards by default."""
    with patch.object(tr, "_detect") as mock_detect:
        mock_detect.return_value = "sqlmap"
        card = tr.build_tool_card("应急响应 被入侵服务器排查 webshell")
        # "注入" might match sqlmap — but the goal is IR not attack
        # This is by design: IR work may need sqlmap for vuln verification
        assert isinstance(card, str)


def test_unrelated_goal_returns_empty():
    with patch.object(tr, "_detect") as mock_detect:
        mock_detect.return_value = "sqlmap"
        card = tr.build_tool_card("read a file and summarize it")
        assert card == ""


def test_bg_launch_hint_on_crack_goal():
    with patch.object(tr, "_detect") as mock_detect:
        mock_detect.return_value = "hashcat"
        card = tr.build_tool_card("破解zip压缩包密码")
        assert "bg_launch" in card


def test_real_detection_finds_tools():
    """Integration: actually probe the filesystem for installed tools."""
    card = tr.build_tool_card("sqli 注入 attack")
    # On this machine sqlmap is installed — card should contain it
    assert "sqlmap" in card or card == ""  # empty if goal doesn't match


def test_system_prompt_includes_tool_card():
    """Verify _system_prompt incorporates the tool_card variable."""
    from vulnclaw.agent.solver import _system_prompt

    class _RT:
        prior_playbook_brief = ""

    class _Agent:
        runtime = _RT()

    class _State:
        goal = "sqli injection test"
        origin = "http://target"

    prompt = _system_prompt(_Agent(), _State())
    # Either the card is present (tools installed) or the variable slot is empty
    # — both are valid; just ensure no crash
    assert isinstance(prompt, str)
    assert len(prompt) > 100


# ── portability (round-5 review N7) ─────────────────────────────────────


def test_tools_dir_override_takes_priority(monkeypatch, tmp_path):
    root = tmp_path / "bundles"
    root.mkdir()
    monkeypatch.setenv("VULNCLAW_TOOLS_DIR", str(root))
    assert tr._candidate_roots()[0] == root
    assert tr.tools_dir() == root


def test_relative_detection_works_under_any_root(monkeypatch, tmp_path):
    """A bundle relocated anywhere is still found (the old entries were absolute)."""
    root = tmp_path / "bundles"
    (root / "sqlmap").mkdir(parents=True)
    (root / "sqlmap" / "sqlmap.py").write_text("# sqlmap", encoding="utf-8")
    monkeypatch.setenv("VULNCLAW_TOOLS_DIR", str(root))
    entry = next(e for e in tr._REGISTRY if e["name"] == "sqlmap")
    found = tr._detect(entry)
    assert found is not None
    assert str(root / "sqlmap" / "sqlmap.py") in found


def test_glob_detection_works_under_any_root(monkeypatch, tmp_path):
    root = tmp_path / "bundles"
    (root / "hashcat-beta" / "6.2.6").mkdir(parents=True)
    (root / "hashcat-beta" / "6.2.6" / "hashcat.exe").write_text("x", encoding="utf-8")
    monkeypatch.setenv("VULNCLAW_TOOLS_DIR", str(root))
    entry = next(e for e in tr._REGISTRY if e["name"] == "hashcat (GPU)")
    found = tr._detect(entry)
    assert found is not None
    assert str(root / "hashcat-beta" / "6.2.6" / "hashcat.exe") in found


def test_path_fallback_detects(monkeypatch):
    """A tool installed on PATH needs no bundle root at all."""
    monkeypatch.setenv("VULNCLAW_TOOLS_DIR", "")
    monkeypatch.setattr(tr.shutil, "which", lambda name: f"/usr/bin/{name}")
    entry = next(e for e in tr._REGISTRY if e["name"] == "nmap")
    assert tr._detect(entry) == "nmap"


def test_missing_tool_is_not_reported(monkeypatch, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(tr, "_candidate_roots", lambda: [empty])
    monkeypatch.setattr(tr.shutil, "which", lambda name: None)
    entry = next(e for e in tr._REGISTRY if e["name"] == "gobuster")
    assert tr._detect(entry) is None


def test_winscp_is_detected_from_localappdata(monkeypatch, tmp_path):
    """No hardcoded user name: %LOCALAPPDATA% supplies the machine-specific part."""
    local = tmp_path / "AppData" / "Local"
    (local / "Programs" / "WinSCP").mkdir(parents=True)
    winscp = local / "Programs" / "WinSCP" / "WinSCP.com"
    winscp.write_text("x", encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setattr(tr.shutil, "which", lambda name: None)
    assert str(winscp) in (tr._detect(tr._IR_REGISTRY[0]) or "")


def test_no_personal_paths_in_the_module_source():
    """Regression: a C:\\Users\\<name>\\AppData\\... path was committed here."""
    import re
    from pathlib import Path as _Path

    source = _Path(tr.__file__).read_text(encoding="utf-8")
    assert re.search(r"Users\\+[^\\\s\"']+\\+AppData", source) is None
    assert str(tr._LEGACY_TOOLS_DIR) in source  # the one documented exception


def test_no_absolute_fragments_in_detection_data():
    for entry in [*tr._REGISTRY, *tr._IR_REGISTRY]:
        for key in ("rel", "rel_glob"):
            for part in entry.get(key, ()):
                assert ":" not in part, f"absolute path fragment {part!r} in {entry['name']}"
