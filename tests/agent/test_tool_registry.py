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


def _all_present(entry):
    """Side effect for _detect: pretend every entry is installed.

    Assertions must name the tool they mean; a blanket ``return_value`` makes the
    card's contents independent of which entry matched, so a test can pass on the
    wrong entry entirely.
    """
    return entry.get("cmd") or entry.get("name")


def test_hash_goal_matches_hashcat_john():
    with patch.object(tr, "_detect", side_effect=_all_present):
        card = tr.build_tool_card("crack the md5 hash password")
    # Was `assert "hashcat" in card or "External tools" in card` — the second
    # disjunct is true for ANY non-empty card, so the assertion could not fail.
    assert "hashcat" in card
    assert "john" in card


def test_pwn_goal_matches_ropgadget():
    with patch.object(tr, "_detect", side_effect=_all_present):
        card = tr.build_tool_card("pwn ret2libc stack overflow exploit")
    assert "ROPgadget" in card


def test_ir_specific_tools_reach_the_card():
    """Regression: _IR_REGISTRY was defined but never read by build_tool_card.

    The WinSCP entry detects correctly and its keywords match IR goals, yet the
    card came back empty for "用 SFTP 把取证文件传到本地" because the builder only
    iterated _REGISTRY. Detection working is not enough — it has to be rendered.
    """
    with patch.object(tr, "_detect", side_effect=_all_present):
        card = tr.build_tool_card("用 SFTP 把取证文件传到本地")
    assert "WinSCP" in card
    assert "Incident-response" in card


def test_both_registries_are_rendered_when_all_match():
    """Every entry that MATCHES must be rendered — no silently dropped list.

    The goal is deliberately keyword-rich but cannot be expected to hit all 25
    entries; the invariant is matched == rendered, which is what fails when one
    registry is skipped.
    """
    goal = (
        "sftp 取证 collect upload 端口扫描 hashcat 破解 目录 enum pwn rop "
        "固件 firmware exif 元数据 sqli 注入 子域名 持久化 自启动 进程 webshell "
        "事件日志 时间线 prefetch dns 内存镜像 网络连接"
    )
    with patch.object(tr, "_detect", side_effect=_all_present):
        card = tr.build_tool_card(goal)
    matched = [
        e["name"]
        for e in [*tr._REGISTRY, *tr._IR_REGISTRY]
        if tr._match(goal.lower(), e.get("keywords", []))
    ]
    assert len(matched) >= 10, "goal should exercise both registries"
    for name in matched:
        assert name in card, f"{name} matched but was not rendered"
    # And the IR section must actually be present for an IR-heavy goal.
    assert "Incident-response" in card


def test_ir_goal_still_reports_attack_tools_it_matches():
    """IR goals may legitimately pull attack tools (vuln verification)."""
    with patch.object(tr, "_detect", side_effect=_all_present):
        card = tr.build_tool_card("应急响应 被入侵服务器排查 webshell")
    assert "nmap" in card  # via 服务/服务器 substring overlap
    assert "D盾_Web查杀" in card  # "webshell" is an explicit IR keyword

    with patch.object(tr, "_detect", side_effect=_all_present):
        card2 = tr.build_tool_card("检查被植入的 webshell 后门文件")
    assert "D盾_Web查杀" in card2
    assert "Incident-response" in card2


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
    # Was `assert "sqlmap" in card or card == ""` — the empty branch made a
    # completely broken detector pass. Skip instead of accepting silence when the
    # probe for this machine found nothing.
    if not any(tr._detect(e) for e in tr._REGISTRY):
        import pytest

        pytest.skip("no external tool bundles installed on this machine")
    assert "sqlmap" in card


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
    assert isinstance(prompt, str)
    assert len(prompt) > 100
    # Presence of the card depends on installed tools, but the SLOT must be wired:
    # when a tool is detectable the card text has to reach the prompt.
    if any(tr._detect(e) for e in tr._REGISTRY):
        built = tr.build_tool_card(_State.goal)
        if built:
            assert built.strip() in prompt, "tool card was built but not injected"


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
