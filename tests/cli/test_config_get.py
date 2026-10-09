"""``vulnclaw config get`` must traverse dict nodes, not just Pydantic attributes.

Field motivation (2026-10-09 audit, fifth round): ``set_config_value`` was taught to
walk plain dicts, but ``config_get`` kept a bare ``getattr`` loop, so the very keys the
schema comment advertises -- ``platforms.ctf2.enabled``,
``mcp.servers.chrome-devtools.enabled`` -- raised
``AttributeError: 'dict' object has no attribute 'ctf2'`` straight out of the CLI.
"""

from __future__ import annotations

from typer.testing import CliRunner

from vulnclaw.cli.main import app


def _isolate_config(monkeypatch, tmp_path):
    import vulnclaw.config.settings as settings_mod

    monkeypatch.setattr(settings_mod, "CONFIG_FILE", tmp_path / "config.yaml")
    monkeypatch.setattr(settings_mod, "CONFIG_DIR", tmp_path)
    return settings_mod


def test_config_get_reads_a_dict_backed_key(monkeypatch, tmp_path):
    settings_mod = _isolate_config(monkeypatch, tmp_path)
    settings_mod.set_config_value("platforms.ctf2.enabled", "false")

    result = CliRunner().invoke(app, ["config", "get", "platforms.ctf2.enabled"])

    assert result.exit_code == 0, result.output
    assert "platforms.ctf2.enabled = False" in result.output


def test_config_get_reads_an_extra_section_created_by_set(monkeypatch, tmp_path):
    # ``platforms.<name>`` is an ``extra="allow"`` section: the key does not exist
    # until ``set`` creates it, so both the traversal and the creation path matter.
    settings_mod = _isolate_config(monkeypatch, tmp_path)
    settings_mod.set_config_value("mcp.servers.chrome-devtools.enabled", "false")

    result = CliRunner().invoke(
        app, ["config", "get", "mcp.servers.chrome-devtools.enabled"]
    )

    assert result.exit_code == 0, result.output
    assert "mcp.servers.chrome-devtools.enabled = False" in result.output


def test_setting_a_new_extra_section_does_not_fail_open(monkeypatch, tmp_path):
    # ``bool("false")`` is True and ``_config_enabled`` reads the mapping entry as
    # ``bool(entry.get("enabled"))`` — so a stringly-typed write into a freshly
    # created section used to switch the platform ON. Guard that specifically.
    settings_mod = _isolate_config(monkeypatch, tmp_path)
    settings_mod.set_config_value("platforms.ctf2.enabled", "false")

    from vulnclaw.platforms.registry import _config_enabled

    assert _config_enabled("ctf2", settings_mod.load_config()) is False

    settings_mod.set_config_value("platforms.ctf2.enabled", "true")
    assert _config_enabled("ctf2", settings_mod.load_config()) is True


def test_config_get_reads_a_pydantic_backed_key(monkeypatch, tmp_path):
    settings_mod = _isolate_config(monkeypatch, tmp_path)
    settings_mod.set_config_value("session.task_mode", "pentest")

    result = CliRunner().invoke(app, ["config", "get", "session.task_mode"])

    assert result.exit_code == 0, result.output
    assert "session.task_mode = pentest" in result.output


def test_config_get_unknown_key_exits_nonzero_without_a_traceback(monkeypatch, tmp_path):
    _isolate_config(monkeypatch, tmp_path)

    result = CliRunner().invoke(app, ["config", "get", "nope.nothing"])

    assert result.exit_code == 2
    assert "未知配置键" in result.output
    assert "Traceback" not in result.output
