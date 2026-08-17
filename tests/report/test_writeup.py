from pathlib import Path

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.i18n import current_lang, init_i18n
from vulnclaw.report.writeup import (
    WriteupMeta,
    default_writeup_dir,
    extract_scripts,
    generate_writeup,
    render_evidence_popup,
    render_writeup,
)


def _completed_state() -> AgentState:
    state = AgentState(origin="CTF2{writeup-demo}", goal="capture flag")
    state.pin_fact("Linked endpoint: select-waf.php", evidence_id="e001")
    state.pin_fact("JS/API endpoint: api/?id=", evidence_id="e002")
    state.pin_fact(
        "Source SQL: select id,username,password from ctfshow_user "
        "where username !='flag' and id = '$_GET[id]' limit 1",
        evidence_id="e003",
    )
    state.record_step(
        reason="Read page and script endpoints",
        observation="select-waf.php and api/?id found",
        tool_calls=["fetch"],
    )
    state.record_step(
        reason="Replay minimal SQL expression payload",
        observation="flag row returned",
        tool_calls=["http_probe_batch"],
    )
    output = """
# http_probe_batch results (2 request(s))
[1] GET baseline 200 len=111 hash=aaa 10ms type=text/html
    url=https://example.challenge.ctf.show/api/?id=1
    body_length=111
    body:
{"code":0,"data":[{"id":"1","username":"admin","password":"admin"}]}
[2] GET concat-no-comment 200 len=151 hash=bbb 10ms type=text/html
    url=https://example.challenge.ctf.show/api/?id=0%27%7C%7Cusername%3D%27flag
    body_length=151
    body:
{"code":0,"data":[{"id":"26","username":"flag","password":"ctfshow{report-ok}"}]}
"""
    evidence = state.remember_tool_result(
        tool="http_probe_batch",
        arguments={"requests": []},
        output=output,
        status=200,
    )
    state.record_tool_call(
        tool="http_probe_batch",
        arguments={"requests": []},
        status=200,
        evidence_id=evidence.id,
        summary=evidence.summary,
    )
    state.record_llm_usage(prompt_tokens=1234, completion_tokens=567)
    state.mark_complete(
        "verified flag from recorded evidence: ctfshow{report-ok}",
        final_answer="FINAL: ctfshow{report-ok}",
        evidence_ids=[evidence.id],
    )
    return state


def _meta() -> WriteupMeta:
    return WriteupMeta(
        team_name="摸鱼干饭专业队",
        rank="1",
        solved_count="3",
        total_tokens=1801,
        model_name="gpt-5",
        exercise_name="SQLi Challenge",
        category="WEB",
    )


def test_render_writeup_contains_team_header_and_chain():
    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        report = render_writeup(_completed_state(), meta=_meta())

        assert "SQLi Challenge" in report
        assert "摸鱼干饭专业队" in report
        assert "gpt-5" in report
        assert "1801" in report
        assert "ctfshow{report-ok}" in report
        assert "解题步骤" in report
        assert "select-waf.php" in report
    finally:
        init_i18n(lang=previous_lang)


def test_render_evidence_popup_reports_line_numbers():
    popup = render_evidence_popup(_completed_state())

    assert popup is not None
    assert "http_probe_batch" in popup
    assert "ctfshow{report-ok}" in popup


def test_extract_scripts_skips_noop_tools():
    scripts = extract_scripts(_completed_state())

    assert isinstance(scripts, list)
    for script in scripts:
        assert script.code.strip()


def test_generate_writeup_writes_markdown(tmp_path):
    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        output = generate_writeup(
            _completed_state(),
            meta=_meta(),
            output_path=tmp_path / "writeup.md",
        )
    finally:
        init_i18n(lang=previous_lang)

    assert output == Path(tmp_path / "writeup.md")
    assert output.exists()
    assert "摸鱼干饭专业队" in output.read_text(encoding="utf-8")


def test_generate_writeup_default_dir_env(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNCLAW_WRITEUP_DIR", str(tmp_path))

    output = generate_writeup(_completed_state(), meta=_meta())

    assert output.parent == tmp_path
    assert output.exists()


def test_generate_writeup_directory_target_builds_filename(tmp_path):
    output = generate_writeup(_completed_state(), meta=_meta(), output_path=tmp_path)

    assert output.parent == tmp_path
    assert output.suffix == ".md"
    assert output.exists()


def test_default_writeup_dir_prefers_env(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNCLAW_WRITEUP_DIR", str(tmp_path))

    assert default_writeup_dir() == tmp_path
