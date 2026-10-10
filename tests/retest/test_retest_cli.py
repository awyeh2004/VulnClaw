"""``vulnclaw retest`` CLI 接线：能发起、能结案、能列清单，且失败不静默."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from vulnclaw.cli.main import app
from vulnclaw.config.domain_models import VulnerabilityFinding
from vulnclaw.retest.store import RetestStore


def _finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        title="SQLi in /login",
        severity="High",
        vuln_type="SQLi",
        description="d",
        evidence="e",
        remediation="r",
        target="http://example.test",
        endpoint="http://example.test/login",
        method="POST",
    )


def _write_findings(tmp_path, finding: VulnerabilityFinding) -> str:
    path = tmp_path / "findings.json"
    path.write_text(
        json.dumps({"findings": [finding.model_dump(mode="json")]}, ensure_ascii=False),
        encoding="utf-8",
    )
    return str(path)


def test_retest_start_prints_the_session_and_the_brief(tmp_path):
    finding = _finding()
    store_dir = tmp_path / "store"

    result = CliRunner().invoke(
        app,
        [
            "retest",
            finding.finding_id,
            "--findings",
            _write_findings(tmp_path, finding),
            "--store",
            str(store_dir),
            "--constraints",
            "scope=example.test,methods=POST",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "复测会话" in result.output
    assert "最小定向复测" in result.output
    record = RetestStore(store_dir).latest(finding.finding_id)
    assert record is not None and record.round == 1
    assert record.snapshot["constraints"] == {"scope": "example.test", "methods": "POST"}


def test_retest_verdict_fixed_is_recorded_and_flips_disposition(tmp_path):
    finding = _finding()
    store_dir = tmp_path / "store"
    findings = _write_findings(tmp_path, finding)
    runner = CliRunner()
    runner.invoke(app, ["retest", finding.finding_id, "--findings", findings, "--store", str(store_dir)])

    result = runner.invoke(
        app,
        [
            "retest",
            finding.finding_id,
            "--findings",
            findings,
            "--store",
            str(store_dir),
            "--verdict",
            "fixed",
            "--note",
            "打补丁后同一 payload 返回 403",
        ],
    )

    assert result.exit_code == 0, result.output
    record = RetestStore(store_dir).latest(finding.finding_id)
    assert record.verdict == "fixed"
    assert record.status.value == "completed"
    assert "翻转为 fixed" in result.output
    # The wording must not read as "written back": the command deliberately keeps
    # findings.json untouched (module docstring), so say where the flip lives.
    # Compare with whitespace stripped — the console wraps long lines.
    assert "未写回findings.json" in "".join(result.output.split())


def test_retest_verdict_does_not_rewrite_the_findings_file(tmp_path):
    finding = _finding()
    store_dir = tmp_path / "store"
    findings = _write_findings(tmp_path, finding)
    before = open(findings, encoding="utf-8").read()
    runner = CliRunner()
    runner.invoke(app, ["retest", finding.finding_id, "--findings", findings, "--store", str(store_dir)])

    result = runner.invoke(
        app,
        [
            "retest",
            finding.finding_id,
            "--findings",
            findings,
            "--store",
            str(store_dir),
            "--verdict",
            "fixed",
        ],
    )

    assert result.exit_code == 0, result.output
    assert open(findings, encoding="utf-8").read() == before


def test_retest_list_reports_recorded_sessions(tmp_path):
    finding = _finding()
    store_dir = tmp_path / "store"
    runner = CliRunner()
    findings = _write_findings(tmp_path, finding)
    runner.invoke(app, ["retest", finding.finding_id, "--findings", findings, "--store", str(store_dir)])

    result = runner.invoke(app, ["retest", "--list", "--store", str(store_dir)])

    assert result.exit_code == 0, result.output
    assert finding.finding_id in result.output
    assert "round=1" in result.output


def test_retest_unknown_finding_exits_nonzero_with_a_message(tmp_path):
    finding = _finding()
    result = CliRunner().invoke(
        app,
        [
            "retest",
            "fid-does-not-exist",
            "--findings",
            _write_findings(tmp_path, finding),
            "--store",
            str(tmp_path / "store"),
        ],
    )

    assert result.exit_code != 0
    assert "fid-does-not-exist" in result.output


def test_retest_without_a_finding_is_a_usage_error(tmp_path):
    result = CliRunner().invoke(app, ["retest", "--store", str(tmp_path / "store")])

    assert result.exit_code == 2
    assert "finding id" in result.output


def test_retest_mistyped_verdict_is_a_message_not_a_traceback(tmp_path):
    """A bad ``--verdict`` must reach the user as one line, not a raw traceback.

    ``conclude`` validates the verdict; the store's own error family is what the
    CLI catches, so the rejection has to be a member of it. A bare ``ValueError``
    is not caught and escapes as a traceback.
    """

    finding = _finding()
    store_dir = tmp_path / "store"
    findings = _write_findings(tmp_path, finding)
    runner = CliRunner()
    runner.invoke(app, ["retest", finding.finding_id, "--findings", findings, "--store", str(store_dir)])

    result = runner.invoke(
        app,
        [
            "retest",
            finding.finding_id,
            "--findings",
            findings,
            "--store",
            str(store_dir),
            "--verdict",
            "not-a-verdict",
        ],
    )

    assert result.exit_code == 1, result.output
    assert "not-a-verdict" in result.output
    assert "Traceback" not in result.output
    assert "unknown retest verdict" in result.output
