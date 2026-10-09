"""How bound evidence reaches the report: durable, labelled, and never silent.

The behaviour under test is the fix for the defect that motivated the snapshot
layer: evidence used to be resolved from the reclaimable capture log and
``continue``-d on a miss, so a finding whose proof had been dropped looked
exactly like one that never had proof.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from vulnclaw.agent.context import EvidenceRef, SessionState, VulnerabilityFinding
from vulnclaw.config.domain_models import evidence_binding_signature
from vulnclaw.i18n import current_lang, init_i18n
from vulnclaw.report.generator import (
    _evidence_staleness_notice,
    generate_report,
)
from vulnclaw.traffic.binding import bind_finding_evidence
from vulnclaw.traffic.evidence import EvidenceStore
from vulnclaw.traffic.models import CapturedExchange, CapturedRequest, CapturedResponse
from vulnclaw.traffic.store import TrafficStore

ERROR_BODY = b"SQL syntax error near ''1'"


def _capture(traffic: TrafficStore, url: str) -> str:
    return traffic.record(
        CapturedExchange(
            request=CapturedRequest(method="GET", url=url, headers={"Host": "app.test"}),
            response=CapturedResponse(status=500, body=ERROR_BODY),
        ),
        source="proxy",
    ).request_id


def _run_and_report(tmp_path, *, mutate=None):
    """Build a run with a bound, verified finding and generate its report."""
    run_dir = tmp_path / "run"
    traffic = TrafficStore(run_dir / "evidence" / "traffic")
    evidence = EvidenceStore(run_dir / "evidence")

    baseline = _capture(traffic, "http://app.test/user?id=1")
    proof = _capture(traffic, "http://app.test/user?id=1'")

    finding = VulnerabilityFinding(
        title="SQL Injection in /user",
        severity="High",
        vuln_type="SQLi",
        evidence="id parameter is injectable",
        remediation="Use parameterized queries",
    )
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[
            {"request_id": baseline, "role": "baseline", "note": "normal account"},
            {"request_id": proof, "role": "proof", "note": "payload triggers the error"},
        ],
    )
    finding.mark_verified(note="confirmed via error-based injection")

    session = SessionState(target="http://app.test")
    session.add_finding(finding)

    if mutate is not None:
        mutate(traffic, evidence, finding, run_dir)

    report_path = generate_report(session, output_path=str(run_dir / "report.md"))
    return report_path.read_text(encoding="utf-8"), finding, evidence, run_dir


def test_report_renders_pinned_evidence_after_the_capture_log_is_gone(tmp_path):
    """Bind, reclaim the capture log, then report: the proof must still be there."""
    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        text, finding, _, run_dir = _run_and_report(
            tmp_path,
            mutate=lambda traffic, evidence, finding, run_dir: shutil.rmtree(
                run_dir / "evidence" / "traffic"
            ),
        )
    finally:
        init_i18n(lang=previous_lang)

    assert "抓包复现证据" in text
    assert "```http" in text
    assert "GET /user?id=1' HTTP/1.1" in text
    assert "SQL syntax error near" in text
    # the durable handle is what the report cites, not the capture-log id
    assert finding.evidence_refs[1].snapshot_id in text


def test_report_labels_the_role_of_each_exchange(tmp_path):
    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        text, _, _, _ = _run_and_report(tmp_path)
    finally:
        init_i18n(lang=previous_lang)

    assert "对照请求" in text  # baseline
    assert "证明请求" in text  # proof


def test_report_renders_binding_notes(tmp_path):
    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        text, _, _, _ = _run_and_report(tmp_path)
    finally:
        init_i18n(lang=previous_lang)

    assert "normal account" in text
    assert "payload triggers the error" in text


def test_report_marks_bound_but_unreadable_evidence_instead_of_dropping_it(tmp_path):
    """The headline regression: a corrupt body must be visible, not absent."""

    def corrupt(traffic, evidence, finding, run_dir):
        # Destroy one pinned body, leaving the binding in place.
        digest = finding.evidence_refs[1].sha256
        evidence._blob_path(digest).write_bytes(b"tampered")

    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        text, _, _, _ = _run_and_report(tmp_path, mutate=corrupt)
    finally:
        init_i18n(lang=previous_lang)

    assert "正文不可读取" in text
    assert "SQL syntax error near" not in text


def test_report_reports_a_pinned_handle_that_is_gone_entirely(tmp_path):
    """A binding whose snapshot was deleted must not vanish silently."""

    def drop_snapshot(traffic, evidence, finding, run_dir):
        shutil.rmtree(run_dir / "evidence" / "traffic")
        shutil.rmtree(evidence.blobs_dir)

    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        text, _, _, _ = _run_and_report(tmp_path, mutate=drop_snapshot)
    finally:
        init_i18n(lang=previous_lang)

    assert "正文不可读取" in text


def test_legacy_request_id_only_refs_still_render_from_the_capture_log(tmp_path):
    """Refs bound before the snapshot layer existed must keep working."""
    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        run_dir = tmp_path / "run"
        traffic = TrafficStore(run_dir / "evidence" / "traffic")
        request_id = _capture(traffic, "http://app.test/user?id=1'")

        finding = VulnerabilityFinding(
            title="SQL Injection in /user",
            severity="High",
            vuln_type="SQLi",
            evidence="injectable",
            evidence_refs=[EvidenceRef(kind="http_capture", request_id=request_id)],
        )
        finding.mark_verified()
        session = SessionState(target="http://app.test")
        session.add_finding(finding)

        report_path = generate_report(session, output_path=str(run_dir / "report.md"))
        text = report_path.read_text(encoding="utf-8")
    finally:
        init_i18n(lang=previous_lang)

    assert "GET /user?id=1' HTTP/1.1" in text
    assert "SQL syntax error near" in text
    # No pinned snapshot exists, so no staleness warning is warranted.
    assert "证据版本在报告生成期间发生变化" not in text


def test_a_finding_without_evidence_refs_renders_no_http_blocks(tmp_path):
    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        run_dir = tmp_path / "run"
        finding = VulnerabilityFinding(
            title="Reflected XSS",
            severity="Medium",
            vuln_type="XSS",
            evidence="payload reflected",
            remediation="encode output",
        )
        finding.mark_verified()
        session = SessionState(target="http://app.test")
        session.add_finding(finding)

        text = generate_report(
            session, output_path=str(run_dir / "report.md")
        ).read_text(encoding="utf-8")
    finally:
        init_i18n(lang=previous_lang)

    assert "Reflected XSS" in text
    assert "```http" not in text


# ── the staleness notice ────────────────────────────────────────────────────


def test_staleness_notice_is_empty_when_nothing_changed():
    finding = VulnerabilityFinding(title="x", severity="Low")
    before = {id(finding): (0, evidence_binding_signature(finding.evidence_refs))}
    assert _evidence_staleness_notice([finding], before) == ""


def test_staleness_notice_fires_when_a_version_moved():
    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        finding = VulnerabilityFinding(title="SQLi in /user", severity="High")
        # Same signature, different version -- isolates the version leg.
        before = {id(finding): (0, evidence_binding_signature(finding.evidence_refs))}
        finding.evidence_version = 3

        notice = _evidence_staleness_notice([finding], before)
    finally:
        init_i18n(lang=previous_lang)

    assert "证据版本在报告生成期间发生变化" in notice
    assert "SQLi in /user" in notice


def test_staleness_notice_fires_when_only_the_signature_moved():
    """A note or role edit bumps the signature without touching the version."""
    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        finding = VulnerabilityFinding(
            title="SQLi",
            severity="High",
            evidence_refs=[EvidenceRef(kind="http_capture", request_id="aa", role="proof")],
        )
        # Version matches; only the recorded signature is stale.
        before = {id(finding): (0, "deadbeefdeadbeef")}

        notice = _evidence_staleness_notice([finding], before)
    finally:
        init_i18n(lang=previous_lang)

    assert "证据版本在报告生成期间发生变化" in notice


# ── cross-run isolation (T7): two runs, one process, no shared bytes ─────────


def _capture_with(traffic: TrafficStore, url: str, body: bytes) -> str:
    return traffic.record(
        CapturedExchange(
            request=CapturedRequest(method="GET", url=url, headers={"Host": "app.test"}),
            response=CapturedResponse(status=500, body=body),
        ),
        source="proxy",
    ).request_id


def _bound_report(tmp_path, run_name: str, host: str, path_proof: str, *, output_path=None):
    """Run A/B helper: capture → bind → verify → report; returns (text, info).

    Each run gets a unique response body, so snapshot digests are unique too and
    an id appearing in a sibling report is unambiguous evidence of a leak.
    """
    run_dir = tmp_path / run_name
    traffic = TrafficStore(run_dir / "evidence" / "traffic")
    evidence = EvidenceStore(run_dir / "evidence")

    body = f"SQL syntax error near ''1' [{run_name}]".encode()
    baseline = _capture_with(traffic, f"http://{host}/", body)
    proof = _capture_with(traffic, f"http://{host}{path_proof}", body)

    finding = VulnerabilityFinding(
        title=f"SQL Injection in {run_name}",
        severity="High",
        vuln_type="SQLi",
        evidence="injectable",
    )
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[
            {"request_id": baseline, "role": "baseline", "note": f"{run_name} normal"},
            {"request_id": proof, "role": "proof", "note": f"{run_name} payload"},
        ],
    )
    finding.mark_verified()

    session = SessionState(target=f"http://{host}")
    session.add_finding(finding)

    target = Path(output_path) if output_path is not None else run_dir / "report.md"
    text = generate_report(session, output_path=str(target), run_dir=str(run_dir)).read_text(
        encoding="utf-8"
    )
    return text, {
        "run_dir": run_dir,
        "host": host,
        "proof_path": path_proof,
        "marker": run_name,
        "snapshot_ids": [r.snapshot_id for r in finding.evidence_refs if r.snapshot_id],
    }


def test_a_sibling_run_never_sees_another_runs_captures(tmp_path):
    """End-to-end isolation: run B must not render run A's captured bytes.

    Pre-fix the reader fell back to the process-wide evidence root, so a run with
    an empty store could pick up whatever a prior run in the same process had
    written. Two runs, two run dirs, one process -- the byte streams must not
    cross.
    """
    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        text_a, info_a = _bound_report(tmp_path, "run-a", "a.test", "/user?id=1'")
        text_b, info_b = _bound_report(tmp_path, "run-b", "b.test", "/item?id=2'")
    finally:
        init_i18n(lang=previous_lang)

    # Each report proves its own run's finding from its own store.
    assert f"GET {info_a['proof_path']} HTTP/1.1" in text_a
    assert f"run-a" in text_a
    assert f"GET {info_b['proof_path']} HTTP/1.1" in text_b
    assert f"run-b" in text_b

    # Nothing unique to run A may surface in run B -- not its host, its request
    # line, its body marker, nor any of its durable snapshot handles.
    assert f"GET {info_a['proof_path']}" not in text_b
    assert "a.test" not in text_b
    assert "[run-a]" not in text_b
    for snapshot_id in info_a["snapshot_ids"]:
        assert snapshot_id not in text_b


def test_output_path_outside_the_run_still_reads_the_runs_own_evidence(tmp_path):
    """D3: where the report file lands is not where the evidence lives.

    The legacy default writes the report under ``SESSIONS_DIR``; if the reader
    resolved evidence from ``output.parent`` it would miss the run tree -- every
    passing scan would render with no proof at all.
    """
    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        out_dir = tmp_path / "sessions"
        out_dir.mkdir()
        text, info = _bound_report(
            tmp_path,
            "run-x",
            "x.test",
            "/user?id=1'",
            output_path=out_dir / "report.md",
        )
    finally:
        init_i18n(lang=previous_lang)

    assert f"GET {info['proof_path']} HTTP/1.1" in text
    assert "[run-x]" in text
    # the report was written outside the run tree, but read the run's evidence
    assert (out_dir / "report.md").exists()
    assert (info["run_dir"] / "evidence" / "traffic").exists()


def test_report_ignores_a_stale_global_store(tmp_path, monkeypatch):
    """The plant: a previous run's captures sit in the config-scoped root.

    Run B is given an explicit run dir, so the reader must use B's own (empty)
    event tree and never the global fallback -- otherwise B's report would cite
    an unrelated run's proof.
    """
    global_root = tmp_path / "cfg" / "evidence"
    stale = TrafficStore(global_root / "traffic")
    _capture(stale, "http://other.test/admin?id=9'")
    monkeypatch.setenv("VULNCLAW_EVIDENCE_DIR", str(global_root))

    run_b = tmp_path / "run-b"
    (run_b / "evidence").mkdir(parents=True)
    finding = VulnerabilityFinding(
        title="Reflected XSS", severity="Medium", vuln_type="XSS", evidence="reflected"
    )
    finding.mark_verified()
    session = SessionState(target="http://app.test")
    session.add_finding(finding)

    previous_lang = current_lang()
    init_i18n(lang="zh")
    try:
        text = generate_report(
            session, output_path=str(run_b / "report.md"), run_dir=str(run_b)
        ).read_text(encoding="utf-8")
    finally:
        init_i18n(lang=previous_lang)

    assert "Reflected XSS" in text
    assert "```http" not in text
    assert "other.test" not in text
    assert "GET /admin?id=9'" not in text
