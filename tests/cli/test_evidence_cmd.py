"""``vulnclaw evidence``：GC 调度与解绑/重排的暴露面（缺口 1 / 2）。

两个纪律在这里被钉死：GC 只作用于给定的 run；解绑 / 重排**默认只看不写** ——
它们是会削弱报告证据面、改变引用顺序的动作，必须 ``--write`` 才真的落盘。
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from typer.testing import CliRunner

from vulnclaw.cli.main import app
from vulnclaw.config.domain_models import EvidenceRef, VulnerabilityFinding
from vulnclaw.traffic.paths import evidence_dir
from vulnclaw.traffic.evidence import EvidenceStore
from vulnclaw.traffic.store import TrafficStore
from tests.traffic.test_evidence_store import _exchange

SNAP_A = "snap-aaaa"
SNAP_B = "snap-bbbb"


def _finding(*snapshot_ids: str) -> VulnerabilityFinding:
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
        evidence_version=3,
        evidence_refs=[
            EvidenceRef(kind="http_capture", path=f"blobs/{sid}.bin", snapshot_id=sid)
            for sid in snapshot_ids
        ],
    )


FID = _finding().finding_id  # "SQLi" —— finding_id 由 vuln_type 派生


def _write_findings(tmp_path: Path, finding: VulnerabilityFinding) -> Path:
    path = tmp_path / "findings.json"
    path.write_text(
        json.dumps({"version": "test", "findings": [finding.model_dump(mode="json")]}),
        encoding="utf-8",
    )
    return path


def _entry(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))["findings"][0]


def _run_dir_with_aged_orphan(tmp_path: Path) -> tuple[Path, str]:
    """A run whose evidence store holds one orphaned blob past any grace window."""

    run_dir = tmp_path / "run"
    root = evidence_dir(run_dir)
    traffic = TrafficStore(root / "traffic")
    evidence = EvidenceStore(root)
    record = traffic.record(_exchange(), source="proxy")
    evidence.pin(traffic, record.request_id, pinned_at=1.0)

    digest = hashlib.sha256(b"orphan body").hexdigest()
    evidence._write_blob(b"orphan body")
    os.utime(evidence._blob_path(digest), (1.0, 1.0))
    assert time.time() > 2.0
    return run_dir, digest


# ── gc ──────────────────────────────────────────────────────────────────────


def test_gc_dry_run_lists_the_orphan_and_deletes_nothing(tmp_path):
    run_dir, digest = _run_dir_with_aged_orphan(tmp_path)

    result = CliRunner().invoke(app, ["evidence", "gc", str(run_dir), "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "dry-run" in result.output and digest in result.output
    store = EvidenceStore(evidence_dir(run_dir))
    assert store._blob_path(digest).exists()


def test_gc_reclaims_the_orphan(tmp_path):
    run_dir, digest = _run_dir_with_aged_orphan(tmp_path)

    result = CliRunner().invoke(app, ["evidence", "gc", str(run_dir)])

    assert result.exit_code == 0, result.output
    assert "已回收 1" in result.output
    assert not EvidenceStore(evidence_dir(run_dir))._blob_path(digest).exists()


def test_gc_defaults_to_a_one_day_grace(tmp_path):
    """刚写下的孤立 blob 不该被默认 gc 收走（报告可能马上要读它）。"""

    run_dir = tmp_path / "run"
    root = evidence_dir(run_dir)
    evidence = EvidenceStore(root)
    digest = hashlib.sha256(b"fresh orphan").hexdigest()
    evidence._write_blob(b"fresh orphan")

    result = CliRunner().invoke(app, ["evidence", "gc", str(run_dir)])

    assert result.exit_code == 0, result.output
    assert "已回收 0" in result.output
    assert evidence._blob_path(digest).exists()


# ── unbind ──────────────────────────────────────────────────────────────────


def test_unbind_without_write_only_reports(tmp_path):
    findings = _write_findings(tmp_path, _finding(SNAP_A, SNAP_B))

    result = CliRunner().invoke(
        app,
        ["evidence", "unbind", FID, "--findings", str(findings), "--snapshot", SNAP_A],
    )

    assert result.exit_code == 0, result.output
    assert "未落盘" in result.output
    entry = _entry(findings)
    assert len(entry["evidence_refs"]) == 2 and entry["evidence_version"] == 3


def test_unbind_with_write_drops_the_binding_and_bumps_the_version(tmp_path):
    findings = _write_findings(tmp_path, _finding(SNAP_A, SNAP_B))

    result = CliRunner().invoke(
        app,
        [
            "evidence",
            "unbind",
            FID,
            "--findings",
            str(findings),
            "--snapshot",
            SNAP_A,
            "--write",
        ],
    )

    assert result.exit_code == 0, result.output
    entry = _entry(findings)
    assert [ref["snapshot_id"] for ref in entry["evidence_refs"]] == [SNAP_B]
    assert entry["evidence_version"] == 4


def test_unbind_of_an_unknown_snapshot_says_so(tmp_path):
    """没匹配上时绑定面不动。

    ⚠️ 注意 ``unbind_finding_evidence`` 的 docstring 说"即使没匹配上也 bump 版本"，
    但实现只在 ``removed`` 非空时 bump（2026-10-09 复核）。CLI 因此必须自己把
    "没匹配到"说出来，否则调用方从版本号看不出这次请求被考虑过。
    """
    findings = _write_findings(tmp_path, _finding(SNAP_A))

    result = CliRunner().invoke(
        app,
        [
            "evidence",
            "unbind",
            FID,
            "--findings",
            str(findings),
            "--snapshot",
            "snap-nope",
            "--write",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "没有匹配到" in result.output
    entry = _entry(findings)
    # 现网语义：没匹配上就不 bump（见下方测试注释）；绑定面必须原样
    assert entry["evidence_version"] == 3
    assert len(entry["evidence_refs"]) == 1


# ── reorder ─────────────────────────────────────────────────────────────────


def test_reorder_rejects_an_incomplete_list(tmp_path):
    findings = _write_findings(tmp_path, _finding(SNAP_A, SNAP_B))

    result = CliRunner().invoke(
        app,
        [
            "evidence",
            "reorder",
            FID,
            "--findings",
            str(findings),
            "--handles",
            SNAP_A,
            "--write",
        ],
    )

    assert result.exit_code != 0
    assert "must name every binding" in result.output
    assert [ref["snapshot_id"] for ref in _entry(findings)["evidence_refs"]] == [SNAP_A, SNAP_B]


def test_reorder_with_write_applies_the_new_order(tmp_path):
    findings = _write_findings(tmp_path, _finding(SNAP_A, SNAP_B))

    result = CliRunner().invoke(
        app,
        [
            "evidence",
            "reorder",
            FID,
            "--findings",
            str(findings),
            "--handles",
            f"{SNAP_B},{SNAP_A}",
            "--write",
        ],
    )

    assert result.exit_code == 0, result.output
    entry = _entry(findings)
    assert [ref["snapshot_id"] for ref in entry["evidence_refs"]] == [SNAP_B, SNAP_A]
    assert entry["evidence_version"] == 4


def test_unknown_finding_id_is_a_usage_error(tmp_path):
    findings = _write_findings(tmp_path, _finding(SNAP_A))

    result = CliRunner().invoke(
        app,
        ["evidence", "unbind", "fid-nope", "--findings", str(findings), "--snapshot", SNAP_A],
    )

    assert result.exit_code == 2
    assert "fid-nope" in result.output
