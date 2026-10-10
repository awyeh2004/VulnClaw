"""``findings_io`` 的写回契约：只动目标条目，且不吞掉模型不认识的键。

``evidence unbind/reorder --write`` 与 retest 都经这条路径改 ``findings.json``。
既有的「只替换一条、保留文档其他键」纪律已钉住；这里补上第二条容易被忽略的：
``VulnerabilityFinding`` 是普通 ``BaseModel``（``extra`` 默认 ``ignore``），
校验时就把未知键丢了 —— 写回若直接用 ``model_dump`` 整条替换，会把新版本或
手写留下的前向兼容字段静默删除。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnclaw.cli.findings_io import (
    FindingsFileError,
    load_finding,
    save_finding,
)


def _write_doc(tmp_path: Path, entry: dict) -> Path:
    path = tmp_path / "findings.json"
    document = {"version": 1, "summary": {"total": 1}, "findings": [entry]}
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _base_entry(**extra) -> dict:
    entry = {"finding_id": "f1", "title": "SQLi", "severity": "High"}
    entry.update(extra)
    return entry


def test_unknown_fields_on_the_entry_survive_a_write_back(tmp_path):
    """A foreign key the model does not know must not be dropped by the rewrite."""
    path = _write_doc(tmp_path, _base_entry(future_field="KEEP_ME", cvss_note="note"))

    finding = load_finding(path, "f1")
    save_finding(path, finding)

    entry = json.loads(path.read_text(encoding="utf-8"))["findings"][0]
    assert entry["future_field"] == "KEEP_ME"
    assert entry["cvss_note"] == "note"


def test_the_edit_actually_takes_effect(tmp_path):
    """Preserving unknown keys must not mean ignoring the model's own values."""
    path = _write_doc(tmp_path, _base_entry(future_field="KEEP_ME"))

    finding = load_finding(path, "f1")
    finding.title = "SQLi (edited)"
    finding.severity = "Critical"
    save_finding(path, finding)

    entry = json.loads(path.read_text(encoding="utf-8"))["findings"][0]
    assert entry["title"] == "SQLi (edited)"
    assert entry["severity"] == "Critical"
    assert entry["future_field"] == "KEEP_ME"


def test_document_level_keys_and_siblings_are_untouched(tmp_path):
    """Only the one entry changes; the document's own keys survive."""
    path = tmp_path / "findings.json"
    path.write_text(
        json.dumps(
            {
                "version": 7,
                "summary": {"total": 2, "verified": 1},
                "findings": [
                    _base_entry(**{"finding_id": "f1"}),
                    {"finding_id": "f2", "title": "Other", "severity": "Low", "x": 9},
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    finding = load_finding(path, "f1")
    save_finding(path, finding)

    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["version"] == 7
    assert document["summary"] == {"total": 2, "verified": 1}
    assert document["findings"][1] == {"finding_id": "f2", "title": "Other", "severity": "Low", "x": 9}


def test_an_absent_finding_is_refused(tmp_path):
    """Writing back an id that is not in the document raises rather than appending."""
    path = _write_doc(tmp_path, _base_entry())

    finding = load_finding(path, "f1")
    finding.finding_id = "not-in-file"

    with pytest.raises(FindingsFileError):
        save_finding(path, finding)
