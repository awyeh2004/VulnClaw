"""Retest store invariants (A1 / ARTEX ``finding_retests.go`` 的文件式对应物).

Round-3 (2026-10-09) port: 一个 finding 只允许一个活跃复测（重复请求返回既有记录、
不新开）；复测结论只有第一轮能写；进程重启把遗留 running 封成 stopped，不自动重放。
"""

from __future__ import annotations

import json

import pytest

from vulnclaw.config.domain_models import RetestStatus, VulnerabilityFinding
from vulnclaw.retest.store import (
    RetestConflictError,
    RetestNotFoundError,
    RetestStore,
    RetestStoreCorruptError,
)


def _finding(**overrides) -> VulnerabilityFinding:
    base = {
        "title": "SQL injection in /login",
        "severity": "High",
        "vuln_type": "SQLi",
        "description": "unparameterised query",
        "evidence": "sqlmap payload 1' OR '1'='1 returned 5 rows",
        "remediation": "use parameterised queries",
        "target": "http://example.test",
        "endpoint": "http://example.test/login",
        "method": "POST",
    }
    base.update(overrides)
    return VulnerabilityFinding(**base)


def test_start_creates_a_running_round_one_record(tmp_path):
    store = RetestStore(tmp_path)
    record = store.start("fid-1", snapshot={"title": "x"})

    assert record.round == 1
    assert record.status is RetestStatus.RUNNING
    assert record.verdict == ""
    assert record.finding_id == "fid-1"
    assert record.retest_id
    assert store.active("fid-1").retest_id == record.retest_id


def test_start_dedupes_an_active_record_instead_of_opening_a_second_one(tmp_path):
    store = RetestStore(tmp_path)
    first = store.start("fid-1", snapshot={"title": "x"})
    second = store.start("fid-1", snapshot={"title": "changed"})

    assert second.retest_id == first.retest_id
    assert second.snapshot == first.snapshot  # frozen at start, not re-snapshotted
    assert len(store.history("fid-1")) == 1


def test_active_is_none_once_the_record_is_concluded(tmp_path):
    store = RetestStore(tmp_path)
    store.start("fid-1", snapshot={})
    store.conclude("fid-1", verdict="fixed", note="patched")

    assert store.active("fid-1") is None


def test_conclude_records_the_verdict_and_completion_time(tmp_path):
    store = RetestStore(tmp_path)
    store.start("fid-1", snapshot={})
    done = store.conclude("fid-1", verdict="fixed", note="back to 200")

    assert done.status is RetestStatus.COMPLETED
    assert done.verdict == "fixed"
    assert done.note == "back to 200"
    assert done.completed_at


def test_conclude_rejects_an_unknown_or_duplicate_verdict(tmp_path):
    store = RetestStore(tmp_path)
    with pytest.raises(RetestNotFoundError):
        store.conclude("fid-nope", verdict="fixed")

    store.start("fid-1", snapshot={})
    store.conclude("fid-1", verdict="fixed")
    with pytest.raises(RetestConflictError):
        store.conclude("fid-1", verdict="reproduced")

    with pytest.raises(ValueError):
        store.conclude("fid-2", verdict="maybe")


def test_follow_up_round_cannot_overwrite_the_first_verdict(tmp_path):
    store = RetestStore(tmp_path)
    store.start("fid-1", snapshot={})
    store.conclude("fid-1", verdict="fixed")

    follow_up = store.follow_up("fid-1", question="还在跑吗？")

    assert follow_up.round == 2
    assert follow_up.verdict == ""
    # 追问轮只能记录，不能携带结论
    with pytest.raises(RetestConflictError):
        store.conclude("fid-1", verdict="reproduced")
    assert store.history("fid-1")[0].verdict == "fixed"


def test_stop_orphans_stamps_abandoned_runs_as_stopped(tmp_path):
    store = RetestStore(tmp_path)
    store.start("fid-1", snapshot={})
    store.start("fid-2", snapshot={})

    stamped = store.stop_orphans()

    assert sorted(stamped) == ["fid-1", "fid-2"]
    assert store.active("fid-1") is None
    assert store.history("fid-1")[0].status is RetestStatus.STOPPED
    # 不自动重放：sweep 过之后再扫没有新东西
    assert store.stop_orphans() == []


def test_history_survives_a_reopen(tmp_path):
    RetestStore(tmp_path).start("fid-1", snapshot={"title": "x"})

    reopened = RetestStore(tmp_path)
    history = reopened.history("fid-1")

    assert [r.round for r in history] == [1]
    assert history[0].snapshot == {"title": "x"}


def test_corrupt_store_file_is_named_not_silently_emptied(tmp_path):
    store = RetestStore(tmp_path)
    store.start("fid-1", snapshot={})
    path = next(tmp_path.glob("*.json"))
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(RetestStoreCorruptError) as excinfo:
        store.history("fid-1")

    assert str(path) in str(excinfo.value)


def test_store_is_content_addressed_by_a_sanitised_finding_id(tmp_path):
    store = RetestStore(tmp_path)
    record = store.start("../../etc/passwd", snapshot={})

    written = list(tmp_path.glob("*.json"))
    assert len(written) == 1
    assert written[0].parent == tmp_path
    assert ".." not in written[0].name
    assert store.history("../../etc/passwd")[0].retest_id == record.retest_id
    payload = json.loads(written[0].read_text(encoding="utf-8"))
    assert payload["records"][0]["retest_id"] == record.retest_id
