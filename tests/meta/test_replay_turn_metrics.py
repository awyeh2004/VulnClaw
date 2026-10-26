"""scripts/replay_turn_metrics.py: both log generations parse (audit item B)."""

from __future__ import annotations

from pathlib import Path

from scripts.replay_turn_metrics import main, replay_file


def _write(path: Path, records: list[dict]) -> Path:
    import json

    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records),
        encoding="utf-8",
    )
    return path


def test_telemetry_generation_is_prefered(tmp_path):
    log = _write(
        tmp_path / "t.events.ndjson",
        [
            {"kind": "turn_metrics", "step": 1, "chars": 100, "printable_ratio": 0.9,
             "nonempty_lines": 3, "tools_used": 2, "new_evidence": 1},
            {"kind": "turn_metrics", "step": 2, "chars": 50, "printable_ratio": 0.5,
             "nonempty_lines": 1, "tools_used": 0, "new_evidence": 0},
            # Older-generation records present too: must be ignored once
            # telemetry exists, not mixed in.
            {"kind": "agent_observation", "step": 3, "reason": "x", "tools": ["a"]},
            {"kind": "completed"},
        ],
    )
    report = replay_file(log)
    assert report["telemetry"] is True
    assert report["completed"] is True
    assert [s["tools"] for s in report["steps"]] == [2, 0]
    assert report["zero_tool_streak"] == 1


def test_proxy_generation_is_marked_as_proxy(tmp_path):
    log = _write(
        tmp_path / "p.events.ndjson",
        [
            {"kind": "agent_step", "step": 1},
            {"kind": "agent_observation", "step": 1, "reason": "hello world",
             "tools": ["t1", "t2"], "evidence": "e001: x"},
            {"kind": "agent_observation", "step": 2, "reason": "",
             "tools": []},
        ],
    )
    report = replay_file(log)
    assert report["telemetry"] is False
    assert report["proxy"] is True
    assert report["steps"][0]["proxy"] is True
    assert report["steps"][0]["printable_ratio"] == 1.0
    assert report["steps"][1]["tools"] == 0


def test_cli_reports_verdict_when_no_telemetry(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write(
        tmp_path / "x.events.ndjson",
        [{"kind": "agent_observation", "step": 1, "reason": "r", "tools": []}],
    )
    rc = main([str(tmp_path / "*.events.ndjson")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "0 with real turn_metrics" in out
    assert "cannot be evaluated from proxy rows" in out
