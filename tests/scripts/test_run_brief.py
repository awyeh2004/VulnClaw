"""The run brief must condense a run without pretending to judge it.

Motivation, measured 2026-11-17 on the oldsvr run: the facts a reviewer needs were
in none of the obvious places.

* ``final_answer`` and ``compact_summary`` were empty — the run died on
  ``token budget exhausted``, which writes neither.
* ``events/events.jsonl`` held 5 lines (run_created + checkpoints), no trajectory.
* All 148 evidence records, 162 tool calls and 17 steps lived only in
  ``targets/<key>/state/current.json``.

The collector is therefore judged on two things: it reads that state file
correctly, and every statement it emits is a count or a quoted string — never a
conclusion. A tool that guessed would launder its guess into evidence for the
review, which is the failure mode this whole workflow exists to avoid.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "run_brief.py"


@pytest.fixture(scope="module")
def brief_mod():
    spec = importlib.util.spec_from_file_location("run_brief", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def _make_run(
    root: Path,
    name: str = "20261117T000000Z-solve-demo",
    *,
    goal: str = "find the bug",
    tool_calls: int = 3,
    evidence: int = 3,
    claims: int = 0,
    pinned: int = 0,
    complete_reason: str = "",
    completed: bool = False,
    final_answer: str = "",
    flag_token: str = "",
) -> Path:
    run = root / name
    (run / "targets" / "abc123").mkdir(parents=True, exist_ok=True)
    (run / "run.json").write_text(
        json.dumps(
            {
                "run_name": name,
                "status": "completed",
                "started_at": "2026-11-17T00:00:00Z",
                "targets": [{"canonical": "10.0.0.1:1883"}],
            }
        ),
        encoding="utf-8",
    )
    ev = [
        {
            "id": f"e{i:03d}",
            "tool": "fetch" if i % 2 else "python_execute",
            "content": f"output {i}" + (f" {flag_token}" if flag_token and i == 1 else ""),
            "summary": "s",
        }
        for i in range(1, evidence + 1)
    ]
    calls = [
        {
            "tool": "fetch" if i % 2 else "python_execute",
            "key_args": '{"url": "http://10.0.0.1:1883/x"}',
            "evidence_id": f"e{i:03d}",
            "ok": True,
        }
        for i in range(1, tool_calls + 1)
    ]
    (run / "targets" / "abc123" / "state").mkdir(parents=True, exist_ok=True)
    (run / "targets" / "abc123" / "state" / "current.json").write_text(
        json.dumps(
            {
                "agent_state": {
                    "goal": goal,
                    "completed": completed,
                    "complete_reason": complete_reason,
                    "verified_claims": [{"claim": "c"}] * claims,
                    "pinned_facts": [{"text": "f"}] * pinned,
                    "evidence": ev,
                    "tool_calls": calls,
                    "steps": [{"index": 1, "reason": "", "observation": ""}],
                    "final_answer": final_answer,
                    "compact_summary": "",
                },
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    return run


def test_reads_counts_from_the_state_file(brief_mod, tmp_path):
    run = _make_run(tmp_path, tool_calls=12, evidence=9, claims=2, pinned=3)

    brief = brief_mod.build_brief(run)

    assert brief.tool_calls == 12
    assert brief.evidence == 9
    assert brief.steps == 1
    assert brief.verified_claims == 2
    assert brief.pinned_facts == 3
    assert brief.target == "10.0.0.1:1883"


def test_empty_blackboard_after_a_long_run_is_flagged(brief_mod, tmp_path):
    """The 2026-11-17 shape: 162 calls, nothing written down."""
    run = _make_run(tmp_path, tool_calls=162, evidence=148, claims=0, pinned=0)

    brief = brief_mod.build_brief(run)

    assert brief.empty_blackboard is True
    assert any("0 verified claims" in note for note in brief.health)


def test_short_run_with_no_claims_is_not_flagged(brief_mod, tmp_path):
    """A 3-call run has not had the chance to conclude; saying otherwise is noise."""
    run = _make_run(tmp_path, tool_calls=3, evidence=3, claims=0, pinned=0)

    brief = brief_mod.build_brief(run)

    assert brief.empty_blackboard is True  # the fact is still true
    assert not any("0 verified claims" in note for note in brief.health)


def test_budget_exhaustion_is_named_as_such(brief_mod, tmp_path):
    run = _make_run(
        tmp_path,
        complete_reason="token budget exhausted: 6305234 tokens used > 6000000",
        completed=False,
    )

    brief = brief_mod.build_brief(run)

    assert brief.spent_budget is True
    assert any("token budget" in note for note in brief.health)


def test_missing_final_answer_is_reported_not_hidden(brief_mod, tmp_path):
    run = _make_run(tmp_path)

    text = brief_mod.render_text(brief_mod.build_brief(run))

    assert "recorded no conclusion" in text


def test_run_status_and_task_completion_are_reported_separately(brief_mod, tmp_path):
    """run.json status is about the process; agent_state.completed is about the task.

    A run that burns its budget exits cleanly with completed=False. Showing only
    one number invites the wrong reading.
    """
    run = _make_run(tmp_path, completed=False, complete_reason="token budget exhausted")

    text = brief_mod.render_text(brief_mod.build_brief(run))

    assert "run=completed" in text
    assert "task_completed=False" in text


def test_tool_histogram_is_ordered_by_frequency(brief_mod, tmp_path):
    run = _make_run(tmp_path, tool_calls=10, evidence=10)

    brief = brief_mod.build_brief(run)

    counts = [t.calls for t in brief.tools]
    assert counts == sorted(counts, reverse=True)
    assert sum(counts) == 10


def test_hosts_are_recovered_from_recorded_arguments(brief_mod, tmp_path):
    """The reviewer needs "what did it aim at", not "what did it receive"."""
    run = _make_run(tmp_path, tool_calls=2, evidence=2)

    brief = brief_mod.build_brief(run)

    assert brief.distinct_targets_probed == ["10.0.0.1"]


def test_flag_shaped_tokens_are_surfaced_without_a_verdict(brief_mod, tmp_path):
    """Reported, not filtered: on CMB eight such tokens were all noise."""
    run = _make_run(tmp_path, flag_token="flag{deadbeef1234}")

    brief = brief_mod.build_brief(run)

    tokens = [item["token"] for item in brief.flag_shaped]
    assert "flag{deadbeef1234}" in tokens
    assert any("unverified" in line for line in brief_mod.render_text(brief).splitlines())


def test_template_flags_are_labelled_not_dropped(brief_mod, tmp_path):
    """A source template and a real value must both appear, and be distinguishable.

    Measured 2026-11-17 on NeuronShuffle: the brief listed ``flag{body}``,
    ``flag{5c2aabdc...}`` and ``flag{"+body+"}`` together. Filtering by shape
    alone would have thrown away the real one or kept the templates.
    """
    run = _make_run(tmp_path, flag_token='flag{body} flag{"+body+"} flag{5c2aabdc937513bde1ba502f14cc51b6}')

    brief = brief_mod.build_brief(run)

    by_token = {item["token"]: item["kind"] for item in brief.flag_shaped}
    assert by_token.get("flag{body}") == "template"
    assert by_token.get('flag{"+body+"}') == "template"
    assert by_token.get("flag{5c2aabdc937513bde1ba502f14cc51b6}") == "value"


def test_rendered_lines_carry_the_label(brief_mod, tmp_path):
    run = _make_run(tmp_path, flag_token="flag{body} flag{c0ffee1234}")

    text = brief_mod.render_text(brief_mod.build_brief(run))

    assert "[template]" in text
    assert "[value   ]" in text


def test_log_signals_are_counted(brief_mod, tmp_path):
    run = _make_run(tmp_path)
    log = tmp_path / "solve.log"
    log.write_text(
        "Path stall: 6 turns with no new confirmed fact\n"
        "Traceback (most recent call last):\n"
        "Traceback (most recent call last):\n"
        "token budget exhausted\n",
        encoding="utf-8",
    )

    brief = brief_mod.build_brief(run, log)

    assert brief.log_signals["path_stall"] == 1
    assert brief.log_signals["traceback"] == 2
    assert brief.log_signals["token_budget"] == 1


def test_stdlib_shadowing_in_the_log_is_called_out(brief_mod, tmp_path):
    run = _make_run(tmp_path)
    log = tmp_path / "solve.log"
    log.write_text("AttributeError: module 'dis' has no attribute 'COMPILER_FLAG_NAMES'", encoding="utf-8")

    brief = brief_mod.build_brief(run, log)

    assert brief.log_signals.get("shadowing") == 1
    assert any("stdlib-shadowing" in note for note in brief.health)


def test_last_thinking_block_is_extracted_verbatim(brief_mod, tmp_path):
    """The only place a misread premise appears — it never reaches the blackboard."""
    run = _make_run(tmp_path)
    log = tmp_path / "solve.log"
    log.write_text(
        "<thinking>\nfirst\n</thinking>\n...\n<thinking>\nthe operator knows the password\n</thinking>\n",
        encoding="utf-8",
    )

    brief = brief_mod.build_brief(run, log)

    assert "the operator knows the password" in brief.last_thinking
    assert "first" not in brief.last_thinking


def test_missing_state_file_degrades_gracefully(brief_mod, tmp_path):
    run = tmp_path / "empty-run"
    (run / "targets").mkdir(parents=True)
    (run / "run.json").write_text("{}", encoding="utf-8")

    brief = brief_mod.build_brief(run)

    assert brief.tool_calls == 0
    assert any("nothing to review" in note for note in brief.health)


def test_broken_json_does_not_raise(brief_mod, tmp_path):
    run = tmp_path / "broken"
    (run / "targets" / "k" / "state").mkdir(parents=True)
    (run / "run.json").write_text("{not json", encoding="utf-8")
    (run / "targets" / "k" / "state" / "current.json").write_text("{also bad", encoding="utf-8")

    brief = brief_mod.build_brief(run)

    assert brief.tool_calls == 0


def test_largest_target_state_wins(brief_mod, tmp_path):
    """Multi-target runs: the reviewer wants the one with content."""
    run = _make_run(tmp_path, tool_calls=5, evidence=5)
    small = run / "targets" / "tiny" / "state"
    small.mkdir(parents=True)
    (small / "current.json").write_text('{"agent_state": {}}', encoding="utf-8")

    brief = brief_mod.build_brief(run)

    assert brief.tool_calls == 5


def test_json_output_is_serialisable(brief_mod, tmp_path):
    run = _make_run(tmp_path, tool_calls=4, evidence=4)

    payload = brief_mod.brief_to_dict(brief_mod.build_brief(run))

    assert json.loads(json.dumps(payload))["tool_calls"] == 4


def test_cli_rejects_a_missing_directory(brief_mod, tmp_path):
    assert brief_mod.main([str(tmp_path / "nope")]) == 2


def test_cli_requires_a_target(brief_mod, capsys):
    with pytest.raises(SystemExit):
        brief_mod.main([])

# ── --latest must find runs wherever they actually live ─────────────────────
#
# Measured 2026-11-17: a run that had just finished was reported "not found",
# because `--latest` only looked at ~/.vulnclaw/runs while `session.solve_work_root`
# had moved runs to E:\vulnclaw\work\runs. Re-implementing the config precedence
# here would drift; scanning both is cheaper and stays correct.


def test_latest_scans_the_solve_work_root(brief_mod, tmp_path, monkeypatch):
    work_root = tmp_path / "work"
    (work_root / "runs").mkdir(parents=True)
    run = _make_run(work_root / "runs", name="20261117T120000Z-solve-work-root")

    monkeypatch.setattr(brief_mod, "_solve_work_root", lambda: work_root)
    monkeypatch.setenv("VULNCLAW_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.delenv("VULNCLAW_RUNS_DIR", raising=False)

    found = brief_mod._latest_anywhere("", "")

    assert found == run


def test_latest_picks_the_globally_newest_across_roots(brief_mod, tmp_path, monkeypatch):
    work_root = tmp_path / "work"
    (work_root / "runs").mkdir(parents=True)
    (tmp_path / "cfg" / "runs").mkdir(parents=True)
    _make_run(tmp_path / "cfg" / "runs", name="20261117T100000Z-solve-old")
    newer = _make_run(work_root / "runs", name="20261117T130000Z-solve-new")

    monkeypatch.setattr(brief_mod, "_solve_work_root", lambda: work_root)
    monkeypatch.setenv("VULNCLAW_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.delenv("VULNCLAW_RUNS_DIR", raising=False)

    assert brief_mod._latest_anywhere("", "") == newer


def test_latest_orders_by_recorded_start_time_not_name(brief_mod, tmp_path, monkeypatch):
    """Directory names are truncated; `started_at` is not.

    Two runs of the same target in the same second collide in name space, so the
    ordering has to come from the recorded timestamp when it is present.
    """
    root = tmp_path / "runs"
    (root).mkdir(parents=True)
    older = _make_run(root, name="20261117T120000Z-solve-a")
    newer = _make_run(root, name="20261117T110000Z-solve-b")
    # Rewrite run.json so the *timestamps* order opposite to the names.
    (older / "run.json").write_text(
        json.dumps({"run_name": older.name, "started_at": "2026-11-17T09:00:00Z",
                    "targets": [{"canonical": "x"}]}), encoding="utf-8")
    (newer / "run.json").write_text(
        json.dumps({"run_name": newer.name, "started_at": "2026-11-17T19:00:00Z",
                    "targets": [{"canonical": "x"}]}), encoding="utf-8")

    monkeypatch.setattr(brief_mod, "_solve_work_root", lambda: root.parent)
    monkeypatch.setenv("VULNCLAW_RUNS_DIR", str(root))
    monkeypatch.delenv("VULNCLAW_CONFIG_DIR", raising=False)

    assert brief_mod._latest_anywhere("", "") == newer


def test_candidate_roots_are_deduplicated(brief_mod, tmp_path, monkeypatch):
    monkeypatch.setenv("VULNCLAW_RUNS_DIR", str(tmp_path / "same"))
    monkeypatch.setenv("VULNCLAW_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(brief_mod, "_solve_work_root", lambda: tmp_path)

    roots = brief_mod._candidate_roots("")

    assert len(roots) == len({str(p).lower() for p in roots})


def test_missing_config_does_not_break_latest(brief_mod, tmp_path, monkeypatch):
    """`-I` runs against arbitrary directories: config is a convenience."""
    def _boom():
        raise RuntimeError("no config here")

    monkeypatch.setattr(brief_mod, "_solve_work_root", brief_mod._solve_work_root)
    monkeypatch.setenv("VULNCLAW_CONFIG_DIR", str(tmp_path / "nonexistent"))
    monkeypatch.delenv("VULNCLAW_RUNS_DIR", raising=False)

    # Must not raise even though nothing is configured.
    roots = brief_mod._candidate_roots("")
    assert roots


def test_log_signals_count_both_chinese_and_english_markers(brief_mod, tmp_path):
    """TeeStreamSink writes Chinese; the runner's diagnostics are English.

    Counting only one means the tool under-reports depending on which sink
    produced the log — the 2026-11-17 NeuronShuffle transcript scored zero tool
    calls until both spellings matched.
    """
    run = _make_run(tmp_path)
    log = tmp_path / "solve.log"
    log.write_text(
        "→ 调用工具: python_execute {}\n"
        "→ 调用工具: shell_command {}\n"
        "→ tool: fetch {}\n"
        "→ 工具结果:\n[+] ok\n",
        encoding="utf-8",
    )

    brief = brief_mod.build_brief(run, log)

    assert brief.log_signals["tool_call"] == 3
    assert brief.log_signals["tool_result"] == 1


# ── Structured signals: the machine-readable half of the contract ────────────
#
# The review step's whole contribution on oldsvr was noticing "0 claims after 162
# calls" and telling the next round to switch from dictionary search to a prefix
# constraint search. That observation must survive as a field, not a sentence —
# otherwise a different reviewer (another model, a harness, a script) has to parse
# prose to find it.


def test_json_carries_a_schema_version(brief_mod, tmp_path):
    run = _make_run(tmp_path, tool_calls=5, evidence=5)

    payload = brief_mod.brief_to_dict(brief_mod.build_brief(run))

    assert payload["schema_version"] == brief_mod.SCHEMA_VERSION
    assert payload["schema_version"] >= 1


def test_no_conclusions_signal_is_structured(brief_mod, tmp_path):
    run = _make_run(tmp_path, tool_calls=162, evidence=148, claims=0, pinned=0)

    brief = brief_mod.build_brief(run)

    signal = next(s for s in brief.signals if s.id == "no_conclusions")
    assert signal.severity == brief_mod.SEVERITY_HIGH
    assert signal.counts["tool_calls"] == 162
    assert signal.counts["verified_claims"] == 0


def test_budget_exhaustion_is_its_own_signal(brief_mod, tmp_path):
    run = _make_run(tmp_path, complete_reason="token budget exhausted: over", completed=False)

    brief = brief_mod.build_brief(run)

    ids = [s.id for s in brief.signals]
    assert "budget_exhausted" in ids


def test_a_clean_successful_run_emits_no_signals(brief_mod, tmp_path):
    """Nothing to look at is the correct output for a run that worked."""
    run = _make_run(
        tmp_path,
        tool_calls=44,
        evidence=44,
        claims=1,
        pinned=3,
        completed=True,
        complete_reason="verified flag from recorded evidence: flag{x}",
    )

    payload = brief_mod.brief_to_dict(brief_mod.build_brief(run))

    assert payload["signals"] == []


def test_signals_are_sorted_by_severity_in_text(brief_mod, tmp_path):
    run = _make_run(tmp_path, tool_calls=162, evidence=148, complete_reason="token budget exhausted")

    text = brief_mod.render_text(brief_mod.build_brief(run))
    section = text[text.index("SIGNALS"):]

    high = section.index("(high)")
    medium_idx = section.find("(medium)")
    if medium_idx != -1:
        assert high < medium_idx


def test_health_mirrors_signal_messages(brief_mod, tmp_path):
    """The text field is derived, so the two can never disagree."""
    run = _make_run(tmp_path, tool_calls=162, evidence=148, complete_reason="token budget exhausted")

    brief = brief_mod.build_brief(run)

    assert brief.health == [s.message for s in brief.signals]


def test_each_signal_has_an_id_and_severity(brief_mod, tmp_path):
    run = _make_run(tmp_path, tool_calls=162, evidence=148, complete_reason="token budget exhausted")

    for signal in brief_mod.build_brief(run).signals:
        assert signal.id
        assert signal.severity in {
            brief_mod.SEVERITY_HIGH,
            brief_mod.SEVERITY_MEDIUM,
            brief_mod.SEVERITY_INFO,
        }


def test_json_round_trips_through_serialisation(brief_mod, tmp_path):
    run = _make_run(tmp_path, tool_calls=162, evidence=148, complete_reason="token budget exhausted")

    payload = brief_mod.brief_to_dict(brief_mod.build_brief(run))
    restored = json.loads(json.dumps(payload))

    assert restored["signals"][0]["counts"]["tool_calls"] == 162


def test_no_state_signal_is_reported_not_silent(brief_mod, tmp_path):
    run = tmp_path / "empty"
    (run / "targets").mkdir(parents=True)
    (run / "run.json").write_text("{}", encoding="utf-8")

    brief = brief_mod.build_brief(run)

    assert any(s.id == "no_state" for s in brief.signals)
