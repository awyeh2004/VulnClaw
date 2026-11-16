"""The negated-hypothesis detector must find real conflicts and nothing else.

Its whole purpose is to decide, from recorded runs rather than from anecdotes,
whether a "conclusion contradicts later proof" gate is worth building. A
detector that also fires on shell output would answer that question wrongly in
the expensive direction (build a gate that rejects good runs), so the negative
cases here matter as much as the positive one.

The positive fixture is the real ezphp sequence: a candidate fact declared the
Redis session un-forgeable, then a later fact recorded HTTP 500 from a forged
serialised value — the proof that the path works.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "detect_negated_hypotheses.py"


@pytest.fixture(scope="module")
def detector():
    import sys

    spec = importlib.util.spec_from_file_location("detect_negated_hypotheses", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # dataclasses resolves annotations through sys.modules[cls.__module__]; a
    # module that is never registered makes every @dataclass in it fail with a
    # bare AttributeError on None. Register before executing.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def _session(tmp_path: Path, evidence: list[tuple[str, str]]) -> Path:
    payload = {
        "agent_state": {
            "evidence": [
                {"created_at": stamp, "content": body} for stamp, body in evidence
            ]
        }
    }
    path = tmp_path / "session.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_finds_the_ezphp_conflict(detector, tmp_path):
    path = _session(
        tmp_path,
        [
            (
                "2026-10-31T15:50:25",
                "[blackboard] fact n2 candidate: PHP session handler is Redis: "
                "value 'encrypted_session_data|s:388:...' is tamper-protected, so "
                "session forging is not viable without config secret.",
            ),
            (
                "2026-10-31T15:58:41",
                '[blackboard] fact n8 candidate: PHP session data is unserialized '
                'from Redis: writing PHPREDIS_SESSION:<sid> value '
                '\'encrypted_session_data|O:8:"stdClass":0:{}\' yields HTTP 500 '
                "(TypeError) — confirms PHP object injection.",
            ),
        ],
    )

    hits = detector.scan_session(path)

    assert len(hits) == 1
    assert "not viable" in hits[0].negative_text
    assert "confirms" in hits[0].positive_text


def test_ignores_shell_output_that_merely_contains_a_negative_word(detector, tmp_path):
    """The false-positive shape: a command string, not a conclusion."""
    path = _session(
        tmp_path,
        [
            (
                "2026-10-31T12:39:31",
                "[blackboard] LOCK set (n1): model_B.bin is unrelated noise.",
            ),
            (
                "2026-10-31T13:01:56",
                "Command: $ErrorActionPreference='SilentlyContinue' foreach($p in "
                '@("E:\\work\\x.md")){ $t=[IO.File]::ReadAllText($p) }  # model_B works',
            ),
        ],
    )

    assert detector.scan_session(path) == []


def test_ignores_blackboard_text_smuggled_inside_a_command_dump(detector, tmp_path):
    """A dumped file that *mentions* "[blackboard]" is still not a board write.

    NeuronShuffle piped a knowledge file through PowerShell; that file's own
    text contains the marker, so a substring test turned command output into a
    phantom blackboard statement.
    """
    path = _session(
        tmp_path,
        [
            (
                "2026-10-31T12:39:31",
                "[blackboard] LOCK set (n1): model_B.bin is unrelated noise.",
            ),
            (
                "2026-10-31T13:01:56",
                'Command: Get-Content notes.md\nOutput: "saw [blackboard] fact '
                'n9 CONFIRMED: model_B works"',
            ),
        ],
    )

    assert detector.scan_session(path) == []


def test_a_conflict_must_run_forward_in_time(detector, tmp_path):
    """Proof recorded BEFORE the dismissal is not a contradiction of it."""
    path = _session(
        tmp_path,
        [
            (
                "2026-10-31T10:00:00",
                '[blackboard] fact n1 CONFIRMED: forged value yields HTTP 500 and '
                "confirms object injection.",
            ),
            (
                "2026-10-31T11:00:00",
                "[blackboard] fact n2 candidate: session forging is not viable.",
            ),
        ],
    )

    assert detector.scan_session(path) == []


def test_requires_enough_shared_subject(detector, tmp_path):
    """A negative about one subject and proof about another is not a conflict."""
    path = _session(
        tmp_path,
        [
            (
                "2026-10-31T10:00:00",
                "[blackboard] fact n1 candidate: whole-file XOR keys are ruled out.",
            ),
            (
                "2026-10-31T11:00:00",
                '[blackboard] fact n2 CONFIRMED: challenge brief is '
                '{"name": "ELFStudy", "points": 1000}.',
            ),
        ],
    )

    hits = detector.scan_session(path)
    # Overlap is at most a stray word; the default min-overlap filter drops it.
    assert all(hit.overlap < 2 for hit in hits)


def test_garbage_session_file_is_skipped_not_fatal(detector, tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")

    assert detector.scan_session(path) == []


def test_cli_reports_zero_on_empty_dir(detector, tmp_path):
    assert detector.main(["--sessions", str(tmp_path)]) == 0


def test_cli_errors_on_missing_dir(detector, tmp_path):
    assert detector.main(["--sessions", str(tmp_path / "nope")]) == 2