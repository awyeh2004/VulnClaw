"""Deterministic playbook reuse: auto-capture + auto-injection.

Covers the solve loop's code-guaranteed knowledge persistence — capture_run_notes
must distill blackboard conclusions into a quality-gate-compliant draft without
any model initiative, and target_fingerprint must re-find it on the next run.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent import playbook as pb
from vulnclaw.agent.blackboard import Blackboard


@pytest.fixture()
def tmp_playbooks(monkeypatch, tmp_path):
    """Isolate PLAYBOOKS_DIR so tests never touch the real store."""
    d = tmp_path / "playbooks"
    d.mkdir()
    monkeypatch.setattr(pb, "PLAYBOOKS_DIR", d)
    return d


def _seed_blackboard() -> Blackboard:
    bb = Blackboard()
    bb.set_lock("Heap UAF on user description pointer; flag in /flag")
    f = bb.create_fact("puts@got leak yields libc base", evidence_ref="e001")
    bb.confirm_fact(f.id)
    a = bb.create_angle("bruteforce canary")
    bb.miss_angle(a.id)
    b = bb.create_angle("overwrite desc ptr to leak libc")
    bb.hit_angle(b.id)
    return bb


def test_capture_creates_gate_compliant_draft(tmp_playbooks):
    bb = _seed_blackboard()
    ack = pb.capture_run_notes(
        target="E:\\vulnclaw\\work\\babyfengshui\\challenge.elf",
        goal="pwn the heap challenge",
        blackboard=bb,
        outcome="no path found",
    )
    assert ack is not None and "error" not in ack
    assert ack["status"] == "draft"
    stored = (tmp_playbooks / f"{ack['slug']}.md").read_text(encoding="utf-8")
    for heading in ("LOCK:", "CONFIRMED:", "ANGLES:"):
        assert heading in stored
    assert "[miss] bruteforce canary" in stored
    assert "[hit] overwrite desc ptr to leak libc" in stored


def test_capture_empty_blackboard_returns_none(tmp_playbooks):
    assert (
        pb.capture_run_notes(
            target="http://x", goal="g", blackboard=Blackboard(), outcome="fail"
        )
        is None
    )
    assert (
        pb.capture_run_notes(target="http://x", goal="g", blackboard=None) is None
    )


def test_capture_is_cover_update(tmp_playbooks):
    bb = _seed_blackboard()
    first = pb.capture_run_notes(
        target="http://t/", goal="g", blackboard=bb, outcome="a"
    )
    bb.create_fact("another confirmed insight")
    second = pb.capture_run_notes(
        target="http://t/", goal="g", blackboard=bb, outcome="b"
    )
    assert first is not None and second is not None
    assert first["slug"] == second["slug"]  # same target -> same slug
    autos = [p for p in tmp_playbooks.iterdir() if p.name.startswith("autonotes")]
    assert len(autos) == 1


def test_capture_fingerprints_full_flags(tmp_playbooks):
    bb = Blackboard()
    bb.set_lock("flag lives in /flag")
    f = bb.create_fact(
        "retrieved flag{abcdefghijklmnop} from the service", evidence_ref="e1"
    )
    bb.confirm_fact(f.id)
    ack = pb.capture_run_notes(
        target="http://t/", goal="g", blackboard=bb, outcome="solved"
    )
    assert ack is not None
    stored = (tmp_playbooks / f"{ack['slug']}.md").read_text(encoding="utf-8")
    assert "flag{abcdefghijklmnop}" not in stored
    assert "flag{abcd…mnop}" in stored


def test_target_fingerprint_stable_for_binary(tmp_path):
    binary = tmp_path / "chall.elf"
    binary.write_bytes(b"\x7fELF" + b"A" * 64)
    fp1 = pb.target_fingerprint(str(binary), "pwn it")
    fp2 = pb.target_fingerprint(str(binary), "pwn it")
    assert fp1 == fp2 and "sha256:" in fp1
    binary.write_bytes(b"\x7fELF" + b"B" * 64)
    assert pb.target_fingerprint(str(binary), "pwn it") != fp1


def test_auto_lookup_roundtrip(tmp_playbooks):
    bb = _seed_blackboard()
    target = "E:\\vulnclaw\\work\\babyfengshui\\challenge.elf"
    pb.capture_run_notes(target=target, goal="pwn the heap", blackboard=bb)
    hits = pb.lookup_playbook(pb.target_fingerprint(target, "pwn the heap"), limit=2)
    assert hits, "next run must find the captured notes"
    assert hits[0]["name"].startswith("AutoNotes")
    assert hits[0]["status"] == "draft"


def test_solver_prompt_injects_prior_brief():
    from vulnclaw.agent.solver import _system_prompt

    class _RT:
        prior_playbook_brief = "\n\n# Prior-run notes for this exact target\n- x"

    class _Agent:
        runtime = _RT()

    class _State:
        goal = "capture the flag"
        origin = "http://target"

    prompt = _system_prompt(_Agent(), _State())
    assert "Prior-run notes for this exact target" in prompt


def test_lock_quality_gate_rejects_vague(tmp_playbooks):
    from vulnclaw.agent.blackboard import Blackboard as BB

    bb = BB()
    assert bb.set_lock("unknown") is None            # placeholder
    assert bb.set_lock("no idea yet") is None        # too short/few words
    node = bb.set_lock("heap UAF on user description pointer; flag at /flag")
    assert node is not None


def test_capture_synthesizes_lock_from_final_answer(tmp_playbooks):
    # Blackboard-avoidant run (0 usage) but completed: notes must not be empty.
    ack = pb.capture_run_notes(
        target="E:/x/challenge.elf",
        goal="pwn it and capture the flag",
        blackboard=None,
        outcome="solved",
        status="validated",
        final_answer="Flag CTF2{xxxx} — heap UAF on description pointer, "
        "libc leak via puts@got, system over free hook, /bin/sh desc trigger",
    )
    assert ack is not None and "error" not in ack
    stored = (tmp_playbooks / f"{ack['slug']}.md").read_text(encoding="utf-8")
    assert "LOCK: (from final answer)" in stored


def test_capture_still_none_when_nothing_at_all(tmp_playbooks):
    # Mid-run capture on an avoidant run: no board, no final answer yet.
    assert (
        pb.capture_run_notes(
            target="http://t/", goal="g", blackboard=None, outcome="in progress"
        )
        is None
    )
