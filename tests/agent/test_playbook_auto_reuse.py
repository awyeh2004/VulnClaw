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


class TestTheFingerprintGateActuallyRedacts:
    """Why a green test above did NOT catch the broken gate.

    The old rule was `len(inner) > 12 -> fingerprint, else keep the match unchanged`.
    The test above uses a SIXTEEN-character body, which lands on the passing side of
    that boundary -- so the gate looked fine while every flag body of 12 characters or
    fewer was written to disk in full. Measured on the playbooks real runs produced on
    2026-09-23: 7 of 10 real flag shapes leaked, including `flag{222441144222}` (the
    flag submitted and ACCEPTED that day) and every `CTF2{...}`.
    """

    @pytest.mark.parametrize(
        "flag",
        [
            "flag{222441144222}",       # 12 chars: the boundary that leaked
            "flag{0123456789ab}",       # 12 chars
            "flag{0123456789abc}",      # 13 chars: just over the old boundary
            "flag{abcd}",               # 4 chars
            "flag{abcd1234}",           # 8 chars
            "flag{this_Is_a_EaSyRe}",   # 16 chars: the case that did pass
        ],
    )
    def test_no_body_length_is_written_in_full(self, flag):
        out = pb._fingerprint_flags(f"CONFIRMED: {flag} (accepted)")
        assert flag not in out, f"{flag} survived the hygiene gate"
        assert "…" in out

    @pytest.mark.parametrize(
        "flag",
        [
            # The platform this tool drives. `CTF{}` cannot cover it: `CTF2{` has a "2"
            # where the brace would have to be, so the old two-name copy never matched.
            "CTF2{9f113b92-cb26-424a-8003-aa8ef322e092}",
            "DASCTF{abcdef123456}",
            "BUUCTF{abcdef123456}",
            "NSSCTF{abcd-1234-ef56}",
            "CTFshow{abcdef123456}",
            "ISCTF{abcdef123456}",
        ],
    )
    def test_platform_prefixes_are_redacted_too(self, flag):
        out = pb._fingerprint_flags(flag)
        assert flag not in out, f"{flag} is not covered by the redaction regex"
        assert "…" in out

    def test_it_still_leaves_ordinary_prose_alone(self):
        text = "the service returned 200 and a JSON body"
        assert pb._fingerprint_flags(text) == text

    def test_the_regex_is_derived_from_the_one_canonical_list(self):
        """A fourth hand-maintained copy of the prefix list must not be expressible."""
        from vulnclaw.agent.ctf_mode import FLAG_PREFIX_NAMES

        for name in FLAG_PREFIX_NAMES:
            assert pb._fingerprint_flags(f"{name}{{abcdefghijkl}}") != f"{name}{{abcdefghijkl}}", name

    def test_adding_a_name_to_the_canonical_list_is_honoured(self, monkeypatch):
        """The gate reads the shared tuple, so this file cannot drift behind it."""
        import vulnclaw.agent.ctf_mode as ctf_mode

        monkeypatch.setattr(pb, "FLAG_PREFIX_NAMES", (*ctf_mode.FLAG_PREFIX_NAMES, "NEWPREFIX"))
        monkeypatch.setattr(
            pb,
            "_FLAG_FINGERPRINT_RE",
            __import__("re").compile(
                "(" + "|".join(__import__("re").escape(n) for n in pb.FLAG_PREFIX_NAMES)
                + r")\{([^{}]{1,80})\}",
                __import__("re").IGNORECASE,
            ),
        )
        assert "NEWPREFIX{abcdefghijkl}" not in pb._fingerprint_flags("NEWPREFIX{abcdefghijkl}")


def test_save_playbook_redacts_before_writing(tmp_playbooks):
    """The gate has to work on the model-initiated path too, not only capture_run_notes."""
    ack = pb.save_playbook(
        name="maze",
        fingerprint="fp",
        steps="LOCK: 5x5 maze.\nCONFIRMED: flag = flag{222441144222} accepted.\n" + "x" * 80,
        status="validated",
    )
    assert "error" not in ack, ack
    stored = (tmp_playbooks / f"{ack['slug']}.md").read_text(encoding="utf-8")
    assert "flag{222441144222}" not in stored
    assert "flag{2224…4222}" in stored


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
