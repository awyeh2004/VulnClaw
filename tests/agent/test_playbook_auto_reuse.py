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
    # Realistic target on purpose: `http://t/` tokenizes to nothing (the scheme is a stop
    # word), so it is exactly the degenerate shape TestCaptureRefusesToWrite... covers --
    # a fixture that cannot be recalled would make this test about the wrong thing.
    target = "http://direct-ctf2.dasctf.com:27532"
    first = pb.capture_run_notes(
        target=target, goal="pwn the heap", blackboard=bb, outcome="a"
    )
    bb.create_fact("another confirmed insight")
    second = pb.capture_run_notes(
        target=target, goal="pwn the heap", blackboard=bb, outcome="b"
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
        target="http://direct-ctf2.dasctf.com:27532",
        goal="pwn the heap",
        blackboard=bb,
        outcome="solved",
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


class TestNoFieldOfANoteLeaksAFlag:
    """Round-8 finding R8-5: the write-path gate covered `steps` only.

    Measured on HEAD: `save_playbook(name='DASCTF{222441144222aaaa} title', …)` wrote the
    flag into the `name:` frontmatter line AND into the filename slug, while `steps` came
    out fingerprinted. Both surfaces reach a later run -- `format_playbook_list` prints
    the name straight into the prompt, and the slug is how the note is addressed there --
    so the leak reopened exactly the cross-instance resubmission channel the gate exists
    to close. A model marking a note `validated` is holding the flag at that moment; a
    flag in the title is ordinary behaviour, not a contrived payload.
    """

    FLAG = "DASCTF{222441144222aaaa}"

    def _stored(self, tmp_playbooks, ack) -> str:
        return (tmp_playbooks / f"{ack['slug']}.md").read_text(encoding="utf-8")

    def test_the_name_is_fingerprinted(self, tmp_playbooks):
        ack = pb.save_playbook(
            name=f"{self.FLAG} titled note",
            fingerprint="fp",
            steps="LOCK: x\n" + "y" * 80,
            status="validated",
        )
        assert "error" not in ack, ack
        stored = self._stored(tmp_playbooks, ack)
        assert self.FLAG not in stored
        assert "DASCTF{2224…aaaa}" in stored
        assert self.FLAG not in ack["name"]

    def test_the_slug_never_carries_the_flag_body(self, tmp_playbooks):
        ack = pb.save_playbook(
            name=f"{self.FLAG} titled note",
            fingerprint="fp",
            steps="LOCK: x\n" + "y" * 80,
        )
        assert "222441144222aaaa" not in ack["slug"], ack["slug"]
        assert self.FLAG not in " ".join(p.name for p in tmp_playbooks.iterdir())

    def test_a_caller_supplied_slug_is_redacted_too(self, tmp_playbooks):
        """The slug is the filename; a caller can pass one directly."""
        ack = pb.save_playbook(
            name="plain",
            fingerprint="fp",
            slug=f"note-{self.FLAG}",
            steps="LOCK: x\n" + "y" * 80,
        )
        assert "222441144222aaaa" not in ack["slug"], ack["slug"]

    def test_the_fingerprint_field_is_covered(self, tmp_playbooks):
        ack = pb.save_playbook(
            name="plain",
            fingerprint=f"target {self.FLAG} real easy",
            steps="LOCK: x\n" + "y" * 80,
        )
        assert self.FLAG not in self._stored(tmp_playbooks, ack)

    def test_a_note_already_on_disk_is_inert_when_read(self, tmp_playbooks):
        """The write-path fix cannot clean what is already stored -- the read path must.

        Real store, 2026-09-23: notes written before the gate covered their fields still
        have a full flag in the `name:` line, and those are exactly the notes a future run
        loads. Redaction is idempotent, so filtering on read is safe for new notes.
        """
        (tmp_playbooks / "legacy.md").write_text(
            "\n".join(
                [
                    "---",
                    f"name: {self.FLAG} legacy note",
                    "fingerprint: Weblogic CVE-2017-10271 real easy",
                    "status: validated",
                    "source: curated",
                    "---",
                    "",
                    f"LOCK: found {self.FLAG} via wls-wsat",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        note = pb.list_playbooks()[0]
        assert self.FLAG not in note.name
        assert self.FLAG not in note.steps
        rendered = pb.format_playbook_list(
            [{"name": note.name, "slug": note.slug, "status": note.status,
              "score": 1.0, "steps": note.steps}]
        )
        assert self.FLAG not in rendered, "the prompt-facing render must not carry it"

    def test_cover_update_still_matches_a_legacy_cleartext_name(self, tmp_playbooks):
        """A legacy note must be COVERED, not duplicated into a second file.

        Both sides of the comparison are redacted, so `name='DASCTF{…} note'` still finds
        the stored `name: DASCTF{…} note` and rewrites it in place -- which is also what
        cleans that file up.
        """
        (tmp_playbooks / "legacy.md").write_text(
            "\n".join(
                [
                    "---",
                    f"name: {self.FLAG} note",
                    "fingerprint: fp",
                    "status: draft",
                    "source: curated",
                    "---",
                    "",
                    f"LOCK: old body with {self.FLAG}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        ack = pb.save_playbook(
            name=f"{self.FLAG} note",
            fingerprint="fp",
            steps="LOCK: refreshed\n" + "y" * 80,
            status="validated",
        )
        assert ack["slug"] == "legacy", ack
        assert len(list(tmp_playbooks.iterdir())) == 1, "a duplicate note was created"
        stored = self._stored(tmp_playbooks, ack)
        assert self.FLAG not in stored


class TestTheGateDoesNotDependOnKnowingThePlatform:
    """Round-8 finding R8-6: the prefix list is not, and cannot be, a closed set.

    Deriving the regex from `FLAG_PREFIX_NAMES` fixed the DRIFT (three copies had already
    diverged) but not the CLOSURE: the audit named `HGAME{}`, `GWHT{}`, `HTB{}`, `THM{}`,
    `cyberpeace{}`, `0xGame{}` and `ISCC{}` as real platforms missing from it, and the
    shape limits on top leaked two more ways -- a separator spelling (`flag1{`, `flag_{`)
    never matched, and a body longer than 80 characters was stored verbatim.

    The gate is now two-tier: a known platform prefix is redacted whatever its body looks
    like, and an UNKNOWN prefix is redacted when the body looks like flag material. That
    second tier is what makes the list non-load-bearing.

    `FLAG_PREFIX_NAMES` itself is deliberately left alone: it is also the flag-CLAIM
    detection list, where `ctf_mode.GENERIC_FLAG_PATTERN` already covers any `word{...}`,
    so widening it there would change detection, not hygiene.
    """

    @pytest.mark.parametrize(
        "flag",
        [
            "HGAME{abcdef123456}",
            "GWHT{abcdef123456}",
            "HTB{abcdef123456}",
            "THM{abcdef123456}",
            "cyberpeace{abcdef123456}",
            "0xGame{abcdef123456}",          # digit-leading prefix
            "ISCC{abcdef123456}",
            "SomePlatformNobodyHasHeardOf{Y3t_a9ain}",
        ],
    )
    def test_an_unknown_platform_prefix_is_still_redacted(self, flag):
        out = pb._fingerprint_flags(f"CONFIRMED: {flag} accepted")
        assert flag not in out, f"{flag} survived a list-based gate"
        assert "…" in out

    @pytest.mark.parametrize("flag", ["flag1{abcdef123456}", "flag_{abcdef123456}",
                                      "flag2{abcdef123456}", "FLAG_9{abcdef123456}"])
    def test_a_separator_before_the_brace_no_longer_escapes(self, flag):
        assert flag not in pb._fingerprint_flags(flag), flag

    def test_a_body_longer_than_the_old_cap_is_redacted(self):
        """80 was a redaction cap, i.e. a length that made storing a flag acceptable."""
        for size in (81, 120, 199):
            body = ("a1" * 120)[:size]
            flag = f"flag{{{body}}}"
            assert flag not in pb._fingerprint_flags(flag), size

    def test_a_known_prefix_is_redacted_whatever_the_body_looks_like(self):
        """Tier 1 does not consult the body -- a platform flag can be any shape."""
        for flag in ("CTF2{a.b:c}", "flag{hello world}", "DASCTF{!!weird!!}"):
            assert flag not in pb._fingerprint_flags(flag), flag

    @pytest.mark.parametrize(
        "flag",
        [
            "HGAME{abcdefghijklmnop}",       # long, all lowercase, no separator
            "THM{thisisaquiteLongBody}",     # long, no digit either
        ],
    )
    def test_a_lowercase_body_is_still_a_flag_when_it_is_long_enough(self, flag):
        """Some platforms issue all-lowercase flags; length is the tell, not digits."""
        assert flag not in pb._fingerprint_flags(flag), flag

    def test_a_short_unknown_body_is_left_alone_and_that_is_documented(self):
        """The documented limit of tier 2: `GWHT{x}` is kept.

        Redacting every `word{short}` would mangle `if{ready}`-shaped code, and a
        sub-12-character lowercase body is not a submittable flag in any observed format.
        """
        assert pb._fingerprint_flags("GWHT{x}") == "GWHT{x}"
        assert pb._fingerprint_flags("if{ready}") == "if{ready}"
        assert pb._fingerprint_flags("sha256{deadbeef}") == "sha256{deadbeef}"

    @pytest.mark.parametrize(
        "text",
        [
            "the page uses body{color:red} and returns 200",
            "if (x) else{return} nothing",
            "the regex [a-z]{3} matches the token",
            "payload {{7*7}} for the SSTI probe",
            r"python: re.sub(r'\d{4}', '', s)",
            "bash: for i in array{1..10}; do echo $i; done",
            "a plain JSON body {\"k\": \"v\"} in the response",
            "media(min-width:600px){.a{color:red}}",
        ],
    )
    def test_ordinary_code_in_a_note_is_left_alone(self, text):
        """The unknown-prefix tier must not mangle the scripts a note carries."""
        assert pb._fingerprint_flags(text) == text

    def test_redaction_is_idempotent(self):
        """The read path applies it to already-redacted notes; twice must equal once."""
        for flag in ("HGAME{abcdef123456}", "flag1{abcdef123456}", "flag{222441144222}"):
            once = pb._fingerprint_flags(flag)
            assert pb._fingerprint_flags(once) == once, flag


class TestTheNoteIsWrittenAtomically:
    """Round7's out-of-scope finding, still open: `save_playbook` used a bare `write_text`.

    The playbook store is shared across sessions by design (`~/.vulnclaw/playbooks`), and
    `write_text` truncates first and writes through the OS cache: a concurrent
    `list_playbooks` can read a half-written note, and two sessions saving the same slug
    can lose an update. The KB path got the atomic writer in af3c4f2; this one did not.
    """

    STEPS = "LOCK: x\n" + "y" * 80

    def _save(self, **over):
        kwargs = dict(name="maze", fingerprint="fp", steps=self.STEPS, status="validated")
        kwargs.update(over)
        return pb.save_playbook(**kwargs)

    def test_it_goes_through_the_shared_atomic_writer(self, tmp_playbooks, monkeypatch):
        """Structural: a bare `write_text` bypasses the Windows-retry/fsync machinery."""
        seen: list[str] = []
        real = pb.atomic_write_text

        def spy(path, text, **kwargs):
            seen.append(str(path))
            return real(path, text, **kwargs)

        monkeypatch.setattr(pb, "atomic_write_text", spy)
        ack = self._save()
        assert "error" not in ack, ack
        assert seen and seen[0].endswith(f"{ack['slug']}.md"), seen

    def test_a_failed_commit_leaves_the_previous_note_byte_identical(
        self, tmp_playbooks, monkeypatch
    ):
        """The commit point is the rename: a failure before it must change nothing."""
        import pytest

        from vulnclaw.utils import atomic_write

        ack = self._save()
        path = tmp_playbooks / f"{ack['slug']}.md"
        before = path.read_bytes()

        def boom(src, dst):
            raise PermissionError("simulated sharing violation")

        monkeypatch.setattr(atomic_write, "replace_with_retry", boom)
        with pytest.raises(PermissionError):
            self._save(steps="LOCK: rewritten\n" + "z" * 80)

        assert path.read_bytes() == before
        assert [p.name for p in tmp_playbooks.iterdir()] == [path.name], (
            "a failed write must not leave its temp file behind"
        )


class TestTheCollisionSuffixIsStableAcrossProcesses:
    """Round7's other out-of-scope finding: `abs(hash(fingerprint)) % 10000`.

    CPython randomises `str.__hash__` per process (PYTHONHASHSEED), so the disambiguating
    suffix differed between runs of the same input. The store's contract is one file per
    challenge family, updated in place; an unstable suffix turns a collision into a new
    note every time, and the copy then competes with the original in every lookup.

    Measured with two real subprocesses (different PYTHONHASHSEED), because that is the
    only way this property can be observed -- inside one process `hash()` is stable.
    """

    _SCRIPT = """
import sys
from vulnclaw.agent import playbook as pb
ack = pb.save_playbook(name="maze", fingerprint="fp-fixed", steps="LOCK: x\\n" + "y" * 80)
print(ack["slug"])
"""

    def _slug_in_a_fresh_process(self, store, root, seed):
        import os
        import subprocess
        import sys

        env = dict(os.environ, PYTHONHASHSEED=seed, VULNCLAW_CONFIG_DIR=str(store.parent))
        result = subprocess.run(
            [sys.executable, "-c", self._SCRIPT],
            cwd=str(root), env=env, capture_output=True, text=True, encoding="utf-8",
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip().splitlines()[-1]

    def test_two_processes_agree_on_the_suffix(self, tmp_path):
        from pathlib import Path

        root = Path(__file__).resolve().parents[2]
        store = tmp_path / "playbooks"
        store.mkdir(parents=True)
        # Force the collision branch: a file already owns the un-suffixed slug, and its
        # name does NOT match the incoming one (or the cover-update branch would win).
        (store / "maze.md").write_text(
            "---\nname: some other note\nfingerprint: other\nstatus: draft\nsource: curated\n"
            "---\n\nLOCK: other\n",
            encoding="utf-8",
        )

        # Both processes must write to the same path; clear between runs so the second
        # one starts from the same state (otherwise the first run's own file is what it
        # collides with, which is a different assertion).
        first = self._slug_in_a_fresh_process(store, root, "1")
        for extra in store.glob("maze-*.md"):
            extra.unlink()
        second = self._slug_in_a_fresh_process(store, root, "2")

        assert first.startswith("maze-") and second.startswith("maze-")
        assert first == second, (first, second)

    def test_the_suffix_is_a_digest_of_the_fingerprint(self, tmp_path, monkeypatch):
        """Structural: it must not come from `hash()` at all."""
        from hashlib import sha256
        from pathlib import Path

        store = tmp_path / "playbooks"
        store.mkdir(parents=True)
        monkeypatch.setattr(pb, "PLAYBOOKS_DIR", store)
        (store / "maze.md").write_text(
            "---\nname: some other note\nfingerprint: other\nstatus: draft\nsource: curated\n"
            "---\n\nLOCK: other\n",
            encoding="utf-8",
        )

        ack = pb.save_playbook(
            name="maze", fingerprint="fp-fixed", steps="LOCK: x\n" + "y" * 80
        )
        expected = sha256(b"fp-fixed").hexdigest()[:4]
        assert ack["slug"] == f"maze-{expected}", ack
        assert Path(store / f"{ack['slug']}.md").is_file()


class TestASuffixCollisionWidensInsteadOfOverwriting:
    """Round14 F-D: the 4-hex suffix is 16 bits, and the suffixed name was
    written with no further existence check — a second note whose fingerprint
    hashed to the same prefix silently overwrote the first (measured with
    three same-shaped Chinese targets collapsing onto slug "autonotes").
    """

    def test_colliding_fingerprint_lands_on_a_wider_suffix(self, tmp_path, monkeypatch):
        from hashlib import sha256
        from pathlib import Path

        store = tmp_path / "playbooks"
        store.mkdir(parents=True)
        monkeypatch.setattr(pb, "PLAYBOOKS_DIR", store)
        # An earlier ASCII-named note owns the un-suffixed slug, so every
        # Chinese-named note falls into the suffix branch.
        (store / "autonotes.md").write_text(
            "---\nname: AutoNotes\nfingerprint: other\nstatus: draft\nsource: curated\n"
            "---\n\nLOCK: other\n",
            encoding="utf-8",
        )

        first = pb.save_playbook(
            name="AutoNotes 靶机一", fingerprint="fp-alpha", steps="LOCK: x\n" + "y" * 80
        )
        suffix = first["slug"].rsplit("-", 1)[-1]
        assert len(suffix) == 4 and first["slug"] != "autonotes", first
        original = (store / f"{first['slug']}.md").read_bytes()

        # A different fingerprint hashing to the SAME 4-hex prefix: before
        # round14 F-D this note's save overwrote the first one byte-for-byte.
        candidate = "fp-beta-0"
        while sha256(candidate.encode("utf-8")).hexdigest()[:4] != suffix:
            candidate = f"fp-beta-{int(candidate.rsplit('-', 1)[1]) + 1}"
        assert candidate != "fp-alpha"

        second = pb.save_playbook(
            name="AutoNotes 靶机二", fingerprint=candidate, steps="LOCK: y\n" + "z" * 80
        )

        assert second["slug"] != first["slug"], "collision silently overwrote the first note"
        assert (store / f"{first['slug']}.md").read_bytes() == original, (
            "the pre-existing colliding note was overwritten"
        )
        assert Path(store / f"{second['slug']}.md").is_file(), second
        # The widened suffix is still a stable prefix of the same digest, not
        # a random or time-varying tail.
        assert second["slug"].startswith("autonotes-"), second
        assert second["slug"].rsplit("-", 1)[-1].startswith(suffix), second


class TestARefusalSaysWhyItRefused:
    """Round7 L8: three different refusals all returned a bare `None`.

    "This run had nothing to record" and "there WAS a conclusion and the store refused it"
    were the same event for the caller, so a dropped conclusion was indistinguishable from
    an empty run -- and the caller (the solve loop) discarded the result entirely.
    `out_reason` reports it, the same way `lookup_playbook_multi`'s `out_blocked` reports
    the rows its overlap floor withholds.
    """

    def test_nothing_recorded_is_named(self, tmp_playbooks):
        reason: list[str] = []
        ack = pb.capture_run_notes(
            target="http://direct-ctf2.dasctf.com:27532",
            goal="pwn the heap",
            blackboard=None,
            outcome="failed",
            out_reason=reason,
        )
        assert ack is None
        assert reason and "recorded nothing" in reason[0], reason

    def test_an_unrecallable_note_is_named_and_is_a_different_reason(self, tmp_playbooks):
        """The `'E:'` shape: a conclusion existed, but no query could ever find it."""
        from vulnclaw.agent.blackboard import Blackboard

        bb = Blackboard()
        # NOTE the long text: `set_lock` silently ignores a lock that is too short
        # (measured: "flag lives in /flag" is dropped, current_lock() stays None), so a
        # short one here would test the "recorded nothing" branch instead.
        bb.set_lock("Heap UAF on the user description pointer; flag in /flag")
        reason: list[str] = []
        ack = pb.capture_run_notes(
            target="E:",          # a bare drive letter: not hashable, and tokenizes to nothing
            goal="",
            blackboard=bb,
            outcome="solved",
            out_reason=reason,
        )
        assert ack is None
        assert reason and "no query could ever find this note" in reason[0], reason

    def test_a_short_conclusion_is_named(self, tmp_playbooks):
        """A fake board so the short-steps branch is reached deterministically.

        `set_lock`'s own quality rule sits between the too-short and the acceptable lock,
        so a real Blackboard cannot be aimed at this branch reliably.
        """
        from types import SimpleNamespace

        board = SimpleNamespace(
            current_lock=lambda: SimpleNamespace(description="short"),
            confirmed_facts=lambda: [],
            all_nodes=lambda: [],
        )
        reason: list[str] = []
        ack = pb.capture_run_notes(
            target="http://x",
            goal="g",
            blackboard=board,
            out_reason=reason,
        )
        assert ack is None
        assert reason and "too short" in reason[0], reason

    def test_a_successful_capture_reports_no_reason(self, tmp_playbooks):
        bb = Blackboard()
        bb.set_lock("Heap UAF on the user description pointer; flag in /flag")
        reason: list[str] = []
        ack = pb.capture_run_notes(
            target="http://direct-ctf2.dasdctf.com:27532".replace("dasdctf", "dasctf"),
            goal="pwn the heap challenge",
            blackboard=bb,
            outcome="no path found",
            out_reason=reason,
        )
        assert ack is not None and "error" not in ack, ack
        assert reason == []

    def test_existing_callers_are_unaffected(self, tmp_playbooks):
        """`out_reason` is optional: the old call shape must behave exactly as before."""
        assert (
            pb.capture_run_notes(
                target="http://x", goal="g", blackboard=None, outcome="fail"
            )
            is None
        )

    def test_the_solve_loop_surfaces_the_reason_to_the_operator(self, tmp_playbooks):
        """End to end through the real call site: the notice must reach the sink."""
        import inspect

        from vulnclaw.agent import solver

        source = inspect.getsource(solver._solve_impl)
        assert "out_reason=notes_outcome" in source
        assert "no run notes captured" in source


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


class TestEveryNoteCanBeFoundAgain:
    """A note nobody can ever look up is a note that was never written.

    Measured 2026-09-24 on the real home store: `autonotes-babyfengshui-33c3-2016` has the
    stored fingerprint ``'E:'`` -- a bare Windows drive fragment. Its ``tokens()`` is
    therefore EMPTY, so :meth:`Playbook.score` returns 0.0 for every possible query, and
    the note cannot be retrieved by ANY target string (verified against the path it was
    captured on, the file inside it, the bare directory name and an unrelated path --
    12 combinations, all score=0.000). It survives in the store as dead weight and never
    transfers anything, which defeats the module's stated contract ("deterministic
    reuse": the next run of the same challenge finds the note again).

    Nothing in the suite covered this, because the existing roundtrip test captures and
    looks up in the SAME call with a well-formed target. The property worth pinning is
    the one the store actually depends on: what was written must be findable by its own
    recorded fingerprint.
    """

    def test_a_captured_note_is_found_by_its_own_fingerprint(self, tmp_playbooks):
        bb = _seed_blackboard()
        targets = [
            "E:\\vulnclaw\\work\\babyfengshui_33c3_2016",
            "E:\\vulnclaw\\work\\babyfengshui_33c3_2016\\challenge.elf",
            "http://direct-ctf2.dasctf.com:27532",
            "local-7",
        ]
        for target in targets:
            ack = pb.capture_run_notes(
                target=target, goal="capture the flag", blackboard=bb, outcome="solved"
            )
            assert ack is not None and "error" not in ack, ack
            note = next(n for n in pb.list_playbooks() if n.slug == ack["slug"])
            assert note.tokens(), (
                f"captured note {ack['slug']} has an empty fingerprint token set "
                f"({note.fingerprint!r}): it can never be recalled"
            )
            hits = pb.lookup_playbook(note.fingerprint, limit=5)
            assert any(h["slug"] == note.slug for h in hits), (
                f"{ack['slug']} is not found by its own fingerprint {note.fingerprint!r}"
            )

    def test_a_drive_only_fingerprint_cannot_recall_its_note(self, tmp_playbooks):
        """Documents the observed failure shape, so a future fix has a target.

        A bare ``E:`` is the degenerate case: ``_tokenize`` drops it entirely (one
        character), leaving nothing to match on. This test asserts the CURRENT
        behaviour of such a store entry rather than pretending it is fine.
        """
        ack = pb.save_playbook(
            name="AutoNotes babyfengshui_33c3_2016",
            fingerprint="E:",
            steps="LOCK: x\nCONFIRMED: y\nANGLES: z\n" + "pad " * 30,
            status="draft",
            source=pb.SOURCE_AUTO,
        )
        note = next(n for n in pb.list_playbooks() if n.slug == ack["slug"])
        assert note.tokens() == set(), "a bare drive letter carries no token"
        assert note.score(note.fingerprint) == 0.0
        assert pb.lookup_playbook(note.fingerprint, limit=5) == []


class TestCaptureRefusesToWriteANoteNobodyCanRecall:
    """The write side of the same defect: `capture_run_notes` must not store a dead key.

    Measured context (2026-09-24, real home store): the note
    ``autonotes-babyfengshui-33c3-2016`` was captured with ``target='E:'`` and its stored
    fingerprint is exactly that. ``Path('E:').exists()`` is True on Windows while
    ``is_file()`` is False, so a bare drive letter is neither hashed nor rejected --
    ``target_fingerprint`` returns it verbatim and ``_tokenize`` then discards it.

    The rule pinned here: a captured note must be findable by the key it records. When the
    target cannot provide one, the GOAL is allowed to widen it (that keeps a run's confirmed
    conclusions); when neither can, nothing is written.
    """

    def test_a_drive_letter_target_is_widened_with_the_goal(self, tmp_playbooks):
        bb = _seed_blackboard()
        ack = pb.capture_run_notes(
            target="E:",
            goal="babyfengshui_33c3_2016 heap UAF",
            blackboard=bb,
            outcome="solved",
        )
        assert ack is not None, "the conclusions are worth keeping; only the key was broken"
        note = next(n for n in pb.list_playbooks() if n.slug == ack["slug"])
        assert "babyfengshui" in note.fingerprint, note.fingerprint
        assert note.tokens(), "the widened fingerprint must be tokenizable"
        hits = pb.lookup_playbook(note.fingerprint, limit=5)
        assert any(h["slug"] == note.slug for h in hits), "the note must be findable by its own key"
        # and a future run working on the same technique finds it too
        widened = pb.lookup_playbook("babyfengshui_33c3_2016 heap UAF", limit=5)
        assert any(h["slug"] == note.slug for h in widened)

    def test_nothing_tokenizable_means_nothing_is_written(self, tmp_playbooks):
        """`target='E:'` with a goal that also tokenizes to nothing -> decline.

        A stored note with an empty token set is a net loss: it occupies a slot, it is
        offered to nobody, and it makes the store look richer than it is.

        (The goal here used to be a Chinese phrase, back when ``_tokenize`` dropped
        CJK entirely; since the CJK-bigram fix a Chinese goal is a legitimate
        recallable key, so the degenerate stand-in is punctuation-only.)
        """
        bb = _seed_blackboard()
        assert (
            pb.capture_run_notes(target="E:", goal="!!!???---", blackboard=bb, outcome="solved")
            is None
        )
        assert list(tmp_playbooks.glob("*.md")) == []

    def test_a_chinese_goal_now_widens_and_the_note_is_recallable(self, tmp_playbooks):
        """CJK-bigram flip side (2026-10-04): a Chinese GOAL is a real key now.

        Before the fix this exact call declined to write (the goal tokenized to
        nothing); now it widens the fingerprint with queryable bigrams and the
        note is found by a pure-Chinese query.
        """
        bb = _seed_blackboard()
        ack = pb.capture_run_notes(
            target="E:", goal="中文应急响应排查目标", blackboard=bb, outcome="solved"
        )
        assert ack is not None, "a Chinese goal is a queryable key since the CJK fix"
        note = next(n for n in pb.list_playbooks() if n.slug == ack["slug"])
        assert note.tokens(), "the widened fingerprint must be tokenizable"
        hits = pb.lookup_playbook("应急响应 排查", limit=5)
        assert any(h["slug"] == note.slug for h in hits), (
            "the note must be found by a pure-Chinese query sharing its goal tokens"
        )

    def test_a_normal_target_is_stored_unchanged(self, tmp_playbooks):
        """The widening must not touch the normal path (URL / binary fingerprints)."""
        bb = _seed_blackboard()
        target = "http://direct-ctf2.dasctf.com:27532"
        ack = pb.capture_run_notes(
            target=target, goal="capture the flag", blackboard=bb, outcome="solved"
        )
        note = next(n for n in pb.list_playbooks() if n.slug == ack["slug"])
        assert note.fingerprint == pb.target_fingerprint(target, "capture the flag")

    def test_every_note_in_the_store_is_recallable(self, tmp_playbooks):
        """The invariant this class exists for, checked over a whole captured store."""
        bb = _seed_blackboard()
        for target, goal in (
            ("E:", "heap UAF on description pointer"),
            ("http://direct-ctf2.dasctf.com:27532", "capture the flag"),
            ("local-7", "pwn the heap"),
            ("/tmp/chall.elf", "reverse the binary"),
        ):
            ack = pb.capture_run_notes(target=target, goal=goal, blackboard=bb, outcome="solved")
            assert ack is not None, (target, goal)
        for note in pb.list_playbooks():
            assert note.tokens(), f"{note.slug} has an empty fingerprint token set"
            hits = pb.lookup_playbook(note.fingerprint, limit=10)
            assert any(h["slug"] == note.slug for h in hits), f"{note.slug} is not recallable"


class TestAScoreOfZeroIsUnreachableByNameToo:
    """round7 D1 correction, measured at round9: the NAME does not rescue such a note.

    `PLAYBOOK-REUSE-RESULT.md` §4.7 and §6 used to say the stale `'E:'` entry "靠 name 里的
    babyfengshui 还能被按题名查的路径召回". That is false, and the distinction matters for
    anyone deciding whether a legacy entry can be left in place:

    * `Playbook.score()` counts the QUERY's tokens found in `self.tokens()`, i.e. the
      FINGERPRINT only;
    * the name enters `identity_tokens()`, which is consulted for the OVERLAP COUNT in
      `lookup_playbook_multi` -- a step that runs only for rows that ALREADY cleared
      `score >= min_score`.

    So a note whose fingerprint tokenizes to nothing is unreachable by every read path,
    including a query made of its own title.
    """

    def _legacy_note(self, tmp_playbooks):
        (tmp_playbooks / "autonotes-babyfengshui-33c3-2016.md").write_text(
            "\n".join(
                [
                    "---",
                    "name: AutoNotes babyfengshui_33c3_2016",
                    "fingerprint: E:",
                    "status: draft",
                    "source: auto",
                    "---",
                    "",
                    "LOCK: heap UAF on the user description pointer; flag in /flag",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    def test_the_name_tokens_are_there_but_do_not_help(self, tmp_playbooks):
        self._legacy_note(tmp_playbooks)
        note = pb.list_playbooks()[0]
        assert note.tokens() == set(), "precondition: the fingerprint tokenizes to nothing"
        assert "babyfengshui" in note.identity_tokens(), (
            "the name tokens exist -- they are simply not what score() reads"
        )
        assert pb._note_is_queryable("E:", note.name) is False

    @pytest.mark.parametrize(
        "query",
        [
            "babyfengshui_33c3_2016",
            "babyfengshui",
            "AutoNotes babyfengshui",
            "babyfengshui_33c3_2016 heap UAF",
            "E:",
            "heap UAF",
        ],
    )
    def test_no_query_reaches_it(self, tmp_playbooks, query):
        self._legacy_note(tmp_playbooks)
        assert pb.lookup_playbook(query, limit=5) == []
        rows = pb.lookup_playbook_multi([("target", query), ("class", query)], limit=5)
        assert rows == [], f"{query!r} reached the note: {rows}"


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
