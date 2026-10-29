"""Frontmatter must survive a value that spans lines (2026-10-28).

Two defects, one shape. ``save_playbook`` wrote ``name`` / ``fingerprint``
verbatim, so a captured CTF2 goal -- the whole challenge prompt, description
and platform policy text included -- became a dozen physical lines under one
``fingerprint:`` key. ``_parse_frontmatter`` then closed the block at the first
``---`` PREFIX anywhere in that text. A Chinese book's 勘误表 separator
(``----``) and a Markdown horizontal rule (``---``) both ended it early, so:

* ``status: validated`` and ``target_ref:`` were read as BODY. The note
  loaded as a draft with no identity -- invisible to the validated-only
  auto-inject path in ``solver.py``;
* ``fingerprint`` was truncated to its first physical line, so the tokens the
  note was recalled by were a fraction of the intended set.

Measured on the home store before the fix: 144 notes carried a multi-line
value, 18 of them loaded with no ``status`` at all.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent import playbook as pb

STEPS = (
    "LOCK: 伪加密判定先看 LFH/CD 标志位是否一致。\n"
    "CONFIRMED: 清 CD bit0 后 deflate 解出 flag{deadbeef}。\n"
    "ANGLES: [hit] 读中央目录标志位再清位。"
)


@pytest.fixture()
def tmp_playbooks(monkeypatch, tmp_path):
    d = tmp_path / "playbooks"
    d.mkdir()
    monkeypatch.setattr(pb, "PLAYBOOKS_DIR", d)
    return d


class TestDelimiterMustBeAWholeLine:
    def test_dash_rule_inside_the_block_does_not_close_it(self):
        text = (
            "---\n"
            "name: n\n"
            "fingerprint: f\n"
            "note: 勘误表\n"
            "----\n"
            "status: validated\n"
            "---\n"
            "body\n"
        )
        meta, body = pb._parse_frontmatter(text)
        assert meta["status"] == "validated"
        assert body.strip() == "body"

    def test_delimited_text_is_not_a_delimiter(self):
        text = "---\nname: n\n--- not the end\nstatus: validated\n---\nbody\n"
        meta, body = pb._parse_frontmatter(text)
        assert meta["status"] == "validated"
        assert body.strip() == "body"

    def test_no_closing_delimiter_still_means_no_frontmatter(self):
        text = "---\nname: n\nstatus: validated\nbody without a close\n"
        assert pb._parse_frontmatter(text) == ({}, text)

    def test_ordinary_block_is_unchanged(self):
        text = "---\nname: n\nstatus: draft\n---\nbody\n"
        meta, body = pb._parse_frontmatter(text)
        assert meta == {"name": "n", "status": "draft"}
        assert body == "body\n"


class TestWriterKeepsValuesOnOneLine:
    def test_multiline_fingerprint_round_trips(self, tmp_playbooks):
        goal = (
            "Solve CTF2 challenge 'x' (category REVERSE).\n"
            "Challenge description follows:\n"
            "line one\n"
            "\n"
            "----\n"
            "\n"
            "line two after a dash rule\n"
        )
        slug = pb.save_playbook(
            name="AutoNotes ctf2:practice:g:c",
            fingerprint=f"ctf2:practice:g:c {goal}",
            steps=STEPS,
            status="validated",
            slug="autonotes-x",
        )["slug"]
        raw = (tmp_playbooks / f"{slug}.md").read_text(encoding="utf-8")
        fm = raw.split("\n---\n", 1)[0]
        assert fm.count("\n") == len(fm.splitlines()) - 1
        assert not any(line.strip() in ("---", "----") for line in fm.splitlines()[1:])

        loaded = {p.slug: p for p in pb.list_playbooks()}[slug]
        assert loaded.status == "validated"
        assert "\n" not in loaded.fingerprint
        assert "line two after a dash rule" in loaded.fingerprint

    def test_multiline_target_ref_is_flattened(self, tmp_playbooks):
        slug = pb.save_playbook(
            name="AutoNotes t",
            fingerprint="t",
            steps=STEPS,
            target_ref="ctf2:practice:g:c\nmore",
            slug="autonotes-t",
        )["slug"]
        raw = (tmp_playbooks / f"{slug}.md").read_text(encoding="utf-8")
        assert "target_ref: ctf2:practice:g:c more" in raw
        loaded = {p.slug: p for p in pb.list_playbooks()}[slug]
        assert "\n" not in loaded.target_ref

    def test_whitespace_only_values_are_squeezed_not_dropped(self, tmp_playbooks):
        ack = pb.save_playbook(
            name="  AutoNotes  spaced  ",
            fingerprint="  a\n\nb  ",
            steps=STEPS,
            slug="autonotes-spaced",
        )
        assert ack["slug"] == "autonotes-spaced"
        loaded = {p.slug: p for p in pb.list_playbooks()}["autonotes-spaced"]
        assert loaded.fingerprint == "a b"


class TestCrlfFilesStillParse:
    """Round22 audit (2026-10-29): the whole-line delimiter regex must accept CRLF.

    With ``splitlines(keepends=True)`` a Windows-edited note's delimiter line is
    ``---\r\n``; ``[ \t]*$`` cannot consume ``\\r``, so a strict ``$`` rejected
    the whole block and the note lost its frontmatter -- the exact
    status/target_ref loss 52f0943 set out to fix, via a different trigger
    (hand edit or restore from an E-drive backup). The pre-52f0943 parser
    (``^---\\s*\\n``) accepted CRLF, so this is a regression guard, not new
    tolerance.
    """

    CRLF_NOTE = (
        "---\r\n"
        "name: n\r\n"
        "fingerprint: f\r\n"
        "status: validated\r\n"
        "---\r\n"
        "body\r\n"
    )

    def test_crlf_delimiters_parse(self):
        meta, body = pb._parse_frontmatter(self.CRLF_NOTE)
        assert meta["status"] == "validated"
        assert meta["name"] == "n"
        assert body.strip() == "body"

    def test_crlf_block_with_dash_rule_inside_still_holds(self):
        text = (
            "---\r\n"
            "name: n\r\n"
            "fingerprint: 勘误表\r\n"
            "----\r\n"
            "status: validated\r\n"
            "---\r\n"
            "body\r\n"
        )
        meta, body = pb._parse_frontmatter(text)
        assert meta["status"] == "validated"
        assert meta["fingerprint"] == "勘误表"
        assert body.strip() == "body"


class TestTargetHashMatchesStoredRef:
    """Round22 audit (2026-10-29): the hash must be taken from the stored line.

    ``target_ref`` is flattened before it is written; hashing the pre-flatten
    original meant the stored ``target_hash`` could never be reproduced from the
    stored ``target_ref``. No consumer compares them today (verified: the field
    is write-only across the repo), so this pins the invariant for whoever adds
    the first comparison.
    """

    def test_hash_is_recomputable_from_the_stored_ref(self, tmp_playbooks):
        slug = pb.save_playbook(
            name="AutoNotes h",
            fingerprint="h",
            steps=STEPS,
            target_ref="ctf2:practice:g:c\nmore",
            slug="autonotes-hash",
        )["slug"]
        raw = (tmp_playbooks / f"{slug}.md").read_text(encoding="utf-8")
        ref_line = next(l for l in raw.splitlines() if l.startswith("target_ref:"))
        hash_line = next(l for l in raw.splitlines() if l.startswith("target_hash:"))
        stored_ref = ref_line[len("target_ref:"):].strip()
        assert hash_line == f"target_hash: {pb._target_ref_hash(stored_ref)}"
