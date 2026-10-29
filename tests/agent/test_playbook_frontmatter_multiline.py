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
