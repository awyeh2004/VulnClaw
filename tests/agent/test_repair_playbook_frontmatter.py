"""The repair script must not lose a multi-line ``name`` (2026-10-29).

``save_playbook`` wrote ``name`` verbatim exactly like ``fingerprint``, so a
captured title that wrapped left continuation lines under the ``name:`` key.
``_split_corrupted`` used to read only the first physical line, silently
dropping the rest on ``--apply`` -- and the script's TOKENS printout could not
see the loss because it rebuilt the before-count from the same truncated meta.
"""

from __future__ import annotations

from scripts.repair_playbook_frontmatter import _render, _split_corrupted
from vulnclaw.agent import playbook as pb


def _corrupted_note() -> str:
    # Shape produced by the pre-52f0943 writer: single-line keys interrupted by
    # a verbatim multi-line value, a ``----`` rule inside the goal text, and the
    # real tail keys stranded below it.
    return (
        "---\n"
        "name: DASBOOK 7.5.2 pdf隐写\n"
        "（勘误表见正文末尾，按 2026-10 印次）\n"
        "fingerprint: ctf2:practice:11111111:22222222 解题全文第一行\n"
        "解题全文第二行\n"
        "----\n"
        "解题全文第三行\n"
        "status: validated\n"
        "source: auto\n"
        "updated_at: 2026-10-28T12:00:00+00:00\n"
        "---\n"
        "\n"
        "LOCK: x\n"
        "CONFIRMED: y\n"
        "ANGLES: [hit] z\n"
    )


class TestSplitCorruptedKeepsMultilineName:
    def test_name_continuation_lines_survive(self):
        parts = _split_corrupted(_corrupted_note())
        assert parts is not None
        meta, body = parts
        assert meta["name"] == (
            "DASBOOK 7.5.2 pdf隐写 （勘误表见正文末尾，按 2026-10 印次）"
        )
        assert "ctf2:practice:11111111:22222222" in meta["fingerprint"]
        assert "解题全文第三行" in meta["fingerprint"]

    def test_repaired_note_round_trips(self):
        meta, body = _split_corrupted(_corrupted_note())
        rendered = _render(meta, body)
        check_meta, check_body = pb._parse_frontmatter(rendered)
        assert check_meta["name"] == meta["name"]
        assert check_meta["status"] == "validated"
        assert check_meta["fingerprint"] == meta["fingerprint"]
        assert check_body.strip() == body.strip()

    def test_single_line_name_is_unchanged(self):
        # Still a corrupted note (multi-line fingerprint) so the splitter
        # recognises it; ``name`` itself never wrapped, so nothing may change.
        note = (
            "---\n"
            "name: AutoNotes t\n"
            "fingerprint: 解题全文第一行\n"
            "解题全文第二行\n"
            "status: validated\n"
            "source: auto\n"
            "updated_at: 2026-10-28T12:00:00+00:00\n"
            "---\n"
            "\n"
            "LOCK: x\n"
            "CONFIRMED: y\n"
            "ANGLES: [hit] z\n"
        )
        parts = _split_corrupted(note)
        assert parts is not None
        meta, _body = parts
        assert meta["name"] == "AutoNotes t"
        assert "解题全文第二行" in meta["fingerprint"]
