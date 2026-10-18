"""Two measured dead ends from an afternoon of CTF2 grinding (2026-10-18).

Both are environment/accounting problems, not model-capability problems, and
both were rediscovered from scratch on every run because nothing in the repo
mentioned them.

**1. RAR extraction.** Several MISC/FORENSICS challenges ship a RAR attachment.
The agent spent entire stall windows hunting for a way to open one: `rarfile`
(installed, but its backend `unrar` is not), `py7zr` (no RAR support), the
bundled `E:\\vulnclaw\\tools\\7zr.exe` (lists the RAR header, then fails with
"Cannot open the file as archive"), and a full-disk scan for `unrar*.exe`.
Meanwhile `bsdtar` / libarchive 3.7.7 was already on PATH and extracts
RAR/ZIP/7z/tar with no helper binary. `reverse1` only got past the same gap
because the model happened to guess `tar`. The tool card now names the tool AND
the trap.

**2. Stall-guard accounting.** ``_path_progress_fingerprint`` counts turns since
the last CONFIRMED fact / decided ANGLE / changed LOCK -- deliberately not since
the last tool call (see ``tests/agent/test_path_stall_guard.py`` for the measured
justification). The prompt taught HOW to record coverage but never said that NOT
recording ends the run, so productive work (enumerating stego variants, probing a
sandbox) read as stalled and was handed back to the operator. Measured: four
challenges died that way in one afternoon.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.tool_registry import build_tool_card


class TestArchiveToolOnCard:
    def test_rar_goal_offers_bsdtar(self):
        card = build_tool_card(
            "Solve challenge: 附件是 rar 压缩包，需要解压后分析", mode="ctf"
        )
        assert "bsdtar" in card, card

    def test_card_names_the_trap_not_just_the_tool(self):
        """'extract archives' was not enough -- the run kept hunting for unrar.

        The card now names 7-Zip as the RAR answer and says outright that bsdtar
        can list but not DECRYPT a RAR, which is the case that sent runs off to
        install extractors mid-challenge (measured 2026-10-18).
        """
        card = build_tool_card("rar 压缩包 解压", mode="ctf")
        lowered = card.lower()
        assert "7-zip" in lowered, "the RAR-capable tool must be named"
        assert "加密 rar" in lowered, "the encrypted-RAR case must be called out"
        assert "tar.exe" in lowered, "the Windows fallback must still be documented"
        assert "unrar" not in lowered or "没有 unrar" in lowered, (
            "if unrar is mentioned it must be to say it is absent"
        )

    def test_windows_tar_fallback_is_documented(self):
        card = build_tool_card("zip archive extract", mode="ctf")
        assert "System32" in card and "tar.exe" in card, card


class TestStallAccountingIsToldToTheModel:
    """The prompt must explain what the record is FOR.

    The first attempt at this used a survival framing ("recording keeps the run
    alive"), which measurably backfired: one run read it as a threat and skipped
    accounting entirely (9 minutes / 286 KB / zero angles before going to look up
    a writeup), another dumped four angles in the final step only. The text now
    frames angles as working memory — why *you* need the record — and these tests
    pin that framing so it cannot drift back into a threat.
    """

    @pytest.fixture()
    def prompt_source(self) -> str:
        import inspect

        from vulnclaw.agent import solver

        return inspect.getsource(solver)

    def test_prompt_frames_angles_as_working_memory(self, prompt_source):
        assert "working memory" in prompt_source.lower(), (
            "the prompt must explain what the record is for, not threaten the run"
        )

    def test_prompt_does_not_threaten_termination(self, prompt_source):
        """The survival framing is what caused the regression; keep it out.

        Only the PROMPT STRING matters here, not the explanatory comments above
        it — those quote the old wording on purpose to record what went wrong.
        """
        prompt_literals = [
            line for line in prompt_source.splitlines()
            if line.lstrip().startswith('"') or line.lstrip().startswith("'")
        ]
        text = "\n".join(prompt_literals)
        assert "keeps the run alive" not in text
        assert "ends your run" not in text

    def test_prompt_names_the_two_habits(self, prompt_source):
        lowered = prompt_source.lower()
        assert "before you enumerate variants" in lowered
        assert "record the lock" in lowered

    def test_prompt_keeps_the_reason_concrete(self, prompt_source):
        """'re-probing the same ground' is the measurable cost of no record."""
        lowered = prompt_source.lower()
        assert "re-probing" in lowered or "ruled out" in lowered


class TestAlwaysEntryIsScopedToCtf:
    """`always` must not leak a CTF-shaped tool into a bug-hunting run.

    An engagement report ("test this site for SQLi") is not a challenge handout,
    so a "how to unzip" line it never needs is pure context cost. The entry is
    `always` under `ctf` ONLY; `pentest`/`auto` stay keyword-driven, so an
    archive-related goal still gets bsdtar, and an unrelated one gets nothing.
    """

    BUG_HUNT = "Test https://target.example.com for SQL injection and access control issues"
    CTF_GOAL = "Solve CTF2 challenge 'x' (category MISC, difficulty Easy)"

    def test_pentest_goal_without_archive_keyword_has_no_bsdtar(self):
        card = build_tool_card(self.BUG_HUNT, mode="pentest")
        assert "bsdtar" not in card, card

    def test_pentest_goal_with_archive_keyword_still_gets_bsdtar(self):
        card = build_tool_card("the source is provided as a zip archive", mode="pentest")
        assert "bsdtar" in card, card

    def test_ctf_goal_always_gets_bsdtar(self):
        assert "bsdtar" in build_tool_card(self.CTF_GOAL, mode="ctf")

    def test_ir_mode_never_gets_the_ctf_archive_entry(self):
        card = build_tool_card("排查主机 webshell 与持久化", mode="ir")
        assert "bsdtar" not in card, card
