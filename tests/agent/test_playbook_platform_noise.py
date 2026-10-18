"""Platform-shape noise: CTF2 goals must not make every note match every note.

Measured 2026-10-18 on the real store while solving BUUCTF challenges through
``vulnclaw ctf2``. Every CTF2 run builds its goal from the same sentence::

    Solve CTF2 challenge '<name>' (category <CAT>, difficulty <DIFF>)
    on practice <practice-uuid>.

so the goal text carries the practice UUID (three four-character hex groups),
``ctf2``, ``practice``, ``category``, ``difficulty``, ``easy`` and ``solve`` --
none of which says anything about WHICH challenge it is. ``_tokenize`` kept
them all, so a query for one challenge scored against every sibling note:

    query RSAROLL -> 14 tokens, 13 platform boilerplate, 1 real (`rsaroll`)
    results: score=1.000 RSAROLL
             score=0.929 Alice与Bob
             score=0.929 RSA2
             score=0.929 世上无难事
             score=0.929 robomunication

The right note still ranked first (its UUID slice overlapped), but the other
two slots of the automatic injection went to unrelated challenges -- so the
"prior playbooks" brief the model reads was mostly wrong ones.

The fix filters platform-shape words and UUID/hash fragments at tokenization
time. These tests pin both halves and, just as importantly, pin the cases that
must NOT be filtered (real words that happen to be valid hex).
"""

from __future__ import annotations

import re

import pytest

from vulnclaw.agent import playbook as pb


# The exact goal shape ``cli/commands_platform.ctf2()`` builds.
GOAL = (
    "Solve CTF2 challenge 'RSAROLL' (category CRYPTO, difficulty Easy) on "
    "practice b9bbb32f-f186-458f-b90b-12440c0f6aea."
)


class TestPlatformBoilerplateDropped:
    def test_goal_leaves_only_discriminating_tokens(self):
        """The whole point: 14 tokens in, the challenge identity out."""
        tokens = pb._tokenize(GOAL)
        assert tokens == {"rsaroll", "crypto"}, tokens

    def test_platform_words_are_stop_words(self):
        for word in ("ctf2", "practice", "category", "difficulty", "easy", "solve"):
            assert word in pb._STOP, f"{word} is CTF2 boilerplate and must be dropped"

    def test_uuid_groups_are_id_fragments(self):
        """A UUID is 8-4-4-4-12; the middle groups are 4 chars, so the length
        floor has to be 4 or three of the five groups leak through."""
        for part in ("b9bbb32f", "f186", "458f", "b90b", "12440c0f6aea"):
            assert pb._is_id_fragment(part), part

    def test_bare_practice_string_tokenizes_to_nothing(self):
        assert pb._tokenize("ctf2 practice b9bbb32f-f186-458f-b90b-12440c0f6aea") == set()


class TestRealWordsSurvive:
    """The digit requirement is what keeps this from eating English."""

    def test_hex_looking_english_words_are_kept(self):
        tokens = pb._tokenize("cafe face dead beef feed")
        assert tokens == {"cafe", "face", "dead", "beef", "feed"}, tokens

    def test_short_hex_without_digit_is_kept(self):
        assert pb._tokenize("cafe") == {"cafe"}

    def test_tech_words_are_untouched(self):
        """Regression guard: the previously-passing tokenizer contract."""
        assert pb._tokenize("Weblogic uddiexplorer") == {"weblogic", "uddiexplorer"}

    def test_vuln_vocabulary_survives(self):
        tokens = pb._tokenize("ssrf xxe sqli rce lfi 反序列化")
        assert {"ssrf", "xxe", "sqli", "rce", "lfi"} <= tokens


class TestDiscriminationOnRealStore:
    """End-to-end: with the fix, an unrelated sibling must score well below."""

    @staticmethod
    def _write(store, *, slug: str, name: str, fingerprint: str) -> None:
        """Write the note directly: ``save_playbook`` has quality gates (min step
        length, LOCK/CONFIRMED headings) that would reject a fixture body, and
        this file is testing retrieval, not ingestion."""
        block = [
            "---",
            f"name: {name}",
            f"fingerprint: {fingerprint}",
            "status: validated",
            "source: curated",
            "updated_at: 2026-10-18T00:00:00+00:00",
            "---",
            "",
            "LOCK: fixture note.",
            "",
        ]
        (store / f"{slug}.md").write_text("\n".join(block), encoding="utf-8")

    @pytest.fixture()
    def store(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pb, "CONFIG_DIR", tmp_path)
        monkeypatch.setattr(pb, "PLAYBOOKS_DIR", tmp_path / "playbooks")
        pb.ensure_dirs()
        store = tmp_path / "playbooks"
        # Two different challenges in the SAME practice ground: before the fix
        # they shared 13 of 14 query tokens.
        self._write(
            store,
            slug="rsaroll-note",
            name="RSAROLL",
            fingerprint=(
                "Solve CTF2 challenge 'RSAROLL' (category CRYPTO, difficulty Easy) on "
                "practice b9bbb32f-f186-458f-b90b-12440c0f6aea. small modulus rsa e=19"
            ),
        )
        self._write(
            store,
            slug="alice-note",
            name="Alice与Bob",
            fingerprint=(
                "Solve CTF2 challenge 'Alice与Bob' (category CRYPTO, difficulty Easy) on "
                "practice b9bbb32f-f186-458f-b90b-12440c0f6aea. md5 small exponent"
            ),
        )
        return store

    def test_right_note_scores_1_and_sibling_scores_half(self, store):
        hits = pb.lookup_playbook(GOAL, limit=5)
        by_name = {h["name"]: h["score"] for h in hits}
        assert by_name.get("RSAROLL") == 1.0, by_name
        # 1 of 2 remaining tokens (`crypto`) -- no longer the old 0.929.
        if "Alice与Bob" in by_name:
            assert by_name["Alice与Bob"] <= 0.5, by_name

    def test_sibling_no_longer_reaches_the_overlap_floor(self, store):
        """The automatic injection path floors on MIN_OVERLAP_TOKENS distinct
        tokens. Platform noise used to push an unrelated note over it."""
        blocked: list[dict] = []
        rows = pb.lookup_playbook_multi([("target", GOAL)], limit=3, out_blocked=blocked)
        names = [r["name"] for r in rows]
        assert "RSAROLL" in names, names
        assert "Alice与Bob" not in names, (
            f"unrelated sibling should be gated by the overlap floor, got {names}"
        )


class TestFilteringNeverMakesANoteUnreachable:
    """Full-store sweep (2026-10-18) found 14 of 516 notes that became dead.

    Their fingerprint is a single ``http://<20-hex>.http-ctf2.dasctf.com:80`` URL:
    the random host label is an id fragment and ``http``/``com`` are stop words, so
    filtering consumed EVERY token and the note could never be recalled again.
    Those notes carry real solutions (e.g. the ``[极客大挑战 2019]Knife`` webshell
    recipe), so the loss was silent but severe -- exactly the recall regression
    ``_recallable_fingerprint`` warns about in its own docstring.

    The fallback is deliberately narrow: it restores raw tokens ONLY for URL-shaped
    text. A bare ``ctf2:practice:<uuid>`` string stays empty, because its slices are
    shared by every challenge in that ground and keeping them re-creates the
    cross-sibling collision this filter exists to remove.
    """

    def test_url_shaped_fingerprint_is_rescued(self):
        toks = pb._tokenize("http://52a9808e5f42e688b4a496e0.http-ctf2.dasctf.com:80")
        assert toks, "a URL-only fingerprint must stay recallable"
        assert "52a9808e5f42e688b4a496e0" in toks

    def test_bare_practice_id_is_not_rescued(self):
        """Rescuing this would put the ground uuid back into every sibling query."""
        assert pb._tokenize("ctf2 practice b9bbb32f-f186-458f-b90b-12440c0f6aea") == set()
        assert pb._tokenize("ctf2:practice:b9bbb32f-f186-458f-b90b-12440c0f6aea:x") == set()

    def test_normal_fingerprints_keep_their_discriminating_tokens(self):
        toks = pb._tokenize("Weblogic uddiexplorer /wls-wsat RCE")
        assert {"weblogic", "uddiexplorer", "rce"} <= toks
        assert "wls" in toks  # real word fragment, not an id

    def test_a_url_with_real_words_keeps_the_words_not_the_id(self):
        """When words survive, the id slices must still be dropped."""
        toks = pb._tokenize("http://b9bbb32f-x.http-ctf2.dasctf.com/shrine jinja2 ssti")
        assert {"shrine", "jinja2", "ssti"} <= toks
        assert "b9bbb32f" not in toks
