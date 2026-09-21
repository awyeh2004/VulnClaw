"""Fact verification must accept a witnessed observation, and reject a fabricated one.

Both failure modes are pinned here, because the fix moves the bar and the risk of
moving it is confirmation of claims that were never witnessed.

The real failures it fixes, from live solve runs: `blackboard_verify_fact` refused
facts whose evidence plainly contained the observation, because

* the evidence is stored JSON-escaped, so ``\\n`` / ``\\"`` sat between the fact and
  the text it quoted;
* a fact is written as narration plus a quoted observation, and the narration is the
  agent's own words -- absent from the evidence by construction -- so requiring the
  whole sentence to be witnessed rejected it.

The guard's purpose is preserved by requiring a substantive clause (>= 24 chars) to
match, not by accepting a loose bag of common words.
"""

from __future__ import annotations

from vulnclaw.agent.blackboard import (
    _fingerprints,
    _unescape_evidence,
    _witnessed_in_evidence,
)

# Verbatim shape of the browser evidence from the live BUU BURP run (e022): the
# tool result was stored as a JSON-escaped string.
ESCAPED_EVIDENCE = (
    '"<html><head></head><body>\\u767b\\u5f55\\u6210\\u529f\\uff01'
    'CTF2{13641798-4ff5-454c-a0ca-ec09e00bb792}\\n</body></html>"'
)

PLAIN_EVIDENCE = (
    "recv: n1book{851939e4e90b864b8d20fe6228564522}\n"
    "-rwxr----- 1 0 1000 41 Dec  2  2019 flag\n"
)


class TestUnescape:
    def test_newlines_and_quotes_are_undone(self):
        assert _unescape_evidence('a\\nb\\"c') == 'a\nb"c'

    def test_text_without_escapes_is_untouched(self):
        assert _unescape_evidence("plain text") == "plain text"

    def test_empty_is_safe(self):
        assert _unescape_evidence("") == ""
        assert _unescape_evidence(None) == ""


class TestWitnessedObservation:
    def test_narration_plus_quoted_flag_is_accepted(self):
        """The measured case: the prose is the agent's, the flag is in the evidence."""
        fact = (
            'Submitting prefilled login form (username=admin) returned body '
            '"登录成功！CTF2{13641798-4ff5-454c-a0ca-ec09e00bb792}" '
            '— flag CTF2{13641798-4ff5-454c-a0ca-ec09e00bb792}'
        )
        assert _witnessed_in_evidence(fact, PLAIN_EVIDENCE.replace("n1book{851939e4e90b864b8d20fe6228564522}", "CTF2{13641798-4ff5-454c-a0ca-ec09e00bb792}")) is True

    def test_quoted_body_with_escaped_evidence(self):
        fact = 'the page returned 登录成功！CTF2{13641798-4ff5-454c-a0ca-ec09e00bb792} after login'
        assert _witnessed_in_evidence(fact, ESCAPED_EVIDENCE) is True

    def test_flag_clause_after_a_dash(self):
        fact = (
            "Paid load with ret2text gave a shell; file /flag was readable "
            "— flag n1book{851939e4e90b864b8d20fe6228564522}"
        )
        assert _witnessed_in_evidence(fact, PLAIN_EVIDENCE) is True

    def test_whole_description_still_matches_when_it_is_verbatim(self):
        assert _witnessed_in_evidence("plain text", "some plain text here") is True


class TestFabricationIsStillRejected:
    def test_unrelated_claim_is_not_witnessed(self):
        fact = "The target is running kernel 6.8.4 and has an unpatched CVE-2024-9999"
        assert _witnessed_in_evidence(fact, PLAIN_EVIDENCE) is False

    def test_claim_quoting_nothing_from_the_evidence(self):
        fact = 'the server replied "ACCESS GRANTED" and exposed /admin/backup.sql'
        assert _witnessed_in_evidence(fact, ESCAPED_EVIDENCE) is False

    def test_short_common_words_do_not_confirm(self):
        """A loose bag of shared words must not be enough."""
        fact = "this that with from the data was true and false"
        assert _witnessed_in_evidence(fact, "the from with this that true false") is False

    def test_empty_inputs(self):
        assert _witnessed_in_evidence("", PLAIN_EVIDENCE) is False
        assert _witnessed_in_evidence("something", "") is False


class TestRound5Tightening:
    """The three ways a shared literal used to confirm an unwitnessed claim."""

    def test_decimal_numbers_are_not_fingerprints(self):
        """A 16+ digit decimal (timestamp, row id) is not a hex fingerprint.

        It matched the old ``[0-9a-fA-F]{16,}`` pattern, so any tool output that
        printed an id gave a fabricated fact something to "share".
        """
        stamp = "1758432000123456"
        assert _fingerprints(stamp) == set()
        fact = f"job id {stamp} proves the payload executed on the host"
        evidence = f"2026-09-21 cron.daily finished, job id {stamp}"
        assert _fingerprints(fact) & _fingerprints(evidence) == set()
        assert _witnessed_in_evidence(fact, evidence) is False

    def test_hex_value_still_counts(self):
        assert _fingerprints("851939e4e90b864b8d20fe6228564522") == {
            "851939e4e90b864b8d20fe6228564522"
        }

    def test_lone_shared_hash_does_not_confirm_a_fabricated_narrative(self):
        """Round-5 review: invented prose + one real hash used to pass."""
        digest = "851939e4e90b864b8d20fe6228564522"
        fact = (
            f"the dropped file with md5 {digest} is an APT implant that "
            "persists via LD_PRELOAD"
        )
        evidence = f"-rw-r--r-- 1 root root 41 Dec 2 2019 /tmp/.cache; md5={digest}"
        assert _witnessed_in_evidence(fact, evidence) is False

    def test_hash_confirms_when_its_own_clause_is_witnessed(self):
        digest = "851939e4e90b864b8d20fe6228564522"
        fact = f"md5sum {digest} /tmp/.cache_update.sh"
        evidence = f"md5sum  {digest}  /tmp/.cache_update.sh\n"
        assert _witnessed_in_evidence(fact, evidence) is True

    def test_flag_absent_from_the_evidence_is_never_witnessed(self):
        fact = (
            "login succeeded and the page returned "
            "CTF2{deadbeef-1111-2222-3333-444455556666}"
        )
        assert _witnessed_in_evidence(fact, PLAIN_EVIDENCE) is False

    def test_every_cited_flag_must_be_present(self):
        a = "CTF2{11111111-1111-1111-1111-111111111111}"
        b = "CTF2{22222222-2222-2222-2222-222222222222}"
        evidence = f"accepted: {a}"
        assert _witnessed_in_evidence(f"submitted {a} and {b}, both accepted", evidence) is False
        assert _witnessed_in_evidence(f"submitted {a}", evidence) is True

    def test_partial_word_matches_do_not_count(self):
        """Tokens are matched whole: "config" must not match "configuration"."""
        assert _witnessed_in_evidence("config panel", "the configuration panel") is False
        assert _witnessed_in_evidence("config panel", "config panel") is True

    def test_clause_carrying_an_unseen_literal_cannot_pass_on_wording(self):
        digest = "deadbeefdeadbeefdeadbeefdeadbeef"
        fact = f"md5sum abcdef /tmp/x; md5sum {digest} /tmp/y"
        evidence = "md5sum abcdef /tmp/x"
        assert _witnessed_in_evidence(fact, evidence) is False

