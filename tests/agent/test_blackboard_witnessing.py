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

from vulnclaw.agent.blackboard import _unescape_evidence, _witnessed_in_evidence

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
