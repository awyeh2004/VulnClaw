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
    _SHARED_SPAN_MIN_CHARS,
    _SHARED_SPAN_MIN_COVERAGE,
    _fingerprints,
    _has_shared_ngram,
    _is_corroborating_only,
    _longest_common_substring,
    _norm_text,
    _shared_span_carries_content,
    _span_carries_content,
    _substantive_tokens,
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



class TestNarrationGluedToQuotedObservation:
    """Live CTF regression (2026-10-12): every candidate fact was refused because
    the fact glues the model's narration to a *verbatim* quote, and tool output
    interleaves punctuation or CJK the clause does not reproduce byte-for-byte.
    Three consecutive runs ended with an unverifiable board (only the flag token
    ever confirmed), because the whole clause -- narration included -- had to
    match. The shared contiguous span is the witness now, not the whole clause.
    """

    def test_quoted_banner_plus_narration(self):
        fact = (
            'REPL banner: "=== MDM 策略审查器 v2.6 (Policy REPL) ===" with '
            "commands config/certs/spki/try/submit; reachable only over TLS"
        )
        evidence = (
            "trytls=True BANNER: '=== MDM 策略审查器 v2.6 (Policy REPL) ===\n"
            "某加固 App 的 TLS 策略层被导出到本引擎。\n'"
        )
        assert _witnessed_in_evidence(fact, evidence) is True

    def test_spki_pin_quoted_with_differing_separators(self):
        pin = "VavPInyCtffT0H19c/LteQIqOZ+ZIY3+AUwmoSFawHI"
        fact = f"spki 1 = spki 2 = {pin} (matches primary pin)"
        evidence = f"### spki 1:\npin-sha256={pin}\n\npolicy> \n"
        assert _witnessed_in_evidence(fact, evidence) is True

    def test_json_snippet_quoted_inside_a_clause(self):
        fact = (
            'submitting a1=/portal returns "Q1 ok, Q2 wrong"; '
            "a1=portal returns \"Q1 wrong\" — the first document request is /portal"
        )
        evidence = (
            '/portal 200 {"ok": false, "why": "Q1 ok, Q2 wrong"}\n'
            'portal 200 {"ok": false, "why": "Q1 wrong"}'
        )
        assert _witnessed_in_evidence(fact, evidence) is True

    def test_cjk_observation_quoted_with_prefix(self):
        fact = "try 1: pin 匹配主 pin,但 pin-set expiration=2025-01-01 已过"
        evidence = (
            "=== try 1 ===\n"
            "pin 匹配主 pin,但 pin-set expiration=2025-01-01 已过 -> 整个 pin-set 失效。\n"
        )
        assert _witnessed_in_evidence(fact, evidence) is True

    def test_bare_id_alone_still_does_not_confirm(self):
        """The shared-span tier must not resurrect the round-5 hole: a fact whose
        only shared span is an id/timestamp run is not witnessed."""
        fact = "job id 1758432000123456 proves the payload executed on the host"
        evidence = "2026-09-21 cron.daily finished, job id 1758432000123456"
        assert _witnessed_in_evidence(fact, evidence) is False

    def test_narrative_wrapped_hash_is_still_rejected(self):
        digest = "851939e4e90b864b8d20fe6228564522"
        fact = (
            f"the dropped file with md5 {digest} is an APT implant that "
            "persists via LD_PRELOAD"
        )
        evidence = f"/tmp/.cache; md5={digest}"
        assert _witnessed_in_evidence(fact, evidence) is False

    def test_short_common_words_still_do_not_confirm(self):
        assert (
            _witnessed_in_evidence(
                "this that with from the data was true and false",
                "the from with this that true false",
            )
            is False
        )


class TestRound6CopiedTokenCannotWitness:
    """A *copied* token must not carry an invented claim.

    Three holes were measured on live sessions (round-6 audit) and are pinned here:

    * the substantive word only had to appear *somewhere* in the evidence instead of
      inside the shared span, so copying a real id and adding "which proves ..."
      passed on a generic word appearing elsewhere in a 64 KB blob;
    * a UUID's segments are not hex runs, so they counted as content;
    * a CJK run of two characters inside the span counted as content by itself, so a
      borrowed five-character run witnessed an invented Chinese sentence.

    The fourth test guards the opposite direction: the bar scales with the clause, so
    a real observation quoted with a little narration must still be witnessed.
    """

    EVIDENCE = (
        "GET /admin HTTP/1.1 200 OK\n"
        "set-cookie: sid=1dff1955-496b-40be-81f7-c37ccae980c3; Path=/\n"
        "状态码code=404服务器内错 请重试\n"
    )

    def test_borrowed_uuid_plus_invented_claim_is_rejected(self):
        fact = (
            "I confirmed 1dff1955-496b-40be-81f7-c37ccae980c3 which proves the "
            "internal admin panel qzxwvu exposes scoring"
        )
        assert _witnessed_in_evidence(fact, self.EVIDENCE) is False

    def test_uuid_verbatim_with_invented_tail_is_rejected(self):
        fact = (
            "sid 1dff1955-496b-40be-81f7-c37ccae980c3 proves the admin panel "
            "trusts unsigned session cookies from any host"
        )
        assert _witnessed_in_evidence(fact, self.EVIDENCE) is False

    def test_short_cjk_run_in_the_span_is_not_content(self):
        fact = "错误码code=404服务器内错说明后台未鉴权"
        assert _witnessed_in_evidence(fact, self.EVIDENCE) is False

    def test_long_cjk_observation_is_still_witnessed(self):
        fact = "note: 服务器返回登录成功请重试 -> 说明未鉴权"
        evidence = "note: 服务器返回登录成功请重试\n"
        assert _witnessed_in_evidence(fact, evidence) is True

    def test_one_quoted_word_does_not_carry_a_long_invented_tail(self):
        evidence = "response header x-powered-by: PHP/7.4.3\n"
        fact = (
            "x-powered-by is PHP/7.4.3 which proves the upload endpoint accepts "
            "arbitrary files and the scoring service trusts whatever it is handed"
        )
        assert _witnessed_in_evidence(fact, evidence) is False

    def test_uuid_fragments_are_not_substantive_content(self):
        span = "1dff1955-496b-40be-81f7-c37ccae980c3"
        assert _is_corroborating_only("1dff1955", span) is True
        assert _is_corroborating_only("c37ccae980c3", span) is True
        # Outside a UUID the same word is ordinary content.
        assert _is_corroborating_only("powered", "x-powered-by:php/7.4.3") is False


class TestSpanSearchStaysCheap:
    """The span search is on the fact-verification hot path.

    Real sessions carry 64 KB and 21 MB evidence records; the quadratic scan cost
    371 ms and 87 s respectively per clause. The n-gram prefilter must be a pure
    necessary condition and must keep large evidence off the quadratic path.
    """

    def test_prefilter_is_a_necessary_condition(self):
        cases = [
            ("abc", "abc"),
            ("abcdefgh", "zzzzzzzz"),
            ("the quick brown fox", "a quick brown fox jumps"),
            ("", "anything"),
            ("x" * 40, "y" * 40),
            ("normalised span here", "prefix normalised span here suffix"),
        ]
        for a, b in cases:
            na, nb = _norm_text(a), _norm_text(b)
            long_enough = len(_longest_common_substring(na, nb)) >= _SHARED_SPAN_MIN_CHARS
            assert _has_shared_ngram(na, nb) is long_enough

    def test_large_evidence_is_not_quadratic(self):
        import time

        evidence = ("GET /admin HTTP/1.1 200 OK\n" * 8000)  # ~216 KB
        fact = "I confirmed the internal admin panel qzxwvu exposes scoring to anyone"
        start = time.perf_counter()
        assert _witnessed_in_evidence(fact, evidence) is False
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"span search too slow on large evidence: {elapsed:.2f}s"

    def test_verbatim_long_evidence_clause_is_still_witnessed(self):
        witness = "response body: login succeeded and the session cookie is accepted"
        evidence = ("noise line\n" * 500) + witness + ("\ntrailing noise" * 500)
        assert _witnessed_in_evidence(witness, evidence) is True


class TestAnchoredSpanSearch:
    """The span search must stay linear on large evidence without moving the bar.

    The previous implementation computed the longest common substring over the whole
    evidence for every clause -- measured 94.97 s for one 6.46 MB evidence blob -- and
    that cost landed on every review pass. The anchor scan aligns on the clause's own
    content words instead. Test 1 pins that it accepts what the rule it replaced
    accepted (the replacement is "exists a qualifying run", the old code checked the
    longest run only, so the safety direction is: old true => new true). Test 2 pins
    the cost on evidence that really does share a run, which is the case the prefilter
    could not save.
    """

    @staticmethod
    def _longest_run_rule(candidate, norm_fact, norm_chunk, bar, tokens, fp):
        span = _longest_common_substring(norm_fact, norm_chunk)
        return len(span) >= bar and _span_carries_content(candidate, span, tokens, fp)

    def test_never_loses_an_acceptance_the_longest_run_rule_made(self):
        import math

        cases = [
            ("GET /admin HTTP/1.1 200 OK admin panel open",
             "noise GET /admin HTTP/1.1 200 OK zzz"),
            ("theandtheandtheand adminpanel exposed",
             "theandtheandtheand adminpanel"),
            ("错误码code=404服务器内错说明后台未鉴权", "状态码code=404服务器内错 请重试"),
            ("borrowed 1dff1955-496b-40be-81f7-c37ccae980c3 proves admin open",
             "set-cookie: sid=1dff1955-496b-40be-81f7-c37ccae980c3; Path=/"),
            ("sid 1dff1955-496b-40be-81f7-c37ccae980c3 trusts unsigned cookies",
             "set-cookie: sid=1dff1955-496b-40be-81f7-c37ccae980c3; Path=/"),
        ]
        for fact, evidence in cases:
            nf, nch = _norm_text(fact), _norm_text(evidence)
            tokens, fp = _substantive_tokens(evidence), _fingerprints(evidence)
            bar = max(_SHARED_SPAN_MIN_CHARS, math.ceil(_SHARED_SPAN_MIN_COVERAGE * len(nf)))
            old = self._longest_run_rule(fact, nf, nch, bar, tokens, fp)
            new = _shared_span_carries_content(nf, nch, fact, bar, tokens, fp)
            assert (not old) or new, f"lost a previous acceptance: {fact[:44]}"

    def test_span_search_on_evidence_with_a_genuine_shared_run_is_linear(self):
        import time

        noise = "zzzz-no-match-here " * 20_000          # ~380 KB either side
        witness = "theandtheandtheandtheand adminpanel"
        chunk = noise + witness + noise
        fact = "theandtheandtheandtheand adminpanel is exposed to anyone on the network"

        start = time.perf_counter()
        result = _witnessed_in_evidence(fact, chunk)
        elapsed = time.perf_counter() - start

        assert result is True
        # The replaced implementation spent seconds here (longest common substring over
        # ~380 KB of evidence per clause); the anchor scan is milliseconds plus the
        # token/fingerprint regexes.
        assert elapsed < 3.0, f"span search too slow on shared-run evidence: {elapsed:.2f}s"
