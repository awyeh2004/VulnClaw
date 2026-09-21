"""Ref tokens: the platform-prefixed address that makes cross-platform calls impossible.

The token grammar is a contract between the tool face and each adapter, so it is
pinned here verbatim: if a future adapter changes the shape, these tests fail
rather than silently emitting refs nothing can parse.
"""

from __future__ import annotations

import pytest

from vulnclaw.platforms.refs import (
    ChallengeRef,
    CorpusRef,
    RefError,
    make_token,
    parse_fields,
    platform_of,
    split_token,
)


class TestTokenShapes:
    @pytest.mark.parametrize(
        ("ref", "expected"),
        [
            (ChallengeRef("ctf2", "practice", "12"), "ctf2:practice:12"),
            (ChallengeRef("ctf2", "practice", "12", "345"), "ctf2:practice:12:345"),
            (ChallengeRef("ctf2", "stage", "7", "345"), "ctf2:stage:7:345"),
            (ChallengeRef("ctf2", "daily"), "ctf2:daily"),
            (ChallengeRef("ctf2", "daily", "", "350"), "ctf2:daily:350"),
            (ChallengeRef("gcs", "exercise"), "gcs:exercise"),
            (ChallengeRef("gcs", "exercise", "", "10662"), "gcs:exercise:10662"),
        ],
    )
    def test_challenge_ref_token(self, ref, expected):
        assert ref.token() == expected

    @pytest.mark.parametrize(
        ("corpus", "expected"),
        [
            (CorpusRef("ctf2", "practice", "12"), "ctf2:practice:12"),
            (CorpusRef("ctf2", "daily"), "ctf2:daily"),
            (CorpusRef("gcs", "exercise"), "gcs:exercise"),
        ],
    )
    def test_corpus_ref_token(self, corpus, expected):
        assert corpus.token() == expected

    def test_group_is_omitted_when_absent_so_gcs_needs_no_empty_field(self):
        """A uniform arity would force `gcs:exercise::10662`; honesty over symmetry."""
        assert ChallengeRef("gcs", "exercise", "", "10662").token() == "gcs:exercise:10662"

    def test_key_is_the_token(self):
        """The guard/cache key must be the token, or state stops being shareable."""
        ref = ChallengeRef("ctf2", "practice", "12", "345")
        assert ref.key == ref.token()


class TestTokenSplitting:
    def test_round_trip_through_the_prefix(self):
        for token in ("ctf2:practice:12:345", "gcs:exercise:10662", "ctf2:daily"):
            platform, tail = split_token(token)
            assert token == make_token(platform, *parse_fields(tail))

    def test_platform_of(self):
        assert platform_of("gcs:exercise:10662") == "gcs"

    @pytest.mark.parametrize("token", ["", "   ", "nodivider", ":tail", "platform:", "  :  "])
    def test_malformed_tokens_are_rejected(self, token):
        with pytest.raises(RefError):
            split_token(token)

    def test_bare_id_is_rejected_with_an_actionable_message(self):
        """Design decision Q2: never guess the platform, even for a lone id."""
        with pytest.raises(RefError) as excinfo:
            split_token("10662")
        message = str(excinfo.value)
        assert "no platform prefix" in message
        assert "platform_list" in message

    def test_only_the_first_separator_splits_the_prefix(self):
        """The tail is the adapter's business; a colon inside it is not our error."""
        assert split_token("ctf2:practice:12:345") == ("ctf2", "practice:12:345")

    def test_parse_fields_rejects_empty_segments(self):
        with pytest.raises(RefError):
            parse_fields("practice::345")


class TestTokenValidation:
    @pytest.mark.parametrize("field", ["", "a:b", " padded", "padded ", "has space"])
    def test_make_token_rejects_unusable_fields(self, field):
        with pytest.raises(RefError):
            make_token("ctf2", field)

    def test_make_token_requires_a_tail(self):
        with pytest.raises(RefError):
            make_token("ctf2")

    def test_make_token_rejects_empty_platform(self):
        with pytest.raises(RefError):
            make_token("", "practice")

    @pytest.mark.parametrize(
        ("platform", "kind"),
        [("", "practice"), ("ctf2", ""), ("a:b", "practice")],
    )
    def test_challenge_ref_validates_platform_and_kind(self, platform, kind):
        with pytest.raises(RefError):
            ChallengeRef(platform, kind)

    def test_challenge_ref_validates_group_and_id_when_present(self):
        with pytest.raises(RefError):
            ChallengeRef("ctf2", "practice", "1:2")
        with pytest.raises(RefError):
            ChallengeRef("ctf2", "practice", "12", "3 4")

    def test_refs_are_hashable_and_comparable(self):
        ref = ChallengeRef("ctf2", "practice", "12", "345")
        assert {ref, ChallengeRef("ctf2", "practice", "12", "345")} == {ref}
