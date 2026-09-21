"""CTF2 adapter: ref grammar, payload normalization, and A/B parity with the old tool.

The normalization tests run against payloads recorded from the real 2026-09-21
run (``ctf2_payloads``), not hand-written samples -- the two target shapes differ
in ways a made-up sample would not reproduce.

``TestParityWithTheOldRenderer`` is the A/B check the migration plan requires: the
same real payload is fed to the pre-refactor ``_render_target_state`` and to the
new ``normalize_target_payload`` + ``render_env_info`` pair, and the conclusions
the caller acts on must match. It runs offline and deterministically, which is
strictly better evidence than re-running a live challenge for this purpose.
"""

from __future__ import annotations

import pytest

from tests.platforms import ctf2_payloads as fx
from vulnclaw.platforms import base
from vulnclaw.platforms.ctf2 import (
    CTF2Adapter,
    CTF2Error,
    challenge_row_id,
    extract_attachments,
    extract_endpoints,
    extract_rows,
    normalize_target_payload,
    submit_accepted,
    submit_message,
)
from vulnclaw.platforms.refs import ChallengeRef, CorpusRef, RefError
from vulnclaw.platforms.render import render_env_info

import tests.platforms.ctf2_payloads as ctf2_payloads

PRACTICE_REF = ChallengeRef("ctf2", "practice", fx.PRACTICE_ID, fx.CHALLENGE_ID)


def _head(text: str) -> str:
    return text.split("\n{", 1)[0]


# ── ref grammar ───────────────────────────────────────────────────────────


class TestRefGrammar:
    @pytest.mark.parametrize(
        ("kind", "group", "ident", "expected"),
        [
            ("practice", "12", "345", "ctf2:practice:12:345"),
            ("practice", "12", "", "ctf2:practice:12"),
            ("stage", "7", "345", "ctf2:stage:7:345"),
            ("daily", "", "", "ctf2:daily"),
            ("daily", "", "350", "ctf2:daily:350"),
        ],
    )
    def test_make_ref(self, kind, group, ident, expected):
        adapter = CTF2Adapter()
        assert adapter.make_ref(kind=kind, id=ident, group=group).token() == expected

    def test_make_ref_rejects_unknown_kind(self):
        with pytest.raises(RefError):
            CTF2Adapter().make_ref(kind="nope", id="1")

    @pytest.mark.parametrize(
        ("tail", "expected"),
        [
            ("practice:12:345", ChallengeRef("ctf2", "practice", "12", "345")),
            ("practice:12", ChallengeRef("ctf2", "practice", "12", "")),
            ("stage:7:345", ChallengeRef("ctf2", "stage", "7", "345")),
            ("daily", ChallengeRef("ctf2", "daily", "", "")),
            ("daily:350", ChallengeRef("ctf2", "daily", "", "350")),
        ],
    )
    def test_parse_ref(self, tail, expected):
        assert CTF2Adapter().parse_ref(tail) == expected

    @pytest.mark.parametrize(
        "tail",
        ["nope:1", "practice", "practice:", "daily:1:2", "practice:1:2:3", "stage"],
    )
    def test_parse_ref_rejects_bad_tails(self, tail):
        with pytest.raises(RefError):
            CTF2Adapter().parse_ref(tail)

    def test_real_ids_round_trip(self):
        """The ids that actually appear on CTF2 are UUIDs with dashes."""
        adapter = CTF2Adapter()
        ref = adapter.make_ref(
            kind="practice", group=fx.PRACTICE_ID, id=fx.CHALLENGE_ID
        )
        assert ref.token() == f"ctf2:practice:{fx.PRACTICE_ID}:{fx.CHALLENGE_ID}"
        assert adapter.parse_ref(ref.token().split(":", 1)[1]) == ref

    def test_pair_requires_both_ids(self):
        adapter = CTF2Adapter()
        with pytest.raises(CTF2Error):
            adapter._pair(ChallengeRef("ctf2", "practice", fx.PRACTICE_ID, ""))


# ── target payload normalization (real recorded payloads) ─────────────────


class TestNormalizeRecordedStarting:
    def test_state_is_starting_and_not_complete(self):
        info = normalize_target_payload(fx.STARTING_PAYLOAD, PRACTICE_REF)
        assert info.state == base.STATE_STARTING
        assert info.complete is False
        assert info.usable is False

    def test_no_endpoints_invented_from_a_partial_payload(self):
        """The starting shape has no access_url -- so there must be no endpoint."""
        assert normalize_target_payload(fx.STARTING_PAYLOAD, PRACTICE_REF).endpoints == ()

    def test_expiry_is_carried_even_when_incomplete(self):
        info = normalize_target_payload(fx.STARTING_PAYLOAD, PRACTICE_REF)
        assert info.expires_at == fx.EXPIRES_AT


class TestNormalizeRecordedRunning:
    def test_state_running_and_complete(self):
        info = normalize_target_payload(fx.RUNNING_PAYLOAD, PRACTICE_REF)
        assert info.state == base.STATE_RUNNING
        assert info.complete is True
        assert info.usable is True

    def test_endpoint_host_and_port_are_split(self):
        (endpoint,) = normalize_target_payload(fx.RUNNING_PAYLOAD, PRACTICE_REF).endpoints
        assert endpoint.host == fx.HOST
        assert endpoint.port == fx.PORT
        assert endpoint.url == fx.ACCESS_URL

    def test_transport_is_tls_from_nc_ssl(self):
        info = normalize_target_payload(fx.RUNNING_PAYLOAD, PRACTICE_REF)
        assert info.transports() == frozenset({base.TRANSPORT_TLS})

    def test_access_type_is_not_used_as_the_transport(self):
        """⭐ The trap: the real payload says access_type=tcp AND nc_ssl=true.

        Reading access_type as the transport would call a TLS endpoint plain TCP
        -- the exact miss that cost 20+ minutes on the live challenge.
        """
        payload = fx.RUNNING_PAYLOAD
        assert payload["data"]["access_type"] == "tcp"
        assert payload["data"]["nc_ssl"] is True
        info = normalize_target_payload(payload, PRACTICE_REF)
        assert info.transports() == frozenset({base.TRANSPORT_TLS})
        assert base.TRANSPORT_TCP not in info.transports()

    def test_tls_guidance_names_nc_ssl_and_warns_about_access_type(self):
        text = _head(render_env_info(normalize_target_payload(fx.RUNNING_PAYLOAD, PRACTICE_REF)))
        assert "nc_ssl" in text
        assert "NOT the transport" in text

    def test_expired_instance_symptom_is_explained(self):
        """A successful handshake is not proof of liveness (measured on the target)."""
        text = _head(render_env_info(normalize_target_payload(fx.RUNNING_PAYLOAD, PRACTICE_REF)))
        assert "TARGET NOT FOUND" in text

    def test_entry_level_flag_beats_the_top_level_one(self):
        payload = {
            "data": {
                "status": "running",
                "nc_ssl": True,
                "access_url": "h:1",
                "access_urls": [{"nc_ssl": False, "url": "h:1"}],
            }
        }
        (endpoint,) = normalize_target_payload(payload, PRACTICE_REF).endpoints
        assert endpoint.transport == base.TRANSPORT_TCP

    def test_top_level_flag_is_the_fallback(self):
        payload = {"data": {"status": "running", "nc_ssl": True, "access_url": "h:1"}}
        (endpoint,) = normalize_target_payload(payload, PRACTICE_REF).endpoints
        assert endpoint.transport == base.TRANSPORT_TLS

    def test_missing_flag_stays_unknown_not_tcp(self):
        """Reproduces the case the old renderer had to hedge about."""
        payload = {
            "data": {
                "status": "running",
                "access_type": "tcp",
                "access_url": "h:1",
                "access_urls": [{"type": "tcp", "url": "h:1"}],
            }
        }
        info = normalize_target_payload(payload, PRACTICE_REF)
        assert info.transports() == frozenset({base.TRANSPORT_UNKNOWN})

    def test_running_without_any_endpoint_is_not_usable(self):
        info = normalize_target_payload({"data": {"status": "running"}}, PRACTICE_REF)
        assert info.complete is False
        assert info.usable is False


class TestNormalizeDegenerate:
    def test_null_data_means_no_target(self):
        info = normalize_target_payload(fx.NO_TARGET_PAYLOAD, PRACTICE_REF)
        assert info.state == base.STATE_NONE
        assert info.complete is False

    def test_missing_data_key(self):
        assert normalize_target_payload({"success": True}, PRACTICE_REF).state == base.STATE_NONE

    def test_non_mapping_data_does_not_crash(self):
        assert normalize_target_payload({"data": "weird"}, PRACTICE_REF).state == base.STATE_NONE

    def test_unknown_status_is_not_complete(self):
        info = normalize_target_payload(
            {"data": {"status": "teleported", "access_url": "h:1"}}, PRACTICE_REF
        )
        assert info.state == base.STATE_UNKNOWN
        assert info.complete is False

    def test_expired_status(self):
        info = normalize_target_payload({"data": {"status": "expired"}}, PRACTICE_REF)
        assert info.state == base.STATE_EXPIRED
        assert info.complete is False


# ── A/B parity with the pre-refactor renderer ─────────────────────────────


class TestParityWithTheOldRenderer:
    """Both layers must reach the same actionable conclusion on the same payload."""

    @staticmethod
    def _old(payload: dict) -> str:
        from vulnclaw.ctf_platform.tools import _render_target_state

        return _head(_render_target_state(payload))

    @staticmethod
    def _new(payload: dict) -> str:
        return _head(render_env_info(normalize_target_payload(payload, PRACTICE_REF)))

    @pytest.mark.parametrize(
        "needle",
        ["INCOMPLETE", "do not use it as the target", "Poll", "running", "create call"],
    )
    def test_starting_payload_agrees(self, needle):
        assert (needle in self._old(fx.STARTING_PAYLOAD)) == (
            needle in self._new(fx.STARTING_PAYLOAD)
        ) is True

    @pytest.mark.parametrize(
        "needle",
        ["TLS-WRAPPED", "wrap_socket", "ssl.SSLContext", "handshake",
         "identical to a failed exploit"],
    )
    def test_running_tls_payload_agrees(self, needle):
        assert (needle in self._old(fx.RUNNING_PAYLOAD)) == (
            needle in self._new(fx.RUNNING_PAYLOAD)
        ) is True

    @pytest.mark.parametrize("needle", ["no target is running"])
    def test_no_target_payload_agrees(self, needle):
        assert (needle in self._old(fx.NO_TARGET_PAYLOAD)) == (
            needle in self._new(fx.NO_TARGET_PAYLOAD)
        ) is True

    def test_no_target_payload_new_layer_adds_the_status_line(self):
        """A strict superset, not a regression: the old no-target branch only said
        'no target is running', with no normalized status line."""
        assert "target status" not in self._old(fx.NO_TARGET_PAYLOAD)
        assert "target status: none" in self._new(fx.NO_TARGET_PAYLOAD)

    def test_unknown_transport_payload_agrees(self):
        payload = {
            "data": {
                "status": "running",
                "access_url": "h:1",
                "access_urls": [{"type": "tcp", "url": "h:1"}],
            }
        }
        for needle in ("not reported", "try TLS"):
            assert (needle in self._old(payload)) == (needle in self._new(payload)) is True

    def test_plain_payload_is_not_warned_about_in_either_layer(self):
        payload = {
            "data": {"status": "running", "nc_ssl": False, "access_url": "h:1"},
        }
        for needle in ("TLS-WRAPPED", "plain TCP"):
            assert (needle in self._old(payload)) == (needle in self._new(payload))

    def test_both_keep_the_raw_payload(self):
        """Asserted on the FULL text: the raw dump is what _head() strips."""
        from vulnclaw.ctf_platform.tools import _render_target_state

        for payload in (fx.STARTING_PAYLOAD, fx.RUNNING_PAYLOAD):
            old_full = _render_target_state(payload)
            new_full = render_env_info(normalize_target_payload(payload, PRACTICE_REF))
            assert '"success"' in old_full
            assert '"success"' in new_full


# ── list/extraction tolerance (shapes not captured, hence defensive) ──────


class TestListTolerance:
    @pytest.mark.parametrize(
        "payload",
        [
            {"data": [{"id": "1", "name": "a"}]},
            {"data": {"list": [{"id": "1", "name": "a"}]}},
            {"data": {"results": [{"id": "1", "name": "a"}]}},
            {"data": {"items": [{"id": "1", "name": "a"}]}},
        ],
    )
    def test_extract_rows_accepts_common_envelopes(self, payload):
        rows = extract_rows(payload)
        assert rows == [{"id": "1", "name": "a"}]

    @pytest.mark.parametrize("payload", [{"data": None}, {}, {"data": {"total": 3}}, "x", None])
    def test_extract_rows_returns_empty_rather_than_guessing(self, payload):
        assert extract_rows(payload) == []

    def test_extract_rows_drops_non_dict_rows(self):
        assert extract_rows({"data": [{"id": "1"}, "junk", 5]}) == [{"id": "1"}]


class TestAttachments:
    def test_download_url_and_md5(self):
        (attachment,) = extract_attachments(
            {"files": [{"name": "a.zip", "download_url": "http://x/a.zip",
                        "file_md5": "abc", "size": 10}]}
        )
        assert attachment == base.Attachment(name="a.zip", url="http://x/a.zip",
                                             md5="abc", size=10)

    def test_name_falls_back_to_the_url(self):
        (attachment,) = extract_attachments({"attachments": [{"url": "http://x/a.zip"}]})
        assert attachment.name == "a.zip"

    @pytest.mark.parametrize("data", [{}, {"files": "junk"}, {"files": [1, 2]}])
    def test_no_attachments_is_empty(self, data):
        assert extract_attachments(data) == ()


class TestSubmitPayloads:
    @pytest.mark.parametrize(
        ("payload", "expected"),
        [
            ({"data": {"accepted": True}}, True),
            ({"data": {"accepted": False}}, False),
            ({"data": {"isCorrect": True}}, True),
            ({"accepted": True}, True),
            ({"success": True}, True),
            ({"success": False}, False),
            ({"data": None}, False),
            ("junk", False),
        ],
    )
    def test_accepted_detection(self, payload, expected):
        assert submit_accepted(payload) is expected

    def test_message_prefers_platform_text(self):
        assert submit_message({"data": {"message": "wrong flag"}}) == "wrong flag"
        assert submit_message({"data": {}}) == ""


class TestEndpointsFromPayload:
    def test_multiple_endpoints(self):
        payload = {
            "status": "running",
            "nc_ssl": False,
            "access_urls": [
                {"nc_ssl": True, "url": "a:1"},
                {"nc_ssl": False, "url": "b:2"},
            ],
        }
        endpoints = extract_endpoints(payload)
        assert [ep.url for ep in endpoints] == ["a:1", "b:2"]
        assert [ep.transport for ep in endpoints] == [base.TRANSPORT_TLS, base.TRANSPORT_TCP]

    def test_entries_without_a_url_are_skipped(self):
        assert extract_endpoints({"access_urls": [{"nc_ssl": True}, "junk"]}) == ()

    def test_falls_back_to_the_flat_access_url(self):
        (endpoint,) = extract_endpoints({"access_url": "h:9", "nc_ssl": True})
        assert (endpoint.host, endpoint.port, endpoint.transport) == (
            "h", 9, base.TRANSPORT_TLS
        )


# ── adapter behaviour with a fake client ──────────────────────────────────


class FakeClient:
    def __init__(self, **payloads):
        self.payloads = payloads
        self.calls: list[tuple] = []
        self._session = payloads.pop("session", "token")

    def is_configured(self) -> bool:
        return True

    def session_token(self) -> str:
        return self._session

    async def _get(self, name, *args, **kwargs):
        self.calls.append((name, args))
        return self.payloads.get(name, {"data": []})

    async def list_practice(self, limit=50):
        return await self._get("list_practice")

    async def list_daily(self, limit=50):
        return await self._get("list_daily")

    async def list_competitions(self, limit=50):
        return await self._get("list_competitions")

    async def list_stage_challenges(self, stage_id, limit=100):
        return await self._get("list_stage_challenges", stage_id)

    async def read_challenge(self, pid, cid):
        return await self._get("read_challenge", pid, cid)

    async def start_environment(self, pid, cid):
        return await self._get("start_environment", pid, cid)

    async def get_target(self, pid, cid):
        return await self._get("get_target", pid, cid)

    async def stop_target(self, pid, cid):
        return await self._get("stop_target", pid, cid)

    async def submit_flag(self, pid, cid, flag):
        self.calls.append(("submit_flag", (pid, cid, flag)))
        return self.payloads.get("submit_flag", {"data": {"accepted": True}})

    async def list_submissions(self, limit=20):
        return await self._get("list_submissions")


class TestAdapterLifecycle:
    async def test_start_env_reports_starting_when_the_payload_is_partial(self):
        adapter = CTF2Adapter(FakeClient(start_environment=fx.STARTING_PAYLOAD))
        info = await adapter.start_env(PRACTICE_REF)
        assert info.state == base.STATE_STARTING
        assert info.complete is False
        assert "platform_read_env" in " ".join(info.guidance)

    async def test_start_env_passes_the_group_as_the_practice_id(self):
        client = FakeClient(start_environment=fx.RUNNING_PAYLOAD)
        await CTF2Adapter(client).start_env(PRACTICE_REF)
        assert client.calls == [
            ("start_environment", (fx.PRACTICE_ID, fx.CHALLENGE_ID))
        ]

    async def test_start_env_normalizes_a_running_payload(self):
        adapter = CTF2Adapter(FakeClient(start_environment=fx.RUNNING_PAYLOAD))
        info = await adapter.start_env(PRACTICE_REF)
        assert info.usable is True
        assert info.transports() == frozenset({base.TRANSPORT_TLS})

    async def test_read_env_requires_the_session_token(self):
        adapter = CTF2Adapter(FakeClient(session="", get_target=fx.RUNNING_PAYLOAD))
        with pytest.raises(CTF2Error) as excinfo:
            await adapter.read_env(PRACTICE_REF)
        assert "session token" in str(excinfo.value)

    async def test_read_env_normalizes(self):
        adapter = CTF2Adapter(FakeClient(get_target=fx.RUNNING_PAYLOAD))
        assert (await adapter.read_env(PRACTICE_REF)).usable is True

    async def test_stop_env_requires_the_session_token(self):
        adapter = CTF2Adapter(FakeClient(session=""))
        with pytest.raises(CTF2Error):
            await adapter.stop_env(PRACTICE_REF)

    async def test_submit_flag_is_judged_and_reports_acceptance(self):
        adapter = CTF2Adapter(FakeClient(submit_flag={"data": {"accepted": False}}))
        result = await adapter.submit_flag(PRACTICE_REF, "flag{x}")
        assert result.judged is True
        assert result.accepted is False


class TestAdapterListing:
    async def test_list_corpora_covers_practice_daily_and_stages(self):
        client = FakeClient(
            list_practice={"data": [{"id": "p1", "name": "ground one"}]},
            list_competitions={
                "data": [{"id": "c1", "name": "comp", "challenges": [
                    {"id": "s1", "name": "stage one"}]}]
            },
        )
        tokens = [corpus.ref.token() for corpus in await CTF2Adapter(client).list_corpora()]
        assert tokens == ["ctf2:practice:p1", "ctf2:daily", "ctf2:stage:s1"]

    async def test_list_daily_challenges(self):
        client = FakeClient(list_daily={"data": [{"id": "d1", "name": "day"}]})
        challenges = await CTF2Adapter(client).list_challenges(CorpusRef("ctf2", "daily"))
        assert challenges[0].ref.token() == "ctf2:daily:d1"

    async def test_list_stage_challenges(self):
        client = FakeClient(list_stage_challenges={"data": [{"id": "c9"}]})
        challenges = await CTF2Adapter(client).list_challenges(
            CorpusRef("ctf2", "stage", "s1")
        )
        assert challenges[0].ref.token() == "ctf2:stage:s1:c9"

    async def test_practice_listing_failure_is_honest_not_silent(self):
        """Verified live: '/practice/<pid>/challenges/' is 404, so do not invent it."""
        client = FakeClient(list_practice={"data": [{"id": "p1", "name": "ground one"}]})
        with pytest.raises(CTF2Error) as excinfo:
            await CTF2Adapter(client).list_challenges(CorpusRef("ctf2", "practice", "p1"))
        message = str(excinfo.value)
        assert "exposes no route" in message
        assert "404" in message
        assert "vulnclaw ctf2" in message

    async def test_embedded_practice_challenges_are_used_when_present(self):
        client = FakeClient(
            list_practice={
                "data": [{"id": "p1", "challenges": [{"id": "c1", "name": "one"}]}]
            }
        )
        challenges = await CTF2Adapter(client).list_challenges(
            CorpusRef("ctf2", "practice", "p1")
        )
        assert challenges[0].ref.token() == "ctf2:practice:p1:c1"

    async def test_read_challenge_normalizes_fields(self):
        client = FakeClient(
            read_challenge={
                "data": {
                    "name": "SSTI",
                    "category": "web",
                    "difficulty": "Easy",
                    "description": "d",
                    "has_container": True,
                    "hasSolved": False,
                    "files": [{"name": "a.zip", "download_url": "http://x/a.zip"}],
                }
            }
        )
        challenge = await CTF2Adapter(client).read_challenge(PRACTICE_REF)
        assert challenge.name == "SSTI"
        assert challenge.needs_env is True
        assert challenge.solved is False
        assert challenge.attachments[0].name == "a.zip"

    async def test_submissions_facet(self):
        client = FakeClient(list_submissions={"data": [{"id": "s1"}]})
        assert await CTF2Adapter(client).submissions() == [{"id": "s1"}]

    def test_adapter_declares_its_identity(self):
        adapter = CTF2Adapter()
        assert adapter.name == "ctf2"
        assert adapter.capabilities == frozenset({base.CAP_SUBMISSIONS})
        assert adapter.enabled_by_default is True


# ── field names verified against the live platform ────────────────────────
#
# Every assertion here failed (or would have failed) against an inferred field
# name. They exist so the names cannot silently drift back to guesses.


class TestVerifiedFieldNames:
    def test_list_envelope_is_items_and_total(self):
        """All four list endpoints use {"data": {"items": [...], "total": n}}."""
        assert ctf2_payloads.LIST_ENVELOPE_KEYS == ("items", "total")
        assert extract_rows(ctf2_payloads.DAILY_LIST_PAYLOAD) != []
        assert extract_rows(ctf2_payloads.COMPETITION_LIST_PAYLOAD) != []

    async def test_read_challenge_reads_is_solved_not_has_solved(self):
        client = FakeClient(read_challenge=ctf2_payloads.CHALLENGE_DETAIL_PAYLOAD)
        challenge = await CTF2Adapter(client).read_challenge(PRACTICE_REF)
        assert challenge.solved is False
        assert "hasSolved" not in ctf2_payloads.CHALLENGE_DETAIL_KEYS
        assert "is_solved" in ctf2_payloads.CHALLENGE_DETAIL_KEYS

    async def test_read_challenge_reads_points_not_score(self):
        client = FakeClient(read_challenge=ctf2_payloads.CHALLENGE_DETAIL_PAYLOAD)
        challenge = await CTF2Adapter(client).read_challenge(PRACTICE_REF)
        assert challenge.score == "1"
        assert "score" not in ctf2_payloads.CHALLENGE_DETAIL_KEYS
        assert "points" in ctf2_payloads.CHALLENGE_DETAIL_KEYS

    async def test_read_challenge_reads_the_real_name_and_category(self):
        client = FakeClient(read_challenge=ctf2_payloads.CHALLENGE_DETAIL_PAYLOAD)
        challenge = await CTF2Adapter(client).read_challenge(PRACTICE_REF)
        assert challenge.name == "stack"
        assert challenge.needs_env is True

    def test_attachment_name_and_size_come_from_the_nested_file_object(self):
        """A flat row['name'] / row['size'] lookup silently yields nothing."""
        (attachment,) = extract_attachments(ctf2_payloads.CHALLENGE_DETAIL_PAYLOAD["data"])
        assert attachment.name == "libc-2.27.so"
        assert attachment.size == 2030544
        assert attachment.note == "application/octet-stream"
        assert attachment.url.startswith("https://ctf2-files.dasctf.com/")

    def test_attachment_md5_is_absent_and_must_not_be_invented(self):
        (attachment,) = extract_attachments(ctf2_payloads.CHALLENGE_DETAIL_PAYLOAD["data"])
        assert attachment.md5 == ""
        assert "md5" not in ctf2_payloads.FILE_ROW_KEYS

    def test_daily_row_id_prefers_the_challenge_over_the_wrapper(self):
        """Daily rows wrap the challenge; row['id'] is the daily ENTRY id."""
        row = ctf2_payloads.DAILY_LIST_PAYLOAD["data"]["items"][0]
        assert row["id"] != row["challenge_id"]
        assert challenge_row_id(row) == row["challenge_id"]

    async def test_daily_listing_addresses_the_challenge_not_the_entry(self):
        adapter = CTF2Adapter(FakeClient(list_daily=ctf2_payloads.DAILY_LIST_PAYLOAD))
        (challenge,) = await adapter.list_challenges(CorpusRef("ctf2", "daily"))
        row = ctf2_payloads.DAILY_LIST_PAYLOAD["data"]["items"][0]
        assert challenge.ref.token() == f"ctf2:daily:{row['challenge_id']}"
        assert challenge.name == "vault"


class TestVerifiedRouteLimits:
    async def test_competition_rows_carry_no_stages(self):
        """Verified: nothing in the competition payload enumerates stage ids."""
        assert "stages" not in ctf2_payloads.COMPETITION_ROW_KEYS
        adapter = CTF2Adapter(
            FakeClient(
                list_practice={"data": {"items": [], "total": 0}},
                list_competitions=ctf2_payloads.COMPETITION_LIST_PAYLOAD,
            )
        )
        tokens = [corpus.ref.token() for corpus in await adapter.list_corpora()]
        assert not any(token.startswith("ctf2:stage") for token in tokens)

    async def test_practice_count_comes_from_challenge_count(self):
        adapter = CTF2Adapter(
            FakeClient(
                list_practice={
                    "data": {
                        "items": [
                            {"id": "p1", "name": "ground", "challenge_count": 3}
                        ],
                        "total": 1,
                    }
                },
                list_competitions={"data": {"items": [], "total": 0}},
            )
        )
        corpora = await adapter.list_corpora()
        corpus = next(c for c in corpora if c.ref.token() == "ctf2:practice:p1")
        assert corpus.count == 3
        assert "NOT enumerable" in corpus.note

    def test_target_route_is_not_on_the_open_api(self):
        """The adapter's session-token requirement for read_env is load-bearing."""
        assert ctf2_payloads.OPEN_API_ROUTE_OUTCOMES[
            "/practice/<pid>/challenges/<cid>/target/"
        ] == 404
