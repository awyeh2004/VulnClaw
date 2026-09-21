"""GCS adapter: ref grammar, flag-based readiness normalization, and the capability gate.

Two things are being pinned that the design doc calls out explicitly:

1. **The abstraction must not flatten GCS.** GCS's event info / notices /
   scoreboard have no CTF2 equivalent, so they must appear as capability-gated
   tools -- and must appear for GCS while staying absent when only CTF2 is exposed
   (and vice versa for CTF2's submission history).
2. **GCS needs no session token for anything.** Its client is a single API surface,
   unlike CTF2's Open/session split.

Evidence caveat, stated because it changes how much these tests prove: no GCS
credential was available, so unlike the CTF2 adapter there are no recorded payloads
here. Shapes come from the platform's own documented vocabulary and are marked
``[inferred]`` in ``platforms/gcs.py``; these tests pin the *behaviour* (readiness
mapping, envelope unwrapping, ref shape), not measured field names.
"""

from __future__ import annotations

import pytest

from vulnclaw.platforms import base, bootstrap, registry
from vulnclaw.platforms.gcs import (
    GCSAdapter,
    GCSError,
    extract_endpoints,
    exercise_tree,
    normalize_exercise_env,
    notice_from_row,
    submit_accepted,
)
from vulnclaw.platforms.refs import ChallengeRef, CorpusRef, RefError
from vulnclaw.platforms.render import render_env_info
from vulnclaw.platforms.tools import CORE_TOOL_NAMES, platform_tool_schemas


def _head(text: str) -> str:
    return text.split("\n{", 1)[0]


# ── ref grammar ───────────────────────────────────────────────────────────


class TestRefGrammar:
    @pytest.mark.parametrize(
        ("tail", "expected"),
        [
            ("exercise", ChallengeRef("gcs", "exercise", "", "")),
            ("exercise:10662", ChallengeRef("gcs", "exercise", "", "10662")),
            ("category:0", ChallengeRef("gcs", "category", "", "0")),
        ],
    )
    def test_parse_ref(self, tail, expected):
        assert GCSAdapter().parse_ref(tail) == expected

    @pytest.mark.parametrize("tail", ["nope", "exercise:", "exercise:1:2", "category"])
    def test_parse_ref_rejects_bad_tails(self, tail):
        with pytest.raises(RefError):
            GCSAdapter().parse_ref(tail)

    def test_make_ref_ignores_group_because_gcs_has_no_sub_grouping(self):
        """GCS refs must stay two-field: `gcs:exercise:10662`, not `gcs:exercise::...`."""
        assert GCSAdapter().make_ref(kind="exercise", id="10662").token() == "gcs:exercise:10662"
        assert GCSAdapter().make_ref(kind="exercise").token() == "gcs:exercise"

    def test_make_ref_rejects_ctf2_kinds(self):
        with pytest.raises(RefError):
            GCSAdapter().make_ref(kind="practice", id="1")

    def test_exercise_id_must_be_numeric(self):
        adapter = GCSAdapter()
        with pytest.raises(GCSError):
            adapter._exercise_id(ChallengeRef("gcs", "exercise", "", "abc"))

    def test_a_corpus_ref_is_not_a_challenge_ref(self):
        adapter = GCSAdapter()
        with pytest.raises(GCSError):
            adapter._exercise_id(ChallengeRef("gcs", "exercise", "", ""))


# ── readiness normalization (GCS uses flags, not a status enum) ───────────


REF = ChallengeRef("gcs", "exercise", "", "10662")


class TestReadinessMapping:
    """Fixtures pass the BODY: what ``gcs_platform.client`` actually returns.

    ``client._request`` unwraps the ``{code, message, data}`` envelope itself, so
    an adapter sees ``data``. These tests used to wrap every fixture in
    ``{"data": ...}`` — the envelope shape the real client never returns — which
    is exactly why the adapter's own double-unwrap went unnoticed.
    """

    def test_still_initializing(self):
        info = normalize_exercise_env(
            {"name": "x", "isNeedCheck": True, "exposeIps": ["h:1"]}, REF
        )
        assert info.state == base.STATE_STARTING
        assert info.complete is False
        assert info.usable is False

    def test_ready_with_endpoints(self):
        info = normalize_exercise_env(
            {"name": "x", "isNeedCheck": False, "exposeIps": ["h:1337"]}, REF
        )
        assert info.state == base.STATE_RUNNING
        assert info.complete is True
        assert info.transports() == frozenset({base.TRANSPORT_UNKNOWN})

    def test_check_finished_but_no_endpoint_is_not_usable(self):
        info = normalize_exercise_env({"name": "x", "isNeedCheck": False}, REF)
        assert info.complete is False

    def test_challenge_needs_no_environment(self):
        info = normalize_exercise_env({"name": "x", "isNeedInit": False}, REF)
        assert info.state == base.STATE_NOT_REQUIRED
        assert info.complete is True

    def test_empty_payload_means_no_target(self):
        info = normalize_exercise_env({}, REF)
        assert info.state == base.STATE_NONE
        assert info.complete is False

    def test_envelope_shaped_payload_is_not_dug_into(self):
        """A body that happens to carry a ``data`` member is not replaced by it.

        Tolerance would reintroduce the same silent-wrong-shape failure as the
        double-unwrap, so the accessor is deliberately strict; such a payload
        degrades to "no target", which is loud and fail-safe.
        """
        info = normalize_exercise_env(
            {"name": "x", "isNeedCheck": False, "exposeIps": ["h:1"],
             "data": {"isNeedCheck": True}},
            REF,
        )
        assert info.state == base.STATE_RUNNING  # the outer body wins

    def test_transport_is_never_assumed_to_be_tcp(self):
        """GCS publishes no TLS flag; guessing tcp is the CTF2 20-minute mistake."""
        info = normalize_exercise_env(
            {"isNeedCheck": False, "exposeIps": ["h:1"]}, REF
        )
        assert base.TRANSPORT_TCP not in info.transports()
        text = _head(render_env_info(info))
        assert "not reported" in text
        assert "try TLS" in text

    def test_transport_note_only_for_bare_host_port(self):
        """A scheme answers the question the note exists to ask.

        Round-6 review F2: the note was emitted unconditionally, so an https
        endpoint got "the transport is unknown -- try plain TCP first" in the same
        message as the renderer's "THIS TARGET IS TLS-WRAPPED" block: two
        statements pointing in opposite directions, on precisely the side the
        scheme-based transport fix was written to stop misleading.
        """
        tls = normalize_exercise_env(
            {"isNeedCheck": False, "exposeIps": ["https://h:443"]}, REF
        )
        assert [ep.transport for ep in tls.endpoints] == [base.TRANSPORT_TLS]
        assert not any("transport is unknown" in line for line in tls.guidance)
        assert "TLS-WRAPPED" in render_env_info(tls)

        plain = normalize_exercise_env(
            {"isNeedCheck": False, "exposeIps": ["http://h:80"]}, REF
        )
        assert [ep.transport for ep in plain.endpoints] == [base.TRANSPORT_TCP]
        assert not any("transport is unknown" in line for line in plain.guidance)

        bare = normalize_exercise_env({"isNeedCheck": False, "exposeIps": ["h:1337"]}, REF)
        assert [ep.transport for ep in bare.endpoints] == [base.TRANSPORT_UNKNOWN]
        note = next(line for line in bare.guidance if "transport is unknown" in line)
        assert "h:1337" in note  # names which endpoint is unknown

    def test_running_guidance_warns_that_transport_is_unknown(self):
        info = normalize_exercise_env(
            {"isNeedCheck": False, "exposeIps": ["h:1"]}, REF
        )
        assert any("transport is unknown" in line for line in info.guidance)

    def test_not_required_guidance_explains_the_challenge(self):
        info = normalize_exercise_env({"isNeedInit": False}, REF)
        assert any("needs no" in line for line in info.guidance)


class TestEndpointExtraction:
    @pytest.mark.parametrize(
        "key", ["exposeIps", "expose_ips", "endpoints", "access_urls", "targets", "ips", "hosts"]
    )
    def test_documented_endpoint_keys(self, key):
        (endpoint,) = extract_endpoints({key: ["10.0.0.1:8080"]})
        assert (endpoint.host, endpoint.port) == ("10.0.0.1", 8080)

    def test_url_shaped_values_are_kept_as_urls(self):
        (endpoint,) = extract_endpoints({"endpoints": ["http://10.0.0.1:80/app"]})
        assert endpoint.url == "http://10.0.0.1:80/app"
        assert endpoint.port == 80

    def test_host_plus_port_list_becomes_endpoints(self):
        endpoints = extract_endpoints({"ip": "10.0.0.1", "ports": [22, 80]})
        assert {ep.port for ep in endpoints} == {22, 80}

    def test_user_is_carried_when_present(self):
        (endpoint,) = extract_endpoints({"exposeIps": ["h:1"], "users": ["root"]})
        assert endpoint.user == "root"

    def test_nested_structures_are_searched(self):
        (endpoint,) = extract_endpoints({"endpoints": [{"proxy": ["h:9"]}]})
        assert endpoint.port == 9

    @pytest.mark.parametrize("data", [{}, {"exposeIps": []}, {"exposeIps": ["no-port"]}])
    def test_no_endpoint_rather_than_a_half_parsed_one(self, data):
        assert extract_endpoints(data) == ()

    def test_duplicates_are_collapsed(self):
        endpoints = extract_endpoints({"exposeIps": ["h:1", "h:1"]})
        assert len(endpoints) == 1


# ── the exercise tree ─────────────────────────────────────────────────────


class TestExerciseTree:
    def test_category_tree_is_flattened(self):
        payload = [
            {"id": 1, "name": "Web", "corpus": [{"id": 11, "name": "w1"}]},
            {"id": 2, "name": "Pwn", "corpus": [{"id": 21, "name": "p1"}, {"id": 22}]},
        ]
        tree = exercise_tree(payload)
        assert [name for name, _ in tree] == ["Web", "Pwn"]
        assert len(tree[1][1]) == 2

    def test_mapping_body_nesting_the_rows_under_list(self):
        """Some list endpoints put the rows under ``list``/``items`` in the body."""
        tree = exercise_tree({"list": [{"id": 1, "name": "Web", "corpus": []}]})
        assert [name for name, _ in tree] == ["Web"]

    @pytest.mark.parametrize("payload", [None, {}, "x", {"a": 1}, []])
    def test_degenerate_payloads(self, payload):
        assert exercise_tree(payload) == []

    def test_non_mapping_categories_are_skipped(self):
        assert exercise_tree(["junk", {"name": "Web", "corpus": []}])[0][0] == "Web"


# ── adapter behaviour with a fake client ──────────────────────────────────


class FakeClient:
    """Shaped like gcs_platform.client: one surface, envelope already unwrapped.

    Keep every fixture in ``payloads`` in the *unwrapped* shape — that is what
    ``client._request`` returns. Wrapping fixtures in ``{"data": ...}`` is how the
    adapter's double-unwrap survived this suite.
    """

    def __init__(self, *, configured: bool = True, **payloads):
        self._configured = configured
        self.payloads = payloads
        self.calls: list[tuple] = []

    def is_configured(self) -> bool:
        return self._configured

    async def _get(self, name, *args):
        self.calls.append((name, args))
        return self.payloads.get(name, {})

    async def exercise_list(self):
        return await self._get("exercise_list")

    async def exercise(self, exercise_id):
        return await self._get("exercise", exercise_id)

    async def build_environment(self, exercise_id):
        return await self._get("build_environment", exercise_id)

    async def recover_environment(self, exercise_id):
        return await self._get("recover_environment", exercise_id)

    async def submit_answer(self, exercise_id, flag):
        self.calls.append(("submit_answer", (exercise_id, flag)))
        return self.payloads.get("submit_answer", {"isCorrect": True})

    async def match_info(self):
        return await self._get("match_info")

    async def notice_list(self):
        return await self._get("notice_list")

    async def notice_detail(self, notice_id):
        return await self._get("notice_detail", notice_id)

    async def overview(self):
        return await self._get("overview")


TREE = [
    {"name": "Web", "corpus": [{"id": 11, "name": "w1", "hasSolved": True}]},
    {"name": "Pwn", "corpus": [{"id": 21, "name": "p1", "isNeedInit": True}]},
]


class TestAdapterBehaviour:
    async def test_list_corpora_exposes_categories_plus_whole_tree(self):
        adapter = GCSAdapter(FakeClient(exercise_list=TREE))
        tokens = [c.ref.token() for c in await adapter.list_corpora()]
        assert tokens == ["gcs:category:0", "gcs:category:1", "gcs:exercise"]

    async def test_list_challenges_in_a_category(self):
        adapter = GCSAdapter(FakeClient(exercise_list=TREE))
        (challenge,) = await adapter.list_challenges(CorpusRef("gcs", "category", "1"))
        assert challenge.ref.token() == "gcs:exercise:21"
        assert challenge.needs_env is True

    async def test_list_challenges_across_the_whole_tree(self):
        adapter = GCSAdapter(FakeClient(exercise_list=TREE))
        challenges = await adapter.list_challenges(CorpusRef("gcs", "exercise"))
        assert [c.ref.token() for c in challenges] == ["gcs:exercise:11", "gcs:exercise:21"]
        assert challenges[0].solved is True

    async def test_out_of_range_category_is_reported_not_ignored(self):
        adapter = GCSAdapter(FakeClient(exercise_list=TREE))
        with pytest.raises(GCSError):
            await adapter.list_challenges(CorpusRef("gcs", "category", "7"))

    async def test_read_challenge_uses_the_numeric_exercise_id(self):
        client = FakeClient(
            exercise={"name": "p1", "difficulty": "Easy", "isNeedInit": True}
        )
        challenge = await GCSAdapter(client).read_challenge(REF)
        assert challenge.name == "p1"
        assert challenge.needs_env is True
        assert client.calls == [("exercise", (10662,))]

    async def test_start_env_polls_rather_than_trusting_the_ack(self):
        """build-exercise-env is async: an acknowledgement is not the target.

        The poll instruction is asserted on the RENDERED text, not on
        ``info.guidance``: the renderer owns that sentence (see
        tests/platforms/test_no_duplicate_guidance.py), so what matters is that the
        model still reads it — exactly once.
        """
        client = FakeClient(build_environment={"name": "p1"})
        info = await GCSAdapter(client).start_env(REF)
        assert info.state == base.STATE_STARTING
        assert info.complete is False
        head = render_env_info(info).split("\n{", 1)[0]
        assert head.lower().count("poll platform_read_env") == 1
        assert "INCOMPLETE" in head

    async def test_start_env_passes_through_a_ready_payload(self):
        client = FakeClient(
            build_environment={"isNeedCheck": False, "exposeIps": ["h:1"]}
        )
        assert (await GCSAdapter(client).start_env(REF)).usable is True

    async def test_read_env_hits_the_same_upstream_as_read_challenge(self):
        """GCS has no separate target resource; both read the exercise detail."""
        client = FakeClient(
            exercise={"isNeedCheck": False, "exposeIps": ["h:1"]}
        )
        adapter = GCSAdapter(client)
        await adapter.read_env(REF)
        await adapter.read_challenge(REF)
        assert client.calls == [("exercise", (10662,)), ("exercise", (10662,))]

    async def test_stop_env_recovers(self):
        client = FakeClient()
        await GCSAdapter(client).stop_env(REF)
        assert client.calls == [("recover_environment", (10662,))]

    async def test_submit_reads_is_correct(self):
        client = FakeClient(submit_answer={"isCorrect": False})
        result = await GCSAdapter(client).submit_flag(REF, "flag{x}")
        assert result.judged is True
        assert result.accepted is False
        assert client.calls == [("submit_answer", (10662, "flag{x}"))]


# ── optional facets ───────────────────────────────────────────────────────


class TestFacets:
    async def test_event_info_joins_note_and_rule(self):
        client = FakeClient(match_info={"note": "N", "rule": "R"})
        assert await GCSAdapter(client).event_info() == "N\nR"

    async def test_event_info_falls_back_to_the_raw_payload(self):
        client = FakeClient(match_info={"success": True})
        text = await GCSAdapter(client).event_info()
        assert isinstance(text, str) and text

    async def test_notices_lists_or_reads_one(self):
        client = FakeClient(
            notice_list=[{"id": 1, "title": "t"}],
            notice_detail={"id": 2, "title": "d"},
        )
        adapter = GCSAdapter(client)
        assert await adapter.notices() == [{"id": 1, "title": "t"}]
        assert await adapter.notices("2") == {"id": 2, "title": "d"}
        assert client.calls[-1] == ("notice_detail", (2,))

    async def test_notice_id_must_be_numeric(self):
        with pytest.raises(GCSError):
            await GCSAdapter(FakeClient()).notices("abc")

    async def test_overview(self):
        client = FakeClient(overview={"stageRank": "3"})
        assert await GCSAdapter(client).overview() == {"stageRank": "3"}

    def test_notice_from_row(self):
        notice = notice_from_row({"id": 5, "title": "T", "content": "C"})
        assert (notice.id, notice.title, notice.content) == ("5", "T", "C")


class TestSubmitAccepted:
    @pytest.mark.parametrize(
        ("payload", "expected"),
        [
            ({"data": {"isCorrect": True}}, True),
            ({"data": {"isCorrect": False}}, False),
            ({"data": {"accepted": True}}, True),
            ({"isCorrect": True}, True),
            ({"success": False}, False),
            ({"data": None}, False),
            ("junk", False),
        ],
    )
    def test_detection(self, payload, expected):
        assert submit_accepted(payload) is expected


# ── the identity the registry and tool face depend on ─────────────────────


class TestIdentityAndExposure:
    def test_declares_three_gcs_only_capabilities(self):
        adapter = GCSAdapter()
        assert adapter.name == "gcs"
        assert adapter.capabilities == frozenset(
            {base.CAP_EVENT_INFO, base.CAP_NOTICES, base.CAP_OVERVIEW}
        )

    def test_hidden_by_default(self):
        """Legacy integration: registered, but the agent must not see it unasked."""
        assert GCSAdapter().enabled_by_default is False

    @pytest.fixture(autouse=True)
    def _own_registry(self, monkeypatch):
        registry.clear_adapters()
        bootstrap.reset_bootstrap()
        monkeypatch.setattr(
            "vulnclaw.platforms.bootstrap.ensure_adapters",
            lambda force=False: registry.all_adapters(),
        )
        yield
        registry.clear_adapters()
        bootstrap.reset_bootstrap()

    def test_registered_but_not_exposed_by_default(self, monkeypatch):
        registry.register_adapter(GCSAdapter(FakeClient()))
        assert "gcs" in registry.registered_names()
        assert registry.configured_adapters() == {}
        assert platform_tool_schemas() == []

    def test_enabling_it_exposes_the_core_six_plus_its_three_facets(self, monkeypatch):
        monkeypatch.setattr(
            "vulnclaw.platforms.registry._config_enabled", lambda name: True
        )
        registry.register_adapter(GCSAdapter(FakeClient()))
        names = {t["function"]["name"] for t in platform_tool_schemas()}
        assert set(CORE_TOOL_NAMES) <= names
        assert {"platform_event_info", "platform_notices", "platform_overview"} <= names
        # CTF2-only capability must NOT appear when only GCS is exposed.
        assert "platform_submissions" not in names

    def test_ctf2_only_remains_ctf2_only(self, monkeypatch):
        from vulnclaw.platforms.ctf2 import CTF2Adapter

        monkeypatch.setattr(
            "vulnclaw.platforms.registry._config_enabled", lambda name: True
        )
        registry.register_adapter(CTF2Adapter(FakeClient()))
        names = {t["function"]["name"] for t in platform_tool_schemas()}
        assert "platform_submissions" in names
        for gcs_only in ("platform_event_info", "platform_notices", "platform_overview"):
            assert gcs_only not in names

    def test_both_exposed_merges_the_capability_union(self, monkeypatch):
        from vulnclaw.platforms.ctf2 import CTF2Adapter

        monkeypatch.setattr(
            "vulnclaw.platforms.registry._config_enabled", lambda name: True
        )
        registry.register_adapter(CTF2Adapter(FakeClient()))
        registry.register_adapter(GCSAdapter(FakeClient()))
        names = {t["function"]["name"] for t in platform_tool_schemas()}
        assert {
            "platform_submissions",
            "platform_event_info",
            "platform_notices",
            "platform_overview",
        } <= names

    def test_an_unconfigured_gcs_stays_hidden_even_when_enabled(self, monkeypatch):
        monkeypatch.setattr(
            "vulnclaw.platforms.registry._config_enabled", lambda name: True
        )
        registry.register_adapter(GCSAdapter(FakeClient(configured=False)))
        assert platform_tool_schemas() == []
