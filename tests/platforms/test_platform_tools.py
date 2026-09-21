"""The platform-neutral tool face: convergence parity, gates, and the prune fix.

Three things are pinned here:

1. **19-row parity.** Every one of the 19 platform-bound tools must have a home in
   the new face. A row without a destination is lost capability, and the design
   requires all 19 to be accounted for.
2. **The single submit path.** The platform comes from the ref, and the
   irreversible-action gate plus the attempt guard apply to every platform (the
   measured defect was that the gate existed only on the CTF2 path).
3. **The prune regression.** `_infer_allowed_tools` prunes the schema from the
   goal text; a goal containing a task keyword used to drop the entire platform
   face (`n=41, ctf2 in: []`), which is a silent loss of the ability to address
   the platform at all.
"""

from __future__ import annotations

import pytest

from vulnclaw.platforms import base, bootstrap, registry
from vulnclaw.platforms.refs import RefError
from vulnclaw.platforms.tools import (
    CORE_TOOL_NAMES,
    PLATFORM_TOOL_NAMES,
    dispatch_platform_tool,
    platform_tool_schemas,
)

# Every platform-bound tool that existed before this refactor must map somewhere.
OLD_TO_NEW: dict[str, str] = {
    "ctf2_list_practice": "platform_list",
    "ctf2_list_daily": "platform_list",
    "ctf2_read_challenge": "platform_read",
    "ctf2_start_environment": "platform_start_env",
    "ctf2_get_target": "platform_read_env",
    "ctf2_stop_environment": "platform_stop_env",
    "ctf2_submit_flag": "platform_submit",
    "ctf2_list_competitions": "platform_list",
    "ctf2_list_stage_challenges": "platform_list",
    "ctf2_list_submissions": "platform_submissions",
    "gcs_match_info": "platform_event_info",
    "gcs_notice_list": "platform_notices",
    "gcs_notice_detail": "platform_notices",
    "gcs_overview": "platform_overview",
    "gcs_exercise_list": "platform_list",
    "gcs_read_exercise": "platform_read",
    "gcs_build_env": "platform_start_env",
    "gcs_recover_env": "platform_stop_env",
    "gcs_submit_flag": "platform_submit",
}


class FakeAdapter:
    """A minimal but complete adapter: enough to exercise the tool face."""

    def __init__(
        self,
        name: str = "fake",
        *,
        configured: bool = True,
        enabled_by_default: bool = True,
        capabilities: frozenset[str] = frozenset(),
    ) -> None:
        self.name = name
        self.capabilities = capabilities
        self.enabled_by_default = enabled_by_default
        self._configured = configured
        self.calls: list[tuple] = []

    def is_configured(self) -> bool:
        return self._configured

    def make_ref(self, *, kind: str, id: str, group: str = "") -> base.ChallengeRef:
        from vulnclaw.platforms.refs import ChallengeRef

        return ChallengeRef(self.name, kind, group, id)

    def parse_ref(self, tail: str):
        from vulnclaw.platforms.refs import ChallengeRef, parse_fields

        fields = parse_fields(tail)
        if len(fields) == 1:
            return ChallengeRef(self.name, fields[0], "", "")
        if len(fields) == 2:
            return ChallengeRef(self.name, fields[0], fields[1], "")
        return ChallengeRef(self.name, fields[0], fields[1], fields[2])

    async def list_corpora(self):
        from vulnclaw.platforms.refs import CorpusRef

        return [base.Corpus(ref=CorpusRef(self.name, "practice", "1"), name="ground", count=2)]

    async def list_challenges(self, corpus):
        from vulnclaw.platforms.refs import ChallengeRef

        return [
            base.Challenge(
                ref=ChallengeRef(self.name, "practice", corpus.id, "9"),
                name="a challenge",
                category="web",
                difficulty="Easy",
                score="100",
                needs_env=True,
            )
        ]

    async def read_challenge(self, ref):
        return base.Challenge(
            ref=ref,
            name="read me",
            description="some description",
            attachments=(base.Attachment(name="a.zip", url="http://x/a.zip", size=12),),
            raw={"ok": True},
        )

    async def start_env(self, ref):
        return base.EnvInfo(ref=ref, state=base.STATE_STARTING, complete=False, raw={"s": 1})

    async def read_env(self, ref):
        return base.EnvInfo(
            ref=ref,
            state=base.STATE_RUNNING,
            complete=True,
            endpoints=(base.EnvEndpoint(host="h", port=1, transport=base.TRANSPORT_TLS),),
        )

    async def stop_env(self, ref):
        self.calls.append(("stop_env", ref.token()))

    async def submit_flag(self, ref, flag):
        self.calls.append(("submit_flag", ref.token(), flag))
        return base.SubmitResult(accepted=flag.endswith("good}"), judged=True)

    async def submissions(self, limit: int = 20):
        return [{"id": "s1"}]

    async def event_info(self) -> str:
        return "rules"

    async def notices(self, notice_id=None):
        return {"id": notice_id or "all"}

    async def overview(self):
        return {"rank": 1}


@pytest.fixture(autouse=True)
def _controlled_registry(monkeypatch):
    """Own the registry: never let the built-in bootstrap auto-register CTF2."""
    registry.clear_adapters()
    bootstrap.reset_bootstrap()
    monkeypatch.setattr(
        "vulnclaw.platforms.bootstrap.ensure_adapters",
        lambda force=False: registry.all_adapters(),
    )
    yield
    registry.clear_adapters()
    bootstrap.reset_bootstrap()


@pytest.fixture
def fake():
    adapter = FakeAdapter()
    registry.register_adapter(adapter)
    return adapter


# ── parity ────────────────────────────────────────────────────────────────


class TestParityWithTheOldToolFace:
    def test_all_nineteen_old_tools_are_accounted_for(self):
        assert len(OLD_TO_NEW) == 19

    def test_the_table_matches_the_real_old_tool_names(self):
        """Guards against the table drifting from the names it claims to cover."""
        from vulnclaw.ctf_platform.tools import CTF_TOOL_NAMES
        from vulnclaw.gcs_platform.tools import GCS_TOOL_NAMES

        assert set(OLD_TO_NEW) == set(CTF_TOOL_NAMES) | set(GCS_TOOL_NAMES)

    def test_every_destination_exists_in_the_new_face(self):
        for old, new in OLD_TO_NEW.items():
            assert new in PLATFORM_TOOL_NAMES, f"{old} -> {new} does not exist"

    def test_core_destinations_are_the_six_verbs(self):
        destinations = {new for new in OLD_TO_NEW.values()} 
        core_hits = destinations & set(CORE_TOOL_NAMES)
        assert core_hits == set(CORE_TOOL_NAMES)

    def test_optional_destinations_are_capability_gated(self):
        optional = set(OLD_TO_NEW.values()) - set(CORE_TOOL_NAMES)
        assert optional == {
            "platform_submissions",
            "platform_event_info",
            "platform_notices",
            "platform_overview",
        }

    def test_no_old_tool_name_is_its_own_destination(self):
        """The whole point: the new names carry no platform."""
        for new in OLD_TO_NEW.values():
            assert "ctf2" not in new and "gcs" not in new


# ── schema exposure ───────────────────────────────────────────────────────


class TestSchemaExposure:
    def test_nothing_configured_means_no_tools(self):
        assert platform_tool_schemas() == []

    def test_core_six_appear_when_a_platform_is_configured(self, fake):
        names = {t["function"]["name"] for t in platform_tool_schemas()}
        assert set(CORE_TOOL_NAMES) <= names

    def test_optional_tools_follow_declared_capabilities(self):
        registry.register_adapter(
            FakeAdapter(
                "withcaps",
                capabilities=frozenset(
                    {base.CAP_SUBMISSIONS, base.CAP_EVENT_INFO, base.CAP_OVERVIEW}
                ),
            )
        )
        names = {t["function"]["name"] for t in platform_tool_schemas()}
        assert {"platform_submissions", "platform_event_info", "platform_overview"} <= names
        assert "platform_notices" not in names

    def test_a_disabled_platform_exposes_nothing(self):
        registry.register_adapter(FakeAdapter("off", enabled_by_default=False))
        assert platform_tool_schemas() == []

    def test_unconfigured_platform_exposes_nothing(self):
        registry.register_adapter(FakeAdapter("nokey", configured=False))
        assert platform_tool_schemas() == []

    def test_every_schema_has_a_handler(self, fake):
        for tool in platform_tool_schemas():
            assert tool["function"]["name"] in PLATFORM_TOOL_NAMES


# ── dispatch ──────────────────────────────────────────────────────────────


class TestDispatchGuards:
    async def test_missing_ref_is_explained(self, fake):
        out = await dispatch_platform_tool("platform_read", {})
        assert "missing `ref`" in out

    async def test_bare_id_is_refused(self, fake):
        out = await dispatch_platform_tool("platform_read", {"ref": "9"})
        assert "no platform prefix" in out

    async def test_unknown_platform_lists_what_exists(self, fake):
        out = await dispatch_platform_tool("platform_read", {"ref": "nope:1"})
        assert "fake" in out

    async def test_unknown_tool_name(self, fake):
        assert "unknown platform tool" in await dispatch_platform_tool("platform_nope", {})

    async def test_no_configured_platform(self):
        out = await dispatch_platform_tool("platform_list", {})
        assert "no CTF platform is configured" in out


class TestDispatchBehaviour:
    async def test_list_without_ref_lists_collections(self, fake):
        out = await dispatch_platform_tool("platform_list", {})
        assert "fake:practice:1" in out

    async def test_list_with_ref_lists_challenges(self, fake):
        out = await dispatch_platform_tool("platform_list", {"ref": "fake:practice:1"})
        assert "fake:practice:1:9" in out

    async def test_read_renders_the_ref_and_attachments(self, fake):
        out = await dispatch_platform_tool("platform_read", {"ref": "fake:practice:1:9"})
        assert "fake:practice:1:9" in out
        assert "a.zip" in out
        assert "http://x/a.zip" in out

    async def test_start_env_renders_incomplete_state(self, fake):
        out = await dispatch_platform_tool("platform_start_env", {"ref": "fake:practice:1:9"})
        assert "INCOMPLETE" in out

    async def test_read_env_renders_tls_guidance(self, fake):
        out = await dispatch_platform_tool("platform_read_env", {"ref": "fake:practice:1:9"})
        assert "TLS-WRAPPED" in out
        assert "wrap_socket" in out

    async def test_stop_env_calls_the_adapter(self, fake):
        out = await dispatch_platform_tool("platform_stop_env", {"ref": "fake:practice:1:9"})
        assert "released" in out
        assert ("stop_env", "fake:practice:1:9") in fake.calls

    async def test_submissions_uses_the_capable_adapter(self):
        registry.register_adapter(FakeAdapter("s", capabilities=frozenset({base.CAP_SUBMISSIONS})))
        out = await dispatch_platform_tool("platform_submissions", {})
        assert '"s1"' in out

    async def test_submissions_without_capability(self, fake):
        out = await dispatch_platform_tool("platform_submissions", {})
        assert "no configured platform exposes" in out

    async def test_notices_and_overview_and_event_info(self):
        registry.register_adapter(
            FakeAdapter(
                "g",
                capabilities=frozenset(
                    {base.CAP_NOTICES, base.CAP_OVERVIEW, base.CAP_EVENT_INFO}
                ),
            )
        )
        assert "rules" in await dispatch_platform_tool("platform_event_info", {})
        assert "all" in await dispatch_platform_tool("platform_notices", {})
        assert "rank" in await dispatch_platform_tool("platform_overview", {})

    async def test_adapter_exception_becomes_text_not_a_crash(self, fake):
        async def boom(ref):
            raise RuntimeError("platform exploded")

        fake.read_challenge = boom
        out = await dispatch_platform_tool("platform_read", {"ref": "fake:practice:1:9"})
        assert "platform exploded" in out
        assert out.startswith("[platform]")


class TestSubmitPath:
    async def test_submission_is_off_by_default(self, fake, monkeypatch):
        monkeypatch.setattr(
            "vulnclaw.platforms.tools._flag_submission_enabled", lambda: False
        )
        out = await dispatch_platform_tool(
            "platform_submit", {"ref": "fake:practice:1:9", "flag": "flag{good}"}
        )
        assert "platform_submit_disabled" in out
        assert fake.calls == []  # nothing reached the platform

    async def test_flag_gate_is_fail_closed_on_config_error(self, monkeypatch):
        from vulnclaw.platforms import tools as platform_tools

        def boom(*a, **k):
            raise RuntimeError("no config")

        monkeypatch.setattr("vulnclaw.config.settings.load_config", boom)
        assert platform_tools._flag_submission_enabled() is False

    async def test_accepted_flag_is_reported(self, fake, monkeypatch):
        monkeypatch.setattr(
            "vulnclaw.platforms.tools._flag_submission_enabled", lambda: True
        )
        monkeypatch.setattr("vulnclaw.platforms.tools.get_guard", _fresh_guard)
        out = await dispatch_platform_tool(
            "platform_submit", {"ref": "fake:practice:1:9", "flag": "flag{good}"}
        )
        assert "ACCEPTED" in out
        assert ("submit_flag", "fake:practice:1:9", "flag{good}") in fake.calls

    async def test_rejected_flag_is_reported(self, fake, monkeypatch):
        monkeypatch.setattr(
            "vulnclaw.platforms.tools._flag_submission_enabled", lambda: True
        )
        monkeypatch.setattr("vulnclaw.platforms.tools.get_guard", _fresh_guard)
        out = await dispatch_platform_tool(
            "platform_submit", {"ref": "fake:practice:1:9", "flag": "flag{bad}"}
        )
        assert "not accepted" in out

    async def test_missing_flag_is_rejected_before_the_platform(self, fake, monkeypatch):
        monkeypatch.setattr(
            "vulnclaw.platforms.tools._flag_submission_enabled", lambda: True
        )
        out = await dispatch_platform_tool("platform_submit", {"ref": "fake:practice:1:9"})
        assert "`flag` is required" in out
        assert fake.calls == []

    async def test_infrastructure_failure_consumes_no_attempt(self, fake, monkeypatch):
        from vulnclaw.platforms.submit_guard import SubmitGuard

        guard = SubmitGuard()
        monkeypatch.setattr(
            "vulnclaw.platforms.tools._flag_submission_enabled", lambda: True
        )
        monkeypatch.setattr("vulnclaw.platforms.tools.get_guard", lambda: guard)

        async def boom(ref, flag):
            raise RuntimeError("network down")

        fake.submit_flag = boom
        out = await dispatch_platform_tool(
            "platform_submit", {"ref": "fake:practice:1:9", "flag": "flag{x}"}
        )
        assert "network down" in out
        assert guard.attempts("fake:practice:1:9") == 0

    async def test_guard_blocks_a_repeat_of_a_failed_flag(self, fake, monkeypatch):
        from vulnclaw.platforms.submit_guard import SubmitGuard

        guard = SubmitGuard()
        guard.record("fake:practice:1:9", accepted=False, flag="flag{same}")
        monkeypatch.setattr(
            "vulnclaw.platforms.tools._flag_submission_enabled", lambda: True
        )
        monkeypatch.setattr("vulnclaw.platforms.tools.get_guard", lambda: guard)
        out = await dispatch_platform_tool(
            "platform_submit", {"ref": "fake:practice:1:9", "flag": "flag{same}"}
        )
        assert "[submit_blocked]" in out
        assert "anti brute-force" in out


def _fresh_guard():
    from vulnclaw.platforms.submit_guard import SubmitGuard

    return SubmitGuard()


# ── the prune regression (measured bug) ───────────────────────────────────


class TestPruneRegression:
    WEB_GOAL = "Solve this web challenge, the login password parameter is injectable http://x/y"

    def test_core_platform_tools_survive_a_web_keyword_goal(self):
        """Measured before the fix: n=41 and zero platform tools survived.

        A model that cannot see a platform tool cannot address the platform, and
        nothing in the output says so.
        """
        from vulnclaw.agent.builtin_tools import _infer_allowed_tools

        allowed = _infer_allowed_tools(self.WEB_GOAL)
        assert allowed is not None, "this goal is expected to trigger pruning"
        missing = [name for name in CORE_TOOL_NAMES if name not in allowed]
        assert missing == []

    def test_core_platform_tools_are_pinned_in_always_keep(self):
        from vulnclaw.agent.builtin_tools import _ALWAYS_KEEP_TOOLS

        assert set(CORE_TOOL_NAMES) <= set(_ALWAYS_KEEP_TOOLS)

    @pytest.mark.parametrize(
        "goal",
        [
            "解密这段 base64 密文",
            "分析这个源码，审计 PHP 代码",
            "对 10.0.0.1 做端口扫描和子域名枚举",
            "找出这个二进制里的漏洞",
        ],
    )
    def test_pinned_across_task_types(self, goal):
        from vulnclaw.agent.builtin_tools import _infer_allowed_tools

        allowed = _infer_allowed_tools(goal)
        if allowed is None:
            pytest.skip("this goal keeps every tool")
        assert set(CORE_TOOL_NAMES) <= allowed

    def test_the_old_platform_names_are_still_prunable(self):
        """Proof the fix is targeted: it pins the neutral face, not the old names."""
        from vulnclaw.agent.builtin_tools import _infer_allowed_tools

        allowed = _infer_allowed_tools(self.WEB_GOAL)
        assert allowed is not None
        assert "ctf2_read_challenge" not in allowed


def test_ref_error_is_a_value_error():
    """A bad ref must be catchable as a plain ValueError by callers."""
    assert issubclass(RefError, ValueError)
