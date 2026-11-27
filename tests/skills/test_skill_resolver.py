"""Tests for the deterministic skill resolver (PRD #42).

Table-driven, not prompt snapshots: catalog validation, explicit routing,
positive/conflict/negative examples, bundle budget, prompt integration, and
skill-provenance auditability.
"""

import pytest

from vulnclaw.skills.resolver import (
    SkillProfile,
    SkillQuery,
    SkillResolver,
    build_catalog,
)
from vulnclaw.skills.routing import SkillRouting, normalize_token


@pytest.fixture(scope="module")
def catalog():
    return build_catalog()


@pytest.fixture(scope="module")
def resolver(catalog):
    return SkillResolver(catalog)


# ── Routing schema ───────────────────────────────────────────────────


class TestSkillRouting:
    def test_normalization_maps_free_text_to_canonical(self):
        assert normalize_token("SQL Injection") == "sqli"
        assert normalize_token("sql注入") == "sqli"
        assert normalize_token("Node.js") == "nodejs"
        assert normalize_token("post-exploitation") == "post_exploitation"

    def test_valid_routing_has_no_warnings(self):
        r = SkillRouting.model_validate(
            {
                "target_types": ["Web", "api"],
                "vulnerability_classes": ["SQL Injection", "xss"],
                "phases": ["vuln-discovery"],
            }
        )
        assert r.warnings == []
        assert "sqli" in r.vulnerability_classes
        assert "web" in r.target_types
        assert "vuln_discovery" in r.phases

    def test_unknown_enum_token_warns_not_raises(self):
        r = SkillRouting.model_validate({"vulnerability_classes": ["not_a_real_class"]})
        assert r.vulnerability_classes == []
        assert any("unknown token" in w for w in r.warnings)

    def test_unknown_role_falls_back_to_primary(self):
        r = SkillRouting.model_validate({"role": "captain"})
        assert r.role == "primary"
        assert any("role" in w for w in r.warnings)

    def test_empty_routing_is_empty(self):
        assert SkillRouting().is_empty()


# ── Catalog validation ───────────────────────────────────────────────


class TestCatalog:
    def test_every_skill_becomes_a_profile(self, catalog):
        assert len(catalog) >= 20
        for name, profile in catalog.items():
            assert isinstance(profile, SkillProfile)
            assert profile.name == name

    def test_no_shipped_skill_has_routing_warnings(self, catalog):
        """Unknown enum tokens in shipped frontmatter fail CI."""
        offenders = {n: p.routing.warnings for n, p in catalog.items() if p.routing.warnings}
        assert offenders == {}, f"routing warnings: {offenders}"

    def test_legacy_skills_without_routing_still_load(self, catalog):
        # A skill with no routing block validates into an empty SkillRouting.
        crypto = catalog.get("crypto-toolkit")
        assert crypto is not None
        assert crypto.routing.is_empty()

    def test_known_skills_have_typed_routing(self, catalog):
        assert "web" in catalog["web-security-advanced"].routing.target_types
        assert "sqli" in catalog["web-security-advanced"].routing.vulnerability_classes
        assert catalog["secknowledge-skill"].routing.broad is True
        assert catalog["pentest-flow"].routing.role == "fallback"


# ── Explicit invocation ──────────────────────────────────────────────


class TestExplicit:
    def test_use_vulnclaw_skill_phrase_wins(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("Use VulnClaw skill ctf-web to solve this"))
        assert s.primary == "ctf-web"
        assert s.confidence == 1.0

    def test_slash_command_wins(self, resolver):
        # /ctf-crypto should win even though the text screams web/sqli.
        s = resolver.resolve(SkillQuery.from_input("/ctf-crypto sql注入 xss rce 测试"))
        assert s.primary == "ctf-crypto"

    def test_explicit_unknown_skill_ignored(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("/not-a-skill sql注入 测试"))
        assert s.primary == "web-security-advanced"


# ── Positive examples (typed metadata) ──────────────────────────────

POSITIVE_CASES = [
    ("web injection", dict(target_type="web", vuln_hints=["sqli", "xss"]), "web-security-advanced"),
    ("ctf web", dict(target_type="ctf", task_types=["ctf"], vuln_hints=["ssti"]), "ctf-web"),
    ("ai/mcp", dict(target_type="ai_agent", vuln_hints=["prompt_injection"]), "ai-mcp-security"),
    ("client reverse", dict(target_type="client", task_types=["reverse"]), "client-reverse"),
    ("android", dict(target_type="android", task_types=["pentest"]), "android-pentest"),
    (
        "intranet",
        dict(target_type="intranet", vuln_hints=["lateral_movement"], phase="post_exploitation"),
        "intranet-pentest-advanced",
    ),
    ("crypto ctf", dict(target_type="crypto", task_types=["crypto"]), "ctf-crypto"),
    ("cve triage", dict(task_types=["triage"], phase="vuln_discovery"), "cve-triage"),
    ("osint", dict(task_types=["osint"], phase="recon"), "osint-recon"),
    ("reporting", dict(task_types=["report"], phase="reporting"), "reporting"),
    # Alias-driven: 知识竞赛/quiz text routes to the knowledge-quiz skill.
    ("知识竞赛理论题", dict(), "knowledge-quiz"),
    ("security quiz", dict(), "knowledge-quiz"),
    # Alias/typed-driven: defensive hardening routes to security-hardening.
    ("安全加固", dict(), "security-hardening"),
    ("security hardening baseline", dict(), "security-hardening"),
    ("host hardening", dict(target_type="host", task_types=["audit"]), "security-hardening"),
]


class TestPositive:
    @pytest.mark.parametrize("label,fields,expected", POSITIVE_CASES, ids=[c[0] for c in POSITIVE_CASES])
    def test_expected_primary(self, resolver, label, fields, expected):
        s = resolver.resolve(SkillQuery(text=label, **fields))
        assert s.primary == expected, f"{label}: got {s.primary} ({s.reason})"
        assert s.confidence > 0

    def test_typed_signal_recorded_in_reason(self, resolver):
        s = resolver.resolve(SkillQuery(text="x", target_type="web", vuln_hints=["sqli"]))
        assert any("vuln=sqli" in sig or "target=web" in sig for sig in s.signals)


# ── Conflict resolution ──────────────────────────────────────────────


class TestConflict:
    def test_ctf_web_beats_generic_web_methodology_on_flag(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("flag 弱比较 preg_match绕过 highlight_file"))
        assert s.primary == "ctf-web"

    def test_client_reverse_beats_web_testing_while_replay_blocked(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("客户端签名 无法重放，需要逆向请求链"))
        assert s.primary == "client-reverse"

    def test_web_security_resumes_once_replay_stable(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("重放已稳定，继续 sql注入 xss 测试"))
        assert s.primary == "web-security-advanced"

    def test_broad_kb_never_eclipses_precise_skill_on_tie(self, catalog):
        """A broad KB tied with a precise skill loses the tie-break."""
        resolver = SkillResolver(catalog)
        # Construct a tie via typed signals both share, then confirm the narrow
        # skill (non-broad) is primary and the broad KB rides as support.
        s = resolver.resolve(SkillQuery(text="pentest", target_type="web", task_types=["pentest"]))
        assert s.primary != "secknowledge-skill"
        assert not catalog[s.primary].routing.broad


# ── Negative ─────────────────────────────────────────────────────────


class TestNegative:
    def test_non_security_text_injects_nothing(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("你好今天天气怎么样"))
        assert s.primary is None
        assert s.is_empty()

    def test_generic_pentest_falls_back_to_pentest_flow(self, resolver):
        # Pentest-like signal ("security") but no skill-specific keyword hit.
        s = resolver.resolve(SkillQuery(text="please do a security assessment here"))
        assert s.primary == "pentest-flow"
        assert "fallback" in s.reason


# ── Bundle budget ────────────────────────────────────────────────────


class TestBudget:
    def test_selection_never_exceeds_one_primary_two_support(self, resolver):
        # A signal-rich query that could match many skills.
        s = resolver.resolve(
            SkillQuery(
                text="sql注入 xss rce ssti 逆向 内网 报告",
                target_type="web",
                vuln_hints=["sqli", "xss", "rce"],
            )
        )
        assert s.primary is not None
        assert len(s.supporting) <= 2
        assert len(s.all_skill_ids()) <= 3


# ── Prompt integration ───────────────────────────────────────────────


class TestPromptIntegration:
    def test_context_includes_reference_index_not_skill_body(self):
        from vulnclaw.agent.skill_context import get_active_skill_context

        ctx = get_active_skill_context("对这个APP做逆向分析")
        assert ctx is not None
        assert "optional reference material only" in ctx.lower()
        assert "primary reference: client-reverse" in ctx
        # resolver reason embedded as reference routing metadata
        assert "reference routing:" in ctx
        # reference hints are on-demand
        assert "load_skill_reference" in ctx
        # not the whole corpus: unrelated markers and primary workflow body are absent
        assert "GAARM" not in ctx
        assert "## 当前 Skill" not in ctx

    def test_non_security_input_yields_no_context(self):
        from vulnclaw.agent.skill_context import get_active_skill_context

        assert get_active_skill_context("你好今天天气怎么样") is None

    def test_no_input_yields_no_default_playbook(self):
        from vulnclaw.agent.skill_context import get_active_skill_context

        assert get_active_skill_context(None) is None


# ── Auditability / provenance ────────────────────────────────────────


class TestProvenance:
    def test_selection_to_provenance_is_structured(self, resolver):
        s = resolver.resolve(SkillQuery(text="x", target_type="web", vuln_hints=["sqli"]))
        prov = s.to_provenance(loaded_references=["web-injection.md"])
        assert prov["primary"] == s.primary
        assert prov["references_loaded"] == ["web-injection.md"]
        assert "reason" in prov and "confidence" in prov

    def test_finding_records_active_selection(self, resolver):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding

        state = SessionState(target="http://example.com")
        selection = resolver.resolve(SkillQuery(text="x", target_type="web", vuln_hints=["sqli"]))
        changed = state.set_active_skill_selection(selection.to_provenance())
        assert changed is True

        state.add_finding(VulnerabilityFinding(title="SQLi", vuln_type="SQLi", evidence="e"))
        prov = state.findings[0].skill_provenance
        assert prov is not None
        assert prov["primary"] == selection.primary

    def test_selection_change_emits_run_event(self, resolver):
        from vulnclaw.agent.context import SessionState

        state = SessionState()
        state.set_active_skill_selection({"primary": "web-security-advanced", "supporting": []})
        state.set_active_skill_selection({"primary": "ctf-web", "supporting": []})
        assert len(state.skill_selection_events) == 2
        assert state.skill_selection_events[-1]["primary"] == "ctf-web"

    def test_no_event_when_selection_unchanged(self, resolver):
        from vulnclaw.agent.context import SessionState

        state = SessionState()
        prov = {"primary": "ctf-web", "supporting": []}
        state.set_active_skill_selection(prov)
        state.set_active_skill_selection(dict(prov))
        assert len(state.skill_selection_events) == 1

    def test_explicit_finding_provenance_not_overwritten(self, resolver):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding

        state = SessionState()
        state.set_active_skill_selection({"primary": "web-security-advanced", "supporting": []})
        finding = VulnerabilityFinding(
            title="X", vuln_type="XSS", evidence="e", skill_provenance={"primary": "ctf-web"}
        )
        state.add_finding(finding)
        assert state.findings[0].skill_provenance["primary"] == "ctf-web"


# ── Child-agent task summary ─────────────────────────────────────────


class TestChildAgent:
    def test_task_summary_feeds_routing(self, resolver):
        # No user text, only a child-agent task summary.
        s = resolver.resolve(SkillQuery(text="", task_summary="逆向客户端签名并稳定重放"))
        assert s.primary == "client-reverse"


# ── Runtime wiring (skill_context ↔ session state) ──────────────────


class TestRuntimeWiring:
    def _state(self, **kw):
        from vulnclaw.agent.context import PentestPhase, SessionState

        state = SessionState(**kw)
        return state, PentestPhase

    def test_apply_derives_typed_signals_from_state(self):
        from vulnclaw.agent.skill_context import apply_skill_selection

        state, Phase = self._state(target="http://shop.example.com")
        state.phase = Phase.VULN_DISCOVERY
        ctx = apply_skill_selection(state, "测试SQL注入")
        assert ctx is not None
        # Provenance recorded and consistent with a web injection bundle.
        prov = state.active_skill_selection
        assert prov is not None
        assert prov["primary"] == "web-security-advanced"

    def test_apply_records_provenance_matching_context(self):
        from vulnclaw.agent.skill_context import apply_skill_selection

        state, Phase = self._state()
        ctx = apply_skill_selection(state, "对这个APP做逆向分析")
        assert state.active_skill_selection["primary"] == "client-reverse"
        # The recorded reason is embedded in the very context that was returned.
        assert state.active_skill_selection["reason"].split(" ")[0] in ctx
        assert "optional reference material only" in ctx.lower()

    def test_ascii_vuln_hint_requires_token_boundary(self):
        """`rce` must not fire inside `source` (non-security input stays clean)."""
        from vulnclaw.agent.skill_context import (
            _extract_vuln_hints,
            get_active_skill_context,
        )

        assert _extract_vuln_hints("show me the source code") == []
        assert _extract_vuln_hints("test for rce here") == ["rce"]
        assert get_active_skill_context("show me the source code") is None

    def test_desktop_client_text_routes_to_desktop(self):
        """Electron/ASAR goals must not be inferred as plain web targets.

        Measured 2026-11-04: `_infer_target_type` only knew web/network/android,
        so an audit goal for an Electron client with a local CDP URL inferred
        `web` and the desktop/client skill could never be selected by routing.
        """
        from vulnclaw.agent.skill_context import _infer_target_type

        assert _infer_target_type(None, "审计 Electron 客户端 app.asar") == "desktop"
        assert _infer_target_type(None, "pc客户端 桌面客户端 安全评估") == "desktop"
        assert _infer_target_type("C:/tools/WorkBuddy/app.exe", "") == "desktop"
        assert (
            _infer_target_type("http://127.0.0.1:9223", "审计 WorkBuddy Desktop Electron/MCP Apps")
            == "desktop"
        )

    def test_plain_web_target_stays_web(self):
        from vulnclaw.agent.skill_context import _infer_target_type

        assert _infer_target_type("https://target.example.com", "web pentest") == "web"
        assert _infer_target_type("10.0.0.5", "network scan") == "network"

    def test_electron_mention_does_not_reroute_a_web_target(self):
        """The desktop marker must not swallow ordinary web work.

        `electron` also names the page engine: a host called electron.example.com,
        or a web page that merely happens to run inside Electron, is still a web
        target. Only a client word next to it makes it desktop.
        """
        from vulnclaw.agent.skill_context import _infer_target_type

        assert _infer_target_type("https://electron.example.com", "web pentest") == "web"
        assert (
            _infer_target_type(
                "https://target.example.com", "审计使用 Electron 打开的 Web 页面"
            )
            == "web"
        )

    def test_desktop_request_selects_a_specialized_skill(self):
        """Inference is useless unless the resolver actually picks a skill.

        Measured 2026-11-04: `_infer_target_type` returned `desktop` for Electron
        goals but no skill declared that target type, so every such request fell
        through to the generic pentest-flow fallback.
        """
        from vulnclaw.agent.skill_context import resolve_active_skill_selection

        selection = resolve_active_skill_selection(
            "审计 Electron 客户端 app.asar", target="C:/tools/WorkBuddy/app.exe"
        )
        assert selection is not None
        assert selection.primary == "client-reverse"

        selection = resolve_active_skill_selection(
            "审计 WorkBuddy Desktop Electron/MCP Apps",
            target="http://127.0.0.1:9223",
        )
        assert selection is not None
        assert selection.primary == "client-reverse"

    def test_electron_technology_is_extracted(self):
        from vulnclaw.agent.skill_context import _extract_technologies

        assert "electron" in _extract_technologies("Electron desktop client", None)

    def test_ascii_tech_keyword_requires_token_boundary(self):
        from vulnclaw.agent.skill_context import _extract_technologies

        # "java" must not match inside "javascript".
        assert "java" not in _extract_technologies("a javascript app", None)
        assert "java" in _extract_technologies("a java app", None)

    def test_chinese_ai_wording_is_a_vuln_hint(self):
        """Chinese challenge text says 提示词注入, not "prompt injection".

        Measured 2026-10-30: the hint table only had ``prompt注入``/``prompt
        injection``, so a Chinese AI-injection challenge produced no vuln hint at
        all and the router only had ``target=web`` to go on.
        """
        from vulnclaw.agent.skill_context import _extract_vuln_hints

        assert "prompt_injection" in _extract_vuln_hints("提示词注入：让目标泄露系统提示")
        assert "prompt_injection" in _extract_vuln_hints("提示注入 of the system prompt")
        assert "prompt_injection" in _extract_vuln_hints("这是一个越狱题")
        assert "tool_abuse" in _extract_vuln_hints("测试越权工具调用")

    def test_chinese_ai_challenge_reaches_the_ai_skill(self):
        """An attachment-shaped 人工智能 challenge must reach ctf-ai, not intranet.

        Measured 2026-10-30: ``强网杯 人工智能 方向：附件 model.pth`` resolved to
        intranet-pentest-advanced (keywords:0.21) before the 人工智能 keyword group
        existed.
        """
        from vulnclaw.agent.skill_context import resolve_active_skill_selection

        s = resolve_active_skill_selection(
            "强网杯 人工智能 方向：附件 model.pth，请在模型里找到 flag"
        )
        assert s is not None and s.primary == "ctf-ai", s.reason if s else None

    def test_chinese_injection_goal_with_url_keeps_the_ai_skill_in_the_bundle(self):
        """A URL alone must not evict the AI skill from the bundle.

        ``target=web`` carries TYPED_WEIGHT 3.0, which keeps web-security-advanced
        primary (its references now carry the injection recipe). The AI skill must
        still ride along as support, and the vuln hint must be visible in the
        reason -- otherwise the run has no signal that this is an AI target.
        """
        from vulnclaw.agent.skill_context import resolve_active_skill_selection

        s = resolve_active_skill_selection(
            "提示词注入：访问目标的聊天接口，获取系统提示里的 flag",
            target="http://10.0.0.5:8080",
        )
        assert s is not None
        assert s.primary == "web-security-advanced"
        assert "ai-mcp-security" in s.supporting
        assert "vuln=prompt_injection" in s.reason

    def test_finding_provenance_not_mutated_by_later_reference(self):
        """A reference loaded after a finding must not rewrite its provenance."""
        from vulnclaw.agent.context import VulnerabilityFinding
        from vulnclaw.agent.skill_context import apply_skill_selection

        state, _ = self._state()
        apply_skill_selection(state, "对这个APP做逆向分析")
        state.add_finding(VulnerabilityFinding(title="A", vuln_type="Recon", evidence="e"))
        # Reference loaded AFTER the finding was recorded.
        state.record_loaded_reference("client-reverse", "02-client-api-reverse-and-burp.md")
        assert state.findings[0].skill_provenance["references_loaded"] == []

    def test_non_security_input_records_no_selection(self):
        from vulnclaw.agent.skill_context import apply_skill_selection

        state, _ = self._state()
        ctx = apply_skill_selection(state, "你好今天天气怎么样")
        assert ctx is None
        assert state.active_skill_selection is None

    def test_loaded_reference_recorded_on_provenance(self):
        from vulnclaw.agent.skill_context import apply_skill_selection

        state, _ = self._state()
        apply_skill_selection(state, "对这个APP做逆向分析")
        state.record_loaded_reference("client-reverse", "02-client-api-reverse-and-burp.md")
        loaded = state.active_skill_selection["references_loaded"]
        assert "client-reverse/02-client-api-reverse-and-burp.md" in loaded

    def test_clearing_selection_emits_clear_event(self):
        from vulnclaw.agent.context import SessionState

        state = SessionState()
        state.set_active_skill_selection({"primary": "ctf-web", "supporting": []})
        changed = state.set_active_skill_selection(None)
        assert changed is True
        assert state.skill_selection_events[-1]["kind"] == "skill_selection_cleared"

    def test_unchanged_bundle_preserves_loaded_references(self):
        from vulnclaw.agent.context import SessionState

        state = SessionState()
        state.set_active_skill_selection(
            {"primary": "ctf-web", "supporting": [], "references_loaded": ["ctf-web/a.md"]}
        )
        # Re-resolve to the same bundle (fresh provenance without refs).
        state.set_active_skill_selection({"primary": "ctf-web", "supporting": []})
        assert state.active_skill_selection["references_loaded"] == ["ctf-web/a.md"]


class TestHardeningRouting:
    def test_safety_hardening_routes_to_hardening(self, resolver):
        s = resolver.resolve(SkillQuery(text="安全加固：系统/中间件加固、漏洞修复、权限配置"))
        assert s.primary == "security-hardening"

    def test_ir_goal_mentioning_hardening_stays_ir(self, resolver):
        """An IR answer round that includes a hardening sub-question must not
        be stolen by the new hardening skill."""
        s = resolver.resolve(SkillQuery(text="应急响应：排查后门并加固"))
        assert s.primary == "incident-response"

    def test_explicit_hardening_still_wins_over_ir_vocabulary(self, resolver):
        s = resolver.resolve(SkillQuery(text="安全加固：清除后门并修权限"))
        assert s.primary == "security-hardening"


# ── ctf-endgame reachability (2026-11-23) ────────────────────────────
#
# Measured at入库时: the skill declared `target_types:[ctf]` / `task_types:[ctf]`
# and therefore tied with ctf-ai on typed weight (3.0 + 1.8). The tie-break is
# alphabetical, so EVERY generic CTF query landed on ctf-ai and ctf-endgame was
# never selected — a skill nobody can reach is not in the library. The fix was
# four short keyword groups taken from the phrases the four buried cases were
# actually described with (ezphp's operator wrote 差临门一脚 verbatim).


class TestCtfEndgameIsReachable:
    @pytest.mark.parametrize(
        "text",
        [
            # ezphp 2026-10-31, the operator's own words
            "这个 PHP2shell 已经知道是那个漏洞了，但是就是差临门一脚",
            # Crate-CTF 2026-11-22: two rounds ended with every angle ruled out
            "CTF 收尾，所有路径都判死了，比赛快结束",
            "libc 泄漏已打通，卡在最后一步：没有代码调用堆指针",
            "stuck at the last step, all paths ruled out",
        ],
    )
    def test_endgame_phrasings_select_the_skill(self, resolver, text):
        selection = resolver.resolve(
            SkillQuery.from_input(text, target_type="ctf", task_types=["ctf"])
        )
        assert selection.primary == "ctf-endgame", (
            f"{text!r} → {selection.primary}; ctf-endgame would be unreachable "
            "for the exact phrasing it was written for"
        )

    def test_house_of_husk_routes_to_pwn(self, resolver):
        """Celldelning's official solve: largebin attack into printf's tables."""
        selection = resolver.resolve(
            SkillQuery.from_input(
                "largebin attack 写 __printf_function_table", target_type="ctf",
                task_types=["ctf"],
            )
        )
        assert selection.primary == "ctf-pwn"

    def test_generic_ctf_query_is_not_hijacked(self, resolver):
        """The endgame keywords must not steal ordinary CTF goals."""
        selection = resolver.resolve(
            SkillQuery.from_input(
                "解这道 CTF 题，flag 格式 cratectf{...}", target_type="ctf",
                task_types=["ctf"],
            )
        )
        assert selection.primary != "ctf-endgame"

    def test_parenting_a_concrete_pwn_goal_stays_on_ctf_pwn(self, resolver):
        selection = resolver.resolve(
            SkillQuery.from_input(
                "堆溢出 tcache double free，需要 getshell", target_type="ctf",
                task_types=["ctf"],
            )
        )
        assert selection.primary == "ctf-pwn"


# ── CTF subfield routing (2026-11-23) ────────────────────────────────
#
# Measured at入库时: every CTF KB that declares `target_types:[ctf]` +
# `task_types:[ctf]` scored an identical 4.8 (3.0 + 1.8), and the alphabetical
# tiebreak handed EVERY generic CTF goal to ctf-ai — a misc challenge's primary
# reference said "CTF 人工智能安全". Two further gaps fell out of the fix: web and
# crypto goals whose text names the language/algorithm ("PHP 反序列化",
# "RSA 已知 n e c") hit no keyword group at all, because the groups only held
# jargon (弱比较 / ssti注入 / rsa攻击).


class TestCtfSubfieldRouting:
    @pytest.mark.parametrize(
        "text",
        [
            "解这道 CTF 题，flag 格式 cratectf{...}",
            "这是一道 CTF，附件在本题录下，需要拿到 flag",
        ],
    )
    def test_a_generic_ctf_goal_uses_the_declared_fallback(self, resolver, text):
        """No subfield evidence → the target's fallback, not ctf-ai by alphabet."""
        selection = resolver.resolve(
            SkillQuery.from_input(text, target_type="ctf", task_types=["ctf"])
        )
        assert selection.primary == "ctf-misc", (
            f"{text!r} → {selection.primary}; a typed-only tie must resolve to "
            "the declared ctf fallback"
        )

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("PHP 反序列化，SSTI 注入链", "ctf-web"),
            ("SSRF 打内网，xss 回显", "ctf-web"),
            ("RSA 已知 n e c，求解明文", "ctf-crypto"),
            ("AES-CBC 密文异或，需要解密", "ctf-crypto"),
            ("堆溢出 tcache double free，需要 getshell", "ctf-pwn"),
            ("音频频谱里找 flag", "ctf-misc"),
        ],
    )
    def test_challenge_text_names_the_subfield(self, resolver, text, expected):
        selection = resolver.resolve(
            SkillQuery.from_input(text, target_type="ctf", task_types=["ctf"])
        )
        assert selection.primary == expected, (
            f"{text!r} → {selection.primary}, expected {expected}"
        )

    def test_ai_keywords_still_win_their_own_goal(self, resolver):
        """The fallback must not swallow goals that name a specific subfield."""
        selection = resolver.resolve(
            SkillQuery.from_input(
                "强网杯 人工智能 方向：附件 model.pth，请在模型里找到 flag",
                target_type="ctf",
                task_types=["ctf"],
            )
        )
        assert selection.primary == "ctf-ai"


# ── CTF skills must not claim non-CTF targets (2026-11-23) ────────────
#
# ctf-web declared `target_types: [ctf, web]`, so on ANY web target it earned
# the full typed weight and won: measured, the real SRC goal
# "PHP 代码审计，找反序列化漏洞" (target https://t.example.com) resolved to
# ctf-web instead of web-security-advanced. A CTF knowledge base is the wrong
# primary reference for a live pentest — it teaches guess-the-flag tricks, not
# evidence-driven testing. The `ctf` target type still covers real CTF goals
# because _infer_target_type now detects them from the goal text.


class TestCtfSkillsDoNotClaimLiveTargets:
    def _resolve(self, text, target):
        from vulnclaw.agent.skill_context import resolve_active_skill_selection

        selection = resolve_active_skill_selection(text, target=target)
        return selection.primary if selection else None

    @pytest.mark.parametrize(
        "text",
        [
            "PHP 代码审计，找反序列化漏洞",
            "SSRF 打内网，xss 回显，需要出数据",
            "这个接口有反序列化，帮我确认能不能 RCE",
        ],
    )
    def test_a_live_web_target_keeps_its_pentest_skill(self, text):
        primary = self._resolve(text, "https://target.example.com")
        assert primary != "ctf-web", (
            f"{text!r} on a live web target → {primary}; a CTF KB must not be "
            "the primary reference for a real pentest"
        )
        assert primary is not None

    @pytest.mark.parametrize(
        "text",
        [
            "CTF 题，flag 格式 cratectf{...}，PHP 反序列化",
            "题面：弱比较绕过。附件在本题录下。flag 格式 flag{...}",
            "夺旗赛 web 方向，SSTI 注入",
        ],
    )
    def test_a_ctf_goal_on_a_url_still_reaches_ctf_web(self, text):
        """CTF intent wins over the URL: the URL is the challenge's address."""
        primary = self._resolve(text, "https://ctf.example.com")
        assert primary == "ctf-web", f"{text!r} → {primary}"

    def test_explicit_invocation_is_unaffected(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("Use VulnClaw skill ctf-web"))
        assert s.primary == "ctf-web"


# ── exploit-completion routing (2026-11-26) ──────────────────────────
#
# Adapted from Claude-BugHunter's exploit-completion skill. Division of labour
# with ctf-endgame: endgame decides whether a path may be declared dead;
# exploit-completion is the mechanics of landing ONE attempt's proof. The two
# must not shadow each other — a goal saying "all paths ruled out" belongs to
# endgame, a goal saying "it won't land" belongs here.


class TestExploitCompletionRouting:
    @pytest.mark.parametrize(
        "text",
        [
            "这个 payload 打不进去，试了很多次都没回显",
            "我在重复发送同一个请求，一直重试",
            "怎么判断这个响应算不算成功？有没有对照组",
        ],
    )
    def test_completion_phrasings_select_the_skill(self, resolver, text):
        selection = resolver.resolve(
            SkillQuery.from_input(text, target_type="ctf", task_types=["ctf"])
        )
        assert selection.primary == "exploit-completion", (
            f"{text!r} → {selection.primary}"
        )

    def test_declaring_the_path_dead_still_goes_to_endgame(self, resolver):
        selection = resolver.resolve(
            SkillQuery.from_input(
                "所有路径都判死了，比赛快结束", target_type="ctf", task_types=["ctf"]
            )
        )
        assert selection.primary == "ctf-endgame"

    def test_a_generic_ctf_goal_still_uses_the_fallback(self, resolver):
        selection = resolver.resolve(
            SkillQuery.from_input(
                "解这道 CTF 题，flag 格式 cratectf{...}", target_type="ctf",
                task_types=["ctf"],
            )
        )
        assert selection.primary == "ctf-misc"


    @pytest.mark.parametrize(
        "text",
        [
            "只有一次 OCR 结果，能不能提交？",
            "这条算不算解出？证据强度够吗",
        ],
    )
    def test_evidence_strength_phrasings_also_select_the_skill(self, resolver, text):
        """Mechanic 4 (evidence ladder) is asked about at submit time.

        The check is invoked with the language people actually use right before
        reporting ("only one decode — can I submit?"), not with the word
        "exploit".
        """
        selection = resolver.resolve(
            SkillQuery.from_input(text, target_type="ctf", task_types=["ctf"])
        )
        assert selection.primary == "exploit-completion", (
            f"{text!r} → {selection.primary}"
        )
