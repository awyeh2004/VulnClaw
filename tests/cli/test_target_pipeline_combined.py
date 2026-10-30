"""The target pipeline, as one contract (2026-10-06 merge).

Two fixes had grown on the same path from opposite ends and are complementary:

  * POSITIVE -- ``_ctf2_task_ref`` recognises the platform's ctf2 sentence and fixes
    the *identity* of such a turn (rule 0 of ``_extract_target_from_input``, plus the
    early return in ``_should_auto_pentest``); without it a UUID-only sentence has no
    extractable target at all and the challenge drops into single-turn chat.
  * NEGATIVE -- ``_is_cited_target`` / ``_is_cited_candidate`` keep a CITED
    documentation URL out of the target/scope decisions (GeoServer CVE-2024-36401
    round-21); without it a pasted description retargets the session onto its source
    link and locks scope to it.

This file pins the four questions asked about the same pasted text *together*, because
they are answered at four different places and used to disagree at one of them:

    layer 0  identity   : platform ctf2 sentence -> ctf2:practice:<pid>:<cid>
    layer 1  extraction : the FIRST candidate in the text (raw -- cited URLs included)
    layer 2  verdict    : ``_is_cited_target`` -> is this candidate a citation?
    layer 3  scope      : mined ``allowed_hosts`` (a cited host never enters)
    layer 4  auto mode  : ``_has_actionable_target`` -> a cited URL is not a target

Layer 1 stays raw on purpose: ``tests/cli/test_citation_url_scope.py`` documents why
the gate lives in the decision functions rather than in the regex (a raw first-match
that the guard then REFUSES keeps the conservative "no switch" outcome, whereas
returning the next candidate would happily retarget onto it).
"""

from vulnclaw.agent.input_analysis import detect_target, extract_task_constraints
from vulnclaw.cli.main import (
    _ctf2_task_ref,
    _extract_target_from_input,
    _has_actionable_target,
    _is_cited_target,
    _should_auto_pentest,
    _should_switch_target,
)

PRACTICE = "2de971ac-26fe-448a-8719-01829e52c1d5"
CHALLENGE = "5b52dee0-2e1b-41b8-ab66-500f51e3e4c1"
REF = f"ctf2:practice:{PRACTICE}:{CHALLENGE}"
SENTENCE = f"用 ctf2 工具解练习场 {PRACTICE} 的题目 {CHALLENGE}："

LIVE_TARGET = "direct-ctf2.dasctf.com"
DESCRIPTION = (
    "GeoServer Unauthenticated Remote Code Execution in Evaluating Property Name "
    "Expressions (CVE-2024-36401) 环境来源与官方说明: "
    "https://github.com/vulhub/vulhub/tree/master/geoserver/CVE-2024-36401 "
    "Flag 通过环境变量 FLAG 注入靶机,获取权限后请自行读取(如 env、/proc/1/environ)。"
    "nc direct-ctf2.dasctf.com 25390"
)
CITED_ONLY = "环境来源与官方说明: https://github.com/vulhub/vulhub 渗透测试"


class TestLayer0Identity:
    def test_the_platform_sentence_has_one_identity(self):
        assert _ctf2_task_ref(SENTENCE) == REF
        assert _extract_target_from_input(SENTENCE) == REF
        assert _should_auto_pentest(SENTENCE, None) is True

    def test_a_platform_task_locks_no_scope(self):
        # The sentence carries no URL: nothing is mined, strict_mode stays off, and the
        # run can reach the endpoint the platform hands it at runtime.
        constraints = extract_task_constraints(SENTENCE)
        assert constraints.allowed_hosts == []
        assert constraints.strict_mode is False

    def test_identity_outranks_the_description_that_follows_it(self):
        text = SENTENCE + DESCRIPTION
        assert _extract_target_from_input(text) == REF
        assert detect_target(text) == LIVE_TARGET
        assert extract_task_constraints(text).allowed_hosts == [LIVE_TARGET]
        assert _should_auto_pentest(text, None) is True


class TestLayers1And2ExtractionStaysRaw:
    def test_the_extractor_still_reports_the_cited_url(self):
        assert _extract_target_from_input(DESCRIPTION) == "https://github.com"

    def test_the_verdict_refuses_it_and_the_switch_stays_put(self):
        assert _is_cited_target(DESCRIPTION, "https://github.com") is True
        assert (
            _should_switch_target(DESCRIPTION, "https://github.com", LIVE_TARGET) is False
        )

    def test_a_parenthetical_attribution_is_still_a_citation(self):
        # Merge hardening: the marker window was 16 chars and the attribution below sits
        # 23 chars before the URL, so the doc host was mined as the target again.
        text = (
            "环境来源与官方说明（vulhub 官方仓库）: https://github.com/vulhub/vulhub "
            "目标: 10.0.0.7"
        )
        assert _is_cited_target(text, "https://github.com") is True
        assert detect_target(text) == "10.0.0.7"


class TestLayer4AutoModeSharesTheVerdict:
    def test_a_lone_citation_is_not_a_target(self):
        # Before the merge the auto gate asked the RAW extractor, so a description
        # carrying nothing but its source link went autonomous with no endpoint named
        # anywhere -- while the switch guard refused that very URL.
        assert _extract_target_from_input(CITED_ONLY) == "https://github.com"
        assert _has_actionable_target(CITED_ONLY) is False
        assert _should_auto_pentest(CITED_ONLY, None) is False

    def test_a_live_session_target_still_authorises_auto(self):
        assert _should_auto_pentest(CITED_ONLY, LIVE_TARGET) is True

    def test_a_description_naming_an_endpoint_still_goes_auto(self):
        assert _has_actionable_target(DESCRIPTION) is True
        assert _should_auto_pentest(DESCRIPTION, None) is True


class TestUnchangedBehaviour:
    def test_local_analysis_still_goes_auto(self):
        # detect_target never looks at paths, so the merge keeps a local-artefact branch.
        ask = "分析 misc2.zip 的漏洞并输出报告"
        assert _has_actionable_target(ask) is True
        assert _should_auto_pentest(ask, None) is True

    def test_a_genuine_retarget_still_switches(self):
        ask = "改用 https://real-target.example.com 进行渗透测试"
        assert (
            _should_switch_target(ask, "https://real-target.example.com", LIVE_TARGET)
            is True
        )

    def test_chat_without_a_target_stays_chat(self):
        assert _extract_target_from_input("今天天气怎么样") is None
        assert _has_actionable_target("今天天气怎么样") is False
        assert _should_auto_pentest("今天天气怎么样", None) is False


class TestWebAssetNamesNeverBecomeHosts:
    """Measured 2026-10-27 by driving ``vulnclaw solve`` headlessly.

    The prompt said "取根路径与 /space/app.version.js 各一次". The miner had no
    ``.js`` in its filename extensions, so it took ``app.version.js`` as the one
    allowed host; every request to the real target came back
    ``[constraint_violation] Host opac.ouc.edu.cn is outside allowed scope
    [app.version.js]`` and the whole round was lost to a scope entry that was a
    file name.
    """

    def test_web_source_extensions_are_filenames(self):
        from vulnclaw.agent.input_analysis import _looks_like_filename

        for token in (
            "app.version.js",
            "/space/app.version.js",
            "login.php",
            "site.css",
            "data.json",
            "page.xhtml",
            "app.config.yaml",
            "bundle.js.map",
        ):
            assert _looks_like_filename(token) is True, token

    def test_real_hosts_are_still_hosts(self):
        from vulnclaw.agent.input_analysis import _looks_like_filename

        # .do and .sh are ccTLDs -- a host must not be mistaken for a file.
        for token in ("opac.ouc.edu.cn", "x.com.do", "example.sh", "evil.com"):
            assert _looks_like_filename(token) is False, token

    def test_prompt_naming_a_file_mining_no_host(self):
        from vulnclaw.agent.input_analysis import extract_task_constraints

        constraints = extract_task_constraints("只读：取根路径与 /space/app.version.js 各一次")
        assert constraints.allowed_hosts == []

    def test_prompt_with_target_and_file_keeps_the_target(self):
        from vulnclaw.agent.input_analysis import extract_task_constraints

        constraints = extract_task_constraints(
            "目标 https://opac.ouc.edu.cn/ ，顺便看看 /space/app.version.js"
        )
        assert constraints.allowed_hosts == ["opac.ouc.edu.cn"]


class TestDottedFieldNamesNeverBecomeHosts:
    """Measured 2026-10-27 (second occurrence the same evening).

    The prompt said "计算 coze.token 的 sha256". ``.token`` was not treated as a
    file extension, so ``coze.token`` was mined as the sole allowed host and every
    request to the real target was refused with
    ``[constraint_violation] Host opac.ouc.edu.cn is outside allowed scope
    [coze.token]`` — a whole round lost before its first request.
    """

    def test_field_names_are_not_hosts(self):
        from vulnclaw.agent.input_analysis import _looks_like_hostname

        for token in (
            "coze.token", "config.coze", "app.version.js", "user.password",
            # Two-letter suffixes are ccTLDs AND field suffixes (audit 2026-10-30):
            # ``user.id`` passed the TLD whitelist because ``id`` is Indonesia.
            "user.id", "order.id", "session.id", "item.id", "data.id",
        ):
            assert _looks_like_hostname(token) is False, token

    def test_real_hosts_and_ips_still_qualify(self):
        from vulnclaw.agent.input_analysis import _looks_like_hostname

        for token in (
            "opac.ouc.edu.cn", "evil.com", "x.com.do", "192.168.1.1",
            # A host on an Indonesian .id domain is not a field name.
            "app.id",
        ):
            assert _looks_like_hostname(token) is True, token

    def test_bare_domain_on_a_public_gtld_still_pins_scope(self):
        """A closed whitelist used to drop these silently, leaving NO host scope.

        An empty ``allowed_hosts`` switches the host gate off entirely, so a
        target on an unlisted gTLD went from "locked out" to "unpinned" — the
        failure direction the audit flagged (2026-10-30).
        """
        from vulnclaw.agent.input_analysis import extract_task_constraints

        for token in ("chal.icu", "chal.buzz", "chal.security"):
            constraints = extract_task_constraints(f"对 {token} 做一次基线探测")
            assert constraints.allowed_hosts == [token], token
            assert constraints.strict_mode is True

    def test_field_name_before_a_two_letter_suffix_mines_nothing(self):
        from vulnclaw.agent.input_analysis import extract_task_constraints

        constraints = extract_task_constraints("计算 user.id 的 md5 前 8 位")
        assert constraints.allowed_hosts == []

    def test_prompt_with_a_field_name_mines_nothing(self):
        from vulnclaw.agent.input_analysis import extract_task_constraints

        constraints = extract_task_constraints("计算 coze.token 的 sha256 前 16 位")
        assert constraints.allowed_hosts == []

    def test_prompt_with_host_and_field_keeps_only_the_host(self):
        from vulnclaw.agent.input_analysis import extract_task_constraints

        constraints = extract_task_constraints(
            "取 opac.ouc.edu.cn 配置里 coze.token 的摘要"
        )
        assert constraints.allowed_hosts == ["opac.ouc.edu.cn"]


class TestInternalSuffixesStayHosts:
    """Round22 audit (2026-10-29): the TLD whitelist rejected internal schemes.

    ``corp.local`` (2026-10-11 决赛企业网应急) and ``hancloud.local`` were not
    hosts by the whitelist, so a target named that way never reached
    ``allowed_hosts`` — with another mined host present, every request to the
    real target was refused; with none, the run went out with no host pinning
    at all. ``home`` stays excluded: ``user.home`` is a Java property name, and
    accepting it would re-mine a field name as a host.
    """

    def test_internal_schemes_are_hosts(self):
        from vulnclaw.agent.input_analysis import _looks_like_hostname

        for token in (
            "corp.local", "www.hancloud.local", "web01.lab",
            "dc01.corp", "mysql.intranet", "fw.dmz", "host.home.arpa",
        ):
            assert _looks_like_hostname(token) is True, token

    def test_java_property_shaped_tokens_stay_non_hosts(self):
        from vulnclaw.agent.input_analysis import _looks_like_hostname

        for token in ("user.home", "coze.token", "config.coze"):
            assert _looks_like_hostname(token) is False, token

    def test_prompt_with_internal_target_mines_it(self):
        from vulnclaw.agent.input_analysis import extract_task_constraints

        constraints = extract_task_constraints("对 corp.local 做一次基线探测")
        assert constraints.allowed_hosts == ["corp.local"]

    def test_prompt_with_internal_url_and_allowed_host_keeps_both(self):
        from vulnclaw.agent.input_analysis import extract_task_constraints

        constraints = extract_task_constraints(
            "目标 https://web01.lab/ 做基线，allowed host db.corp"
        )
        assert "web01.lab" in constraints.allowed_hosts
        assert "db.corp" in constraints.allowed_hosts
