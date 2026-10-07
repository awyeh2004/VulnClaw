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
