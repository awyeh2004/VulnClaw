"""Round-21 regression: a CITED documentation URL must not become the target/scope.

2026-10-06, GeoServer CVE-2024-36401 (direct-ctf2.dasctf.com:25390). The operator had the
live endpoint as the session target and pasted a challenge description shaped like this:

    GeoServer Unauthenticated Remote Code Execution … (CVE-2024-36401)
    环境来源与官方说明: https://github.com/vulhub/vulhub/tree/master/geoserver/CVE-2024-36401
    Flag 通过环境变量 FLAG 注入靶机,获取权限后请自行读取(如 env、/proc/1/environ)。
    nc direct-ctf2.dasctf.com 25390

The doc link won BOTH first-match races, so the run locked itself out of the endpoint the
description had just named:

  * ``_extract_target_from_input`` -> ``https://github.com`` -> ``_should_switch_target``
    True -> "[*] Target switch: direct-ctf2.dasctf.com -> https://github.com",
    ``agent.reset_context()``, auto mode dropped;
  * ``detect_target`` -> ``extract_task_constraints`` -> ``allowed_hosts=['github.com']``
    with ``strict_mode=True`` -> the prompt said 仅允许测试主机: github.com and the tool
    layer answered every call against the real endpoint with
    "[constraint_violation] Host … is outside allowed scope [github.com]".

The run ended NO_PATH asking the operator to widen scope to the host the description
already contained. Both halves are pinned here; ``tests/cli/test_quiz_target_guard.py``
keeps pinning that the extractor itself still reports cited URLs, which is why the gate
lives in the *decision* functions rather than in the regex.
"""

from vulnclaw.agent.input_analysis import detect_target, extract_task_constraints
from vulnclaw.cli.main import (
    _extract_target_from_input,
    _is_cited_target,
    _should_switch_target,
)

LIVE_TARGET = "direct-ctf2.dasctf.com"

DESCRIPTION = (
    "GeoServer Unauthenticated Remote Code Execution in Evaluating Property Name "
    "Expressions (CVE-2024-36401) 环境来源与官方说明: "
    "https://github.com/vulhub/vulhub/tree/master/geoserver/CVE-2024-36401 "
    "Flag 通过环境变量 FLAG 注入靶机,获取权限后请自行读取(如 env、/proc/1/environ)。"
    "nc direct-ctf2.dasctf.com 25390"
)

#: The shipped platform prompt as well: rule 0 fixes the *identity* of such a turn, but
#: the scope miner is a separate path — it mined the doc host even with the ref token.
PLATFORM_GOAL = (
    "用 ctf2 工具解练习场 2de971ac-26fe-448a-8719-01829e52c1d5 的题目 "
    "5b52dee0-2e1b-41b8-ab66-500f51e3e4c1：" + DESCRIPTION
)

QUIZ_CITATION = "（判断题）https://www.12377.cn 是非法举报网站。（对/错）"


class TestCitedUrlIsNotATarget:
    def test_the_endpoint_named_later_wins(self):
        assert detect_target(DESCRIPTION) == LIVE_TARGET

    def test_platform_goal_shape_is_fixed_too(self):
        # Before the fix this returned 'https://github.com' even WITH rule 0 applied.
        assert detect_target(PLATFORM_GOAL) == LIVE_TARGET

    def test_the_doc_host_is_never_the_guessed_host(self):
        assert detect_target(DESCRIPTION) != "https://github.com"
        assert detect_target(DESCRIPTION) != "github.com"


class TestMinedScopeExcludesTheCitation:
    def test_allowed_hosts_is_the_real_endpoint(self):
        constraints = extract_task_constraints(DESCRIPTION)
        assert constraints.allowed_hosts == [LIVE_TARGET]
        assert "github.com" not in constraints.allowed_hosts

    def test_strict_mode_still_applies_to_the_real_endpoint(self):
        # The gate itself is wanted: the run must stay on the challenge endpoint.
        constraints = extract_task_constraints(DESCRIPTION)
        assert constraints.strict_mode is True


class TestNoContextResetOnAPastedDescription:
    def test_extractor_reports_the_cited_url(self):
        # Documenting the hazard the decision-level gate neutralises (see the module
        # docstring): the regex is unchanged, the verdict is not.
        assert _extract_target_from_input(DESCRIPTION) == "https://github.com"

    def test_switch_guard_refuses_it(self):
        assert (
            _should_switch_target(
                DESCRIPTION,
                _extract_target_from_input(DESCRIPTION),
                LIVE_TARGET,
            )
            is False
        )

    def test_first_adoption_branch_refuses_it(self):
        assert _is_cited_target(DESCRIPTION, "https://github.com") is True


class TestTheGateStaysNarrow:
    def test_a_bare_doc_host_mention_is_untouched(self):
        # No URL, no citation marker: "渗透测试 github.com" still yields an operator-set
        # target (unchanged behaviour — only URL-form references are filtered).
        assert detect_target("渗透测试 github.com") == "github.com"

    def test_a_genuine_retarget_still_switches(self):
        ask = "改用 https://real-target.example.com 进行渗透测试"
        new_target = _extract_target_from_input(ask)
        assert new_target == "https://real-target.example.com"
        assert _is_cited_target(ask, new_target) is False
        assert _should_switch_target(ask, new_target, LIVE_TARGET) is True

    def test_a_quiz_citation_is_not_swallowed_by_the_new_gate(self):
        # tests/cli/test_quiz_target_guard.py owns the quiz verdict; this pins that the
        # citation gate does not silently take it over (12377.cn is a target-ish host
        # with no citation marker in front of it).
        assert _is_cited_target(QUIZ_CITATION, "https://www.12377.cn") is False

    def test_a_citation_marker_skips_a_non_reference_host(self):
        text = "参考链接: https://blog.example.net/2024/007 然后打 nc 10.0.0.5 8080"
        assert detect_target(text) == "10.0.0.5"
        assert _is_cited_target(text, "https://blog.example.net") is True

    def test_ordinary_targets_are_unchanged(self):
        assert detect_target("测试 https://example.com") == "https://example.com"
        assert detect_target("对 192.168.1.100 进行渗透测试") == "192.168.1.100"
        assert detect_target("扫描 testsite.com") == "testsite.com"
        assert detect_target("没有目标的输入") is None

    def test_a_target_written_after_a_citation_marker_is_still_a_target(self):
        """Round15b (2026-10-07): the citation window made a target written right
        after a marker ("漏洞详情： http://real-target") invisible — every candidate
        sat inside a citation span, so detect_target returned None and the run had
        no target at all. The second pass only runs when the first finds nothing.
        """
        assert (
            detect_target("漏洞详情： http://real-target.local")
            == "http://real-target.local"
        )

    def test_the_second_pass_still_refuses_reference_hosts(self):
        """A citation-only statement must stay target-less, and the second pass
        must not resurrect the bare ``github.com`` the URL pattern mines out of a
        doc link — that would re-create the round-21 ``allowed_hosts=['github.com']``
        scope hazard, so pass 2 rejects reference hosts in bare form too."""
        assert detect_target("漏洞详情： https://github.com/vulhub/vulhub") is None
        assert detect_target("详见 https://readthedocs.io/x") is None
