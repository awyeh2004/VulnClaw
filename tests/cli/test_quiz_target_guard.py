"""CLI guard: pasted knowledge-quiz questions must not reset session context.

Quiz question text often cites IPs/domains ("192.168.1.1 属于哪类地址",
"www.example.com 是否…"). Extracting those as a "new target" used to print
目标切换 and wipe the blackboard/evidence mid-run (same failure family as the
"/证据" mis-extraction fixed in 7419eec).
"""

from vulnclaw.agent.solver import _looks_like_quiz
from vulnclaw.cli.main import _extract_target_from_input, _should_switch_target

CURRENT_TARGET = "http://quiz-platform.example.com:8080"

QUIZ_WITH_IP = (
    "知识竞赛：1. IP 地址 192.168.1.1 属于哪类地址？ A. A类 B. B类 C. C类 D. D类"
)
QUIZ_WITH_DOMAIN = "（判断题）www.example.com 是政府域名。"
REAL_PENTEST_ASK = "接着对 http://real-target.example.com 进行渗透测试"
QUIZ_PROSE_RETARGET_URL = "放弃当前答题平台，改打 http://real-target.example.com 进行渗透测试"


class TestQuizTargetSwitchGuard:
    def test_quiz_text_extracts_decoy_targets(self):
        # The extraction itself still fires — the guard, not the regex, is
        # what neutralizes it.
        assert _extract_target_from_input(QUIZ_WITH_IP) == "192.168.1.1"
        assert _extract_target_from_input(QUIZ_WITH_DOMAIN) == "www.example.com"

    def test_quiz_decoy_target_does_not_switch(self):
        assert _should_switch_target(
            QUIZ_WITH_IP, _extract_target_from_input(QUIZ_WITH_IP), CURRENT_TARGET
        ) is False
        assert _should_switch_target(
            QUIZ_WITH_DOMAIN, _extract_target_from_input(QUIZ_WITH_DOMAIN), CURRENT_TARGET
        ) is False

    def test_real_new_target_still_switches(self):
        assert _should_switch_target(
            REAL_PENTEST_ASK,
            _extract_target_from_input(REAL_PENTEST_ASK),
            CURRENT_TARGET,
        ) is True

    def test_quiz_prose_with_full_url_switches(self):
        """R3: a full URL with explicit retarget phrasing is a real switch."""
        new_target = _extract_target_from_input(QUIZ_PROSE_RETARGET_URL)
        assert new_target == "http://real-target.example.com"
        assert _should_switch_target(
            QUIZ_PROSE_RETARGET_URL, new_target, CURRENT_TARGET
        ) is True

    def test_quiz_prose_citing_url_without_retarget_verb_stays_exempt(self):
        """A URL cited inside a question stem is quiz content, not retargeting."""
        citation = "（判断题）https://www.12377.cn 是非法举报网站。（对/错）"
        new_target = _extract_target_from_input(citation)
        assert new_target == "https://www.12377.cn"
        assert _should_switch_target(citation, new_target, CURRENT_TARGET) is False

    def test_quiz_prose_bare_ip_decoy_still_exempt(self):
        """R3: bare-form decoys in quiz prose stay exempt (no switch)."""
        assert _should_switch_target(
            QUIZ_WITH_IP, _extract_target_from_input(QUIZ_WITH_IP), CURRENT_TARGET
        ) is False

    def test_guard_is_narrow(self):
        assert _looks_like_quiz(REAL_PENTEST_ASK) is False
        assert _looks_like_quiz(QUIZ_WITH_IP) is True


class TestApiPathProseNotATarget:
    """Round-12 postmortem (PrizeEscrow): a task description citing API paths
    ('/storage/{addr}/{slot}', '/logs') must not retarget the session to a
    literal path — that once replaced a live HTTP target with '/storage' and
    applied local-path constraints that locked every real request out of
    scope."""

    TASK = "对 impl 地址 0x31f4b2... 做全槽扫描：/storage/{impl}/0x0 到 0xf，对照 /logs 里 upgradeTo 事件。"
    NEW = _extract_target_from_input(TASK)

    def test_api_path_prose_extracts_a_path_target(self):
        # the extractor DOES return the path (documenting the hazard)
        assert self.NEW == "/storage"

    def test_api_path_target_does_not_switch(self):
        assert _should_switch_target(self.TASK, self.NEW, CURRENT_TARGET) is False

    def test_real_path_retarget_still_works_for_local_files(self):
        # multi-segment local file paths remain valid retargets
        assert _should_switch_target(
            "审计 E:/vulnclaw/work/manual/App.php", "E:/vulnclaw/work/manual/App.php", CURRENT_TARGET
        ) is True


class TestApiPathProseFirstAdoption:
    """round13 F4: the first-adoption branch (``new_target and not
    current_target``) needs the same API-path gate the switch guard got in
    6208773 — a FIRST message citing bare API-path prose must not lock the run
    to a literal path target + strict local constraints (the remaining
    first-shot variant of the 2026-10-01 PrizeEscrow postmortem)."""

    def test_shared_predicate_flags_single_segment_paths(self):
        from vulnclaw.cli.main import _is_api_path_prose

        assert _is_api_path_prose("/storage") is True
        assert _is_api_path_prose("/logs") is True
        assert _is_api_path_prose("http://x.example.com") is False
        assert _is_api_path_prose("192.168.1.1") is False

    def test_newline_artifacts_are_still_prose(self):
        # round13 low note: `$` matched before a string-final newline, but only
        # ONE; "/logs\n\n" slipped through as an adoptable target. The
        # strip+fullmatch form classifies every trailing-newline artifact as
        # prose.
        from vulnclaw.cli.main import _is_api_path_prose

        assert _is_api_path_prose("/logs\n") is True
        assert _is_api_path_prose("/logs\n\n") is True
        assert _is_api_path_prose(" /session ") is True

    def test_multi_segment_paths_stay_adoptable(self):
        from vulnclaw.cli.main import _is_api_path_prose

        # A multi-segment path is a deliberate local-file target, not prose.
        assert _is_api_path_prose("/home/user/ctf") is False
        assert _is_api_path_prose("E:/vulnclaw/work/App.php") is False

    def test_prizeescrow_first_message_would_not_adopt(self):
        # The adoption branch is `new_target and not current_target and not
        # _is_api_path_prose(new_target)`; the prose target the extractor
        # returns is refused there, so current_target stays unset and no
        # local-path constraints are applied.
        from vulnclaw.cli.main import _is_api_path_prose

        new_target = _extract_target_from_input(TestApiPathProseNotATarget.TASK)
        assert new_target == "/storage"
        assert _is_api_path_prose(new_target) is True
