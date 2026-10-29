"""The CTF submit line must depend on the run actually having a platform ref.

Measured 2026-10-29, GBU firmware console challenge (`task_mode: ctf` pinned in
the operator config): the flag was recovered by tool call 12, and the
unconditional "The deliverable is a platform-formatted flag; submit via the
platform submit verb" then sent the model hunting for a challenge ref that could
not exist. ``platform_submit`` requires one (``platforms/tools.py:_resolve``
answers ``missing `ref```), and the goal was a bare
``openssl s_client -connect <host>:9999``. The hunt cost 10 of 28 tool calls and
32 of 79 seconds: ``platform_list`` -> forbidden daily scope (403) -> all 26
practice challenges -> two ended competitions -> the one nc challenge found was
a different challenge in a different flag format.

So the discipline says "submit" only when a ref is present, and otherwise says
the flag VALUE is the deliverable and names the enumeration as out of bounds.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent import solver
from vulnclaw.agent.task_mode import mode_instruction

GROUND = "8e5c9260-3cc2-4de0-a4e4-87bfb6900f2e"
CHAL = "850c2230-5f13-4f53-910a-ebd2ea7ff48c"
PRACTICE_REF = f"ctf2:practice:{GROUND}:{CHAL}"
STAGE_ID = "031d3cf3-d4f7-4eed-9e03-6fecb334ce44"
STAGE_REF = f"ctf2:stage:{STAGE_ID}:cb726241-8aab-40f3-951d-d42172250ad0"

BARE_NC_GOAL = (
    "一台 GBU 边缘设备维护终端通过 nc 提供原始 TCP 控制台。要找回隐藏在固件镜像深处的序列号文本。"
    "openssl s_client -connect 4371b3824ec5205a692699f3.tcp-ctf2.dasctf.com:9999 "
    "-servername 4371b3824ec5205a692699f3.tcp-ctf2.dasctf.com -quiet"
)


class TestModeInstructionSubmitLine:
    def test_with_ref_demands_submission(self):
        text = mode_instruction("ctf", platform_ref=True)
        assert "submit via the platform" in text
        assert "platform_submit" in text

    def test_without_ref_makes_the_flag_value_the_deliverable(self):
        text = mode_instruction("ctf", platform_ref=False)
        assert "submit via the platform" not in text
        assert "flag value IS the deliverable" in text
        # the wasted work this exists to prevent, named explicitly
        assert "platform_list" in text and "ctf2_list_*" in text

    def test_without_ref_still_keeps_the_rest_of_the_discipline(self):
        text = mode_instruction("ctf", platform_ref=False)
        assert "fail-fast" in text
        assert "安全加固" in text and "30-40" in text

    def test_default_is_the_stricter_wording(self):
        """A caller that knows nothing about refs must not lose the submit demand."""
        assert "submit via the platform" in mode_instruction("ctf")

    def test_other_modes_are_untouched(self):
        assert mode_instruction("pentest", platform_ref=False) == ""
        assert mode_instruction("ir", platform_ref=False) == mode_instruction("ir")


class TestRunHasPlatformRef:
    def _state(self, goal, origin, evidence=()):
        return SimpleNamespace(goal=goal, origin=origin, evidence=list(evidence))

    def test_bare_host_has_no_ref(self):
        assert solver._run_has_platform_ref(self._state(BARE_NC_GOAL, "4371b3824ec5205a692699f3.tcp-ctf2.dasctf.com")) is False

    def test_plain_web_target_has_no_ref(self):
        assert solver._run_has_platform_ref(self._state("test https://example.com", "https://example.com")) is False

    def test_practice_ref_in_goal(self):
        assert solver._run_has_platform_ref(self._state(f"Solve it. REF: {PRACTICE_REF}", "http://h:80")) is True

    def test_stage_ref_in_goal_covers_competitions(self):
        """The reason this cannot reuse ``playbook.derive_target_ref``: that one only
        matches the practice shape, so a competition run would be called ref-less --
        and a competition is the one place submitting is mandatory."""
        assert solver._run_has_platform_ref(self._state(f"challenge {STAGE_REF}", "http://h")) is True

    def test_daily_challenge_ref(self):
        assert solver._run_has_platform_ref(
            self._state("ctf2:daily:6fa515a5-b11b-440d-8087-4a34019b68ad", "http://h")
        ) is True

    def test_gcs_ref(self):
        assert solver._run_has_platform_ref(self._state("gcs:exercise:10662", "http://h")) is True

    def test_origin_that_is_itself_the_ref(self):
        assert solver._run_has_platform_ref(self._state("attack it", PRACTICE_REF)) is True

    def test_corpus_ref_is_not_a_challenge_ref(self):
        assert solver._run_has_platform_ref(self._state("list ctf2:daily", "http://h")) is False

    def test_ref_discovered_mid_run_counts(self):
        """``platform_list`` printing the ref must be enough -- that is how a run
        started from a bare host legitimately reaches the platform."""
        evidence = [SimpleNamespace(summary=f"collections: {PRACTICE_REF}")]
        assert solver._run_has_platform_ref(self._state("bare host", "h", evidence)) is True

    def test_broken_evidence_object_does_not_raise(self):
        assert solver._run_has_platform_ref(self._state("bare host", "h", [object()])) is False


class TestSystemPromptUsesTheRefAwareBlock:
    def _prompt(self, goal, origin):
        class _RT:
            prior_playbook_brief = ""

        class _Agent:
            config = SimpleNamespace(session=SimpleNamespace(task_mode="ctf"))
            runtime = _RT()

        class _State:
            pass

        state = _State()
        state.goal = goal
        state.origin = origin
        state.evidence = []
        return solver._system_prompt(_Agent(), state)

    def test_pinned_ctf_mode_without_ref_does_not_demand_submission(self):
        prompt = self._prompt(BARE_NC_GOAL, "4371b3824ec5205a692699f3.tcp-ctf2.dasctf.com")
        assert "CTF flag round" in prompt
        assert "flag value IS the deliverable" in prompt
        assert "submit via the platform submit verb" not in prompt

    def test_pinned_ctf_mode_with_ref_still_demands_submission(self):
        prompt = self._prompt(f"Solve challenge {PRACTICE_REF}", "http://h:80")
        assert "CTF flag round" in prompt
        assert "submit via the platform submit verb" in prompt