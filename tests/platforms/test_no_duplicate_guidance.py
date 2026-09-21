"""A STATE_NONE render must give the start->poll instruction exactly once.

Measured while releasing a target: the adapter and the renderer each supplied the
same sentence, so the model saw it twice. Two instructions that say the same thing
are not merely untidy -- they invite the model to look for the difference.
"""

from __future__ import annotations

from vulnclaw.platforms import base
from vulnclaw.platforms.base import EnvInfo
from vulnclaw.platforms.ctf2 import normalize_target_payload
from vulnclaw.platforms.gcs import normalize_exercise_env
from vulnclaw.platforms.refs import ChallengeRef
from vulnclaw.platforms.render import render_env_info

CTF2_REF = ChallengeRef("ctf2", "practice", "p", "c")
GCS_REF = ChallengeRef("gcs", "exercise", "", "1")
INSTRUCTION = "Start one with platform_start_env"
POLL = "poll platform_read_env"


def _head(text: str) -> str:
    return text.split("\n{", 1)[0]


class TestNoDuplicatedInstruction:
    def test_ctf2_state_none_says_it_once(self):
        info = normalize_target_payload({"data": None, "success": True}, CTF2_REF)
        head = _head(render_env_info(info))
        assert head.count(INSTRUCTION) == 1
        assert head.count(POLL) == 1

    def test_gcs_state_none_says_it_once(self):
        info = normalize_exercise_env({"data": None}, GCS_REF)
        head = _head(render_env_info(info))
        assert head.count(INSTRUCTION) == 1
        assert head.count(POLL) == 1

    def test_state_none_is_still_actionable(self):
        """Removing the duplicate must not remove the instruction itself."""
        head = _head(
            render_env_info(normalize_target_payload({"data": None}, CTF2_REF))
        )
        assert INSTRUCTION in head
        assert "no target is running" in head

    def test_a_hand_built_env_info_also_gets_the_instruction(self):
        """The renderer must stay self-sufficient for adapters that pass no guidance."""
        info = EnvInfo(ref=CTF2_REF, state=base.STATE_NONE, complete=False)
        head = _head(render_env_info(info))
        assert INSTRUCTION in head
        assert head.count(INSTRUCTION) == 1
