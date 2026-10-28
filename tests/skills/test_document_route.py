"""Document/container goals must route to the ctf-misc skill.

Measured 2026-10-28: the DASBOOK 7.5.x goals say "PDF文档隐写" / "Word文档隐写",
and chapter 8 says "伪加密破解" / "磁盘取证方法". The only generic keyword was
"隐写", so a goal naming the FORMAT without the word 隐写 (or naming the attack,
like 伪加密) matched nothing and the run never loaded the document reference.
Same shape as the audio-stego routing gap fixed 2026-10-27 (see
test_audio_stego_hint.py): a reference exists, but is never advertised for the
challenges it was written for.
"""

from __future__ import annotations

import pytest

from vulnclaw.skills.dispatcher import SkillDispatcher


@pytest.mark.parametrize(
    "goal",
    [
        "Solve CTF2 challenge '[7.5.2 PDF文档隐写]pdf隐写' (category 第07章 PDF文档隐写)",
        "[7.5.1 Word文档隐写]解压2",
        "[8.2.1 伪加密破解]zip伪加密",
        "[10.1.2 磁盘取证方法]磁盘取证",
    ],
)
def test_document_goals_route_to_ctf_misc(goal: str):
    result = SkillDispatcher().dispatch(goal)
    assert result, f"no skill routed for {goal!r}"
    skill = result.get("skill") or result.get("name") or ""
    assert skill == "ctf-misc", (goal, result)


def test_a_plain_ctf_goal_does_not_get_the_document_skill():
    """The new keywords must not swallow unrelated goals.

    Note: a goal containing the bare word "flag" routes to ``ctf-web`` (its
    "常见 flag 位置" section), which predates this change -- so the negative case
    deliberately avoids that word.
    """
    result = SkillDispatcher().dispatch("Solve CTF2 challenge '1.3.5 Http'")
    skill = (result or {}).get("skill") or (result or {}).get("name") or ""
    assert skill != "ctf-misc"
