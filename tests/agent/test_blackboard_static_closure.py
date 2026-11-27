"""A MISS worded as a static assertion gets one falsify-first reminder.

Three real buries, all Crate-CTF 2026-11-22, all closed with static wording and
all solved later by the cheapest possible probe:

* ByteDB: "length limit → no overflow" — the query bytes were overflowing the
  bytecode_map itself; one dump of the mappings (option 2) showed the corruption.
* Celldelning: "largebin attack writes heap pointers, nothing calls heap
  pointers" — printf's __printf_function_table/__printf_arginfo_table ARE the
  call sites (House of Husk); the chain fit in the 6-malloc budget.
* Owls and Dragons II: "aspect ratio mismatch" — masks need no uniform scaling;
  the overlay spelled the steghide passphrase.

The nudge is advice attached to the MISS response, never a block (same stance
as goal_wording_warning): honest misses keep their response shape.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.blackboard import (
    Blackboard,
    NodeStatus,
    _static_closure_nudge,
    dispatch_blackboard_tool,
)

# ── detector ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "desc",
    [
        "largebin attack writes heap pointers, nothing calls heap pointers",
        "no code calls the win pointer, FSOP impossible",
        "buffer has a length check, overflow not possible",
        "no overflow possible past the mapping table",
        "next chunk header cannot be reached, overflow impossible",
        "thing.png aspect ratio mismatch, overlay rejected",
        "宽高比不一致，放弃叠加",
        "glibc 2.39 的检查导致无法溢出",
        "此路径不可达",
    ],
)
def test_static_closure_wording_triggers_the_nudge(desc):
    assert _static_closure_nudge(desc), desc


@pytest.mark.parametrize(
    "desc",
    [
        "tcache poisoning retried twice, both runs aborted in _int_free",
        "signed id comparison disproved by objdump at 0x13c8",
        "plain double free detected by tcache key check (rc observed)",
    ],
)
def test_probed_misses_stay_uncluttered(desc):
    assert _static_closure_nudge(desc) == "", desc


@pytest.mark.parametrize(
    "desc",
    [
        "the win function is reachable",
        "overflow impossible per objdump at 0x13c8",
        "nothing calls this pointer (verified with objdump)",
    ],
)
def test_positive_or_probed_wording_is_not_a_static_closure(desc):
    """A positive statement or a cited probe must not trigger the nudge."""
    assert _static_closure_nudge(desc) == ""


def test_nudge_names_the_three_checks():
    nudge = _static_closure_nudge("nothing calls heap pointers")
    assert "dump" in nudge
    assert "House of Husk" in nudge
    assert "非等比缩放" in nudge


# ── dispatch wiring ─────────────────────────────────────────────────────


def _agent_with_board():
    from types import SimpleNamespace

    bb = Blackboard()
    agent = SimpleNamespace(
        runtime=SimpleNamespace(blackboard=bb), context=SimpleNamespace(state=None)
    )
    return bb, agent


@pytest.mark.asyncio
async def test_miss_response_carries_the_nudge_for_static_wording():
    bb, agent = _agent_with_board()
    angle = bb.create_angle("largebin attack writes heap pointers, nothing calls heap pointers")
    out = await dispatch_blackboard_tool(
        agent, "blackboard_miss_angle", {"node_id": angle.id}
    )
    assert "MISS" in out
    assert "静态断言" in out
    assert angle.status == NodeStatus.CHALLENGED


@pytest.mark.asyncio
async def test_miss_response_stays_clean_for_probed_wording():
    bb, agent = _agent_with_board()
    angle = bb.create_angle("tcache key check aborted both double-free attempts")
    out = await dispatch_blackboard_tool(
        agent, "blackboard_miss_angle", {"node_id": angle.id}
    )
    assert "MISS" in out
    assert "静态断言" not in out
    assert angle.status == NodeStatus.CHALLENGED


@pytest.mark.asyncio
async def test_a_second_miss_on_the_same_angle_does_not_repeat_the_nudge():
    bb, agent = _agent_with_board()
    angle = bb.create_angle("nothing calls heap pointers")
    first = await dispatch_blackboard_tool(
        agent, "blackboard_miss_angle", {"node_id": angle.id}
    )
    second = await dispatch_blackboard_tool(
        agent, "blackboard_miss_angle", {"node_id": angle.id}
    )
    assert "静态断言" in first
    assert "静态断言" not in second
    assert "unchanged" in second


def test_nudge_carries_a_variable_change_menu():
    """From Claude-BugHunter's exploit-completion mechanic 3 (2026-11-26).

    Their N=3 rule is only actionable because it ships a menu of what to change
    (injection point / encoding / content-type / the skipped hop / confirmation
    channel). Without the menu "change approach" is advice the model cannot
    execute; with it, the next probe is one edit away.
    """
    nudge = _static_closure_nudge("nothing calls heap pointers")

    for item in ("注入点", "编码与解析器", "content-type", "被跳过的那一跳", "确认通道", "输入长度"):
        assert item in nudge, f"menu missing {item!r}"
    assert "一次只改一个变量" in nudge


def test_nudge_says_identical_resend_is_not_verification():
    nudge = _static_closure_nudge("overflow not possible")
    assert "原样发到第 3 次" in nudge
