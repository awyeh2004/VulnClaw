"""Tests for the whitelist-style completion gate (Muteki port).

The gate must NOT reject a fully-grounded flag just because its content happens
to contain a substring that parses as an unknown evidence id (e.g.
``CTF2{8ff2d98e-e990-...}`` contains ``e990``). Rejection stays for flags that
are NOT grounded in evidence.
"""

import re

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.agent.solver import _completion_gate, _implicit_flag_completion


def _make_flag_state(evidence_text: str) -> AgentState:
    st = AgentState(goal="capture the flag and output it")
    st.evidence = [
        type("Ev", (), {"content": evidence_text, "id": "e008", "evidence_id": "e008"})()
    ]
    return st


def test_flag_containing_evidence_like_substring_passes():
    """A grounded flag whose body contains 'e990' must still complete."""
    flag = "CTF2{8ff2d98e-e990-4604-9235-f012e1b8cb80}"
    st = _make_flag_state(f"0 union select group_concat(flag) -> {flag}")
    ok, reason, _ = _completion_gate(st, f"FINAL: Flag: {flag} (evidence e008)")
    assert ok, reason


def test_ungrounded_flag_still_rejected():
    """A flag not present in evidence is still rejected (no regression)."""
    st = _make_flag_state("login ok, nothing else")
    ok, reason, _ = _completion_gate(st, "FINAL: Flag: DASCTF{local_verify}")
    assert not ok
    assert "not present in tool evidence" in reason


def test_placeholder_flag_rejected():
    st = _make_flag_state("got flag{...} placeholder")
    ok, reason, _ = _completion_gate(st, "FINAL: Flag: flag{...}")
    assert not ok


def test_unknown_citation_is_soft_note_not_rejection():
    """Unknown cited ids become a note appended to the accepted result."""
    flag = "DASCTF{real_grounded_flag_123}"
    st = _make_flag_state(f"output: {flag}")
    ok, reason, cited = _completion_gate(st, f"FINAL: Flag: {flag} (evidence e999)")
    assert ok
    assert "e999" in reason  # surfaced as a soft note
    assert cited == ["e999"]


def test_missing_flag_in_flag_goal_rejected():
    st = _make_flag_state("some evidence here e001")
    ok, reason, _ = _completion_gate(st, "FINAL: the port is open")
    assert not ok


# ── visible incompleteness: an opening brace must be observed to CLOSE ──────
#
# 2026-10-09 (鸡公煲 rehearsal): a flag split into six 7-char fragments was assembled
# from only five, and the model supplied the missing `}` itself. It matched the flag
# regex AND looked grounded, because the model had already written that exact string into
# a blackboard note whose tool result counts as evidence. The platform rejected it.
# These tests pin the tell: the brace, and a UUID body that is short its last group.


def test_five_of_six_fragments_is_refused_even_though_it_looks_grounded():
    # Same SHAPE as the real incident (8-4-4-4-6) but a synthetic body: the real value is
    # a per-instance flag and has no business being stored in the repo.
    flag = "CTF2{01234567-89ab-cdef-0123-456789}"
    st = _make_flag_state(f"note: Full flag = {flag}\n")
    ok, reason, _ = _completion_gate(st, f"FINAL: {flag} (evidence e008)")
    assert not ok
    assert "TRUNCATED" in reason
    assert "12" in reason  # says what a UUID last group should be


def test_complete_uuid_flag_still_completes():
    flag = "CTF2{8ff2d98e-e990-4604-9235-f012e1b8cb80}"
    st = _make_flag_state(f"leaked: {flag}")
    ok, reason, _ = _completion_gate(st, f"FINAL: Flag: {flag} (evidence e008)")
    assert ok, reason


def test_unclosed_candidate_says_not_to_supply_the_brace():
    """No complete flag, only an opening-brace fragment: name the missing brace."""
    st = _make_flag_state("evidence so far: CTF2{01234567-89ab-cdef-0123")
    ok, reason, _ = _completion_gate(
        st, "FINAL: assembled so far CTF2{01234567-89ab-cdef-0123 (缺尾段)"
    )
    assert not ok
    assert "UNCLOSED" in reason
    assert "brace" in reason


def test_completeness_check_is_narrow():
    """Wide enough shapes must pass untouched -- this runs on the completion path."""
    from vulnclaw.agent.ctf_mode import flag_completeness_issues

    complete = [
        "CTF2{8ff2d98e-e990-4604-9235-f012e1b8cb80}",   # full UUID
        "GKCTF{9cf21dda-34be-4f6c-a629-9c4647981ad7}",  # full UUID, other prefix
        "D0g3{3466b11de8894198af3636c5bd1efce2}",       # 32 hex, no dashes
        "flag{189ff9e5b743ae95f940a6ccc6dbd9ab}",       # 32 hex
        "flag{fil3_ext3nsi0ns_4r3nt_r34l}",             # prose-shaped body
        "SETCTF{Fi9ht1ng_3ItH_V1rUs}",
    ]
    for flag in complete:
        assert flag_completeness_issues(f"answer says {flag}", [flag]) == [], flag

    # a masked fingerprint is not an unclosed candidate
    assert flag_completeness_issues("note: CTF2{0123…6789}", []) == []
    # ...but these two shapes are (synthetic bodies, same shapes as the real incident)
    assert flag_completeness_issues("x", ["CTF2{01234567-89ab-cdef-0123-456789}"])
    assert flag_completeness_issues("只有 CTF2{01234567-89ab-cdef-0123 这一段", [])


# ── multi-layer ("套娃") goals ────────────────────────────────────────────────
# 2026-10-31 ezphp: the first flag that reached evidence was a decoy baked into the
# image; the gate accepted it and the run stopped two stages early. For goals that
# themselves say the challenge is nested, FINAL must assert finality.

def _make_multilayer_state(evidence_text: str) -> AgentState:
    st = _make_flag_state(evidence_text)
    st.goal = "这是一道套娃题：每拿到一层答案都要继续，直到拆到底，最终拿到 flag"
    # The deepest-layer rule is a CTF completion policy (see
    # ``solver._multilayer_gate_enabled``); production runs must not trigger it.
    st.task_mode = "ctf"
    return st


def test_multilayer_goal_rejects_grounded_decoy_without_finality_claim():
    flag = "flag{decoy_inner_layer_123}"
    st = _make_multilayer_state(f"GET /flag.php -> {flag}")
    ok, reason, _ = _completion_gate(st, f"FINAL: Flag: {flag} (evidence e008)")
    assert not ok
    assert "deepest layer" in reason


def test_multilayer_goal_accepts_with_finality_claim():
    flag = "flag{real_last_layer_456}"
    st = _make_multilayer_state(f"cat /flag -> {flag}")
    ok, reason, _ = _completion_gate(
        st, f"FINAL: Flag: {flag} —— 已确认这是最深层：flag 文件 mtime 等于容器启动时间 (e008)"
    )
    assert ok, reason


def test_single_layer_goal_unaffected_by_multilayer_rule():
    """An ordinary one-flag goal still completes without any finality wording."""
    flag = "flag{plain_single_layer_789}"
    st = _make_flag_state(f"cat /flag -> {flag}")
    ok, reason, _ = _completion_gate(st, f"FINAL: Flag: {flag} (evidence e008)")
    assert ok, reason


def test_multilayer_goal_still_needs_grounded_flag():
    """Finality wording must not substitute for grounding."""
    st = _make_multilayer_state("nothing here")
    ok, reason, _ = _completion_gate(
        st, "FINAL: Flag: flag{ungrounded_000} —— 这是最深层"
    )
    assert not ok


def test_multilayer_goal_guards_the_implicit_path_too():
    """Dropping the `FINAL:` marker must not bypass the deepest-layer rule.

    The implicit path completes on any grounded flag without citing evidence, so
    a nested goal reached its decoy there even though the explicit gate rejected
    the very same text.
    """
    flag = "flag{decoy_inner_layer_123}"
    st = _make_multilayer_state(f"GET /flag.php -> {flag}")

    ok, reason, _ = _implicit_flag_completion(st, f"拿到 {flag} 了")

    assert not ok
    assert "deepest layer" in reason


def test_multilayer_goal_implicit_path_accepts_finality_claim():
    flag = "flag{real_last_layer_456}"
    st = _make_multilayer_state(f"cat /flag -> {flag}")

    ok, reason, evidence = _implicit_flag_completion(
        st, f"拿到 {flag}，已确认这是最深层，没有下一层"
    )

    assert ok, reason
    assert evidence == ["e008"]


def test_encoding_layers_are_not_a_nested_challenge():
    """`多层编码 / 逐层解码` describes transforms, not hidden stages.

    The flag there IS the end of the task: requiring a finality claim rejected a
    fully-grounded flag and sent the run into pointless extra digging.
    """
    flag = "flag{decoded_final_222}"
    st = _make_flag_state(f"base64 -d | gzip -d -> {flag}")
    st.goal = "这是一道多层编码题，逐层解码直到 flag"

    ok, reason, _ = _completion_gate(st, f"FINAL: Flag: {flag} (evidence e008)")

    assert ok, reason


def test_ordinary_multistage_wording_is_not_a_nested_challenge():
    """`多阶段流程` / `layered defense` / `nested archive` are not 套娃 challenges."""
    flag = "flag{ordinary_flow_333}"
    for goal in (
        "分多阶段流程完成本次资产盘点，最后拿到 flag",
        "layered defense review, then capture the flag",
        "unpack this nested archive to get the flag",
    ):
        st = _make_flag_state(f"tool output -> {flag}")
        st.goal = goal
        ok, reason, _ = _completion_gate(st, f"FINAL: Flag: {flag} (evidence e008)")
        assert ok, f"{goal}: {reason}"


# ── CTF-only scope of the deepest-layer rule ─────────────────────────────────
# The rule protects a CTF run from a decoy flag. A production run may legitimately
# say "multi-stage"/"layered"/"层层" without any hidden answer behind the first
# result, so the rule must never fire there (2026-11-04 review).

def test_deepest_layer_rule_does_not_fire_on_a_production_run():
    flag = "flag{production_layered_444}"
    st = _make_flag_state(f"review output -> {flag}")
    st.goal = "逐层核查 layered defense，最终拿到 flag"
    st.task_mode = "pentest"

    ok, reason, _ = _completion_gate(st, f"FINAL: Flag: {flag} (evidence e008)")

    assert ok, reason


def test_deepest_layer_rule_fires_without_a_stored_mode_when_the_goal_is_ctf():
    """Older snapshots carry no mode: a CTF-marked goal still gets the guard."""
    flag = "flag{decoy_without_mode_555}"
    st = _make_flag_state(f"GET /flag.php -> {flag}")
    st.goal = "这是一道套娃题：拿到 flag{...} 后还要继续"
    st.task_mode = ""

    ok, reason, _ = _completion_gate(st, f"FINAL: Flag: {flag} (evidence e008)")

    assert not ok
    assert "deepest layer" in reason


# ── finality wording ────────────────────────────────────────────────────────
# The gate asks for natural language, so the accepting vocabulary must cover the
# synonyms a model actually writes; a miss rejects a correct answer and feeds the
# rejection back into the run.

def test_finality_synonyms_are_accepted():
    flag = "flag{synonym_final_666}"
    for phrasing in (
        "已确认不存在后续层级",
        "确认没有更深的一层",
        "已经到达最底层",
        "后面没有新的层",
        "no more layers remain",
        "confirmed as the terminal layer",
        "nothing deeper remains",
    ):
        st = _make_multilayer_state(f"cat /flag -> {flag}")
        ok, reason, _ = _completion_gate(
            st, f"FINAL: Flag: {flag} —— {phrasing} (evidence e008)"
        )
        assert ok, f"{phrasing}: {reason}"


def test_negated_finality_is_still_rejected():
    flag = "flag{negated_final_777}"
    for phrasing in (
        "还不能确认没有下一层",
        "尚未到达最深层",
        "cannot confirm no more layers remain",
    ):
        st = _make_multilayer_state(f"cat /flag -> {flag}")
        ok, reason, _ = _completion_gate(
            st, f"FINAL: Flag: {flag} —— {phrasing} (evidence e008)"
        )
        assert not ok, f"{phrasing} must not count as a finality claim"
        assert "deepest layer" in reason


def test_structured_final_status_is_accepted():
    """A deterministic marker must not depend on picking the right synonym."""
    flag = "flag{structured_final_888}"
    st = _make_multilayer_state(f"cat /flag -> {flag}")
    ok, reason, _ = _completion_gate(
        st, f"FINAL: Flag: {flag}\nFINAL_STATUS: deepest_layer_confirmed"
    )
    assert ok, reason
