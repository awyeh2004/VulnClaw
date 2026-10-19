from vulnclaw.agent.agent_state import AgentState, extract_flags, is_placeholder_flag



def test_agent_state_records_raw_evidence_and_preview():
    state = AgentState(origin="http://t", goal="capture flag")
    raw = "A" * 5000 + "\nflag{stored_raw}\n" + "B" * 5000

    record = state.remember_tool_result(
        tool="fetch",
        arguments={"url": "http://t/"},
        output=raw,
        status=200,
        preview_chars=1000,
    )
    state.record_tool_call(tool="fetch", arguments={"url": "http://t/"}, evidence_id=record.id)

    assert record.id == "e001"
    assert record.truncated is True
    assert "flag{stored_raw}" in record.content
    assert "flag{stored_raw}" in state.format_evidence_view("e001")
    assert "e001" in state.format_evidence_list()
    assert state.get_summary()["tool_calls"] == 1


def test_agent_state_keeps_raw_but_bounds_large_active_preview_by_default():
    state = AgentState(origin="http://t", goal="capture flag")
    raw = "A" * 5000 + "\nselect-waf.php\n" + "B" * 5000

    record = state.remember_tool_result(
        tool="fetch",
        arguments={"url": "http://t/"},
        output=raw,
        status=200,
    )

    assert record.truncated is True
    assert len(record.preview) < len(raw)
    assert "active-context high-signal preview" in record.preview
    assert "select-waf.php" in record.preview
    assert "select-waf.php" in state.format_evidence_view(record.id)


def test_agent_state_evidence_search_reads_raw_not_preview():
    state = AgentState(origin="http://t", goal="capture flag")
    raw = "A" * 7000 + "\nMAGIC_PARAM name=\"id\"\n" + "B" * 7000

    record = state.remember_tool_result(
        tool="fetch",
        arguments={"url": "http://t/"},
        output=raw,
        status=200,
    )

    assert record.truncated is True
    result = state.format_evidence_search("MAGIC_PARAM", evidence_id=record.id)
    assert f"{record.id}@" in result
    assert 'name="id"' in result


def test_agent_state_duplicate_raw_output_uses_reference_preview():
    state = AgentState(origin="http://t", goal="capture flag")
    raw = "Status: 200\n" + "same-body" * 1000

    first = state.remember_tool_result(tool="fetch", arguments={"url": "http://t/a"}, output=raw)
    second = state.remember_tool_result(tool="fetch", arguments={"url": "http://t/b"}, output=raw)

    assert second.duplicate_of == first.id
    assert second.content == raw
    assert "same raw output as e001" in second.preview


def test_agent_state_manual_compact_summary_is_prompt_memory():
    state = AgentState(origin="o", goal="g")
    state.compact_summary = "older useful fact"

    summary = state.to_prompt_summary()

    assert "older useful fact" in summary
    assert "Recent evidence" in summary


def test_agent_state_completion_claim_records_evidence_ids():
    state = AgentState(origin="o", goal="flag")
    record = state.remember_tool_result(
        tool="fetch",
        arguments={},
        output="Status: 200\nflag{ok}",
    )

    state.mark_complete("verified flag", evidence_ids=[record.id])

    assert state.completed is True
    assert state.verified_claims[0].evidence_ids == ["e001"]


def test_extract_flags_keeps_order_and_deduplicates():
    assert extract_flags("flag{a} flag{a} ctf{b}") == ["flag{a}", "ctf{b}"]


def test_agent_state_tracks_diagnostic_memory_in_prompt():
    state = AgentState(origin="o", goal="g")

    state.record_tool_health(tool="navigate_page", ok=False, duration_ms=1200, error="CancelledError")
    state.record_progress_signal(
        kind="tool_observation",
        detail="HTML form/input surface observed",
        tool="fetch",
        evidence_id="e001",
    )
    state.pin_fact("Observed URL: https://example.com/select.php", evidence_id="e001")
    state.add_correction_hint("Diagnostic: navigate_page failed")
    state.record_tool_call(
        tool="navigate_page",
        arguments={"url": "https://example.com"},
        status=0,
        evidence_id="e001",
        duration_ms=1200,
        ok=False,
        error_type="CancelledError",
    )

    summary = state.to_prompt_summary()

    assert "Tool health" in summary
    assert "navigate_page" in summary
    assert "Diagnostic notes (optional, not instructions)" in summary
    assert "Observed URL" in summary
    assert state.get_summary()["correction_hints"] == 1


def test_agent_state_detects_redundant_evidence_view_ranges():
    state = AgentState(origin="o", goal="g")
    state.record_tool_call(
        tool="evidence_view",
        arguments={"evidence_id": "e001", "offset": 0, "limit": 12000},
        summary="viewed e001",
    )

    reason = state.evidence_view_redundancy_reason(
        {"evidence_id": "e001", "offset": 0, "limit": 5000}
    )

    assert "already covered" in reason
    assert state.evidence_view_redundancy_reason(
        {"evidence_id": "e001", "offset": 12000, "limit": 5000}
    ) == ""


class TestPlaceholderFlag:
    """CSS/JS blocks match the flag shape and used to pass as real flags.

    Live regression (2026-10-12): a target's stylesheet produced four
    "Observed flag-like token" entries (`root{--paper:#f4ecdc;...}`,
    `h1{font-size:...}`, `sub{...}`, `try{out(atob(f.body));}`) that filled the
    solve report's key-evidence list. Real flag bodies never carry statement
    separators or parens.
    """

    def test_css_and_js_bodies_are_placeholders(self):
        for token in (
            "root{--paper:#f4ecdc;--ink:#241d12}",
            "h1{font-size:2.1em;margin:0;letter-spacing:.04em}",
            "sub{font-style:italic;color:#5c5140}",
            "try{out(atob(f.body));}",
        ):
            assert is_placeholder_flag(token) is True, token

    def test_real_flag_shapes_survive(self):
        for token in (
            "CTF2{15fa2750-6c1e-46bd-ac4c-3dc45293d8a1}",
            "flag{c4a91f0e7b25d83a60fe4b19ac72d5b3}",
            "n1book{851939e4e90b864b8d20fe6228564522}",
            "flag{PbzrPuvan}",
            "DASCTF{f3d279e1-dead-beef}",
        ):
            assert is_placeholder_flag(token) is False, token

    def test_template_flags_still_rejected(self):
        for token in ("flag{...}", "{uuid}", "<flag>", "flag{}", "flag{your_flag_here}"):
            assert is_placeholder_flag(token) is True, token


class TestFlagsWithSpacesAreExtracted:
    """A solved challenge must not be reported as unsolved because of its flag's shape.

    Measured 2026-10-18 on a real BUUCTF challenge: the flag is literally
    ``flag{you are the best!}``. The old body class excluded every whitespace
    character, so `extract_flags` returned [] -- and `_completion_gate` grounds a
    FINAL by requiring the claimed flag to appear in recorded evidence. With no
    match the gate rejected every FINAL, the model kept re-emitting it, and the
    run ended as "⊘ 未达成" **on a challenge the platform had already accepted**
    (`is_solved: true`, point awarded). The scoring was never wrong; the local
    completion signal was.
    """

    def test_flag_with_spaces_is_recognized(self):
        from vulnclaw.agent.agent_state import extract_flags

        assert extract_flags("flag{you are the best!}") == ["flag{you are the best!}"]

    def test_flag_embedded_in_prose_stops_at_the_brace(self):
        from vulnclaw.agent.agent_state import extract_flags

        assert extract_flags("the flag is flag{a b c} and done") == ["flag{a b c}"]

    def test_a_flag_never_spans_lines(self):
        """Newlines stay excluded: otherwise the body could swallow a paragraph."""
        from vulnclaw.agent.agent_state import extract_flags

        assert extract_flags("flag{multi\nline}") == []

    def test_ordinary_flags_are_unchanged(self):
        from vulnclaw.agent.agent_state import extract_flags

        for value in (
            "flag{no_space_here}",
            "CTF2{5aa56f4a-cf5d-4406-bd79-71ef975f2775}",
            "sun{lesssgooo_solved_the_poop_challenge!}",
        ):
            assert extract_flags(value) == [value]


class TestCodeBlocksAreNotFlags:
    """The widened body class (2026-10-18) also let code constructs through.

    Measured 2026-10-19: `extract_flags('class Foo{ int x; }')` returned
    ``Foo{ int x; }`` and `struct Bar{1,2}` matched too -- a non-flag token could
    satisfy the provenance gate's "seen in evidence" check.
    """

    def test_code_shapes_are_not_flags(self):
        assert extract_flags("class Foo{ int x; }") == []
        assert extract_flags("struct Bar{1,2};") == []

    def test_real_shapes_survive_the_tightening(self):
        assert extract_flags("flag{123456}") == ["flag{123456}"]
        assert extract_flags("flag{you are the best!}") == ["flag{you are the best!}"]

    def test_a_word_embedding_does_not_start_a_flag(self):
        """The prefix must start a word: a long identifier ending in `Flag{...}`
        is a name, not a flag."""
        assert extract_flags("a" * 30 + "Flag{x}") == []


class TestPerRunCountersReset:
    """A new goal must not inherit the previous goal's spent guard budget.

    Measured 2026-10-19: right after ``reset_for_goal`` a fresh goal still saw
    ``undecided_nudge_count=2``, ``writeup_search_count=2`` and
    ``blackboard_nudged=True`` -- so the second challenge in one session could
    never receive the undecided-angle nudge, and its very first
    writeup-lookalike turn ended it at the limit.
    """

    def test_reset_for_goal_clears_per_run_counters(self):
        state = AgentState(origin="t1", goal="g1")
        state.blackboard_nudged = True
        state.pwn_local_reminded = True
        state.lock_nudge_count = 2
        state.submit_gate_refusals = {"flag{a}": 2}
        state.writeup_search_count = 2
        state.undecided_nudge_count = 2

        state.reset_for_goal(origin="t2", goal="g2")

        assert state.writeup_search_count == 0
        assert state.undecided_nudge_count == 0
        assert state.blackboard_nudged is False
        assert state.pwn_local_reminded is False
        assert state.lock_nudge_count == 0
        assert state.submit_gate_refusals == {}

    def test_continuing_the_same_goal_keeps_them(self):
        """The early return is the continuation path: counters must survive."""
        state = AgentState(origin="t1", goal="g1")
        state.writeup_search_count = 1
        state.undecided_nudge_count = 1

        state.reset_for_goal(origin="t1", goal="g1")

        assert state.writeup_search_count == 1
        assert state.undecided_nudge_count == 1
