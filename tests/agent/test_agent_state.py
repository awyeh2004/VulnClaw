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
