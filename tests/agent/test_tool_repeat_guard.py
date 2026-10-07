"""Round-22 (2026-10-06) postmortem: the tool repeat guard counts *results*.

In the nginx-ui run (CVE-2026-27944, ``direct-ctf2.dasctf.com:25973``) every
``python_execute`` call targeted the single host in scope, so the URL-only
fingerprint was constant. The guard tripped at 30 calls and then refused the
tool for the *rest of the session* -- even though the 30 responses were all
different (200/403/404/500, different bodies) and each probe used different
logic. The run lost its only execution tool, delegated the work to a group that
could not execute anything, and never read the flag.

The guard's message has always claimed it only counts calls "without producing a
new result"; these tests pin that claim to the implementation.
"""

from __future__ import annotations

import types

from vulnclaw.agent import runtime_state
from vulnclaw.agent.tool_call_manager import (
    _remember_target_result,
    _repeat_guard_violation,
    _result_signature,
)

TARGET = "http://direct-ctf2.dasctf.com:25973"
PROBE = {"code": f'import requests\nrequests.get("{TARGET}/api/backup")\n'}

# Same probe family, genuinely different outcomes (as in the real run).
SAME_RESULT = f"[+] Python execution result (trusted-local):\nGET {TARGET}/api/configs 200 len=1208"
DIFFERENT_RESULTS = [
    f"[+] Python execution result (trusted-local):\nGET {TARGET}/api/backup 200 len={1200 + i}\nbody=backup-{i}"
    for i in range(6)
]


def _agent(limit: int | None = None):
    session = types.SimpleNamespace(
        repeat_tool_limits={"python_execute": limit} if limit is not None else {},
        repeat_tool_limit_default=0,
    )
    return types.SimpleNamespace(
        runtime=runtime_state.RuntimeState(),
        config=types.SimpleNamespace(session=session),
    )


def test_runtime_state_carries_the_result_signature_map():
    assert runtime_state.RuntimeState().tool_target_result_sig == {}


def test_repeated_identical_results_still_trip_the_guard():
    """The guard must keep its teeth: a genuinely stalled probe is throttled."""
    agent = _agent(limit=3)
    for _ in range(3):
        assert _repeat_guard_violation(agent, "python_execute", PROBE) is None
        _remember_target_result(agent, "python_execute", PROBE, SAME_RESULT)

    blocked = _repeat_guard_violation(agent, "python_execute", PROBE)
    assert blocked is not None
    assert "SAME result" in blocked
    assert _result_signature(SAME_RESULT) in blocked


def test_new_results_never_trip_the_guard():
    """40 calls, 40 genuinely different results -> the run keeps its tool."""
    agent = _agent()  # table default for python_execute is 30
    for i in range(40):
        assert _repeat_guard_violation(agent, "python_execute", PROBE) is None, (
            f"guard fired on progressive call #{i}"
        )
        _remember_target_result(
            agent,
            "python_execute",
            PROBE,
            f"GET {TARGET}/api/resource-{i} 200 body=payload-{i}",
        )

    fp = next(iter(agent.runtime.tool_target_calls))
    assert agent.runtime.tool_target_calls[fp] < 30


def test_volatile_fields_fold_but_status_codes_do_not():
    """Timings/sizes/hashes are noise; a new HTTP status is progress."""
    assert _result_signature("len=1208 cost=1.7s") == _result_signature(
        "len=1210 cost=2.9s"
    )
    assert _result_signature("hash=39527c2b6aac") == _result_signature(
        "hash=39527c2b6aaa"
    )
    assert _result_signature("GET /api/users 403") != _result_signature(
        "GET /api/users 200"
    )


def test_results_sharing_a_long_preamble_are_not_folded_together():
    """Round15b (2026-10-07): the signature hashed only the first 800 characters,
    so two genuinely different results that share a long identical preamble (a
    route table, an HTML head) folded to the SAME signature. That is precisely
    the false positive the module docstring rules out — and a false positive
    costs the run its tool (round-22 lost a whole run that way)."""
    preamble = "GET /api/users 200 " + "x" * 1000
    assert _result_signature(preamble + "tail-A") != _result_signature(
        preamble + "tail-B"
    )


def test_counter_resets_exactly_on_a_changed_result():
    agent = _agent(limit=3)
    _repeat_guard_violation(agent, "python_execute", PROBE)
    _remember_target_result(agent, "python_execute", PROBE, SAME_RESULT)
    fp = next(iter(agent.runtime.tool_target_calls))
    assert agent.runtime.tool_target_calls[fp] == 1

    # A changed result zeroes the budget ...
    _repeat_guard_violation(agent, "python_execute", PROBE)
    _remember_target_result(agent, "python_execute", PROBE, DIFFERENT_RESULTS[0])
    assert agent.runtime.tool_target_calls[fp] == 0

    # ... and the following identical result counts from that baseline.
    _repeat_guard_violation(agent, "python_execute", PROBE)
    _remember_target_result(agent, "python_execute", PROBE, DIFFERENT_RESULTS[0])
    assert agent.runtime.tool_target_calls[fp] == 1


def test_the_real_run_would_no_longer_lock_python_execute():
    """Replay of the actual evidence: 30 distinct responses must all be allowed."""
    agent = _agent()
    real_responses = [
        f"GET {TARGET}/api/configs 200 len={n}" for n in (1208, 4096, 1208, 34, 129, 82, 3905)
    ] + [f'POST {TARGET}/api/restore 500 code=4511 params=multipart-{i}' for i in range(23)]
    assert len(real_responses) == 30

    for i, response in enumerate(real_responses):
        assert _repeat_guard_violation(agent, "python_execute", PROBE) is None, (
            f"call #{i} was blocked by the guard"
        )
        _remember_target_result(agent, "python_execute", PROBE, response)
