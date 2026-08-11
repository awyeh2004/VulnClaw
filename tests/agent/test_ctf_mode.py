"""Tests for the CTF flag state machine (vulnclaw.agent.ctf_mode)."""

from __future__ import annotations

from vulnclaw.agent.ctf_mode import detect_flag_claim, update_ctf_state


class _Runtime:
    def __init__(self, *, is_ctf_mode=True):
        self.claimed_flag = None
        self.flag_verified = False
        self.is_ctf_mode = is_ctf_mode
        self.flag_claim_count = 0
        self.post_flag_rounds = 0


class _State:
    def __init__(self):
        self.notes: list[str] = []


class _Ctx:
    def __init__(self):
        self.state = _State()


class _Agent:
    """Minimal double exposing exactly what update_ctf_state touches."""

    def __init__(self, *, is_ctf_mode=True):
        self.runtime = _Runtime(is_ctf_mode=is_ctf_mode)
        self.context = _Ctx()


class TestDetectFlagClaim:
    def test_detects_common_flag_formats(self):
        assert detect_flag_claim("got flag{abc_123}") == "flag{abc_123}"
        assert detect_flag_claim("CTF{xy}") == "CTF{xy}"
        assert detect_flag_claim("NSSCTF{deadbeef}") == "NSSCTF{deadbeef}"
        # Case-insensitive match still returns the captured text.
        assert detect_flag_claim("FLAG{UP}") == "FLAG{UP}"

    def test_returns_none_without_flag(self):
        assert detect_flag_claim("no flag here") is None
        assert detect_flag_claim("") is None


class TestUpdateCtfState:
    def test_first_claim_records_flag_and_keeps_going(self):
        agent = _Agent()
        cont = update_ctf_state(agent, "found flag{first}", result_should_continue=False)
        assert agent.runtime.claimed_flag == "flag{first}"
        assert agent.runtime.flag_verified is False
        assert cont is True  # unverified claim must not stop the run

    def test_explicit_verification_marker_verifies(self):
        agent = _Agent()
        agent.runtime.claimed_flag = "flag{x}"
        update_ctf_state(agent, "flag 验证成功", result_should_continue=True)
        assert agent.runtime.flag_verified is True

    def test_flag_seen_in_two_notes_verifies(self):
        agent = _Agent()
        agent.runtime.claimed_flag = "flag{x}"
        agent.context.state.notes = ["saw flag{x}", "again flag{x}"]
        update_ctf_state(agent, "unrelated text", result_should_continue=True)
        assert agent.runtime.flag_verified is True

    def test_repeated_identical_claims_eventually_verify(self):
        agent = _Agent()
        # Claim the same flag repeatedly; after enough repeats it self-verifies.
        for _ in range(5):
            update_ctf_state(agent, "flag{loop}", result_should_continue=True)
        assert agent.runtime.claimed_flag == "flag{loop}"
        assert agent.runtime.flag_verified is True

    def test_non_ctf_mode_does_not_force_continue(self):
        agent = _Agent(is_ctf_mode=False)
        # No claim, not CTF mode: the incoming should_continue is preserved.
        assert update_ctf_state(agent, "just recon output", result_should_continue=False) is False
