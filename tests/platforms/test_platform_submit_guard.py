"""Flag-submission accounting at the adapter layer.

Three defects the refactor has to fix, each with a test here:

1. **Key collision.** Both platforms shared one guard keyed ``f"{x}/{y}"``, so a
   CTF2 key and a GCS key could collide and silently block a legitimate submit.
2. **The two-id signature.** GCS had to pass the same id twice, which is how the
   key shape above came about.
3. **The platform-specific message.** The escalation text hardcoded a
   ``[ctf2_confirm]`` prefix even when GCS triggered it.

Plus the migration of existing state files, which must not lose counters: the
attempt cap is a safety net, and a reset silently widens it.
"""

from __future__ import annotations

import json

import pytest

from vulnclaw.platforms.submit_guard import (
    ENV_AUTO_LIMIT,
    ENV_MAX_LIMIT,
    ENV_STATE_PATH,
    STATE_VERSION,
    MigrationReport,
    SubmitGuard,
    get_guard,
    guard_reason_to_message,
    legacy_key_to_token,
    migrate_legacy_state,
    reset_guard,
)

CTF2_KEY = "ctf2:practice:12:345"
GCS_KEY = "gcs:exercise:10662"


@pytest.fixture(autouse=True)
def _clean_limits(monkeypatch):
    """Keep the environment's limits out of these tests."""
    monkeypatch.delenv(ENV_AUTO_LIMIT, raising=False)
    monkeypatch.delenv(ENV_MAX_LIMIT, raising=False)
    monkeypatch.delenv(ENV_STATE_PATH, raising=False)
    reset_guard()
    yield
    reset_guard()


class TestPolicy:
    def test_first_submissions_are_allowed(self):
        guard = SubmitGuard()
        for index in range(3):
            allowed, reason = guard.allow(CTF2_KEY, f"flag{index}")
            assert allowed, reason
            guard.record(CTF2_KEY, accepted=False, flag=f"flag{index}")

    def test_after_the_auto_limit_a_human_is_required(self):
        guard = SubmitGuard()
        for index in range(3):
            guard.record(CTF2_KEY, accepted=False, flag=f"flag{index}")
        allowed, reason = guard.allow(CTF2_KEY, "flag4")
        assert not allowed
        assert "human confirmation" in reason

    def test_hard_limit_from_the_handbook(self, monkeypatch):
        monkeypatch.setenv(ENV_MAX_LIMIT, "4")
        guard = SubmitGuard()
        for index in range(4):
            guard.record(CTF2_KEY, accepted=False, flag=f"flag{index}")
        allowed, reason = guard.allow(CTF2_KEY, "flag9")
        assert not allowed
        assert "hard submission limit" in reason

    def test_repeating_a_failed_flag_is_deduped(self):
        guard = SubmitGuard()
        guard.record(CTF2_KEY, accepted=False, flag="flag{same}")
        allowed, reason = guard.allow(CTF2_KEY, "flag{same}")
        assert not allowed
        assert "anti brute-force" in reason

    def test_an_accepted_flag_closes_the_challenge(self):
        guard = SubmitGuard()
        guard.record(CTF2_KEY, accepted=True, flag="flag{win}")
        allowed, reason = guard.allow(CTF2_KEY, "flag{other}")
        assert not allowed
        assert "already solved" in reason

    def test_infrastructure_failure_consumes_nothing(self):
        """The platform never judged the flag, so retrying it must not be blocked."""
        guard = SubmitGuard()
        guard.record_error(CTF2_KEY)
        assert guard.attempts(CTF2_KEY) == 0
        allowed, _ = guard.allow(CTF2_KEY, "flag{retry}")
        assert allowed

    def test_limits_are_env_configurable(self, monkeypatch):
        monkeypatch.setenv(ENV_AUTO_LIMIT, "1")
        guard = SubmitGuard()
        guard.record(CTF2_KEY, accepted=False, flag="flag{one}")
        allowed, _ = guard.allow(CTF2_KEY, "flag{two}")
        assert not allowed

    def test_malformed_limits_fall_back_to_the_defaults(self, monkeypatch):
        monkeypatch.setenv(ENV_AUTO_LIMIT, "not-a-number")
        monkeypatch.setenv(ENV_MAX_LIMIT, "")
        guard = SubmitGuard()
        assert guard.auto_submit_limit() == 3
        assert guard.max_submit_limit() == 50


class TestKeyIsolation:
    def test_one_platform_cannot_exhaust_another(self):
        """The defect: a shared key space let one challenge block a different one."""
        guard = SubmitGuard()
        for index in range(3):
            guard.record(GCS_KEY, accepted=False, flag=f"flag{index}")
        allowed, reason = guard.allow(GCS_KEY, "flag{next}")
        assert not allowed

        allowed, reason = guard.allow(CTF2_KEY, "flag{ctf2}")
        assert allowed, reason

    def test_gcs_and_ctf2_counters_are_separate(self):
        guard = SubmitGuard()
        guard.record(GCS_KEY, accepted=False, flag="a")
        assert guard.attempts(GCS_KEY) == 1
        assert guard.attempts(CTF2_KEY) == 0


class TestPersistence:
    def test_round_trip(self, tmp_path):
        path = tmp_path / "guard.json"
        first = SubmitGuard(state_path=path)
        first.record(CTF2_KEY, accepted=False, flag="flag{a}")
        second = SubmitGuard(state_path=path)
        assert second.attempts(CTF2_KEY) == 1
        assert second.is_accepted(CTF2_KEY) is False

    def test_saved_file_carries_a_version(self, tmp_path):
        path = tmp_path / "guard.json"
        guard = SubmitGuard(state_path=path)
        guard.record(CTF2_KEY, accepted=True, flag="flag{win}")
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert raw["version"] == STATE_VERSION
        assert CTF2_KEY in raw["entries"]

    def test_corrupt_state_file_does_not_block_submissions(self, tmp_path):
        path = tmp_path / "guard.json"
        path.write_text("{not json", encoding="utf-8")
        guard = SubmitGuard(state_path=path)
        allowed, _ = guard.allow(CTF2_KEY, "flag{x}")
        assert allowed

    def test_missing_file_is_fine(self, tmp_path):
        guard = SubmitGuard(state_path=tmp_path / "absent.json")
        assert guard.attempts(CTF2_KEY) == 0


class TestLegacyMigration:
    @pytest.mark.parametrize(
        ("old_key", "expected"),
        [
            ("12/345", "ctf2:practice:12:345"),
            ("abc/def", "ctf2:practice:abc:def"),
            ("10662/10662", "gcs:exercise:10662"),
            ("7/7", "gcs:exercise:7"),
            ("abc/abc", "ctf2:practice:abc:abc"),
        ],
    )
    def test_legacy_key_translation(self, old_key, expected):
        assert legacy_key_to_token(old_key) == expected

    @pytest.mark.parametrize("old_key", ["", "noSlash", "/345", "12/", "/"])
    def test_unusable_legacy_keys_are_rejected(self, old_key):
        assert legacy_key_to_token(old_key) is None

    def test_duplicated_numeric_parts_mean_gcs(self):
        """GCS always wrote the same id twice; CTF2 never has equal ids in practice.

        The residual ambiguity (a CTF2 challenge whose practice id equals its
        challenge id) costs that one entry's counters.  Ordering it the other way
        would misattribute every GCS entry instead.
        """
        assert legacy_key_to_token("555/555") == "gcs:exercise:555"
        assert legacy_key_to_token("555/556") == "ctf2:practice:555:556"

    def test_generation_one_file_is_translated_on_load(self, tmp_path):
        path = tmp_path / "guard.json"
        path.write_text(
            json.dumps(
                {
                    "12/345": {"attempts": 2, "accepted": False, "last_flag": "flag{a}"},
                    "10662/10662": {"attempts": 5, "accepted": True, "last_flag": "flag{b}"},
                }
            ),
            encoding="utf-8",
        )
        guard = SubmitGuard(state_path=path)
        assert guard.attempts("ctf2:practice:12:345") == 2
        assert guard.attempts("gcs:exercise:10662") == 5
        assert guard.is_accepted("gcs:exercise:10662") is True

    def test_counters_are_not_lost_in_migration(self, tmp_path):
        """The cap is a safety net; a reset would silently widen it."""
        path = tmp_path / "guard.json"
        path.write_text(
            json.dumps({"12/345": {"attempts": 3, "accepted": False, "last_flag": "flag{a}"}}),
            encoding="utf-8",
        )
        guard = SubmitGuard(state_path=path)
        allowed, reason = guard.allow("ctf2:practice:12:345", "flag{next}")
        assert not allowed
        assert "human confirmation" in reason

    def test_migration_reports_what_it_did(self, tmp_path):
        path = tmp_path / "guard.json"
        path.write_text(
            json.dumps({"12/345": {"attempts": 1}, "junk": {"attempts": 1}}),
            encoding="utf-8",
        )
        guard = SubmitGuard(state_path=path)
        report = guard.migration
        assert isinstance(report, MigrationReport)
        assert ("12/345", "ctf2:practice:12:345") in report.mapped
        assert "junk" in report.dropped
        assert report.changed

    def test_migration_is_idempotent(self):
        """Reading a legacy file twice must not double-translate the keys."""
        legacy = {"12/345": {"attempts": 2, "accepted": False, "last_flag": None}}
        first = migrate_legacy_state(legacy)
        current = {"version": STATE_VERSION, "entries": first.entries}
        second = migrate_legacy_state(current)
        assert second.entries == first.entries
        assert not second.changed

    def test_generation_two_files_report_no_changes(self):
        report = migrate_legacy_state(
            {"version": STATE_VERSION, "entries": {CTF2_KEY: {"attempts": 1}}}
        )
        assert not report.changed
        assert report.entries == {CTF2_KEY: {"attempts": 1, "accepted": False, "last_flag": None}}

    def test_malformed_entries_are_dropped_not_crashed(self):
        report = migrate_legacy_state({"12/345": "not-a-dict", "1/2": {"attempts": "x"}})
        assert "12/345" in report.dropped
        assert report.entries["ctf2:practice:1:2"]["attempts"] == 0

    def test_non_mapping_input(self):
        report = migrate_legacy_state(["nope"])
        assert report.entries == {}
        assert report.dropped


class TestEscalationMessage:
    def test_message_is_platform_neutral(self):
        """The old text said [ctf2_confirm] even when GCS triggered it."""
        text = guard_reason_to_message(GCS_KEY, "already solved")
        assert "[submit_blocked]" in text
        assert "ctf2" not in text
        assert GCS_KEY in text
        assert "Do not retry automatically" in text


class TestProcessWideGuard:
    def test_get_guard_is_cached(self):
        assert get_guard() is get_guard()

    def test_reset_guard_drops_the_cache(self):
        first = get_guard()
        reset_guard()
        assert get_guard() is not first

    def test_state_path_comes_from_the_environment(self, tmp_path, monkeypatch):
        path = tmp_path / "env-guard.json"
        monkeypatch.setenv(ENV_STATE_PATH, str(path))
        reset_guard()
        get_guard().record(CTF2_KEY, accepted=False, flag="flag{a}")
        assert path.exists()
