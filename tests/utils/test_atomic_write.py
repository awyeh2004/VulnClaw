"""Durable-write contract: retry on Windows sharing violations, never truncate.

Why these exist: six modules persisted state with a bare ``os.replace``, which on
Windows fails intermittently with

    PermissionError: [WinError 5] 拒绝访问。
      '.../graph.json.tmp' -> '.../graph.json'

whenever a scanner or concurrent reader holds the destination open. The symptom
was a *non-deterministic* test failure (a different test each run) and, in the
field, silently dropped durable state. Only this module's logic stands between
that and real data loss, so it is tested directly rather than via its callers.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from vulnclaw.utils.atomic_write import (
    RETRY_ATTEMPTS,
    atomic_write_text,
    replace_with_retry,
)


class TestReplaceWithRetry:
    def test_success_first_try(self, tmp_path):
        src = tmp_path / "a"
        dst = tmp_path / "b"
        src.write_text("x", encoding="utf-8")
        replace_with_retry(src, dst)
        assert dst.read_text(encoding="utf-8") == "x"
        assert not src.exists()

    def test_retries_then_succeeds(self, tmp_path):
        """A transient sharing violation must not lose the write."""
        src = tmp_path / "a"
        dst = tmp_path / "b"
        src.write_text("x", encoding="utf-8")
        real_replace = os.replace
        calls = {"n": 0}

        def flaky(s, d):
            calls["n"] += 1
            if calls["n"] < 3:
                raise PermissionError(5, "拒绝访问。")
            return real_replace(s, d)

        with patch("vulnclaw.utils.atomic_write.os.replace", side_effect=flaky):
            replace_with_retry(src, dst)
        assert calls["n"] == 3
        assert dst.read_text(encoding="utf-8") == "x"

    def test_gives_up_after_budget_and_reraises_the_last_error(self, tmp_path):
        src = tmp_path / "a"
        dst = tmp_path / "b"
        src.write_text("x", encoding="utf-8")
        with patch(
            "vulnclaw.utils.atomic_write.os.replace",
            side_effect=PermissionError(5, "拒绝访问。"),
        ) as mocked:
            with pytest.raises(PermissionError):
                replace_with_retry(src, dst)
        assert mocked.call_count == RETRY_ATTEMPTS

    def test_other_oserror_is_not_retried(self, tmp_path):
        """Only PermissionError is the sharing-violation signal; the rest are real."""
        src = tmp_path / "a"
        dst = tmp_path / "b"
        src.write_text("x", encoding="utf-8")
        with patch(
            "vulnclaw.utils.atomic_write.os.replace",
            side_effect=FileNotFoundError(2, "no such file"),
        ) as mocked:
            with pytest.raises(FileNotFoundError):
                replace_with_retry(src, dst)
        assert mocked.call_count == 1


class TestAtomicWriteText:
    def test_writes_content(self, tmp_path):
        target = tmp_path / "deep" / "x.json"
        atomic_write_text(target, '{"a": 1}')
        assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1}

    def test_creates_missing_parents(self, tmp_path):
        target = tmp_path / "a" / "b" / "c.txt"
        atomic_write_text(target, "hi")
        assert target.read_text(encoding="utf-8") == "hi"

    def test_overwrites_existing(self, tmp_path):
        target = tmp_path / "x.txt"
        target.write_text("old", encoding="utf-8")
        atomic_write_text(target, "new")
        assert target.read_text(encoding="utf-8") == "new"

    def test_survives_a_sharing_violation(self, tmp_path):
        """The whole point: a busy destination must not lose the write."""
        target = tmp_path / "x.txt"
        target.write_text("old", encoding="utf-8")
        real_replace = os.replace
        calls = {"n": 0}

        def flaky(s, d):
            calls["n"] += 1
            if calls["n"] == 1:
                raise PermissionError(5, "拒绝访问。")
            return real_replace(s, d)

        with patch("vulnclaw.utils.atomic_write.os.replace", side_effect=flaky):
            atomic_write_text(target, "new")
        assert target.read_text(encoding="utf-8") == "new"

    def test_failure_leaves_target_untouched_and_no_litter(self, tmp_path):
        target = tmp_path / "x.txt"
        target.write_text("original", encoding="utf-8")
        with patch(
            "vulnclaw.utils.atomic_write.os.replace",
            side_effect=PermissionError(5, "拒绝访问。"),
        ):
            with pytest.raises(PermissionError):
                atomic_write_text(target, "new")
        # The rename is the commit point: the old content must still be intact...
        assert target.read_text(encoding="utf-8") == "original"
        # ...and the temp file must not be left behind.
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != "x.txt"]
        assert leftovers == [], leftovers

    def test_temp_file_is_not_the_target_name(self, tmp_path):
        """A reader must never see the target in a half-written state."""
        target = tmp_path / "x.txt"
        seen: list[str] = []
        real_replace = os.replace

        def observed(s, d):
            seen.extend(p.name for p in tmp_path.iterdir())
            return real_replace(s, d)

        with patch("vulnclaw.utils.atomic_write.os.replace", side_effect=observed):
            atomic_write_text(target, "content")
        assert "x.txt" not in seen or any(n.startswith(".x.txt.") for n in seen)

    def test_unicode_round_trips(self, tmp_path):
        target = tmp_path / "cn.json"
        payload = {"msg": "应急响应 · 持久化"}
        atomic_write_text(target, json.dumps(payload, ensure_ascii=False))
        assert json.loads(target.read_text(encoding="utf-8")) == payload

    def test_accepts_str_and_path(self, tmp_path):
        atomic_write_text(str(tmp_path / "a.txt"), "1")
        atomic_write_text(Path(tmp_path / "b.txt"), "2")
        assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "1"
        assert (tmp_path / "b.txt").read_text(encoding="utf-8") == "2"
