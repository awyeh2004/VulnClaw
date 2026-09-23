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
    append_line_durable,
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


class TestFdopenFailureDoesNotLeak:
    """Audit finding F1: `os.fdopen` sat OUTSIDE the try that cleans up.

    `os.open` creates the file and returns a descriptor; if `os.fdopen` then raised (an
    unknown encoding -> LookupError, or an interrupt landing between the two calls),
    nothing closed the descriptor and nothing removed the temp file -- contradicting the
    docstring's "temp file removed on any failure". The fd belongs to the function until
    `fdopen` takes it over.
    """

    def test_no_temp_file_litter_when_fdopen_raises(self, tmp_path):
        target = tmp_path / "x.txt"
        with patch(
            "vulnclaw.utils.atomic_write.os.fdopen", side_effect=LookupError("bad encoding")
        ):
            with pytest.raises(LookupError):
                atomic_write_text(target, "content", encoding="not-a-codec")

        assert not target.exists()
        assert [p.name for p in tmp_path.iterdir()] == [], "the temp file leaked"

    def test_the_descriptor_is_closed_when_fdopen_raises(self, tmp_path):
        """Closing matters as much as the file: a leaked fd is unbounded per call."""
        opened: list[int] = []
        closed: list[int] = []
        real_open, real_close = os.open, os.close

        def spy_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.append(fd)
            return fd

        def spy_close(fd, *args, **kwargs):
            closed.append(fd)
            return real_close(fd, *args, **kwargs)

        with patch("vulnclaw.utils.atomic_write.os.open", side_effect=spy_open), patch(
            "vulnclaw.utils.atomic_write.os.close", side_effect=spy_close
        ), patch(
            "vulnclaw.utils.atomic_write.os.fdopen", side_effect=LookupError("nope")
        ):
            with pytest.raises(LookupError):
                atomic_write_text(tmp_path / "x.txt", "content")

        assert opened, "the test did not exercise the real os.open"
        assert closed == opened, "the descriptor created for the temp file leaked"


class TestAppendLineDurable:
    """Audit finding E3: fsync was added to one event log and not the other."""

    def test_it_fsyncs(self, tmp_path):
        real_fsync = os.fsync
        seen: list[int] = []

        def spy(fd):
            seen.append(fd)
            return real_fsync(fd)

        with patch("vulnclaw.utils.atomic_write.os.fsync", side_effect=spy):
            append_line_durable(tmp_path / "events.jsonl", '{"a":1}')

        assert seen, "append_line_durable must fsync; that is the whole point"

    def test_it_appends_rather_than_truncates(self, tmp_path):
        path = tmp_path / "events.jsonl"
        append_line_durable(path, '{"n":1}')
        append_line_durable(path, '{"n":2}')

        assert path.read_text(encoding="utf-8") == '{"n":1}\n{"n":2}\n'

    def test_a_missing_newline_is_added(self, tmp_path):
        """Otherwise a caller that forgot one would glue two records together."""
        path = tmp_path / "events.jsonl"
        append_line_durable(path, '{"n":1}')
        append_line_durable(path, '{"n":2}\n')

        assert path.read_text(encoding="utf-8").count("\n") == 2

    def test_it_creates_missing_parents(self, tmp_path):
        path = tmp_path / "nested" / "events" / "events.jsonl"
        append_line_durable(path, "x")
        assert path.read_text(encoding="utf-8") == "x\n"

    def test_it_takes_an_already_serialised_line(self, tmp_path):
        """Module contract: serialisation stays with the caller, so it takes a str."""
        with pytest.raises(TypeError):
            append_line_durable(tmp_path / "x.jsonl", {"a": 1})
