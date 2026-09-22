from __future__ import annotations

import os
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

from vulnclaw.i18n import current_lang, init_i18n

TEST_ROOT = Path(__file__).resolve().parent / ".test-tmp"
TEST_ROOT.mkdir(parents=True, exist_ok=True)
os.environ["VULNCLAW_CONFIG_DIR"] = str(TEST_ROOT / "config")
os.environ["TMPDIR"] = str(TEST_ROOT)
os.environ["TEMP"] = str(TEST_ROOT)
os.environ["TMP"] = str(TEST_ROOT)
tempfile.tempdir = str(TEST_ROOT)

# Nothing below TEST_ROOT is ever cleaned otherwise: the custom tmp_path keeps
# every per-test uuid dir and the sandbox config/kb/runs accumulate on top
# (measured: 29k files / 60MB after a few full-suite runs). Prune at session
# start instead. The staleness window is what makes this safe with two pytest
# processes sharing the checkout (parallel agent sessions): a concurrently
# running suite only ever has fresh files here, and those are left alone.
STALE_TEST_ROOT_HOURS = 12


def _prune_stale_test_root() -> int:
    import shutil
    import time

    cutoff = time.time() - STALE_TEST_ROOT_HOURS * 3600
    removed = 0
    for entry in TEST_ROOT.iterdir():
        try:
            if entry.stat().st_mtime > cutoff:
                continue
        except OSError:
            continue
        if entry.is_dir():
            shutil.rmtree(entry, ignore_errors=True)
        else:
            try:
                entry.unlink()
            except OSError:
                continue
        removed += 1
    return removed


def pytest_sessionstart(session) -> None:
    removed = _prune_stale_test_root()
    if removed:
        print(
            f"[conftest] pruned {removed} stale top-level entr{'y' if removed == 1 else 'ies'} "
            f"from .test-tmp (older than {STALE_TEST_ROOT_HOURS}h)"
        )


@pytest.fixture(autouse=True)
def _restore_global_translator():
    """Undo any global i18n change a test made, whatever it was.

    ``vulnclaw.i18n`` keeps a process-wide ``_translator``, and tests across the
    suite pin the language by calling ``init_i18n`` (170+ call sites). Several
    never restore it, so the active language leaked into unrelated tests: the
    full suite failed *non-deterministically* -- a different handful of
    language-sensitive tests (KB language gate, report headings, agent graph)
    broke on each run depending on which test ran last.

    Snapshotting and restoring the actual translator object (rather than a
    language code) preserves any other state a test configured and needs no
    cooperation from the test itself. Tests that already restore language in a
    ``finally`` are unaffected: this simply runs after them.
    """
    from vulnclaw import i18n as _i18n

    previous = getattr(_i18n, "_translator", None)
    try:
        yield
    finally:
        _i18n._translator = previous


@pytest.fixture
def tmp_path() -> Path:
    """Project-local writable tmp_path replacement for this workspace."""
    path = TEST_ROOT / f"tmp-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    return path


@pytest.fixture
def i18n_language():
    """Set the active language for a test and restore the prior global locale."""
    previous = current_lang()
    yield lambda lang: init_i18n(lang=lang)
    init_i18n(lang=previous)
