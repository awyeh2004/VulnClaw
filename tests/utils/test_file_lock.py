"""One file-lock implementation for the whole repo (round5 residual item).

Measured before the fix: `agent/memory.py`, `kb/experience.py` and `kb/store.py` each carried
their own near-identical `_file_lock`, and they had already drifted -- `kb/store.py` chmod'd
the lock file to 0600 while the other two left it at the process umask, i.e. world-readable on
POSIX. The class of defect is the drift, not the single difference, which is why the fix is
one implementation rather than three corrections.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from vulnclaw.utils.atomic_write import file_lock

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestThereIsOnlyOneImplementation:
    def test_every_module_uses_the_same_function_object(self):
        """Identity, not equivalence: three copies that behave alike are still three copies."""
        import vulnclaw.agent.memory as memory
        import vulnclaw.kb.experience as experience
        import vulnclaw.kb.store as store

        assert memory._file_lock is file_lock
        assert experience._file_lock is file_lock
        assert store._index_file_lock is file_lock

    def test_the_old_copies_are_gone_from_the_source(self):
        """A re-introduced copy would not import this module's lock, so pin the text too."""
        for relative in ("vulnclaw/agent/memory.py", "vulnclaw/kb/experience.py"):
            source = (REPO_ROOT / relative).read_text(encoding="utf-8")
            assert "msvcrt.locking" not in source, f"{relative} grew its own lock again"


class TestTheLockFileItself:
    def test_the_lock_file_is_owner_only_on_posix(self, tmp_path):
        """The measured drift: two of the three copies left this at the umask."""
        lock_path = tmp_path / ".x.lock"
        with file_lock(lock_path):
            pass
        assert lock_path.exists()
        if os.name != "nt":
            mode = lock_path.stat().st_mode & 0o777
            assert mode == 0o600, oct(mode)

    def test_the_locked_file_gets_the_byte_windows_locks(self, tmp_path):
        """`msvcrt.locking` locks a byte RANGE from the current position.

        Locking a zero-length file is not the same thing on Windows, which is why the file is
        created with one byte -- and why it must never be truncated.

        NOTE the read happens AFTER the lock is released: on Windows the locked byte cannot be
        read by anyone while it is held (measured: `PermissionError` on the read inside the
        `with`), which is another reason the lock itself must not try to read the file.
        """
        lock_path = tmp_path / ".x.lock"
        with file_lock(lock_path):
            assert lock_path.stat().st_size >= 1
        with file_lock(lock_path):
            pass
        assert lock_path.read_bytes()[:1] == b"0"

    def test_the_parent_directory_is_created(self, tmp_path):
        lock_path = tmp_path / "nested" / "deeper" / ".x.lock"
        with file_lock(lock_path):
            pass
        assert lock_path.exists()


class TestItActuallyExcludes:
    def test_two_threads_cannot_be_inside_at_once(self, tmp_path):
        lock_path = tmp_path / ".x.lock"
        inside: list[int] = []
        overlaps: list[str] = []

        def worker() -> None:
            with file_lock(lock_path):
                inside.append(1)
                if len(inside) > 1:
                    overlaps.append("two writers inside")
                time.sleep(0.03)
                inside.pop()

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert overlaps == [], overlaps

    def test_another_process_waits_for_the_lock(self, tmp_path):
        """Cross-process is the half a per-process lock cannot provide.

        The child measures how long it had to wait for the lock; the parent holds it for half
        a second first. Before this fix each module had its own lock FILE conventions but the
        same flock semantics, so this pins the shared implementation rather than a change in
        behaviour.
        """
        lock_path = tmp_path / ".x.lock"
        script = (
            "import sys, time\n"
            "from vulnclaw.utils.atomic_write import file_lock\n"
            f"started = time.time()\n"
            f"with file_lock(r'{lock_path}'):\n"
            "    print(round(time.time() - started, 3))\n"
        )
        with file_lock(lock_path):
            holder = subprocess.Popen(
                [sys.executable, "-c", script],
                cwd=str(REPO_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            time.sleep(0.5)  # keep holding while the child starts and blocks
        out, err = holder.communicate(timeout=30)
        assert holder.returncode == 0, err
        waited = float(out.strip().splitlines()[-1])
        assert waited > 0.25, f"the child did not block on the held lock (waited {waited}s)"

    def test_nested_locks_in_one_thread_do_not_deadlock(self, tmp_path):
        """`ExperienceStore` holds its own lock and then the KB index lock.

        With one RLock per lock FILE that ordering could deadlock against a thread taking
        them the other way round; one shared re-entrant process lock makes the nesting safe.
        """
        done = threading.Event()

        def worker() -> None:
            with file_lock(tmp_path / ".experience.lock"):
                with file_lock(tmp_path / ".index.lock"):
                    pass
            done.set()

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=10)
        assert done.is_set(), "nested acquisition deadlocked"

    def test_an_exception_inside_releases_the_lock(self, tmp_path):
        lock_path = tmp_path / ".x.lock"
        with pytest.raises(RuntimeError):
            with file_lock(lock_path):
                raise RuntimeError("boom")

        acquired = threading.Event()

        def worker() -> None:
            with file_lock(lock_path):
                acquired.set()

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=10)
        assert acquired.is_set(), "the lock stayed held after an exception"
