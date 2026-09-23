"""Durable file writes that survive Windows sharing violations.

Every module that persists state had grown its own temp-file-plus-rename dance,
and only ``platforms/submit_guard`` had noticed the Windows failure mode:

    PermissionError: [WinError 5] 拒绝访问。
      '.../graph.json.tmp' -> '.../graph.json'   (os.replace)

``os.replace`` is atomic and POSIX-clean, but on Windows it refuses when the
destination is momentarily open by another process -- typically an antivirus
real-time scanner touching the file the instant it is created, or a concurrent
reader. The failure is intermittent and depends entirely on machine timing, so it
shows up as a *non-deterministic* test failure (a different test each run) and,
in the field, as silently dropped state.

A single un-retried ``os.replace`` therefore makes durable state unreliable on
exactly the platform this tool runs on. :func:`replace_with_retry` is the one
place that knows the workaround; :func:`atomic_write_text` adds the temp-file,
fsync and cleanup around it.

Design note: these take already-serialised ``text``. Callers own their own
serialisation (``json.dumps`` / ``model_dump_json`` / plain strings), which keeps
this module free of any dependency on the callers' data models and avoids
re-serialising what a caller already computed.
"""

from __future__ import annotations

import os
import tempfile
import time
import uuid
from pathlib import Path

__all__ = [
    "atomic_write_text",
    "append_line_durable",
    "replace_with_retry",
    "mkdtemp_sibling",
    "RETRY_ATTEMPTS",
]

#: How many times to retry a sharing violation before giving up. Measured
#: behaviour: a scanner's handle lives for milliseconds, so a handful of short
#: backoffs is enough, and the total worst-case wait stays well under a second.
RETRY_ATTEMPTS = 5

#: Base backoff in seconds; the delay grows linearly per attempt
#: (0.05, 0.10, 0.15, 0.20) so a longer scan cannot be out-waited.
_RETRY_BASE_DELAY = 0.05


def replace_with_retry(src: str | Path, dst: str | Path) -> None:
    """``os.replace`` that tolerates a briefly-busy destination on Windows.

    Only ``PermissionError`` is retried: it is the documented sharing-violation
    signal. Anything else (missing directory, permission denied outright) is a
    real error and propagates immediately rather than being masked by retries.
    """
    last: PermissionError | None = None
    for attempt in range(RETRY_ATTEMPTS):
        try:
            os.replace(src, dst)
            return
        except PermissionError as exc:  # Windows sharing violation
            last = exc
            if attempt + 1 < RETRY_ATTEMPTS:
                time.sleep(_RETRY_BASE_DELAY * (attempt + 1))
    assert last is not None  # only reachable after at least one PermissionError
    raise last


def _fsync_directory(path: Path) -> None:
    """Persist a directory entry after a rename, where the platform supports it.

    Renaming the temp file into place is atomic, but on POSIX the *directory
    entry* itself may still be in cache, so a crash right after the rename can
    lose the file even though its contents were fsync'd. Windows has no
    ``O_DIRECTORY`` and no equivalent, so this is a no-op there (where the rename
    is durable once it succeeds).
    """
    dir_flags = getattr(os, "O_DIRECTORY", None)
    if dir_flags is None:
        return
    try:
        dir_fd = os.open(str(path), dir_flags)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def atomic_write_text(path: str | Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write ``text`` to ``path`` atomically, durably, and Windows-tolerantly.

    * same-directory temp file, so the rename never crosses a filesystem;
    * ``flush`` + ``fsync`` before the rename, so a crash cannot leave a
      truncated or empty file (the rename is the commit point);
    * rename retried on Windows sharing violations;
    * directory entry fsync'd on POSIX, so the rename itself survives a crash;
    * temp file removed on any failure, so a failed write leaves no litter.

    The temp file is created with ``O_EXCL`` and a random name, so two writers
    cannot collide on it.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.parent / f".{target.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"

    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        # `os.fdopen` used to sit OUTSIDE the try below, so anything it raised (an
        # unknown encoding -> LookupError, or an interrupt landing between these two
        # calls) leaked the descriptor AND the temp file -- contradicting the "temp
        # file removed on any failure" contract stated above. The fd belongs to this
        # function until `fdopen` takes it over, so close it here on failure.
        handle = os.fdopen(fd, "w", encoding=encoding)
    except BaseException:
        os.close(fd)
        _remove_quietly(tmp)
        raise
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        replace_with_retry(tmp, target)
        _fsync_directory(target.parent)
    except BaseException:
        # The rename is the commit point: before it, the target is untouched and
        # the temp file is pure litter.
        _remove_quietly(tmp)
        raise


def _remove_quietly(path: str | Path) -> None:
    """Unlink, ignoring the case where it was already gone."""
    try:
        os.unlink(path)
    except OSError:
        pass


def append_line_durable(path: str | Path, line: str, *, encoding: str = "utf-8") -> None:
    """Append one line durably: flush + fsync before returning.

    Takes an ALREADY-SERIALISED line, like the rest of this module (see the design note
    above -- serialisation stays with the caller, so this module never depends on a
    caller's data model).

    ONE implementation on purpose. The identical "append one event line" logic existed in
    two places, and when fsync was added to one of them (`agent_graph._persist_event`) the
    other (`run_context.append_event`) kept writing through the OS cache -- so a crash
    could drop an event that a snapshot, or the completion summary and
    `validate_run_context`, already relied on. A shared helper removes the class of drift
    rather than the single instance.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not isinstance(line, str):
        # Explicit, because the sibling `atomic_write_text` has the same contract and a
        # caller passing a dict here would otherwise get an AttributeError from
        # `str.endswith` deep in the body rather than a statement of the contract.
        raise TypeError(
            f"append_line_durable takes an already-serialised line (str), got "
            f"{type(line).__name__}; use json.dumps(...) at the call site"
        )
    if not line.endswith("\n"):
        line = f"{line}\n"
    with open(target, "a", encoding=encoding) as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def mkdtemp_sibling(path: str | Path) -> tuple[int, str]:
    """Create a same-directory temp file and return ``(fd, name)``.

    For callers that must stream into the handle themselves (e.g. ``json.dump``)
    instead of handing over a finished string. Pair with
    :func:`replace_with_retry`.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    return tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.")
