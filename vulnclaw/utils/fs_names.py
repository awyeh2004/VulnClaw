"""Filesystem-safe name components derived from target-controlled strings.

``SessionState.save()``, the two report generators and the web report service all
derive a file name from ``session.target`` -- a value the operator types or the
model infers, so it is routinely a URL, an absolute path, a bare host, or a
Chinese phrase. Each site grew its own rule and the copies drifted:

* three sites used ``.replace("/", "_").replace(":", "_")``, which does **not**
  touch ``\\`` -- on Windows a target of ``C:\\Users\\x\\Downloads\\a.zip``
  therefore split into a nested directory tree (measured: 7 of the 222 distinct
  targets in this machine's own session history are Windows paths) and the
  deliverable landed under ``SESSIONS_DIR\\WP-C_\\Users\\...`` instead of beside
  it, where ``report_service.list_reports()``'s non-recursive ``*.md`` glob
  cannot even see it;
* the web service used an ASCII-only regex that is safe but lossy: a target of
  ``/证据`` collapsed to a row of underscores.

One helper, one behaviour. This is a leaf module on purpose -- ``utils`` must not
import the agent/config packages, or the report and web layers would inherit
their import cost.
"""

from __future__ import annotations

#: Characters that are path separators or illegal in a Windows path component.
#: ``/`` and ``\\`` are the important ones (they decide whether the value stays a
#: single component); the rest are rejected by Win32 outright.
_UNSAFE_CHARS = '<>:"/\\|?*'

#: Windows device names, which are reserved *with or without* an extension
#: (``con.txt`` is still the console device).
_RESERVED_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


def safe_name_component(
    value: object, *, fallback: str = "unknown", max_length: int = 80
) -> str:
    """Return ``value`` as a single, filesystem-safe path component.

    Guarantees for the result: non-empty, no path separator on any platform, no
    control characters, no trailing dot/space (Win32 strips those silently, so a
    name that keeps one cannot be re-opened by the name we printed), not a
    reserved device name.

    **Non-ASCII is preserved** -- ``/证据`` stays readable. The ASCII-only slugs
    elsewhere in the tree (``headless._slugify_target``, ``writeup._safe_filename``)
    exist to make a *stable, comparable* slug for run directories and serve that
    job well; degrading a Chinese target to a placeholder in a file the operator
    is handed is a different trade and this helper is not it.
    """
    text = str(value if value is not None else "")
    cleaned = "".join(
        "_" if (ch in _UNSAFE_CHARS or ord(ch) < 32 or ord(ch) == 127) else ch
        for ch in text
    )
    # Strip both ends of whitespace, dots and underscores: what is left is the
    # informative part. A target that was only separators ("/") or was only dots
    # ("...") therefore falls back instead of becoming a meaningless "_", while
    # "/证据" becomes "证据" rather than "_证据". Callers always prefix this
    # component ("report_<ts>_..."), so a leading underscore never carried meaning.
    cleaned = cleaned.strip().strip("._")
    if not cleaned:
        return fallback
    if cleaned.split(".", 1)[0].upper() in _RESERVED_STEMS:
        cleaned = "_" + cleaned
    # Cap last: the truncation can expose a trailing dot or empty the string.
    cleaned = cleaned[:max_length].rstrip(". ")
    return cleaned or fallback
