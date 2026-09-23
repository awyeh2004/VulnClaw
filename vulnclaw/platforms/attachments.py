"""Downloading a challenge's published attachments to disk.

Two callers need exactly this, and they must not drift:

* ``vulnclaw competition download`` -- batch insurance at match start;
* the per-challenge pre-download gated on ``competition.predownload_attachments``.

That config field was declared, documented ("At match start, download all challenge
attachments so a slow backend never blocks analysis") and defaulted to **True**, while
nothing in the codebase read it -- so the switch was a lie, and the insurance it
promised did not exist. The capability did exist, inline in the batch command; this
module is that code extracted so both paths share it.

Why the insurance matters: a RE/pwn challenge *is* its attachment. Measured on
"不一样的flag" (Easy RE), the solve downloaded its 9 KB zip from the platform's file
host as the first step -- correct, but it makes the whole run depend on that host
being reachable at solve time.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from vulnclaw.platforms import base

DEFAULT_TIMEOUT = 60.0
CHUNK = 8192


@dataclass(frozen=True)
class AttachmentDownload:
    """Outcome for one attachment. ``error`` is empty exactly when it succeeded."""

    name: str
    url: str
    path: str = ""
    size: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.path)


def safe_name(text: object) -> str:
    """A filesystem-safe file name that never comes back empty."""
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(text))
    return cleaned.strip("._") or "attachment"


def resolve_url(attachment: base.Attachment, adapter: object | None = None) -> str:
    """The absolute URL for an attachment, or ``""`` when it cannot be built.

    A platform may publish a root-relative URL, in which case the adapter has to
    supply the base. Returning ``""`` rather than guessing keeps the caller able to
    report "no usable URL" instead of fetching something arbitrary.
    """
    url = str(getattr(attachment, "url", "") or "").strip()
    if not url:
        return ""
    if not url.startswith("/"):
        return url
    base_url = getattr(adapter, "base_url", None)
    base_url = base_url() if callable(base_url) else ""
    if not base_url:
        return ""
    return f"{str(base_url).rstrip('/')}{url}"


def download_attachment(
    client: object,
    attachment: base.Attachment,
    dest_dir: str,
    *,
    challenge_name: str = "",
    adapter: object | None = None,
) -> AttachmentDownload:
    """Stream one attachment into ``dest_dir``.

    Never raises: a download failure is a reportable value, because the caller is
    usually mid-flow and a missing attachment must degrade rather than abort.
    """
    label = str(getattr(attachment, "name", "") or "attachment")
    url = resolve_url(attachment, adapter)
    if not url:
        declared = str(getattr(attachment, "url", "") or "")
        reason = (
            f"relative URL {declared!r} and the platform exposes no base URL"
            if declared
            else "attachment has no URL"
        )
        return AttachmentDownload(name=label, url=declared, error=reason)

    stem = f"{safe_name(challenge_name)}_" if challenge_name else ""
    local = os.path.join(dest_dir, f"{stem}{safe_name(label)}")
    os.makedirs(dest_dir, exist_ok=True)

    written = 0
    try:
        with client.stream("GET", url, follow_redirects=True) as response:  # type: ignore[attr-defined]
            if response.status_code != 200:
                return AttachmentDownload(
                    name=label, url=url, error=f"HTTP {response.status_code}"
                )
            with open(local, "wb") as handle:
                for chunk in response.iter_bytes(CHUNK):
                    handle.write(chunk)
                    written += len(chunk)
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        return AttachmentDownload(name=label, url=url, error=f"{type(exc).__name__}: {exc}")

    # Verify what the platform told us, when it told us anything. CTF2 publishes no
    # md5 (verified), so size is the available check -- and it catches a truncated
    # body, which is the failure that silently breaks a pwn/RE analysis later.
    declared_size = getattr(attachment, "size", None)
    if declared_size is not None and written != declared_size:
        return AttachmentDownload(
            name=label,
            url=url,
            path=local,
            size=written,
            error=(
                f"size mismatch (declared {declared_size}, got {written}) -- "
                f"the local copy may be truncated"
            ),
        )
    return AttachmentDownload(name=label, url=url, path=local, size=written)


def attachment_dir() -> str:
    """Where attachment insurance lives: ``<work>/attachments``.

    Same location the batch command uses, so a pre-downloaded file is found by the
    same analysis steps a match-start batch download would have produced.
    """
    work = os.environ.get("VULNCLAW_WORK_DIR") or os.path.expandvars(
        r"%USERPROFILE%\vulnclaw\work"
    )
    return os.path.join(work, "attachments")


__all__ = [
    "AttachmentDownload",
    "attachment_dir",
    "download_attachment",
    "resolve_url",
    "safe_name",
]
