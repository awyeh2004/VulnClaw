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

Why both callers verify TLS: an attachment is a file this tool then analyses, unpacks
and (for pwn/RE) executes. The batch command used to pass ``verify=False``, which
accepts ANY certificate for that file; the declared size is no defence because an
on-path attacker chooses it. The host serves a valid DigiCert chain, so verification
costs nothing here. Operators behind a TLS-inspecting proxy keep a way out that does
NOT weaken the download: point ``SSL_CERT_FILE``/``SSL_CERT_DIR`` at the interceptor's
CA -- and a certificate failure now says exactly that (``_describe_download_error``).
"""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from pathlib import Path

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


def _is_certificate_failure(exc: BaseException) -> bool:
    """Whether an exception chain is a TLS certificate-verification failure.

    httpx wraps the ssl error, so the type alone is not enough -- the chain and the
    OpenSSL verifier string both have to be inspected.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        if "CERTIFICATE_VERIFY_FAILED" in str(current):
            return True
        current = current.__cause__ or current.__context__
    return False


#: Appended to a certificate failure. Verification is ON on purpose, so the operator
#: needs the legitimate way out rather than an in-code bypass: an interceptor's CA
#: belongs in the trust store (`SSL_CERT_FILE`/`SSL_CERT_DIR`), which keeps integrity
#: checking while accommodating interception. Turning verification off instead would
#: accept ANY certificate for a file we are about to analyse -- and often execute.
_CERT_HINT = (
    " -- certificate verification FAILED, and that is intentional. Downloaded "
    "artifacts get analysed and often executed, so verification stays on. If you are "
    "behind a TLS-inspecting proxy or a self-signed internal host, point SSL_CERT_FILE "
    "(or SSL_CERT_DIR) at its CA instead of disabling verification."
)


def _describe_download_error(exc: BaseException) -> str:
    """A download failure message, actionable when TLS is the cause."""
    detail = f"{type(exc).__name__}: {exc}"
    return f"{detail}{_CERT_HINT}" if _is_certificate_failure(exc) else detail


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

    The caller owns the client and therefore the TLS policy. Both current callers
    verify; see the module docstring for why artifact downloads are the wrong place to
    disable it.
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
    # Write to a sibling temp file and only `os.replace` on success. A direct
    # `open(local, "wb")` is truncating: a timeout or a dropped connection on a re-run
    # destroyed the PREVIOUS good copy and left a partial one at the canonical path --
    # the exact path whose contents this docstring says get analysed and executed.
    # `atomic_write` in vulnclaw/utils exists for the same reason; the size check
    # already lives here, so the temp file is the missing half.
    partial = f"{local}.part"
    os.makedirs(dest_dir, exist_ok=True)

    written = 0
    try:
        with client.stream("GET", url, follow_redirects=True) as response:  # type: ignore[attr-defined]
            if response.status_code != 200:
                return AttachmentDownload(
                    name=label, url=url, error=f"HTTP {response.status_code}"
                )
            with open(partial, "wb") as handle:
                for chunk in response.iter_bytes(CHUNK):
                    handle.write(chunk)
                    written += len(chunk)
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        _discard_partial(partial)
        return AttachmentDownload(name=label, url=url, error=_describe_download_error(exc))

    # Verify what the platform told us, when it told us anything. CTF2 publishes no
    # md5 (verified), so size is the available check -- and it catches a truncated
    # body, which is the failure that silently breaks a pwn/RE analysis later.
    declared_size = getattr(attachment, "size", None)
    if declared_size is not None and written != declared_size:
        # A truncated artifact is worthless for analysis, and leaving it at the
        # canonical path is how a later step ends up reading half a binary. Discard it
        # and report NO path, so callers cannot treat it as usable.
        _discard_partial(partial)
        return AttachmentDownload(
            name=label,
            url=url,
            size=written,
            error=(
                f"size mismatch (declared {declared_size}, got {written}) -- "
                f"discarded the partial file; re-run to fetch it again"
            ),
        )

    try:
        os.replace(partial, local)
    except OSError as exc:  # pragma: no cover - same-dir rename, but never fatal
        _discard_partial(partial)
        return AttachmentDownload(
            name=label, url=url, error=f"could not move the download into place: {exc}"
        )
    return AttachmentDownload(name=label, url=url, path=local, size=written)


def _discard_partial(path: str) -> None:
    """Remove a temp download, ignoring the case where it was never created."""
    try:
        os.unlink(path)
    except OSError:
        pass


def work_dir() -> str:
    """The work directory: ``$VULNCLAW_WORK_DIR`` or ``~/vulnclaw/work``.

    Platform-neutral on purpose. This used to be
    ``os.path.expandvars(r"%USERPROFILE%\\vulnclaw\\work")``, copied from the CLI: on
    Windows that expands, on POSIX ``%VAR%`` is not expansion syntax, so it silently
    became a LITERAL relative path containing backslashes and the downloaded artifact
    landed somewhere that merely looks like a broken path. It only appeared to work
    because every machine it ran on was Windows.

    ``Path.home()``/``expanduser`` is what the rest of the repo uses
    (``config/settings.py``, ``web/auth.py``, ``agent/tool_registry.py``).
    """
    override = os.environ.get("VULNCLAW_WORK_DIR")
    if override:
        return override
    return str(Path.home() / "vulnclaw" / "work")


def attachment_dir() -> str:
    """Where attachment insurance lives: ``<work>/attachments``.

    Same location the batch command uses, so a pre-downloaded file is found by the
    same analysis steps a match-start batch download would have produced.
    """
    return os.path.join(work_dir(), "attachments")


__all__ = [
    "AttachmentDownload",
    "attachment_dir",
    "download_attachment",
    "resolve_url",
    "safe_name",
    "work_dir",
]
