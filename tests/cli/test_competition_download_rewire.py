"""`competition download` after the shared downloader was extracted into it.

The batch command's per-attachment block used to be inline here and is now
`vulnclaw.platforms.attachments.download_attachment`. Extraction is exactly where a
silent behavior change hides, and one did: `AttachmentDownload.ok` is False for a size
mismatch as well as for a hard failure, so branching on `not result.ok` filed a
truncated-but-written file as a *failure*, where the original warned and still counted
it as ok. These tests pin the three outcomes apart.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.cli import main
from vulnclaw.platforms import attachments as att
from vulnclaw.platforms.base import Attachment, Challenge, ChallengeRef

REF = ChallengeRef("ctf2", "practice", group="p", id="c")


class _Adapter:
    name = "ctf2"
    enabled_by_default = True

    @staticmethod
    def is_configured() -> bool:
        return True

    @staticmethod
    def base_url() -> str:
        return "https://files.example.com/"

    @staticmethod
    async def read_challenge(ref):
        return Challenge(
            ref=ref,
            name="chal",
            attachments=(Attachment(name="a.zip", url="https://files.example.com/a.zip", size=10),),
        )


def _run_batch(monkeypatch, tmp_path, result: att.AttachmentDownload):
    """Drive `competition download` for one challenge with a canned download result."""
    monkeypatch.setattr(
        "vulnclaw.platforms.bootstrap.ensure_adapters", lambda *a, **k: None
    )
    from vulnclaw.platforms import registry

    monkeypatch.setattr(registry, "adapter_for", lambda token: _Adapter())
    monkeypatch.setattr(
        main,
        "_platform_challenges",
        lambda: [("ctf2:practice:p:c", SimpleNamespace(ref=REF, name="chal"))],
    )
    monkeypatch.setattr(att, "download_attachment", lambda *a, **k: result)
    monkeypatch.setenv("VULNCLAW_WORK_DIR", str(tmp_path))

    printed: list[str] = []
    monkeypatch.setattr(main.console, "print", lambda *a, **k: printed.append(str(a[0]) if a else ""))
    monkeypatch.setattr(
        main.err_console, "print", lambda *a, **k: printed.append(str(a[0]) if a else "")
    )

    main._competition_download(SimpleNamespace(competition=SimpleNamespace()))
    return "\n".join(printed)


class TestBatchDownloadOutcomes:
    def test_success_counts_as_ok(self, monkeypatch, tmp_path):
        out = _run_batch(
            monkeypatch,
            tmp_path,
            att.AttachmentDownload(
                name="a.zip", url="https://h/a.zip", path=str(tmp_path / "a.zip"), size=10
            ),
        )
        assert "[ok]" in out
        assert "1 ok, 0 failed" in out

    def test_a_hard_failure_counts_as_failed(self, monkeypatch, tmp_path):
        out = _run_batch(
            monkeypatch,
            tmp_path,
            att.AttachmentDownload(name="a.zip", url="https://h/a.zip", error="HTTP 403"),
        )
        assert "[fail]" in out
        assert "0 ok, 1 failed" in out

    def test_a_size_mismatch_warns_but_still_counts_as_ok(self, monkeypatch, tmp_path):
        """The file WAS written; a truncated copy is still worth keeping.

        Regressed during extraction: branching on `not result.ok` filed this as a
        failure, losing the warn/keep semantics of the original inline code.
        """
        out = _run_batch(
            monkeypatch,
            tmp_path,
            att.AttachmentDownload(
                name="a.zip",
                url="https://h/a.zip",
                path=str(tmp_path / "a.zip"),
                size=4,
                error="size mismatch (declared 10, got 4) -- the local copy may be truncated",
            ),
        )
        assert "[warn]" in out
        assert "[fail]" not in out
        assert "1 ok, 0 failed" in out
