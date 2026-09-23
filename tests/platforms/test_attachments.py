"""The shared attachment downloader.

Extracted because two callers need it (`competition download` and the per-challenge
pre-download), and because the config field that promises the pre-download
(`competition.predownload_attachments`) was declared, documented and defaulted to True
while nothing read it. These tests pin the pieces that were previously inline in the
CLI and therefore untested.
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

import pytest

from vulnclaw.platforms import attachments as att
from vulnclaw.platforms.base import Attachment


class _FakeResponse:
    def __init__(self, status_code: int, body: bytes) -> None:
        self.status_code = status_code
        self._body = body

    def iter_bytes(self, size: int = 8192):
        for start in range(0, len(self._body), size):
            yield self._body[start:start + size]


class _FakeStream:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response

    def __enter__(self) -> _FakeResponse:
        return self._response

    def __exit__(self, *exc) -> bool:
        return False


class _FakeClient:
    def __init__(self, response: _FakeResponse | None = None, boom: Exception | None = None):
        self._response = response
        self._boom = boom
        self.requested: list[str] = []

    def stream(self, method: str, url: str, **kwargs):
        self.requested.append(url)
        if self._boom is not None:
            raise self._boom
        assert self._response is not None
        return _FakeStream(self._response)


class TestResolveUrl:
    def test_absolute_url_passes_through(self):
        attachment = Attachment(name="a.zip", url="https://files.example.com/a.zip")
        assert att.resolve_url(attachment) == "https://files.example.com/a.zip"

    def test_relative_url_uses_the_adapter_base(self):
        class Adapter:
            @staticmethod
            def base_url() -> str:
                return "https://ctf2.dasctf.com/"

        attachment = Attachment(name="a.zip", url="/files/a.zip")
        assert att.resolve_url(attachment, Adapter()) == "https://ctf2.dasctf.com/files/a.zip"

    def test_relative_url_without_a_base_is_not_guessed(self):
        """Better to report 'no usable URL' than to fetch something arbitrary."""
        assert att.resolve_url(Attachment(name="a.zip", url="/files/a.zip"), object()) == ""

    @pytest.mark.parametrize("url", ["", "   ", None])
    def test_empty_url_stays_empty(self, url):
        assert att.resolve_url(Attachment(name="a.zip", url=url or "")) == ""


class TestSafeName:
    def test_strips_path_separators_and_specials(self):
        assert att.safe_name("../../etc/passwd") == "etc_passwd"

    def test_never_returns_empty(self):
        assert att.safe_name("...") == "attachment"
        assert att.safe_name("") == "attachment"

    def test_keeps_a_cjk_filename(self):
        """Measured challenge attachment: "不一样的flag.exe" -- must survive intact."""
        assert att.safe_name("不一样的flag.exe") == "不一样的flag.exe"

    def test_keeps_the_extension(self):
        assert att.safe_name("easyre.zip") == "easyre.zip"


class TestDownloadAttachment:
    def test_successful_download_writes_the_bytes(self, tmp_path):
        body = b"PK\x03\x04 fake zip"
        client = _FakeClient(_FakeResponse(200, body))
        attachment = Attachment(name="easyre.zip", url="https://h/a.zip", size=len(body))

        result = att.download_attachment(client, attachment, str(tmp_path))

        assert result.ok
        assert result.size == len(body)
        assert open(result.path, "rb").read() == body
        assert client.requested == ["https://h/a.zip"]

    def test_challenge_name_prefixes_the_file(self, tmp_path):
        client = _FakeClient(_FakeResponse(200, b"x"))
        attachment = Attachment(name="a.zip", url="https://h/a.zip")

        result = att.download_attachment(
            client, attachment, str(tmp_path), challenge_name="不一样的flag"
        )

        assert os.path.basename(result.path) == "不一样的flag_a.zip"

    def test_http_error_is_reported_not_raised(self, tmp_path):
        client = _FakeClient(_FakeResponse(403, b""))
        result = att.download_attachment(
            client, Attachment(name="a", url="https://h/a"), str(tmp_path)
        )

        assert not result.ok
        assert result.error == "HTTP 403"
        assert result.path == ""

    def test_transport_error_is_reported_not_raised(self, tmp_path):
        client = _FakeClient(boom=RuntimeError("connection reset"))
        result = att.download_attachment(
            client, Attachment(name="a", url="https://h/a"), str(tmp_path)
        )

        assert not result.ok
        assert "connection reset" in result.error

    def test_missing_url_is_reported(self, tmp_path):
        result = att.download_attachment(
            _FakeClient(_FakeResponse(200, b"")), Attachment(name="a", url=""), str(tmp_path)
        )

        assert not result.ok
        assert "no URL" in result.error

    def test_a_size_mismatch_discards_the_partial_and_reports_no_path(self, tmp_path):
        """A truncated artifact must not sit at the canonical path.

        This used to keep the partial file ("the local copy may be truncated") on the
        strength of "the file was written, so it is worth keeping". Audit finding C1:
        the module's own docstring says these files get analysed and EXECUTED, so a
        half-downloaded binary at the canonical path is worse than no file -- and
        because the write was truncating, it had already destroyed the previous good
        copy. Now the download lands in a `.part` file that is removed on any failure.
        """
        client = _FakeClient(_FakeResponse(200, b"short"))
        attachment = Attachment(name="a.zip", url="https://h/a.zip", size=9999)

        result = att.download_attachment(client, attachment, str(tmp_path))

        assert result.path == "", "a failed download must not hand over a usable path"
        assert "size mismatch" in result.error
        assert "discarded" in result.error
        assert not result.ok
        assert os.listdir(tmp_path) == [], "no partial file may be left behind"


class TestAFailedDownloadCannotDamageAnExistingCopy:
    """C1's other half: the write used to be truncating (`open(local, "wb")`)."""

    def test_a_transport_failure_leaves_the_previous_good_file_intact(self, tmp_path):
        good = tmp_path / "a.zip"
        good.write_bytes(b"PK\x03\x04 the real, complete archive")
        client = _FakeClient(boom=RuntimeError("connection reset"))

        result = att.download_attachment(
            client, Attachment(name="a.zip", url="https://h/a.zip"), str(tmp_path)
        )

        assert not result.ok
        assert good.read_bytes() == b"PK\x03\x04 the real, complete archive"
        assert os.listdir(tmp_path) == ["a.zip"], "the .part file must be cleaned up"

    def test_a_size_mismatch_leaves_the_previous_good_file_intact(self, tmp_path):
        good = tmp_path / "a.zip"
        good.write_bytes(b"PK\x03\x04 complete")
        client = _FakeClient(_FakeResponse(200, b"short"))

        result = att.download_attachment(
            client, Attachment(name="a.zip", url="https://h/a.zip", size=9999), str(tmp_path)
        )

        assert not result.ok
        assert good.read_bytes() == b"PK\x03\x04 complete"
        assert os.listdir(tmp_path) == ["a.zip"]

    def test_a_successful_download_replaces_the_previous_copy(self, tmp_path):
        good = tmp_path / "a.zip"
        good.write_bytes(b"OLD")
        body = b"PK\x03\x04 NEW"
        client = _FakeClient(_FakeResponse(200, body))

        result = att.download_attachment(
            client,
            Attachment(name="a.zip", url="https://h/a.zip", size=len(body)),
            str(tmp_path),
        )

        assert result.ok
        assert good.read_bytes() == body
        assert os.listdir(tmp_path) == ["a.zip"], "the .part file must not linger"


class TestTheWorkDirectoryIsPlatformNeutral:
    """Audit finding D1: `%USERPROFILE%` + expandvars is a Windows-only expression."""

    def test_it_does_not_use_a_windows_only_variable_syntax(self):
        assert "%USERPROFILE%" not in att.work_dir()
        assert "USERPROFILE" not in att.work_dir()

    def test_it_defaults_under_the_home_directory(self, monkeypatch):
        monkeypatch.delenv("VULNCLAW_WORK_DIR", raising=False)
        home = str(Path.home())
        assert att.work_dir() == str(Path(home) / "vulnclaw" / "work")

    def test_the_override_wins(self, monkeypatch):
        monkeypatch.setenv("VULNCLAW_WORK_DIR", "/tmp/somewhere")
        assert att.work_dir() == "/tmp/somewhere"
        assert att.attachment_dir() == os.path.join("/tmp/somewhere", "attachments")

    def test_creates_the_destination_directory(self, tmp_path):
        target = tmp_path / "nested" / "attachments"
        client = _FakeClient(_FakeResponse(200, b"x"))

        result = att.download_attachment(
            client, Attachment(name="a", url="https://h/a"), str(target)
        )

        assert result.ok
        assert target.is_dir()


class TestCertificateFailuresAreActionable:
    """Verification stays ON, so a cert failure must say how to proceed.

    An attachment is a file this tool analyses and (for pwn/RE) executes, so the
    legitimate escape hatch for an intercepting proxy is its CA in the trust store —
    not an in-code `verify=False`. A bare SSLError would leave the operator with no
    stated option except disabling verification.
    """

    @staticmethod
    def _cert_error() -> ssl.SSLCertVerificationError:
        return ssl.SSLCertVerificationError(
            1, "certificate verify failed: unable to get local issuer"
        )

    def test_a_certificate_failure_explains_the_trust_store_route(self, tmp_path):
        client = _FakeClient(boom=self._cert_error())

        result = att.download_attachment(
            client, Attachment(name="a.zip", url="https://h/a.zip"), str(tmp_path)
        )

        assert not result.ok
        assert "certificate verification FAILED" in result.error
        assert "SSL_CERT_FILE" in result.error
        assert "instead of disabling verification" in result.error

    def test_a_wrapped_certificate_failure_is_still_recognised(self, tmp_path):
        """httpx raises its own type and chains the ssl error, so the chain is walked."""
        plain = RuntimeError("connection failed")
        plain.__cause__ = self._cert_error()
        by_message = RuntimeError("ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED]")

        for exc in (plain, by_message):
            result = att.download_attachment(
                _FakeClient(boom=exc),
                Attachment(name="a.zip", url="https://h/a.zip"),
                str(tmp_path),
            )
            assert "SSL_CERT_FILE" in result.error, type(exc).__name__

    def test_an_ordinary_failure_does_not_get_the_tls_lecture(self, tmp_path):
        """Otherwise a DNS blip would send the operator chasing certificates."""
        result = att.download_attachment(
            _FakeClient(boom=RuntimeError("connection reset")),
            Attachment(name="a.zip", url="https://h/a.zip"),
            str(tmp_path),
        )

        assert "connection reset" in result.error
        assert "SSL_CERT_FILE" not in result.error
        assert "certificate verification" not in result.error

    def test_an_http_error_does_not_get_it_either(self, tmp_path):
        result = att.download_attachment(
            _FakeClient(_FakeResponse(500, b"")),
            Attachment(name="a.zip", url="https://h/a.zip"),
            str(tmp_path),
        )

        assert result.error == "HTTP 500"
