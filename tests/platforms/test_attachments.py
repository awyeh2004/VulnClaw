"""The shared attachment downloader.

Extracted because two callers need it (`competition download` and the per-challenge
pre-download), and because the config field that promises the pre-download
(`competition.predownload_attachments`) was declared, documented and defaulted to True
while nothing read it. These tests pin the pieces that were previously inline in the
CLI and therefore untested.
"""

from __future__ import annotations

import os

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

    def test_size_mismatch_is_flagged_but_the_file_is_kept(self, tmp_path):
        """A truncated body is the failure that silently breaks analysis later."""
        client = _FakeClient(_FakeResponse(200, b"short"))
        attachment = Attachment(name="a.zip", url="https://h/a.zip", size=9999)

        result = att.download_attachment(client, attachment, str(tmp_path))

        assert result.path, "the partial file must be kept for inspection"
        assert "size mismatch" in result.error
        assert not result.ok

    def test_creates_the_destination_directory(self, tmp_path):
        target = tmp_path / "nested" / "attachments"
        client = _FakeClient(_FakeResponse(200, b"x"))

        result = att.download_attachment(
            client, Attachment(name="a", url="https://h/a"), str(target)
        )

        assert result.ok
        assert target.is_dir()
