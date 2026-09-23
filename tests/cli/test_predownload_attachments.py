"""`competition.predownload_attachments` must actually do something.

The field was declared, documented ("At match start, download all challenge
attachments so a slow backend never blocks analysis") and **defaulted to True**, while
nothing in the codebase read it. The capability existed only inside the batch
`competition download` command, so the promised insurance did not exist -- and a switch
that silently does nothing is worse than no switch, because it makes the operator
believe the insurance is on.

For a RE/pwn challenge the attachment *is* the challenge (measured on "不一样的flag"),
so this wiring matters.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.cli import main
from vulnclaw.platforms import attachments as att
from vulnclaw.platforms.base import Attachment

ATTACHMENTS = (Attachment(name="chal.zip", url="https://files.example.com/chal.zip"),)


def _cfg(predownload: bool):
    return SimpleNamespace(competition=SimpleNamespace(predownload_attachments=predownload))


class _StubAdapter:
    @staticmethod
    def base_url() -> str:
        return "https://files.example.com/"


@pytest.fixture
def seen_downloads(monkeypatch, tmp_path):
    """Capture what the pre-download asked for, without touching the network."""
    calls: list[tuple[str, str]] = []

    def fake_download(client, attachment, dest_dir, *, challenge_name="", adapter=None):
        calls.append((challenge_name, att.resolve_url(attachment, adapter)))
        path = str(tmp_path / f"{challenge_name}_{attachment.name}")
        with open(path, "wb") as handle:
            handle.write(b"payload")
        return att.AttachmentDownload(
            name=attachment.name, url=attachment.url, path=path, size=7
        )

    monkeypatch.setattr(att, "download_attachment", fake_download)
    monkeypatch.setattr(att, "attachment_dir", lambda: str(tmp_path))
    return calls


class TestTheSwitchIsHonoured:
    def test_enabled_downloads_and_returns_local_paths(self, seen_downloads, tmp_path):
        paths = main._predownload_challenge_attachments(
            _cfg(True), "不一样的flag", ATTACHMENTS, _StubAdapter()
        )

        assert len(paths) == 1
        assert paths[0].endswith("不一样的flag_chal.zip")
        assert seen_downloads == [("不一样的flag", "https://files.example.com/chal.zip")]

    def test_disabled_downloads_nothing(self, seen_downloads):
        assert main._predownload_challenge_attachments(
            _cfg(False), "chal", ATTACHMENTS, _StubAdapter()
        ) == []
        assert seen_downloads == []

    def test_no_attachments_is_a_no_op(self, seen_downloads):
        assert main._predownload_challenge_attachments(
            _cfg(True), "chal", (), _StubAdapter()
        ) == []
        assert seen_downloads == []

    def test_a_missing_field_reads_as_off(self, seen_downloads):
        """Fail closed: an old config object without the field must not download."""
        bare = SimpleNamespace(competition=SimpleNamespace())
        assert main._predownload_challenge_attachments(
            bare, "chal", ATTACHMENTS, _StubAdapter()
        ) == []
        assert seen_downloads == []


class TestItNeverBreaksASolve:
    def test_a_download_failure_is_reported_not_raised(self, monkeypatch, tmp_path):
        def boom(*args, **kwargs):
            raise RuntimeError("network down")

        monkeypatch.setattr(att, "download_attachment", boom)
        monkeypatch.setattr(att, "attachment_dir", lambda: str(tmp_path))

        # Insurance must degrade to "the agent fetches it itself".
        assert main._predownload_challenge_attachments(
            _cfg(True), "chal", ATTACHMENTS, _StubAdapter()
        ) == []

    def test_a_failed_attachment_yields_no_path(self, monkeypatch, tmp_path):
        def failing(client, attachment, dest_dir, *, challenge_name="", adapter=None):
            return att.AttachmentDownload(
                name=attachment.name, url=attachment.url, error="HTTP 403"
            )

        monkeypatch.setattr(att, "download_attachment", failing)
        monkeypatch.setattr(att, "attachment_dir", lambda: str(tmp_path))

        assert main._predownload_challenge_attachments(
            _cfg(True), "chal", ATTACHMENTS, _StubAdapter()
        ) == []

    def test_an_unresolvable_ref_yields_no_adapter(self):
        assert main._adapter_for_ref("nonsense") is None


class TestTheGoalHandsOverTheLocalPath:
    """The point of pre-downloading: the agent need not reach the file host at all."""

    def test_ctf2_goal_lists_the_local_path(self, monkeypatch):
        captured: dict = {}
        monkeypatch.setattr(main, "solve", lambda **kwargs: captured.update(kwargs))
        monkeypatch.setattr(main, "has_llm_credentials", lambda llm: True)
        monkeypatch.setattr(
            main, "load_config", lambda: SimpleNamespace(llm=SimpleNamespace(), competition=SimpleNamespace())
        )
        monkeypatch.setattr(main, "_adapter_for_ref", lambda token: _StubAdapter())
        monkeypatch.setattr(
            main, "_predownload_challenge_attachments", lambda *a, **k: ["C:/work/attachments/chal.zip"]
        )

        async def fake_read(practice_id, challenge_id):
            return {"data": {"name": "不一样的flag", "category": "REVERSE", "files": []}}

        monkeypatch.setattr(main, "ctf2_read_challenge", fake_read)
        main.ctf2("cid", "pid")

        goal = captured["goal"]
        assert "ALREADY DOWNLOADED" in goal
        assert "C:/work/attachments/chal.zip" in goal

    def test_competition_solve_goal_lists_the_local_path(self, monkeypatch):
        captured: dict = {}
        monkeypatch.setattr(main, "solve", lambda **kwargs: captured.update(kwargs))
        monkeypatch.setattr(
            main, "_predownload_challenge_attachments", lambda *a, **k: ["C:/work/attachments/x.zip"]
        )

        from vulnclaw.platforms import registry

        class Adapter:
            name = "ctf2"
            enabled_by_default = True

            def is_configured(self) -> bool:
                return True

            def parse_ref(self, tail: str):
                from vulnclaw.platforms.refs import ChallengeRef

                return ChallengeRef("ctf2", "practice", group="p", id="c")

            async def read_challenge(self, ref):
                from vulnclaw.platforms.base import Challenge

                return Challenge(ref=ref, name="chal", attachments=ATTACHMENTS)

        monkeypatch.setattr(registry, "adapter_for", lambda token: Adapter())
        monkeypatch.setattr("vulnclaw.platforms.bootstrap.ensure_adapters", lambda *a, **k: None)

        main._competition_solve(_cfg(True), "ctf2:practice:p:c")

        goal = captured["goal"]
        assert "ALREADY DOWNLOADED" in goal
        assert "C:/work/attachments/x.zip" in goal
