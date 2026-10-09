"""The one filename rule, shared by the report generator / web service / session store.

Round-1 (2026-10-09) postmortem: three sites each carried their own
``.replace("/", "_").replace(":", "_")`` chain. That chain does not touch ``\\``,
so on Windows a target of ``C:\\Users\\x\\d\\a.zip`` split into a directory tree
under ``SESSIONS_DIR`` and the artifact was written *inside* it instead of beside
it -- measured on this machine's own history, 7 of 222 distinct targets are
Windows paths -- and ``report_service.list_reports()``'s non-recursive ``*.md``
glob cannot even see the result. The web service had the opposite failure: an
ASCII-only regex that is safe but turns ``/证据`` into a row of underscores.

These tests pin the *single* rule so a fourth copy cannot drift away from it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnclaw.utils.fs_names import safe_name_component


class TestItIsAlwaysOneComponent:
    @pytest.mark.parametrize(
        "target",
        [
            r"C:\Users\伟\Downloads\a9c4fb8a551948e6981cbcfe84b17ed0.zip",
            r"E:\vulnclaw\work\c96e7862\challenge.elf",
            "/var/www/html/uploads/.cache_update.sh",
            "http://10.0.172.249:7860/admin?x=1",
            "../../etc/passwd",
            r"..\..\windows\system32\config\sam",
        ],
    )
    def test_no_separator_or_illegal_character_survives(self, target):
        safe = safe_name_component(target)

        assert safe
        assert "/" not in safe and "\\" not in safe
        assert not set(safe) & set('<>:"|?*')
        # The OS-level check: what we hand to Path must stay one component.
        assert Path(safe).name == safe

    def test_control_characters_are_replaced(self):
        assert safe_name_component("host\x00\x1bname\n") == "host__name"


class TestPlatformHostileShapes:
    @pytest.mark.parametrize("value", ["CON", "con", "nul", "COM1", "lpt9.log"])
    def test_windows_device_names_are_prefixed(self, value):
        safe = safe_name_component(value)

        # Reserved with or without a suffix (`con.txt` is still the console).
        assert safe.split(".", 1)[0].upper() not in {"CON", "NUL", "COM1", "LPT9"}
        assert safe.startswith("_")

    def test_trailing_dot_or_space_is_dropped(self):
        """Win32 silently strips these; a name we print must be re-openable as printed."""
        assert safe_name_component("host.example.com. ") == "host.example.com"
        assert safe_name_component("10.0.0.1.").endswith("1")

    def test_relative_traversal_cannot_climb_out(self):
        assert ".." not in safe_name_component("../../etc/passwd").split(".")


class TestItDoesNotMangleReadableTargets:
    def test_non_ascii_is_preserved(self):
        """Unlike the ASCII-only slugs, this one is used for files a human is handed."""
        assert safe_name_component("/证据") == "证据"
        assert safe_name_component("证据-报告") == "证据-报告"

    def test_a_normal_target_is_unchanged(self):
        for value in ("10.0.172.249", "10.0.172.249:7860", "ctf.example.com", "/storage"):
            out = safe_name_component(value)
            assert out and out == out.strip()

    def test_a_path_target_is_readable_not_hashed(self):
        out = safe_name_component(r"C:\Users\伟\Downloads\a.zip")

        assert out == "C__Users_伟_Downloads_a.zip"


class TestBoundsAndFallbacks:
    def test_length_is_capped(self):
        assert len(safe_name_component("x" * 500)) == 80

    def test_the_cap_cannot_leave_a_trailing_dot(self):
        assert not safe_name_component("x" * 79 + ".tail").endswith(".")

    @pytest.mark.parametrize("value", [None, "", "   ", "...", "\x00", "/", "\\"])
    def test_junk_falls_back(self, value):
        assert safe_name_component(value) == "unknown"
        assert safe_name_component(value, fallback="target") == "target"
