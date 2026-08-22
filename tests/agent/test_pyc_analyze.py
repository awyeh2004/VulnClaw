"""Tests for the pyc bytecode analysis tool (CTF REVERSE helper).

These tests prefer the real idol.pyc fixture when a local challenge work dir is
configured (``VULNCLAW_ATTACH_DIR`` / ``VULNCLAW_WORK_DIR``). When the fixture is
unavailable the real-file tests are skipped and only the self-contained ones run,
so the suite stays green on any machine without the DASCTF attachments.
"""

import os
import struct

import pytest

from vulnclaw.agent.builtin_tools import (
    _detect_pyc_magic,
    _pyc_scan_consts,
    _PYC_MAGICS,
    execute_pyc_analyze,
)


class MockAgent:
    pass


def _work_dir() -> str:
    """Resolve the local challenge work dir from env vars (no hardcoded paths)."""
    for key in ("VULNCLAW_ATTACH_DIR", "VULNCLAW_WORK_DIR"):
        val = os.environ.get(key, "").strip()
        if val:
            return val
    return os.path.expandvars(r"%USERPROFILE%\vulnclaw\work")


def _idol_pyc() -> str:
    """Locate the real idol.pyc fixture, or return an empty string if absent."""
    base = _work_dir()
    candidates = [
        os.path.join(base, "10749", "idol", "idol.pyc"),
        os.path.join(base, "attachments", "10749_idol", "idol.pyc"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return ""


_idol = _idol_pyc()
_has_idol = pytest.mark.skipif(not _idol, reason="idol.pyc fixture not found")


def _make_pyc(tmp_path, magic):
    """Create a minimal fake pyc: 16-byte header + marshaled int payload."""
    import marshal

    payload = marshal.dumps(12345)
    # header: 4 magic + 4 bitfield + 4 timestamp + 4 source_size
    header = magic.to_bytes(4, "little") + b"\x00" * 12
    p = tmp_path / "fake.pyc"
    p.write_bytes(header + payload)
    return str(p)


def test_detect_magic_recognizes_39():
    # Self-contained: the 3.9 magic bytes should map to (3, 9, *) regardless of
    # a fixture file existing. Build a tiny 3.9-shaped header + payload.
    import marshal

    payload = marshal.dumps(12345)
    # 61 0d 0d 0a is Python 3.9's magic (0x0A0D0D61 little-endian)
    header = (0x0A0D0D61).to_bytes(4, "little") + b"\x00" * 12
    raw = header + payload
    ver, fixed = _detect_pyc_magic(raw)
    assert ver is not None
    assert ver[0] == 3 and ver[1] == 9


@_has_idol
def test_real_idol_magic_is_39():
    raw = open(_idol, "rb").read()
    ver, fixed = _detect_pyc_magic(raw)
    assert ver == (3, 9, 0)
    assert fixed == raw[:16]


@_has_idol
def test_detect_magic_tampered(tmp_path):
    """A tampered magic should be repaired to a version whose payload parses.

    Uses the real idol.pyc payload because a hand-built marshal payload from the
    running interpreter is not a valid cross-version code object for xdis.
    """
    raw = open(_idol, "rb").read()
    corrupted = b"\xde\xad\xbe\xef" + raw[4:]
    ver, fixed = _detect_pyc_magic(corrupted)
    assert ver is not None
    assert fixed[:4] in {m.to_bytes(4, "little") for m in _PYC_MAGICS}


@_has_idol
def test_pyc_scan_consts_extracts_strings():
    from xdis.load import load_module as _xdis_load

    _ver, _ts, _mi, co, _py, _ss, _sh = _xdis_load(_idol)
    consts = _pyc_scan_consts(co)
    assert "Th1s_Is_Fl@g" in consts
    assert "flag.txt" in consts
    assert any(".. - .----" in c for c in consts)  # morse string


@_has_idol
def test_execute_pyc_analyze_consts_mode():
    r = execute_pyc_analyze(
        MockAgent(),
        {"pyc_path": _idol, "mode": "consts"},
    )
    assert "3.9" in r
    assert "Th1s_Is_Fl@g" in r
    assert "consts/strings" in r


def test_execute_pyc_analyze_missing_path():
    r = execute_pyc_analyze(MockAgent(), {"pyc_path": r"E:\nonexistent.pyc"})
    assert "not found" in r


@_has_idol
def test_execute_pyc_analyze_disasm_mode():
    r = execute_pyc_analyze(
        MockAgent(),
        {"pyc_path": _idol, "mode": "disasm"},
    )
    assert "pydisasm" in r or "disasm" in r
