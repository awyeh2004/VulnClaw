"""The zero-install Windows toolbox must keep working under PowerShell 5.1.

Why this exists: it is the fallback for an on-site competition where the venue PC
may have no Python and no permission to install anything -- `certutil`,
`tar.exe`, .NET and Windows PowerShell 5.1 are all that is guaranteed. Every
defect found while building it (2026-10-30) was a 5.1-vs-modern gap that fails
*silently* or with a stack trace at the moment it is needed:

* ``[Convert]::FromHexString`` is .NET 5+ only -> hex decode crashed on 5.1;
* a function parameter named ``$input`` collides with PowerShell's automatic
  variable -> base64/hex silently produced nothing;
* a signature written with an odd number of hex digits (GIF as ``474946383``)
  crashed ``Substring`` and took the whole ``info`` command down.

The tests below run the real script through powershell.exe, so any of those
regressions fails here instead of on a competition machine. Skipped off Windows.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell only")

SCRIPT = Path(__file__).resolve().parent.parent.parent / "scripts" / "ctf_win_toolbox.ps1"
PS = shutil.which("powershell") or shutil.which("pwsh")


def _decode(raw: bytes) -> str:
    """Windows PowerShell writes to a console codepage (GBK on this box), not UTF-8."""
    for encoding in ("utf-8", "gbk", "cp936", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def run(*args: str) -> str:
    proc = subprocess.run(
        [PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT), *args],
        capture_output=True, timeout=180,
    )
    out = _decode(proc.stdout)
    assert proc.returncode == 0, (out + _decode(proc.stderr))[-2000:]
    return out


def test_help_lists_every_subcommand():
    out = run()
    for verb in ("info", "strings", "carve", "lsb", "tail", "unpack", "b64", "hex", "scan"):
        assert verb in out, f"{verb} missing from help"


def test_info_reports_magic_inner_signature_and_png_tail(tmp_path):
    png = (Path(__file__).resolve().parent.parent / "fixtures" / "ocr" / "test_ocr.png").read_bytes()
    poly = tmp_path / "poly.png"
    poly.write_bytes(png + b"\nflag{after_iend}\n")

    out = run("info", str(poly))
    assert "magic     : PNG" in out, out
    assert "flag{after_iend}" in out, out


def test_carve_splits_an_embedded_zip(tmp_path):
    png = (Path(__file__).resolve().parent.parent / "fixtures" / "ocr" / "test_ocr.png").read_bytes()
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inside.txt", "flag{inside_zip}")
    poly = tmp_path / "poly2.png"
    poly.write_bytes(png + buf.getvalue())

    outdir = tmp_path / "carved"
    out = run("carve", str(poly), "-Out", str(outdir))
    assert "ZIP @" in out, out
    carved = list(outdir.glob("*.zip"))
    assert carved, "no zip carved"
    with zipfile.ZipFile(carved[0]) as zf:
        assert "flag{inside_zip}" in zf.read("inside.txt").decode()


def test_hex_and_base64_roundtrip(tmp_path):
    src = tmp_path / "t.txt"
    src.write_text("flag{codec_ok}", encoding="utf-8")
    hexout = tmp_path / "t.hex"
    run("hex", "encode", str(src), "-Out", str(hexout))
    assert hexout.read_text().strip() == "666c61677b636f6465635f6f6b7d"

    back = tmp_path / "back.txt"
    run("hex", "decode", str(hexout), "-Out", str(back))
    assert back.read_text(encoding="utf-8") == "flag{codec_ok}"

    b64 = tmp_path / "t.b64"
    run("b64", "encode", str(src), "-Out", str(b64))
    out = run("b64", "decode", str(b64), "-Out", str(back))
    assert "decoded" in out, out
    assert back.read_text(encoding="utf-8") == "flag{codec_ok}"


def test_lsb_reads_a_bit_plane(tmp_path):
    pytest.importorskip("PIL")
    from PIL import Image

    src = Image.open(Path(__file__).resolve().parent.parent / "fixtures" / "ocr" / "test_ocr.png")
    src = src.convert("RGB")
    payload = b"flag{lsb_ps}\x00"
    bits = [(byte >> i) & 1 for byte in payload for i in range(7, -1, -1)]
    px = src.load()
    k = 0
    for y in range(src.height):
        for x in range(src.width):
            if k >= len(bits):
                break
            rgb = list(px[x, y])
            for channel in range(3):
                if k < len(bits):
                    rgb[channel] = (rgb[channel] & 0xFE) | bits[k]
                    k += 1
            px[x, y] = tuple(rgb)
        if k >= len(bits):
            break
    path = tmp_path / "lsb.png"
    src.save(path)

    out = run("lsb", str(path), "-Out", "0")
    assert "flag{lsb_ps}" in out, out
