#!/usr/bin/env python3
"""One-shot misc/stego triage: run every cheap carrier check, print a report.

Why this exists
---------------
A stego run that hand-rolls its checks spends its turns re-deriving the same six
questions (is there data after IEND? is the chunk list sane? which LSB order?
are there concatenated deflate streams? is there EXIF text? is the audio a
spectrogram?) — and each derivation is a chance to stop one layer too early. The
measured failure mode in this repo is "found a plausible string, declared it the
flag" (a PDF run reported `pass is air123` for 126 tool calls). One call that
answers all six at once removes that.

Everything here is local and read-only with respect to the INPUT: it opens the
file and never modifies it. Derived artifacts go to --dump when given; the one
exception is an audio spectrogram, which is rendered next to the input file so a
batch run cannot litter the current directory.

Usage
-----
    python scripts/stego_sweep.py <file> [--dump DIR] [--max-lsb-bytes 4096]

The report is plain text with a candidate list at the end; the caller (agent or
operator) still decides. It deliberately does NOT claim a flag: a printable
string that looks like a flag is reported as a CANDIDATE with the check that
produced it, so the completion gate's "flag must be in evidence" rule still means
something.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import re
import shutil
import struct
import sys
import zlib
from pathlib import Path

PRINTABLE = re.compile(rb"[ -~]{6,}")
FLAGISH = re.compile(
    rb"(?:flag|ctf|dasctf|ctf2|synt|hgame|nssctf|buu)[{_][^}\n\r]{3,80}[}]",
    re.IGNORECASE,
)
ARCHIVE_MAGIC = {
    b"PK\x03\x04": "zip (PK\\x03\\x04)",
    b"PK\x05\x06": "zip end-of-central-directory",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"Rar!\x1a\x07": "rar",
    b"\x1f\x8b": "gzip",
    b"BZh": "bzip2",
    b"\xfd7zXZ": "xz",
    b"\x28\xb5\x2f\xfd": "zstd",
    b"\x7fELF": "ELF",
    b"MZ": "PE/MZ",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
}


def _ffmpeg() -> str | None:
    found = shutil.which("ffmpeg")
    if found:
        return found
    for cand in (
        Path(__file__).resolve().parent.parent / ".ir-tools" / "bin" / "ffmpeg.exe",
        Path("E:/vulnclaw/.ir-tools/bin/ffmpeg.exe"),
        Path.home() / ".ir-tools" / "bin" / "ffmpeg.exe",
    ):
        if cand.is_file():
            return str(cand)
    return None


def _head(path: Path, n: int = 16) -> bytes:
    with path.open("rb") as fh:
        return fh.read(n)


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def report_basic(path: Path, data: bytes) -> None:
    section("file")
    print(f"path   : {path}")
    print(f"size   : {len(data)}")
    print(f"sha256 : {hashlib.sha256(data).hexdigest()}")
    head = data[:64]
    kinds = [name for magic, name in ARCHIVE_MAGIC.items() if head.startswith(magic)]
    print(f"magic  : {', '.join(kinds) or head[:12].hex()}")
    # a second magic later in the file is the "polyglot" case
    later = []
    for magic, name in ARCHIVE_MAGIC.items():
        idx = data.find(magic, 1)
        if idx > 0:
            later.append((idx, name))
    if later:
        print("embedded magics:")
        for idx, name in sorted(later)[:8]:
            print(f"  offset {idx:8d}  {name}")


def report_trailing(path: Path, data: bytes) -> None:
    section("trailing data (附加字符串 / 图种)")
    for end_magic, name in ((b"IEND\xaeB`\x82", "PNG IEND"), (b"\xff\xd9", "JPEG EOI")):
        idx = data.rfind(end_magic)
        if idx < 0:
            continue
        after = len(data) - (idx + len(end_magic))
        print(f"{name} ends at {idx + len(end_magic)}, trailing bytes: {after}")
        if after > 0:
            tail = data[idx + len(end_magic):]
            print(f"  tail head: {tail[:48]!r}")
            for magic, n2 in ARCHIVE_MAGIC.items():
                if tail.startswith(magic):
                    print(f"  -> trailing payload looks like {n2}")
    # No container end marker at all: the whole file may be raw-carved data
    if b"IEND" not in data and b"\xff\xd9" not in data:
        print("no container end marker found")


def report_png_chunks(data: bytes) -> None:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return
    section("PNG chunks (duplicate/invalid-CRC chunks are the decoy tell)")
    pos = 8
    seen: dict[str, int] = {}
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        if length > len(data):
            print(f"  bogus length {length} at {pos}, stop")
            break
        payload = data[pos + 8:pos + 8 + length]
        crc_ok = True
        if pos + 8 + length + 4 <= len(data):
            (crc,) = struct.unpack(">I", data[pos + 8 + length:pos + 12 + length])
            crc_ok = (zlib.crc32(ctype + payload) & 0xFFFFFFFF) == crc
        try:
            name = ctype.decode("ascii")
        except Exception:
            name = ctype.hex()
        seen[name] = seen.get(name, 0) + 1
        extra = ""
        if name in ("tEXt", "zTXt", "iTXt"):
            extra = f"  text={payload[:80]!r}"
        print(f"  {name:5} len={length:6d} crc_ok={crc_ok}{extra}")
        pos += 12 + length
        if name == "IEND":
            break
    dupes = {k: v for k, v in seen.items() if v > 1}
    if dupes:
        print(f"  duplicate chunk types (decoys): {dupes}")


def report_exif(path: Path) -> None:
    section("EXIF / metadata")
    try:
        import exifread  # type: ignore

        with path.open("rb") as fh:
            tags = exifread.process_file(fh, details=False)
        hits = {k: str(v) for k, v in tags.items() if k not in ("JPEGThumbnail", "TIFFThumbnail")}
        for k, v in list(hits.items())[:12]:
            print(f"  {k}: {v[:100]}")
        if not hits:
            print("  no EXIF tags")
    except Exception as exc:
        print(f"  exifread unavailable/failed: {type(exc).__name__}: {exc}")
    try:
        from PIL import Image  # type: ignore

        with Image.open(path) as im:
            info = {k: str(v)[:80] for k, v in (im.info or {}).items()}
            if info:
                print(f"  PIL info: {info}")
    except Exception:
        pass


def report_lsb(path: Path, max_bytes: int) -> None:
    section("LSB (interleaved stream AND per-plane, 2 traversal orders)")
    try:
        import numpy as np  # type: ignore
        from PIL import Image  # type: ignore
    except Exception as exc:
        print(f"  skipped (numpy/PIL): {exc}")
        return
    try:
        with Image.open(path) as im:
            rgba = np.array(im.convert("RGBA"))
    except Exception as exc:
        print(f"  skipped (not an image): {type(exc).__name__}")
        return

    # Two DIFFERENT carriers, and a run that only tries one stops too early:
    #
    #   interleaved: every pixel byte in order (R,G,B,R,G,B,...) contributes one
    #                bit. Measured 2026-10-29 on this exact DASBOOK LSB challenge:
    #                the working extraction was `arr[:,:,:3].reshape(-1) % 2`, and
    #                the note that recorded it said "plane 0" -- which does not
    #                reproduce. A per-plane-only sweep reports "nothing" on a file
    #                whose flag is right there.
    #   per-plane:   only every 3rd byte (channel index 0/1/2), the classic LSB.
    hits: list[tuple[str, int, bytes]] = []
    for order_name, matrix in (("row", rgba), ("col", rgba.transpose(1, 0, 2))):
        inter = matrix[:, :, :3].reshape(-1)
        for bit in (0,):
            bits = (inter >> bit) & 1
            buf = np.packbits(bits).tobytes()[:max_bytes]
            for m in FLAGISH.finditer(buf):
                hits.append((f"{order_name} interleaved bit{bit}", m.start(), m.group(0)))

        flat = matrix.reshape(-1, 4)
        for plane in range(3):
            bits = (flat[:, plane] >> 0) & 1
            buf = np.packbits(bits).tobytes()[:max_bytes]
            for m in FLAGISH.finditer(buf):
                hits.append((f"{order_name} plane{plane}", m.start(), m.group(0)))

    if not hits:
        printable = 0
        for order_name, matrix in (("row", rgba), ("col", rgba.transpose(1, 0, 2))):
            bits = (matrix[:, :, :3].reshape(-1) & 1)
            buf = np.packbits(bits).tobytes()[:max_bytes]
            printable += len(PRINTABLE.findall(buf))
        print(f"  no flag-shaped bytes; printable runs found: {printable}")
        for order_name, matrix in (("row", rgba), ("col", rgba.transpose(1, 0, 2))):
            bits = (matrix[:, :, :3].reshape(-1) & 1)
            buf = np.packbits(bits).tobytes()[:max_bytes]
            for run in PRINTABLE.findall(buf)[:3]:
                print(f"    {order_name} interleaved: {run[:60]!r}")
    for where, offset, value in hits[:8]:
        print(f"  CANDIDATE [{where}] offset {offset}: {value.decode(errors='replace')}")


def _looks_like_text(blob: bytes) -> bool:
    """Whether a decompressed blob reads as text rather than a lucky accident.

    Printability alone is not enough: compressed media decompresses to runs like
    ``{{{...`` or ``RRRR...`` often enough that "printable" accepted 5 bogus
    segments on the 6 MB MP3 attachment. Real payloads (a log, a script, a flag
    line) carry letters AND digits AND some variety.
    """
    sample = blob[:2048]
    if len(sample) < 16:
        return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    alnum = sum(1 for b in sample if chr(b).isalnum())
    if printable / len(sample) < 0.9:
        return False
    if alnum / len(sample) < 0.5:
        return False
    # a single byte dominating the sample is a fill pattern, not text
    top = max(collections.Counter(sample).values())
    return top / len(sample) < 0.5


def report_deflate(data: bytes) -> None:
    section("concatenated deflate / zlib segments")
    # Bounded twice over. (a) The first version probed EVERY byte offset, which
    # is O(n) zlib objects -- a 6 MB MP3 never finished. (b) Slicing 8 MB per
    # probe then still took 2.5 minutes, so the raw-deflate window is the HEAD
    # only (an embedded raw stream is reached through a payload boundary near
    # the start, e.g. right after a base64 decode), and each probe is capped.
    head = data[:4096]
    offsets: list[tuple[int, int]] = [(i, -15) for i in range(len(head))]
    for i in range(len(data) - 1):
        if data[i] == 0x1F and data[i + 1] == 0x8B:
            offsets.append((i, 47))          # gzip
        elif data[i] == 0x78 and data[i + 1] in (0x01, 0x5E, 0x9C, 0xDA):
            offsets.append((i, 15))          # zlib
        if len(offsets) >= 4096 + 64:
            break

    view = memoryview(data)
    seen = found = rejected = 0
    for start, wbits in offsets:
        seen += 1
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(view[start:start + 1_000_000], 65536)
        except zlib.error:
            continue
        if len(out) < 32:
            continue
        flag_hit = FLAGISH.search(out)
        if not flag_hit and not (d.eof and _looks_like_text(out)):
            rejected += 1
            continue
        found += 1
        print(f"  offset {start} wbits={wbits}: {len(out)} bytes head={out[:48]!r}")
        if flag_hit:
            print(f"    CANDIDATE flag: {flag_hit.group(0).decode(errors='replace')}")
        if found >= 6:
            break
    if not found:
        print(f"  no decompressible TEXT segment ({seen} offsets probed, "
              f"{rejected} rejected as binary fills)")


def report_strings(data: bytes) -> None:
    section("printable strings (flag-shaped only)")
    hits = FLAGISH.findall(data)
    if hits:
        for h in dict.fromkeys(hits):
            print(f"  CANDIDATE: {h.decode(errors='replace')}")
    else:
        print("  no flag-shaped string in raw bytes")
    long_runs = [r for r in PRINTABLE.findall(data) if len(r) >= 16][:5]
    for run in long_runs:
        print(f"  run: {run[:72]!r}")


def report_audio(path: Path, dump: Path | None) -> None:
    suffix = path.suffix.lower()
    if suffix not in (".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma"):
        return
    section("audio (spectrogram render)")
    ffmpeg = _ffmpeg()
    if not ffmpeg:
        print("  ffmpeg not found (PATH or .ir-tools/bin) — cannot render spectrogram")
        return
    print(f"  ffmpeg: {ffmpeg}")
    # Output goes NEXT TO THE INPUT, never to the current directory: the first
    # version defaulted to cwd, and a batch run left four .spec.png files in the
    # repo root (this project keeps artifacts out of the tree).
    out = (dump or path.parent) / f"{path.stem}.spec.png"
    cmd = [
        ffmpeg, "-y", "-loglevel", "error", "-i", str(path),
        "-lavfi", "showspectrumpic=s=1024x512:legend=disabled",
        str(out),
    ]
    import subprocess

    try:
        subprocess.run(cmd, check=True, timeout=180)
        print(f"  spectrogram: {out}")
        print("  -> read it with ocr(method='llm', prompt='describe the image, any text?')")
    except Exception as exc:
        print(f"  render failed: {type(exc).__name__}: {exc}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--dump", default=None, help="write derived artifacts here")
    ap.add_argument("--max-lsb-bytes", type=int, default=4096)
    args = ap.parse_args(argv)

    path = Path(args.path)
    if not path.is_file():
        print(f"not a file: {path}")
        return 2
    data = path.read_bytes()
    dump = Path(args.dump) if args.dump else None
    if dump:
        dump.mkdir(parents=True, exist_ok=True)

    report_basic(path, data)
    report_trailing(path, data)
    report_png_chunks(data)
    report_exif(path)
    report_lsb(path, args.max_lsb_bytes)
    report_deflate(data)
    report_strings(data)
    report_audio(path, dump)

    section("how to read this")
    print("A CANDIDATE is a lead, not an answer: confirm it is the challenge's flag")
    print("(format prefix, uniqueness in the file) before treating it as one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())