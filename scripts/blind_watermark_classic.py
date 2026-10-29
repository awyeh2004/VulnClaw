#!/usr/bin/env python3
"""Classic blind watermark (chishaxie/BlindWaterMark): two-image DFT difference.

The scheme, in one paragraph: encode adds ``alpha * watermark`` to the **unshifted**
2-D DFT of the carrier image, after placing the watermark into the top half of the
spectrum through a seeded permutation and copying it mirrored into the bottom-right
corner. Decode is the same arithmetic backwards -- ``real((fft2(encoded) -
fft2(original)) / alpha)``, un-permute with the SAME seed, mirror, done. The
watermark therefore comes back as an IMAGE of the secret text, not as text.

Two steps are easy to miss and were missed by a hand-rolled enumeration on
2026-10-29 (24 conventions of axes/alpha/sign/quadrant, none worked):

1. the per-row/column permutation ``random.shuffle(range(h//2))`` and
   ``random.shuffle(range(w))`` with ``seed=20160930`` decides WHERE each result
   goes -- without it the output is unstructured noise;
2. the mirrored copy in the bottom-right half.

Usage::

    python scripts/blind_watermark_classic.py decode <original> <encoded> <out.png>
    python scripts/blind_watermark_classic.py encode <image> <watermark> <out.png>

Options: ``--seed N`` (default 20160930), ``--alpha F`` (default 3.0), ``--oldseed``
(python2's random algorithm; a py2-encoded image needs it).

Measured 2026-10-29 on DASBOOK 7.2.4 (blind1.png / blind2.png): decoding with
``decode blind2.png blind1.png out.png`` -- i.e. **blind2 is the original and
blind1 the encoded one** -- yields the watermark image with the flag rendered in
the top-left corner. The other order produces noise, which is the quickest way to
tell which file is which.

The classic script prints an "Unsupported depth ... fallbacked to CV_8U" warning
because it writes the 0..255 float watermark through imwrite; that is expected.
"""
from __future__ import annotations

import argparse
import random
import sys

import cv2
import numpy as np

DEFAULT_SEED = 20160930
DEFAULT_ALPHA = 3.0


def _shuffle_pair(seed: int, half: int, width: int, oldseed: bool) -> tuple[list[int], list[int]]:
    """Seed ONCE, then shuffle rows and columns in that order.

    Seeding again between the two shuffles produces a different column
    permutation than the reference script, and the recovered watermark turns into
    noise with no error message -- measured while writing this port (first version
    seeded inside a per-length helper and produced an unreadable result).
    """
    if oldseed:
        old_shuffle = _py2_shuffle
    else:
        old_shuffle = None

    def _do(values: list[int]) -> None:
        if old_shuffle is not None:
            old_shuffle(values)
        else:
            random.shuffle(values)

    if oldseed:
        random.seed(seed, version=1)
    else:
        random.seed(seed)
    rows = list(range(half))
    cols = list(range(width))
    _do(rows)
    _do(cols)
    return rows, cols


def _py2_shuffle(values: list[int]) -> None:
    """python2's ``random.shuffle`` (the --oldseed path)."""
    for i in reversed(range(1, len(values))):
        j = int(random.random() * (i + 1))
        values[i], values[j] = values[j], values[i]


def decode(original_path: str, encoded_path: str, out_path: str, *,
           seed: int = DEFAULT_SEED, alpha: float = DEFAULT_ALPHA,
           oldseed: bool = False) -> str:
    img = cv2.imread(original_path)
    img_wm = cv2.imread(encoded_path)
    if img is None:
        raise SystemExit(f"cannot read {original_path}")
    if img_wm is None:
        raise SystemExit(f"cannot read {encoded_path}")

    f1 = np.fft.fft2(img.astype(np.float64))
    f2 = np.fft.fft2(img_wm.astype(np.float64))
    rwm = np.real((f2 - f1) / alpha)

    h, w = rwm.shape[0], rwm.shape[1]
    half = int(h * 0.5)
    rows, cols = _shuffle_pair(seed, half, w, oldseed)

    wm = np.zeros(rwm.shape, dtype=np.float64)
    for i in range(half):
        for j in range(w):
            # np.uint8() here is NOT cosmetic: the reference script truncates at
            # assignment, and a negative real part wraps (e.g. -5 -> 251). Keeping
            # raw floats instead shifts every value and the text stops being
            # readable -- measured while writing this port.
            wm[rows[i]][cols[j]] = np.uint8(rwm[i][j])
    for i in range(half):
        for j in range(w):
            wm[h - i - 1][w - j - 1] = wm[i][j]

    cv2.imwrite(out_path, wm)
    return out_path

def encode(image_path: str, watermark_path: str, out_path: str, *,
           seed: int = DEFAULT_SEED, alpha: float = DEFAULT_ALPHA,
           oldseed: bool = False) -> str:
    img = cv2.imread(image_path)
    wm_img = cv2.imread(watermark_path)
    if img is None:
        raise SystemExit(f"cannot read {image_path}")
    if wm_img is None:
        raise SystemExit(f"cannot read {watermark_path}")

    h, w = img.shape[:2]
    rwm = np.zeros(img.shape, dtype=np.float64)
    half = int(h * 0.5)
    rows, cols = _shuffle_pair(seed, half, w, oldseed)

    # place the watermark through the permutation, then mirror it
    hwm = np.zeros((half, w, img.shape[2]), dtype=np.float64)
    hwm2 = np.zeros_like(hwm)
    for i in range(min(wm_img.shape[0], half)):
        for j in range(min(wm_img.shape[1], w)):
            hwm2[i][j] = wm_img[i][j]
    for i in range(half):
        for j in range(w):
            hwm[i][j] = hwm2[rows[i]][cols[j]]
    for i in range(half):
        for j in range(w):
            rwm[i][j] = hwm[i][j]
            rwm[rwm.shape[0] - i - 1][rwm.shape[1] - j - 1] = hwm[i][j]

    f1 = np.fft.fft2(img.astype(np.float64))
    out = np.real(np.fft.ifft2(f1 + alpha * rwm))
    cv2.imwrite(out_path, out, [int(cv2.IMWRITE_JPEG_QUALITY), 100])
    return out_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=("encode", "decode"))
    ap.add_argument("first", help="encode: image   | decode: original (no watermark)")
    ap.add_argument("second", help="encode: watermark image | decode: encoded image")
    ap.add_argument("out")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--alpha", type=float, default=DEFAULT_ALPHA)
    ap.add_argument("--oldseed", action="store_true",
                    help="use python2's random algorithm (for py2-encoded images)")
    args = ap.parse_args(argv)

    if args.cmd == "decode":
        print(decode(args.first, args.second, args.out,
                     seed=args.seed, alpha=args.alpha, oldseed=args.oldseed))
    else:
        print(encode(args.first, args.second, args.out,
                     seed=args.seed, alpha=args.alpha, oldseed=args.oldseed))
    print("then read the output with ocr(method='llm', prompt='描述图中的文字')")
    return 0


if __name__ == "__main__":
    sys.exit(main())