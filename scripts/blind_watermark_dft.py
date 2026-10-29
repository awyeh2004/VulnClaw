#!/usr/bin/env python3
"""Blind watermark, two-image DFT difference: enumerate the conventions.

The classic "盲水印" family hands you two images (original + watermarked) and the
watermark is recovered from the difference of their 2-D DFTs. The published
scripts differ in details that change the answer completely:

* which axes ``np.fft.fft2`` transforms (on an (H,W,3) array the default is
  ``(-2,-1)`` = width AND channel, not height AND width -- a quirk that silently
  mixes channels),
* what the difference is divided by (``alpha``),
* which half of the spectrum the watermark occupies and in which direction the
  index permutations run.

Guessing ONE convention fails; measured 2026-10-29 on the DASBOOK 7.2.4 pair: a
104-tool-call run reconstructed the pipeline from memory and still missed. So
this script enumerates them and SCORES each output by how bimodal it is -- a real
watermark image is almost all 0 and 255, a wrong convention looks like smooth
noise. It writes the top candidates as PNGs; nobody has to trust a guess.

    python scripts/blind_watermark_dft.py <watermarked.png> <original.png> --out DIR

Then read the PNGs with `ocr(method='llm', prompt='describe any text you see')`.
"""
from __future__ import annotations

import argparse
import itertools
import sys
from pathlib import Path

import numpy as np


def _load(path: Path, size: tuple[int, int] | None):
    import cv2  # type: ignore

    img = cv2.imread(str(path), cv2.IMREAD_COLOR)
    if img is None:
        raise SystemExit(f"cannot read {path}")
    if size and (img.shape[1], img.shape[0]) != size:
        img = cv2.resize(img, size, interpolation=cv2.INTER_LINEAR)
    return img


def _score(img: np.ndarray) -> tuple[float, float]:
    """(bimodality, ink share).

    Bimodality alone is not enough: an ALL-BLACK image is perfectly bimodal and
    trivially "wins" (measured on the first version of this script -- every
    candidate scored 1.000, because ``near_zero`` was 1.0 and there was no ink).
    A real watermark is bimodal AND has a plausible amount of foreground, so the
    caller sorts on bimodality but must also see the ink share.
    """
    value = img.astype(np.float32)
    near_zero = float((value <= 8).mean())
    near_255 = float((value >= 247).mean())
    plausible_ink = 0.005 <= near_255 <= 0.6
    return (near_zero + near_255 if plausible_ink else 0.0), near_255


def conventions(a: np.ndarray, b: np.ndarray):
    """Yield (label, watermark_image) for every plausible reconstruction."""
    h, w = a.shape[:2]
    for axes in ((0, 1), (1, 2), (-2, -1)):
        fa = np.fft.fft2(a.astype(np.float64), axes=axes)
        fb = np.fft.fft2(b.astype(np.float64), axes=axes)
        for alpha in (1.0, 3.0, 4.0):
            for sign in (1.0, -1.0):
                diff = np.real(sign * (fb - fa) / alpha)
                for quadrant in ("top-left", "top-band"):
                    if quadrant == "top-left":
                        crop = diff[: h // 2, : w // 2]
                        label = f"axes={axes} alpha={alpha:g} sign={sign:+g} {quadrant}"
                        yield label, np.clip(crop, 0, 255).astype(np.uint8)
                    else:
                        crop = diff[: h // 2, :]
                        label = f"axes={axes} alpha={alpha:g} sign={sign:+g} {quadrant}"
                        yield label, np.clip(crop, 0, 255).astype(np.uint8)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("watermarked")
    ap.add_argument("original")
    ap.add_argument("--out", default=".", help="write candidate PNGs here")
    ap.add_argument("--top", type=int, default=6, help="how many candidates to keep")
    args = ap.parse_args(argv)

    import cv2  # type: ignore

    wm_path, orig_path = Path(args.watermarked), Path(args.original)
    first = _load(wm_path, None)
    size = (first.shape[1], first.shape[0])
    a = first
    b = _load(orig_path, size)

    scored = []
    for label, image in conventions(a, b):
        bimodal, ink = _score(image)
        scored.append((bimodal, ink, label, image))
    scored.sort(key=lambda row: (-row[0], -row[1]))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    print(f"{'bimodal':>8} {'ink':>6}  label")
    for bimodal, ink, label, _ in scored[:12]:
        print(f"{bimodal:8.3f} {ink:6.3f}  {label}")
    print()
    print("bimodal near 1 with ink roughly 0.01-0.6 is a watermark; all-black scores")
    print("0 here on purpose (it is bimodal but has no ink). Candidates written:")
    for bimodal, ink, label, image in scored[: args.top]:
        safe = label.replace(" ", "_").replace("=", "").replace("(", "").replace(")", "")
        safe = safe.replace(",", "-").replace("+", "p").replace(".", "")
        path = out / f"wm_{bimodal:.2f}_ink{ink:.2f}_{safe}.png"
        # upscale so a small watermark stays legible to a vision model
        up = cv2.resize(image, None, fx=4, fy=4, interpolation=cv2.INTER_NEAREST)
        cv2.imwrite(str(path), up)
        print(f"  {path}")
    print()
    print("next: ocr(method='llm', prompt='描述图中文字/图案') on each PNG.")
    return 0


if __name__ == "__main__":
    sys.exit(main())