"""Meta gate for the capability coverage manifest (audit item E, 2026-10-24).

The manifest is the single machine-readable answer to "which shipped
capabilities have never seen a real challenge". It rots the moment a referenced
test moves or a fixture is deleted, so this gate re-validates it on every run:
paths must exist, referenced pytest nodes must be collectable, and the QR
fixture must still round-trip (skip-gated on pyzbar, which not every host has).
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tests" / "fixtures" / "capabilities" / "manifest.yaml"


def _load_manifest() -> dict:
    import yaml

    return yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))


def test_manifest_exists_and_has_version():
    data = _load_manifest()
    assert data.get("version") == 1
    caps = data.get("capabilities") or []
    assert {c["name"] for c in caps} >= {
        "f5_stego",
        "qr_decode",
        "ocr_vision",
        "cve_alias_fallback",
        "exploit_intel",
    }, "a capability row disappeared from the matrix"


def test_every_referenced_repo_path_exists():
    for cap in _load_manifest()["capabilities"]:
        for field in ("fixture", "unit_test"):
            value = str(cap.get(field, "") or "")
            if not value or " " in value or not value.startswith("tests/"):
                continue  # prose/external paths are not repo files
            assert (ROOT / value.split("::")[0]).is_file(), (
                f"{cap['name']}.{field} points at a missing file: {value}"
            )


def test_pytest_nodes_are_collectable():
    """Every `path::node` unit_test reference must still collect exactly once."""
    nodes = []
    for cap in _load_manifest()["capabilities"]:
        value = str(cap.get("unit_test", "") or "")
        if "::" in value and " " not in value:
            nodes.append(value)
    if not nodes:
        return
    result = pytest.main(["--collect-only", "-q", *nodes])
    assert result == 0, "a manifest-referenced test node no longer collects"


def test_qr_fixture_roundtrips():
    pyzbar = pytest.importorskip("pyzbar.pyzbar")
    pytest.importorskip("PIL")
    from PIL import Image

    manifest = _load_manifest()
    cap = next(c for c in manifest["capabilities"] if c["name"] == "qr_decode")
    path = ROOT / cap["fixture"]
    assert path.is_file(), "committed QR fixture vanished"
    decoded = pyzbar.decode(Image.open(path))
    assert decoded, "fixture no longer decodes"
    assert decoded[0].data.decode() == cap["fixture_payload"]
