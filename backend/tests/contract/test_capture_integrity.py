from __future__ import annotations

import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    from verify_capture_integrity import (
        CAPTURE_METHOD,
        EXPECTED_CAPTURE_NAMES,
        capture_entry_issues,
        left_right_pixel_correlation,
        verify_capture_directory,
    )
finally:
    sys.path.remove(str(SCRIPTS))


def _write_non_tiled_image(path: Path, *, width: int = 128, height: int = 64) -> None:
    image = Image.new("RGB", (width, height), "#f3f1ea")
    draw = ImageDraw.Draw(image)
    draw.rectangle((4, 4, width // 3, height - 4), fill="#1b1915")
    draw.ellipse((width // 2, 8, width - 8, height - 8), fill="#b8dc32")
    image.save(path, format="PNG")


def _entry(path: Path, *, landmark_count: int = 1) -> dict[str, object]:
    import hashlib

    return {
        "path": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "width": 128,
        "height": 64,
        "viewport": {"width": 128, "height": 64},
        "primary_landmark_count": landmark_count,
        "source_url": "http://127.0.0.1:3100/overview",
        "capture_method": CAPTURE_METHOD,
    }


def test_tiled_capture_has_near_perfect_left_right_correlation(tmp_path: Path) -> None:
    half = Image.new("RGB", (64, 64), "#f3f1ea")
    draw = ImageDraw.Draw(half)
    draw.rectangle((4, 4, 30, 58), fill="#1b1915")
    draw.ellipse((34, 8, 58, 54), fill="#b8dc32")
    tiled = Image.new("RGB", (128, 64))
    tiled.paste(half, (0, 0))
    tiled.paste(half, (64, 0))
    path = tmp_path / "tiled.png"
    tiled.save(path, format="PNG")

    assert left_right_pixel_correlation(path) >= 0.999


def test_capture_entry_rejects_any_landmark_count_other_than_one(tmp_path: Path) -> None:
    path = tmp_path / "capture.png"
    _write_non_tiled_image(path)

    issues = capture_entry_issues(path, _entry(path, landmark_count=2))

    assert {issue.code for issue in issues} == {"PRIMARY_LANDMARK_COUNT"}


def test_capture_entry_rejects_hash_dimension_method_and_tiling_drift(tmp_path: Path) -> None:
    half = Image.new("RGB", (64, 64), "#f3f1ea")
    draw = ImageDraw.Draw(half)
    draw.rectangle((5, 5, 45, 45), fill="#1b1915")
    tiled = Image.new("RGB", (128, 64))
    tiled.paste(half, (0, 0))
    tiled.paste(half, (64, 0))
    path = tmp_path / "capture.png"
    tiled.save(path, format="PNG")
    entry = {
        **_entry(path),
        "sha256": "0" * 64,
        "width": 127,
        "capture_method": "browser-wrapper",
    }

    issues = capture_entry_issues(path, entry)

    assert {issue.code for issue in issues} == {
        "CAPTURE_METHOD",
        "DIMENSIONS",
        "PIXEL_TILING",
        "SHA256",
    }


def test_committed_capture_manifest_covers_all_30_true_screenshots() -> None:
    manifest_path = ROOT / "output/phase2-tracepaper-final/capture-manifest.json"
    capture_directory = manifest_path.parent

    issues = verify_capture_directory(capture_directory, manifest_path)

    assert len(EXPECTED_CAPTURE_NAMES) == 30
    assert issues == (), "\n" + "\n".join(
        f"{issue.code}: {issue.path}: {issue.detail}" for issue in issues
    )


def test_capture_manifest_is_machine_generated_playwright_provenance() -> None:
    manifest_path = ROOT / "output/phase2-tracepaper-final/capture-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 1
    assert manifest["machine_generated"] is True
    assert manifest["generator"] == "web/tests/e2e/gallery-capture.spec.ts"
    assert manifest["capture_method"] == CAPTURE_METHOD
    assert len(manifest["captures"]) == 30


def test_strict_release_gate_runs_capture_integrity_verifier() -> None:
    release_verifier = (ROOT / "scripts/release_verifier.py").read_text(encoding="utf-8")

    assert '"scripts/verify_capture_integrity.py"' in release_verifier
