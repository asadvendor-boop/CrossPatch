#!/usr/bin/env python3
"""Verify committed CrossPatch captures are true, untiled Playwright screenshots."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from PIL import Image, UnidentifiedImageError

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAPTURE_DIRECTORY = ROOT / "output" / "phase2-tracepaper-final"
DEFAULT_MANIFEST = DEFAULT_CAPTURE_DIRECTORY / "capture-manifest.json"
CAPTURE_METHOD = "playwright.page.screenshot"
CAPTURE_GENERATOR = "web/tests/e2e/gallery-capture.spec.ts"
DESKTOP_PIXEL_CORRELATION_LIMIT = 0.82
NARROW_PIXEL_CORRELATION_LIMIT = 0.97
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

EXPECTED_CAPTURE_NAMES = (
    "approvals-1280x720.png",
    "approvals-1440x900.png",
    "approvals-320x900.png",
    "artifacts-1280x720.png",
    "artifacts-1440x900.png",
    "artifacts-320x900.png",
    "case-detail-1280x720.png",
    "case-detail-1440x900.png",
    "case-detail-320x900.png",
    "cases-1280x720.png",
    "cases-1440x900.png",
    "cases-320x900.png",
    "landing-1280x720.png",
    "landing-1440x900.png",
    "landing-320x900.png",
    "not-found-1280x720.png",
    "not-found-1440x900.png",
    "not-found-320x900.png",
    "open-incident-1280x720.png",
    "open-incident-1440x900.png",
    "open-incident-320x900.png",
    "overview-1280x720.png",
    "overview-1440x900.png",
    "overview-320x900.png",
    "overview-reference-comparison.png",
    "signal-reference-comparison.png",
    "signal-room-1280x720.png",
    "signal-room-1440x900.png",
    "signal-room-320x900.png",
    "signal-room-detail-1280x720.png",
)

_NAMED_DIMENSIONS = re.compile(r"-(?P<width>[1-9][0-9]*)x(?P<height>[1-9][0-9]*)\.png$")


@dataclass(frozen=True, slots=True)
class CaptureIssue:
    code: str
    path: str
    detail: str


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pearson(left: list[int], right: list[int]) -> float:
    if len(left) != len(right) or not left:
        raise ValueError("pixel vectors must be non-empty and equal length")
    count = len(left)
    left_mean = math.fsum(left) / count
    right_mean = math.fsum(right) / count
    numerator = math.fsum(
        (left_value - left_mean) * (right_value - right_mean)
        for left_value, right_value in zip(left, right, strict=True)
    )
    left_energy = math.fsum((value - left_mean) ** 2 for value in left)
    right_energy = math.fsum((value - right_mean) ** 2 for value in right)
    denominator = math.sqrt(left_energy * right_energy)
    if denominator == 0:
        return 1.0 if left == right else 0.0
    return max(-1.0, min(1.0, numerator / denominator))


def left_right_pixel_correlation(path: Path) -> float:
    """Return luminance correlation between equal-width outer image halves."""
    with Image.open(path) as source:
        image = source.convert("L")
        width, height = image.size
        half_width = width // 2
        if half_width < 1 or height < 1:
            raise ValueError("capture is too small for anti-tiling analysis")
        left = image.crop((0, 0, half_width, height))
        right = image.crop((width - half_width, 0, width, height))
        sample_width = min(160, half_width)
        sample_height = min(160, height)
        sample_size = (sample_width, sample_height)
        left = left.resize(sample_size, Image.Resampling.BILINEAR)
        right = right.resize(sample_size, Image.Resampling.BILINEAR)
        return _pearson(
            list(left.get_flattened_data()),
            list(right.get_flattened_data()),
        )


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def capture_entry_issues(path: Path, entry: dict[str, object]) -> tuple[CaptureIssue, ...]:
    issues: list[CaptureIssue] = []
    rendered_path = path.as_posix()
    if entry.get("capture_method") != CAPTURE_METHOD:
        issues.append(
            CaptureIssue("CAPTURE_METHOD", rendered_path, f"must be {CAPTURE_METHOD}")
        )
    if entry.get("primary_landmark_count") != 1:
        issues.append(
            CaptureIssue(
                "PRIMARY_LANDMARK_COUNT",
                rendered_path,
                "capture must contain exactly one primary header/sidebar landmark",
            )
        )
    if not path.is_file():
        issues.append(CaptureIssue("MISSING_FILE", rendered_path, "capture file is missing"))
        return tuple(issues)
    try:
        payload = path.read_bytes()
    except OSError as error:
        issues.append(CaptureIssue("READ_ERROR", rendered_path, str(error)))
        return tuple(issues)
    if not payload.startswith(PNG_SIGNATURE):
        issues.append(CaptureIssue("PNG_SIGNATURE", rendered_path, "file is not a PNG"))
        return tuple(issues)
    expected_hash = entry.get("sha256")
    actual_hash = hashlib.sha256(payload).hexdigest()
    if expected_hash != actual_hash:
        issues.append(CaptureIssue("SHA256", rendered_path, "manifest hash does not match"))
    try:
        with Image.open(path) as image:
            image.load()
            actual_dimensions = image.size
            if image.format != "PNG":
                issues.append(CaptureIssue("PNG_FORMAT", rendered_path, "decoder is not PNG"))
    except (OSError, UnidentifiedImageError) as error:
        issues.append(CaptureIssue("PNG_DECODE", rendered_path, str(error)))
        return tuple(issues)
    manifest_dimensions = (_integer(entry.get("width")), _integer(entry.get("height")))
    if None in manifest_dimensions or actual_dimensions != manifest_dimensions:
        issues.append(
            CaptureIssue(
                "DIMENSIONS",
                rendered_path,
                f"manifest {manifest_dimensions!r} != PNG {actual_dimensions!r}",
            )
        )
    named = _NAMED_DIMENSIONS.search(path.name)
    if named is not None:
        named_dimensions = (int(named.group("width")), int(named.group("height")))
        if actual_dimensions != named_dimensions:
            issues.append(
                CaptureIssue(
                    "FILENAME_DIMENSIONS",
                    rendered_path,
                    f"filename {named_dimensions!r} != PNG {actual_dimensions!r}",
                )
            )
    viewport = entry.get("viewport")
    if not isinstance(viewport, dict) or (
        _integer(viewport.get("width")) is None
        or _integer(viewport.get("height")) is None
    ):
        issues.append(CaptureIssue("VIEWPORT", rendered_path, "viewport is malformed"))
    source_url = entry.get("source_url")
    if not isinstance(source_url, str) or not source_url.strip():
        issues.append(CaptureIssue("SOURCE_URL", rendered_path, "source URL is missing"))
    try:
        correlation = left_right_pixel_correlation(path)
    except (OSError, ValueError, UnidentifiedImageError) as error:
        issues.append(CaptureIssue("PIXEL_ANALYSIS", rendered_path, str(error)))
    else:
        correlation_limit = (
            NARROW_PIXEL_CORRELATION_LIMIT
            if actual_dimensions[0] < 640
            else DESKTOP_PIXEL_CORRELATION_LIMIT
        )
        if correlation >= correlation_limit:
            issues.append(
                CaptureIssue(
                    "PIXEL_TILING",
                    rendered_path,
                    (
                        f"left/right correlation {correlation:.6f} exceeds "
                        f"{correlation_limit:.2f}"
                    ),
                )
            )
    return tuple(issues)


def _manifest_issue(path: Path, code: str, detail: str) -> tuple[CaptureIssue, ...]:
    return (CaptureIssue(code, path.as_posix(), detail),)


def verify_capture_directory(
    capture_directory: Path = DEFAULT_CAPTURE_DIRECTORY,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> tuple[CaptureIssue, ...]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _manifest_issue(manifest_path, "MISSING_MANIFEST", "manifest is missing")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return _manifest_issue(manifest_path, "INVALID_MANIFEST", str(error))
    if not isinstance(manifest, dict):
        return _manifest_issue(manifest_path, "INVALID_MANIFEST", "manifest is not an object")

    issues: list[CaptureIssue] = []
    if manifest.get("schema_version") != 1 or manifest.get("machine_generated") is not True:
        issues.append(
            CaptureIssue(
                "MANIFEST_PROVENANCE",
                manifest_path.as_posix(),
                "invalid schema/provenance",
            )
        )
    if manifest.get("generator") != CAPTURE_GENERATOR:
        issues.append(
            CaptureIssue("MANIFEST_GENERATOR", manifest_path.as_posix(), "unexpected generator")
        )
    if manifest.get("capture_method") != CAPTURE_METHOD:
        issues.append(
            CaptureIssue("MANIFEST_METHOD", manifest_path.as_posix(), "unexpected method")
        )

    actual_names = {path.name for path in capture_directory.glob("*.png")}
    expected_names = set(EXPECTED_CAPTURE_NAMES)
    for missing in sorted(expected_names - actual_names):
        issues.append(CaptureIssue("INVENTORY_MISSING", missing, "expected capture is missing"))
    for extra in sorted(actual_names - expected_names):
        issues.append(CaptureIssue("INVENTORY_EXTRA", extra, "unexpected capture is present"))

    captures = manifest.get("captures")
    if not isinstance(captures, list):
        issues.append(
            CaptureIssue(
                "MANIFEST_CAPTURES",
                manifest_path.as_posix(),
                "captures is not a list",
            )
        )
        return tuple(issues)
    by_name: dict[str, dict[str, object]] = {}
    for index, value in enumerate(captures):
        if not isinstance(value, dict):
            issues.append(
                CaptureIssue("MANIFEST_ENTRY", f"captures[{index}]", "entry is not an object")
            )
            continue
        candidate = value.get("path")
        if not isinstance(candidate, str) or Path(candidate).name != candidate.split("/")[-1]:
            issues.append(
                CaptureIssue("MANIFEST_PATH", f"captures[{index}]", "path is malformed")
            )
            continue
        name = Path(candidate).name
        if name in by_name:
            issues.append(CaptureIssue("MANIFEST_DUPLICATE", name, "duplicate capture entry"))
            continue
        by_name[name] = value
    for missing in sorted(expected_names - set(by_name)):
        issues.append(CaptureIssue("MANIFEST_MISSING", missing, "manifest entry is missing"))
    for extra in sorted(set(by_name) - expected_names):
        issues.append(CaptureIssue("MANIFEST_EXTRA", extra, "unexpected manifest entry"))
    for name in sorted(expected_names & set(by_name)):
        issues.extend(capture_entry_issues(capture_directory / name, by_name[name]))
    return tuple(issues)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=DEFAULT_CAPTURE_DIRECTORY)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    arguments = parser.parse_args(argv)
    issues = verify_capture_directory(arguments.directory, arguments.manifest)
    result: dict[str, Any] = {
        "schema_version": 1,
        "machine_generated": True,
        "generator": "scripts/verify_capture_integrity.py",
        "capture_count": len(EXPECTED_CAPTURE_NAMES),
        "status": "PASS" if not issues else "FAIL",
        "issues": [asdict(issue) for issue in issues],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not issues else 1


if __name__ == "__main__":
    sys.exit(main())
