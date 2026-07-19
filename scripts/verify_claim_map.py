#!/usr/bin/env python3
"""Recompute every checked-in claim artifact hash and fail closed on drift."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CLAIM_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$")


class ClaimMapError(ValueError):
    """Raised when a claim cannot be bound to its checked-in artifact bytes."""


def _repo_file(root: Path, relative: object, *, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ClaimMapError(f"{label} path is missing")
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ClaimMapError(f"{label} path is unsafe: {relative}")
    candidate = root / path
    if candidate.is_symlink():
        raise ClaimMapError(f"{label} must not be a symlink: {relative}")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ClaimMapError(f"{label} is missing: {relative}") from error
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ClaimMapError(f"{label} escapes the repository: {relative}")
    return resolved


def _json_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ClaimMapError(f"{label} is not valid JSON: {path.name}") from error
    if not isinstance(payload, dict):
        raise ClaimMapError(f"{label} is not a JSON object: {path.name}")
    return payload


def verify_claim_map(*, root: Path, claim_map_path: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    claim_map = _json_object(claim_map_path, label="claim map")
    if claim_map.get("schema_version") != 1:
        raise ClaimMapError("claim map schema_version must be 1")
    claims = claim_map.get("claims")
    if not isinstance(claims, list) or not claims:
        raise ClaimMapError("claim map must contain claims")

    claim_ids: set[str] = set()
    verified_artifacts: dict[str, str] = {}
    for claim in claims:
        if not isinstance(claim, dict):
            raise ClaimMapError("claim entry is not an object")
        claim_id = claim.get("claim_id")
        if not isinstance(claim_id, str) or not CLAIM_ID.fullmatch(claim_id):
            raise ClaimMapError("claim_id is invalid")
        if claim_id in claim_ids:
            raise ClaimMapError(f"claim_id is duplicated: {claim_id}")
        claim_ids.add(claim_id)

        relative = claim.get("artifact_path")
        artifact = _repo_file(root, relative, label="claim artifact")
        expected_sha256 = claim.get("artifact_sha256")
        if not isinstance(expected_sha256, str) or not SHA256.fullmatch(expected_sha256):
            raise ClaimMapError(f"artifact SHA256 is invalid for {claim_id}")
        actual_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual_sha256 != expected_sha256:
            raise ClaimMapError(f"artifact SHA256 drift for {claim_id}")
        artifact_key = str(artifact.relative_to(root))
        previous = verified_artifacts.setdefault(artifact_key, expected_sha256)
        if previous != expected_sha256:
            raise ClaimMapError(f"artifact has conflicting claim hashes: {artifact_key}")

        artifact_payload = _json_object(artifact, label="claim artifact")
        if artifact_payload.get("machine_generated") is not True:
            raise ClaimMapError(f"artifact is not machine-generated for {claim_id}")
        if artifact_payload.get("status") != claim.get("artifact_status"):
            raise ClaimMapError(f"artifact status drift for {claim_id}")
        generator_relative = claim.get("generator")
        generator = _repo_file(root, generator_relative, label="claim generator")
        if not os.access(generator, os.X_OK):
            raise ClaimMapError(f"claim generator is not executable for {claim_id}")
        if artifact_payload.get("generator") != generator_relative:
            raise ClaimMapError(f"artifact generator drift for {claim_id}")

    return {
        "claim_count": len(claim_ids),
        "status": "PASS",
        "verified_artifact_count": len(verified_artifacts),
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--claim-map", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    claim_map = arguments.claim_map or arguments.root / "docs" / "CLAIM_MAP.json"
    try:
        result = verify_claim_map(root=arguments.root, claim_map_path=claim_map)
    except (ClaimMapError, OSError) as error:
        print(f"Claim map verification FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
