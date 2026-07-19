#!/usr/bin/env python3
"""Publish validated public export-key proofs without private key material."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = "scripts/publish_export_public_keys.py"
DEFAULT_OUTPUT_DIRECTORY = ROOT / "web/public/verification"
PRODUCTION_SOURCE = (
    ROOT
    / "artifacts/verification/operator-session-20260717T074450Z"
    / "production-export-public-key.json"
)
SEALED_SOURCE = (
    ROOT
    / "artifacts/verification/paced-batches/paced-20260714T103240Z"
    / "local-export-public-key.json"
)
_ALLOWED_PROOF_FIELDS = frozenset(
    {
        "algorithm",
        "checked_at",
        "distribution",
        "encoding",
        "generator",
        "git_sha",
        "machine_generated",
        "private_seed_included",
        "proof_challenge_base64",
        "proof_signature_base64",
        "proof_signature_sha256",
        "public_key_base64",
        "public_key_sha256",
        "release_mode",
        "runtime_service",
        "schema_version",
        "scope",
        "self_test",
        "source",
        "status",
    }
)


class ExportKeyDistributionError(RuntimeError):
    pass


def _decode(payload: dict[str, Any], field: str, *, length: int | None = None) -> bytes:
    value = payload.get(field)
    if not isinstance(value, str):
        raise ExportKeyDistributionError(f"public-key proof field {field} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise ExportKeyDistributionError(
            f"public-key proof field {field} is not valid base64"
        ) from error
    if length is not None and len(decoded) != length:
        raise ExportKeyDistributionError(f"public-key proof field {field} has invalid length")
    return decoded


def _load_validated_proof(path: Path) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExportKeyDistributionError(f"public-key proof is unreadable: {path}") from error
    if not isinstance(payload, dict):
        raise ExportKeyDistributionError(f"public-key proof is not an object: {path}")
    unexpected_fields = set(payload) - _ALLOWED_PROOF_FIELDS
    if unexpected_fields:
        rendered = ", ".join(sorted(unexpected_fields))
        raise ExportKeyDistributionError(
            f"public-key proof contains unexpected fields ({rendered}): {path}"
        )
    if (
        payload.get("machine_generated") is not True
        or payload.get("status") != "PASS"
        or payload.get("private_seed_included") is not False
        or payload.get("algorithm") != "Ed25519"
    ):
        raise ExportKeyDistributionError(f"public-key proof did not pass runtime checks: {path}")

    git_sha = payload.get("git_sha")
    if not isinstance(git_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", git_sha):
        raise ExportKeyDistributionError(f"public-key proof Git SHA is invalid: {path}")
    public_key_bytes = _decode(payload, "public_key_base64", length=32)
    challenge = _decode(payload, "proof_challenge_base64")
    signature = _decode(payload, "proof_signature_base64", length=64)
    if not challenge:
        raise ExportKeyDistributionError(f"public-key proof challenge is empty: {path}")
    if payload.get("public_key_sha256") != hashlib.sha256(public_key_bytes).hexdigest():
        raise ExportKeyDistributionError(f"public-key proof key hash is invalid: {path}")
    if payload.get("proof_signature_sha256") != hashlib.sha256(signature).hexdigest():
        raise ExportKeyDistributionError(f"public-key proof signature hash is invalid: {path}")
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, challenge)
    except (ValueError, InvalidSignature) as error:
        raise ExportKeyDistributionError(f"public-key runtime proof is invalid: {path}") from error
    return raw, payload


def _entry(
    *,
    role: str,
    filename: str,
    source: Path,
    source_bytes: bytes,
    payload: dict[str, Any],
) -> dict[str, object]:
    return {
        "git_sha": payload["git_sha"],
        "public_key_sha256": payload["public_key_sha256"],
        "role": role,
        "runtime_proof_verified": True,
        "runtime_service": payload.get("runtime_service", "api"),
        "source_artifact_path": source.relative_to(ROOT).as_posix(),
        "source_artifact_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "status": "PASS",
        "url": f"/verification/{filename}",
    }


def expected_outputs() -> dict[str, bytes]:
    production_bytes, production = _load_validated_proof(PRODUCTION_SOURCE)
    sealed_bytes, sealed = _load_validated_proof(SEALED_SOURCE)
    production_filename = "production-export-public-key.json"
    sealed_filename = "sealed-cohort-export-public-key.json"
    manifest = {
        "generator": GENERATOR,
        "keys": [
            _entry(
                role="production",
                filename=production_filename,
                source=PRODUCTION_SOURCE,
                source_bytes=production_bytes,
                payload=production,
            ),
            _entry(
                role="sealed-cohort",
                filename=sealed_filename,
                source=SEALED_SOURCE,
                source_bytes=sealed_bytes,
                payload=sealed,
            ),
        ],
        "machine_generated": True,
        "private_seed_included": False,
        "schema_version": "crosspatch.export-public-keys.v1",
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return {
        production_filename: production_bytes,
        sealed_filename: sealed_bytes,
        "export-public-keys.json": manifest_bytes,
    }


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def publish(*, output_directory: Path = DEFAULT_OUTPUT_DIRECTORY) -> set[str]:
    outputs = expected_outputs()
    for filename, payload in outputs.items():
        _atomic_write(output_directory / filename, payload)
    return set(outputs)


def check(*, output_directory: Path = DEFAULT_OUTPUT_DIRECTORY) -> bool:
    return all(
        (output_directory / filename).is_file()
        and stat.S_IMODE((output_directory / filename).stat().st_mode) == 0o644
        and (output_directory / filename).read_bytes() == payload
        for filename, payload in expected_outputs().items()
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", type=Path, default=DEFAULT_OUTPUT_DIRECTORY)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.check:
            return 0 if check(output_directory=arguments.output_directory) else 1
        publish(output_directory=arguments.output_directory)
    except (OSError, ValueError, ExportKeyDistributionError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
