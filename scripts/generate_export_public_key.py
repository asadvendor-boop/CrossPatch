#!/usr/bin/env python3
"""Capture distributable Ed25519 export-verification evidence from the runtime."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from verification_lib import ROOT, atomic_json

GENERATOR = "scripts/generate_export_public_key.py"
PROOF_CHALLENGE = b"crosspatch-export-public-key-runtime-proof-v1"
_PROOF_CHALLENGE_BASE64 = base64.b64encode(PROOF_CHALLENGE).decode("ascii")
_RUNTIME_PROOF_PROGRAM = f"""
import base64
import json
from cryptography.hazmat.primitives import serialization
from crosspatch.runtime.factories import _private_ed25519_key, _release_mode_enabled

if not _release_mode_enabled():
    raise RuntimeError("public-key release evidence requires release mode")
challenge = base64.b64decode("{_PROOF_CHALLENGE_BASE64}")
key = _private_ed25519_key()
public = key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
print(json.dumps({{
    "public_key_base64": base64.b64encode(public).decode("ascii"),
    "signature_base64": base64.b64encode(key.sign(challenge)).decode("ascii"),
}}, sort_keys=True))
""".strip()


class PublicKeyGenerationError(RuntimeError):
    pass


class _Result(Protocol):
    stdout: str
    stderr: str
    returncode: int


Run = Callable[..., _Result]


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PublicKeyGenerationError("public-key evidence timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _git_sha() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    value = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise PublicKeyGenerationError("Git SHA readback is unavailable")
    return value


def runtime_public_key_proof(*, run: Run = subprocess.run) -> tuple[bytes, bytes]:
    result = run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "api",
            "/opt/crosspatch/venv/bin/python",
            "-c",
            _RUNTIME_PROOF_PROGRAM,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise PublicKeyGenerationError("running API signing-key proof failed")
    try:
        payload = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicKeyGenerationError("running API signing-key proof was not JSON") from error
    if not isinstance(payload, dict) or set(payload) != {
        "public_key_base64",
        "signature_base64",
    }:
        raise PublicKeyGenerationError("running API signing-key proof schema is invalid")
    try:
        public_key = base64.b64decode(payload["public_key_base64"], validate=True)
        signature = base64.b64decode(payload["signature_base64"], validate=True)
    except (TypeError, ValueError) as error:
        raise PublicKeyGenerationError(
            "running API signing-key proof encoding is invalid"
        ) from error
    if len(public_key) != 32 or len(signature) != 64:
        raise PublicKeyGenerationError("running API signing-key proof length is invalid")
    return public_key, signature


def build_public_key_evidence(
    public_bytes: bytes,
    signature: bytes,
    *,
    git_sha: str,
    checked_at: datetime,
) -> dict[str, object]:
    if not isinstance(public_bytes, bytes) or len(public_bytes) != 32:
        raise TypeError("runtime Ed25519 public key must contain 32 bytes")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise TypeError("runtime Ed25519 proof signature must contain 64 bytes")
    if not re.fullmatch(r"[0-9a-f]{40}", git_sha):
        raise ValueError("Git SHA must be lowercase 40-character hex")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(signature, PROOF_CHALLENGE)
    except (ValueError, InvalidSignature) as error:
        raise PublicKeyGenerationError("running API signing-key proof is invalid") from error
    return {
        "algorithm": "Ed25519",
        "checked_at": _timestamp(checked_at),
        "distribution": (
            "Distribute this public JSON separately from case archives and pin its SHA-256."
        ),
        "encoding": "raw-base64",
        "generator": GENERATOR,
        "git_sha": git_sha,
        "machine_generated": True,
        "private_seed_included": False,
        "proof_challenge_base64": base64.b64encode(PROOF_CHALLENGE).decode("ascii"),
        "proof_signature_base64": base64.b64encode(signature).decode("ascii"),
        "proof_signature_sha256": hashlib.sha256(signature).hexdigest(),
        "public_key_base64": base64.b64encode(public_bytes).decode("ascii"),
        "public_key_sha256": hashlib.sha256(public_bytes).hexdigest(),
        "runtime_service": "api",
        "schema_version": 1,
        "self_test": "PASS",
        "source": "public key and signed challenge read back from the running API service",
        "status": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "verification" / "export-public-key.json",
    )
    arguments = parser.parse_args()
    try:
        public_key, signature = runtime_public_key_proof()
        evidence = build_public_key_evidence(
            public_key,
            signature,
            git_sha=_git_sha(),
            checked_at=datetime.now(UTC),
        )
    except (OSError, ValueError, PublicKeyGenerationError, subprocess.SubprocessError) as error:
        evidence = {
            "checked_at": _timestamp(datetime.now(UTC)),
            "error": type(error).__name__,
            "generator": GENERATOR,
            "machine_generated": True,
            "private_seed_included": False,
            "schema_version": 1,
            "source": "running API export public-key proof was unavailable",
            "status": "FAIL",
        }
        atomic_json(arguments.output, evidence)
        return 1
    atomic_json(arguments.output, evidence)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
