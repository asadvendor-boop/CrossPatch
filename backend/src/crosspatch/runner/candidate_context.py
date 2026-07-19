"""Verification of runner-issued context for candidate-only test nodes."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from crosspatch.broker.paths import PathPolicyViolation, validate_patch_paths

CONTEXT_FORMAT = "crosspatch-candidate-context-v1"
_BASE_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CONTEXT_KEYS = frozenset(
    {
        "allowed_paths",
        "base_file_sha256",
        "base_sha",
        "candidate_file_sha256",
        "candidate_root",
        "format",
        "patch_sha256",
    }
)
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class CandidateContextViolation(ValueError):
    """Raised when a candidate test is not bound to a real patched worktree."""


@dataclass(frozen=True, slots=True)
class CandidateContext:
    candidate_root: Path
    base_sha: str
    patch_sha256: str
    allowed_paths: tuple[str, ...]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateContextViolation(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate_file_manifest(
    value: Any,
    *,
    allowed_paths: tuple[str, ...],
    field: str,
) -> dict[str, str | None]:
    if not isinstance(value, dict) or set(value) != set(allowed_paths):
        raise CandidateContextViolation(f"{field} must cover exactly the allowed paths")
    result: dict[str, str | None] = {}
    for path, digest in value.items():
        if digest is not None and (not isinstance(digest, str) or not _SHA256.fullmatch(digest)):
            raise CandidateContextViolation(f"{field} contains an invalid file digest")
        result[path] = digest
    return result


def _candidate_file_digest(root: Path, relative_path: str) -> str | None:
    candidate = root / relative_path
    if candidate.is_symlink():
        raise CandidateContextViolation("candidate file paths cannot be symlinks")
    if not candidate.exists():
        return None
    if not candidate.is_file():
        raise CandidateContextViolation("candidate paths must resolve to regular files")
    return hashlib.sha256(candidate.read_bytes()).hexdigest()


def load_and_verify_candidate_context(
    manifest_path: str | Path,
    *,
    expected_root: str | Path,
) -> CandidateContext:
    """Validate a runner-owned manifest against the worktree's actual patch bytes."""
    root = Path(expected_root).resolve(strict=True)
    manifest = Path(manifest_path).resolve(strict=True)
    try:
        manifest.relative_to(root)
    except ValueError:
        pass
    else:
        raise CandidateContextViolation("candidate context must be outside the candidate worktree")

    stat = manifest.stat()
    owner_is_trusted = stat.st_uid in {0, os.geteuid()} or not os.access(manifest, os.W_OK)
    if not owner_is_trusted or stat.st_mode & 0o022:
        raise CandidateContextViolation("candidate context ownership or permissions are unsafe")
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except CandidateContextViolation:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateContextViolation("candidate context is not strict UTF-8 JSON") from error
    if not isinstance(payload, dict) or frozenset(payload) != _CONTEXT_KEYS:
        raise CandidateContextViolation("candidate context fields do not match the v1 contract")
    if payload["format"] != CONTEXT_FORMAT:
        raise CandidateContextViolation("unsupported candidate context format")
    if not isinstance(payload["candidate_root"], str):
        raise CandidateContextViolation("candidate root must be a string")
    try:
        declared_root = Path(payload["candidate_root"]).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise CandidateContextViolation("declared candidate root is unavailable") from error
    if declared_root != root:
        raise CandidateContextViolation("candidate root does not match runner context")

    base_sha = payload["base_sha"]
    patch_sha256 = payload["patch_sha256"]
    raw_paths = payload["allowed_paths"]
    if not isinstance(base_sha, str) or not _BASE_SHA.fullmatch(base_sha):
        raise CandidateContextViolation("candidate base SHA is invalid")
    if not isinstance(patch_sha256, str) or not _SHA256.fullmatch(patch_sha256):
        raise CandidateContextViolation("candidate patch SHA-256 is invalid")
    if hmac.compare_digest(patch_sha256, _EMPTY_SHA256):
        raise CandidateContextViolation("candidate context cannot bind an empty patch")
    if not isinstance(raw_paths, list) or not all(isinstance(path, str) for path in raw_paths):
        raise CandidateContextViolation("candidate allowed paths must be a JSON string array")
    try:
        allowed_paths = validate_patch_paths(root, raw_paths)
    except PathPolicyViolation as error:
        raise CandidateContextViolation("candidate allowed path policy failed") from error
    if list(allowed_paths) != raw_paths:
        raise CandidateContextViolation("candidate allowed paths must be unique and canonical")

    base_files = _validate_file_manifest(
        payload["base_file_sha256"],
        allowed_paths=allowed_paths,
        field="base_file_sha256",
    )
    candidate_files = _validate_file_manifest(
        payload["candidate_file_sha256"],
        allowed_paths=allowed_paths,
        field="candidate_file_sha256",
    )
    if all(base_files[path] == candidate_files[path] for path in allowed_paths):
        raise CandidateContextViolation("candidate context does not describe changed file bytes")
    for path in allowed_paths:
        actual_digest = _candidate_file_digest(root, path)
        expected_digest = candidate_files[path]
        if actual_digest is None or expected_digest is None:
            matches = actual_digest is expected_digest
        else:
            matches = hmac.compare_digest(actual_digest, expected_digest)
        if not matches:
            raise CandidateContextViolation(
                f"candidate file bytes changed after publication: {path}"
            )
    return CandidateContext(
        candidate_root=root,
        base_sha=base_sha,
        patch_sha256=patch_sha256,
        allowed_paths=allowed_paths,
    )
