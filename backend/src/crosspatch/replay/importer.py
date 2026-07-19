"""Verify one sealed archive and atomically build an immutable replay database."""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import hashlib
import io
import json
import os
import re
import secrets
import stat
import zipfile
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from crosspatch.api.models import PublishedCaseView, RoomIncidentView
from crosspatch.db.models import IncidentRecord, PublishedCaseRecord
from crosspatch.domain.hashing import canonical_json, sha256_hex
from crosspatch.export.verifier import VerificationLimits, verify_export
from crosspatch.runtime.database import RuntimeDatabase

_KEY_DOCUMENT_LIMIT = 64 * 1024
_SEALED_RUN_04_ARCHIVE_SHA256 = (
    "c753ed03efc20ad2647b810ebca2d971073b191c9c14747acfcc260ad41c4860"
)
_SEALED_COHORT_PUBLIC_KEY_SHA256 = (
    "949bed254068654a5d5c125079c4631055709fafcac92e097b02a08cd87f9875"
)


class ReplayImportRejected(ValueError):
    """The replay input cannot be proven authentic and publication-safe."""


@dataclass(frozen=True, slots=True)
class ReplayImportResult:
    incident_id: str
    manifest_sha256: str
    source_case_sha256: str
    event_count: int


def _regular_file_bytes(path: Path, maximum: int, *, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReplayImportRejected(f"{label} unavailable") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ReplayImportRejected(f"{label} must be a regular file")
    if metadata.st_size < 1 or metadata.st_size > maximum:
        raise ReplayImportRejected(f"{label} exceeds its size bound")
    try:
        with path.open("rb") as source:
            value = source.read(maximum + 1)
    except OSError as error:
        raise ReplayImportRejected(f"{label} unavailable") from error
    if len(value) != metadata.st_size or len(value) > maximum:
        raise ReplayImportRejected(f"{label} changed while being read")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ReplayImportRejected("JSON contains duplicate keys")
        output[key] = value
    return output


def _json_object(value: bytes, *, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReplayImportRejected(f"{label} is malformed") from error
    if not isinstance(parsed, dict):
        raise ReplayImportRejected(f"{label} must be an object")
    return parsed


def _pinned_public_key(path: Path) -> bytes:
    document = _json_object(
        _regular_file_bytes(path, _KEY_DOCUMENT_LIMIT, label="public-key document"),
        label="public-key document",
    )
    if (
        document.get("algorithm") != "Ed25519"
        or document.get("machine_generated") is not True
        or document.get("private_seed_included") is not False
        or document.get("status") != "PASS"
    ):
        raise ReplayImportRejected("public-key document is not an accepted machine proof")
    try:
        public_key = base64.b64decode(document["public_key_base64"], validate=True)
        challenge = base64.b64decode(document["proof_challenge_base64"], validate=True)
        signature = base64.b64decode(document["proof_signature_base64"], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error) as error:
        raise ReplayImportRejected("public-key document encoding is invalid") from error
    if (
        len(public_key) != 32
        or len(signature) != 64
        or hashlib.sha256(public_key).hexdigest() != document.get("public_key_sha256")
        or hashlib.sha256(signature).hexdigest() != document.get("proof_signature_sha256")
    ):
        raise ReplayImportRejected("public-key document hashes are invalid")
    if hashlib.sha256(public_key).hexdigest() != _SEALED_COHORT_PUBLIC_KEY_SHA256:
        raise ReplayImportRejected("public-key document is not the pinned cohort key")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, challenge)
    except (InvalidSignature, ValueError) as error:
        raise ReplayImportRejected("public-key proof signature is invalid") from error
    return public_key


def _signed_json_member(
    archive_bytes: bytes,
    manifest: dict[str, Any],
    *,
    kind: str,
    suffix: str,
) -> dict[str, Any]:
    entries = [
        entry
        for entry in manifest["files"]
        if entry["kind"] == kind and entry["path"].endswith(suffix)
    ]
    if len(entries) != 1:
        raise ReplayImportRejected(f"sealed replay archive has no unique {suffix}")
    entry = entries[0]
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as source:
            value = source.read(entry["path"])
    except (OSError, KeyError, RuntimeError, zipfile.BadZipFile) as error:
        raise ReplayImportRejected(f"sealed replay member {suffix} is unreadable") from error
    if len(value) != entry["size_bytes"] or hashlib.sha256(value).hexdigest() != entry["sha256"]:
        raise ReplayImportRejected(f"sealed replay member {suffix} changed after verification")
    return _json_object(value, label=f"sealed replay member {suffix}")


def _recorded_patch_paths(projection: dict[str, Any]) -> list[str]:
    artifacts = projection.get("artifacts")
    diff = artifacts.get("diff") if isinstance(artifacts, dict) else None
    text = diff.get("text") if isinstance(diff, dict) else None
    if not isinstance(text, str):
        raise ReplayImportRejected("legacy warrant has no recorded diff paths")
    paths: list[str] = []
    for left, right in re.findall(r"^diff --git a/([^\s]+) b/([^\s]+)$", text, re.MULTILINE):
        path = PurePosixPath(left)
        unsafe = path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts)
        if left != right or unsafe:
            raise ReplayImportRejected("recorded diff path is unsafe or ambiguous")
        if left not in paths:
            paths.append(left)
    if not paths:
        raise ReplayImportRejected("legacy warrant has no recorded diff paths")
    return paths


def _upgrade_legacy_warrant_projection(
    projection: dict[str, Any],
    manifest: dict[str, Any],
    archive_bytes: bytes,
) -> dict[str, Any]:
    """Derive the later public-anatomy DTO solely from fields in the signed archive."""
    warrants = projection.get("warrants")
    if not isinstance(warrants, list) or len(warrants) != 1:
        raise ReplayImportRejected("sealed replay requires one recorded warrant")
    warrant = warrants[0]
    if not isinstance(warrant, dict):
        raise ReplayImportRejected("recorded warrant is malformed")
    required_upgrade = {"nonce_sha256", "public_warrant_bytes", "public_warrant_sha256"}
    present = required_upgrade.intersection(warrant)
    if present == required_upgrade:
        return projection
    if present:
        raise ReplayImportRejected("legacy warrant anatomy is only partially present")

    broker_result = _signed_json_member(
        archive_bytes,
        manifest,
        kind="receipt",
        suffix="/receipts/broker-result.json",
    )
    warrant_id = warrant.get("warrant_id")
    nonce_sha256 = broker_result.get("nonce_sha256")
    if (
        broker_result.get("warrant_id") != warrant_id
        or broker_result.get("status") != "EXECUTED"
        or not isinstance(nonce_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", nonce_sha256) is None
    ):
        raise ReplayImportRejected("signed broker receipt disagrees with the recorded warrant")

    events = projection.get("events")
    if not isinstance(events, list):
        raise ReplayImportRejected("recorded approval events are malformed")
    approval_events = [
        event
        for event in events
        if isinstance(event, dict)
        and event.get("type") == "WARRANT_APPROVED"
        and isinstance(event.get("details"), dict)
        and event["details"].get("warrant_sha256") == warrant.get("canonical_sha256")
    ]
    if len(approval_events) != 1:
        raise ReplayImportRejected("legacy warrant has no unique recorded approval")
    approval = approval_events[0]
    approver_identity = approval["details"].get("approver_identity")
    if not isinstance(approver_identity, str) or approval.get("actor") != approver_identity:
        raise ReplayImportRejected("recorded approval identity is ambiguous")

    artifacts = projection.get("artifacts")
    tests = artifacts.get("tests") if isinstance(artifacts, dict) else None
    if not isinstance(tests, list):
        raise ReplayImportRejected("recorded warrant tests are malformed")
    plan_ids = [
        test.get("label")
        for test in tests
        if isinstance(test, dict)
        and test.get("warrant_id") == warrant_id
        and isinstance(test.get("label"), str)
    ]
    if not plan_ids or len(plan_ids) != len(set(plan_ids)):
        raise ReplayImportRejected("recorded warrant test intentions are ambiguous")
    binding_hashes = warrant.get("binding_hashes")
    if not isinstance(binding_hashes, dict):
        raise ReplayImportRejected("recorded warrant binding hashes are malformed")
    public_warrant = {
        "allowed_paths": _recorded_patch_paths(projection),
        "approver_identity": approver_identity,
        "authority_snapshot_sha256": binding_hashes.get("authority_snapshot_sha256"),
        "base_sha": binding_hashes.get("base_sha"),
        "canonical_warrant_sha256": warrant.get("canonical_sha256"),
        "environment_digest": binding_hashes.get("environment_digest"),
        "expires_at": warrant.get("expires_at"),
        "format": "crosspatch-public-warrant-anatomy-v1",
        "incident_id": manifest["incident"]["id"],
        "nonce_sha256": nonce_sha256,
        "patch_sha256": binding_hashes.get("patch_sha256"),
        "plan_ids": plan_ids,
        "repository_manifest_sha256": binding_hashes.get("repository_manifest_sha256"),
        "reviewed_evidence_manifest_sha256": binding_hashes.get(
            "reviewed_evidence_manifest_sha256"
        ),
        "reviewed_timeline_head": binding_hashes.get("reviewed_timeline_head"),
        "runner_digest": binding_hashes.get("runner_digest"),
        "test_plan_sha256": binding_hashes.get("test_plan_sha256"),
        "verdict_sha256": binding_hashes.get("verdict_sha256"),
        "warrant_id": warrant_id,
    }
    public_bytes = canonical_json(public_warrant).decode("utf-8")
    upgraded = deepcopy(projection)
    upgraded_warrant = upgraded["warrants"][0]
    upgraded_warrant["nonce_sha256"] = nonce_sha256
    upgraded_warrant["public_warrant_bytes"] = public_bytes
    upgraded_warrant["public_warrant_sha256"] = hashlib.sha256(
        public_bytes.encode("utf-8")
    ).hexdigest()
    return upgraded


def _verified_projection(
    archive: Path,
    key_document: Path,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    limits = VerificationLimits()
    archive_bytes = _regular_file_bytes(
        archive,
        limits.max_archive_bytes,
        label="sealed replay archive",
    )
    if hashlib.sha256(archive_bytes).hexdigest() != _SEALED_RUN_04_ARCHIVE_SHA256:
        raise ReplayImportRejected("sealed replay archive is not the pinned run-04 artifact")
    public_key = _pinned_public_key(key_document)
    verification = verify_export(archive_bytes, public_key, limits=limits)
    if not verification.valid or verification.manifest is None:
        code = verification.errors[0] if verification.errors else "ARCHIVE_INVALID"
        raise ReplayImportRejected(f"sealed replay archive rejected: {code}")
    manifest = verification.manifest
    incident = manifest["incident"]
    incident_id = incident["id"]
    timeline_entries = [
        entry
        for entry in manifest["files"]
        if entry["kind"] == "timeline"
        and entry["path"] == f"incidents/{incident_id}/case-file.json"
    ]
    if len(timeline_entries) != 1:
        raise ReplayImportRejected("sealed replay archive has no unique case projection")
    entry = timeline_entries[0]
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as source:
            case_bytes = source.read(entry["path"])
    except (OSError, KeyError, RuntimeError, zipfile.BadZipFile) as error:
        raise ReplayImportRejected("sealed replay case projection is unreadable") from error
    if (
        len(case_bytes) != entry["size_bytes"]
        or hashlib.sha256(case_bytes).hexdigest() != entry["sha256"]
    ):
        raise ReplayImportRejected("sealed replay case projection changed after verification")
    source_projection = _json_object(case_bytes, label="sealed replay case projection")
    if canonical_json(source_projection) != case_bytes:
        raise ReplayImportRejected("sealed replay case projection is not canonical")
    projection = _upgrade_legacy_warrant_projection(
        source_projection,
        manifest,
        archive_bytes,
    )
    projection_sha256 = sha256_hex(projection)
    try:
        PublishedCaseView.model_validate(
            {
                "incident_id": incident_id,
                "revision": 1,
                "manifest_sha256": projection_sha256,
                "projection": projection,
            }
        )
    except ValueError as error:
        raise ReplayImportRejected("sealed replay case projection is not publicable") from error
    return projection, manifest, entry["sha256"]


async def import_sealed_case(
    archive: Path | str,
    key_document: Path | str,
    database_path: Path | str,
) -> ReplayImportResult:
    """Build a read-only SQLite projection after all signature and schema checks pass."""
    archive_path = Path(archive)
    key_path = Path(key_document)
    output = Path(database_path)
    if output.exists() or output.is_symlink():
        raise ReplayImportRejected("replay database already exists")
    projection, manifest, source_case_sha256 = _verified_projection(archive_path, key_path)
    incident_id = manifest["incident"]["id"]
    incident = RoomIncidentView.model_validate(projection["incident"])
    projection_sha256 = sha256_hex(projection)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{secrets.token_hex(12)}.tmp")
    source_identity: tuple[int, int] | None = None
    link_succeeded = False
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{temporary}")
    try:
        await database.bootstrap()
        async with database.sessions() as session, session.begin():
            session.add(
                IncidentRecord(
                    id=incident.id,
                    title=incident.title,
                    scenario=incident.scenario,
                    live_trial=False,
                    owner_subject=None,
                    state=incident.state,
                    base_sha=incident.base_sha,
                    repository_manifest_sha256=None,
                    catalog_sha256=None,
                    pending_warrant_id=None,
                    next_event_sequence=1,
                    event_chain_head=None,
                    created_at=incident.created_at,
                    updated_at=incident.updated_at,
                )
            )
            session.add(
                PublishedCaseRecord(
                    incident_id=incident_id,
                    revision=1,
                    published=True,
                    projection=projection,
                    manifest_sha256=projection_sha256,
                    updated_at=incident.updated_at,
                )
            )
    except Exception:
        await database.close()
        temporary.unlink(missing_ok=True)
        raise
    await database.close()
    try:
        temporary.chmod(0o444)
        source = temporary.lstat()
        source_identity = (source.st_dev, source.st_ino)
        os.link(temporary, output)
        link_succeeded = True
        linked = output.lstat()
        if (linked.st_dev, linked.st_ino) != source_identity:
            raise ReplayImportRejected("replay database identity changed during publication")
        temporary.unlink()
        directory = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        temporary.unlink(missing_ok=True)
        if link_succeeded and source_identity is not None:
            try:
                current = output.lstat()
            except FileNotFoundError:
                current = None
            if current is not None and (current.st_dev, current.st_ino) == source_identity:
                output.unlink()
        raise
    events = projection.get("events")
    return ReplayImportResult(
        incident_id=incident_id,
        manifest_sha256=projection_sha256,
        source_case_sha256=source_case_sha256,
        event_count=len(events) if isinstance(events, list) else 0,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    arguments = parser.parse_args()
    result = asyncio.run(
        import_sealed_case(arguments.archive, arguments.public_key, arguments.database)
    )
    print(
        json.dumps(
            {
                "event_count": result.event_count,
                "incident_id": result.incident_id,
                "manifest_sha256": result.manifest_sha256,
                "source_case_sha256": result.source_case_sha256,
                "status": "VERIFIED",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
