#!/usr/bin/env python3
"""Capture a signed, hash-only C2 provenance attestation from the running API."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import stat
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import asyncpg
from crosspatch.evidence.sanitizer import sanitize_evidence
from crosspatch.runtime.factories import _private_ed25519_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

GENERATOR = "scripts/capture_c2_runtime_provenance.py"
_EVENT_TYPES = ("INCIDENT_OPENED", "REPRODUCTION_STARTED", "EVIDENCE_CAPTURED")


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_object(value: object, *, label: str) -> dict[str, Any]:
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _one_event(
    events: Sequence[Mapping[str, Any]],
    event_type: str,
) -> Mapping[str, Any]:
    matches = [event for event in events if event.get("type") == event_type]
    if len(matches) != 1:
        raise ValueError(f"runtime provenance requires one {event_type} event")
    return matches[0]


def build_runtime_attestation(
    record: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    raw_bytes: bytes,
) -> dict[str, Any]:
    """Derive the attestation from one DB row, its event chain, and raw-store bytes."""
    incident_id = record.get("incident_id")
    evidence_id = record.get("id")
    provenance = record.get("provenance")
    identity = (incident_id, evidence_id, provenance)
    if not all(isinstance(value, str) and value for value in identity):
        raise ValueError("runtime evidence row is incomplete")
    if not isinstance(raw_bytes, bytes):
        raise TypeError("raw evidence must be immutable bytes")

    raw_sha256 = _sha256_bytes(raw_bytes)
    if raw_sha256 != record.get("raw_sha256"):
        raise ValueError("raw artifact hash does not match the control database")
    sanitized = sanitize_evidence(raw_bytes, provenance)
    if sanitized.raw_sha256 != raw_sha256:
        raise ValueError("sanitizer raw hash does not match the artifact")
    if sanitized.sanitized_sha256 != record.get("sanitized_sha256"):
        raise ValueError("sanitizer output does not match the control database")

    envelope = _json_object(record.get("envelope_json"), label="evidence envelope")
    if (
        envelope.get("evidence_id") != evidence_id
        or envelope.get("incident_id") != incident_id
        or envelope.get("raw_sha256") != raw_sha256
        or envelope.get("sanitized_sha256") != sanitized.sanitized_sha256
    ):
        raise ValueError("persisted evidence envelope does not bind the runtime artifact")

    raw_document = _json_object(raw_bytes, label="raw reproduction document")
    observed = raw_document.get("observed_log_entries")
    if not isinstance(observed, list) or len(observed) != 1 or not isinstance(observed[0], str):
        raise ValueError("runtime provenance requires one database-observed log entry")
    log_entry = observed[0].encode("utf-8")

    opened = _one_event(events, "INCIDENT_OPENED")
    started = _one_event(events, "REPRODUCTION_STARTED")
    captured = _one_event(events, "EVIDENCE_CAPTURED")
    expected_profile = {"evidence_profile": "instruction-like-log", "scenario": "webhook-race"}
    if _json_object(opened.get("payload"), label="opening event") != expected_profile:
        raise ValueError("incident opening does not bind the C2 evidence profile")
    if _json_object(started.get("payload"), label="reproduction event") != expected_profile:
        raise ValueError("reproduction start does not bind the C2 evidence profile")
    captured_payload = _json_object(captured.get("payload"), label="capture event")
    if captured_payload != {
        "evidence_id": evidence_id,
        "outcome": "FAILED",
        "sanitized_sha256": sanitized.sanitized_sha256,
    }:
        raise ValueError("evidence-captured event does not bind the runtime artifact")

    event_hashes = {
        event_type: _one_event(events, event_type).get("event_hash")
        for event_type in _EVENT_TYPES
    }
    if any(
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        for value in event_hashes.values()
    ):
        raise ValueError("runtime provenance event hash is malformed")

    return {
        "database_sanitized_sha256": sanitized.sanitized_sha256,
        "evidence_captured_event_hash": event_hashes["EVIDENCE_CAPTURED"],
        "evidence_id": evidence_id,
        "evidence_profile": "instruction-like-log",
        "incident_id": incident_id,
        "incident_opened_event_hash": event_hashes["INCIDENT_OPENED"],
        "log_entry_sha256": _sha256_bytes(log_entry),
        "log_entry_size_bytes": len(log_entry),
        "raw_artifact_sha256": raw_sha256,
        "raw_artifact_size_bytes": len(raw_bytes),
        "reproduction_started_event_hash": event_hashes["REPRODUCTION_STARTED"],
        "sanitizer_tags": sorted({tag.kind for tag in sanitized.tags}),
        "scenario": "webhook-race",
    }


def sign_runtime_attestation(
    attestation: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    captured_at: str,
) -> dict[str, Any]:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("runtime provenance requires an Ed25519 private key")
    generator_sha256 = _sha256_bytes(Path(__file__).read_bytes())
    signed_attestation = {
        **dict(attestation),
        "capture_generator_sha256": generator_sha256,
    }
    canonical = canonical_json_bytes(signed_attestation)
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "attestation": signed_attestation,
        "attestation_sha256": _sha256_bytes(canonical),
        "capture_method": (
            "repeatable-read, read-only control-database snapshot plus hash-verified "
            "content-addressed raw artifact; raw bytes were not exported"
        ),
        "captured_at": captured_at,
        "generator": GENERATOR,
        "generator_sha256": generator_sha256,
        "machine_generated": True,
        "production_public_key_sha256": _sha256_bytes(public_key),
        "schema_version": "crosspatch.c2-runtime-provenance.v2",
        "signature_base64": base64.b64encode(private_key.sign(canonical)).decode("ascii"),
    }


def _read_private_blob(root: Path, incident_id: str, digest: str) -> bytes:
    if root.is_absolute() is False:
        raise ValueError("raw artifact root must be absolute")
    if not incident_id or "/" in incident_id or incident_id in {".", ".."}:
        raise ValueError("incident identifier is unsafe")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("raw artifact digest is malformed")
    path = root / incident_id / digest[:2] / f"{digest}.blob"
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077:
            raise ValueError("raw artifact is not a private regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise ValueError("raw artifact changed during capture")
    finally:
        os.close(descriptor)
    value = b"".join(chunks)
    if _sha256_bytes(value) != digest:
        raise ValueError("raw artifact content hash drifted")
    return value


def _asyncpg_dsn(value: str) -> str:
    if value.startswith("postgresql+asyncpg://"):
        return value.replace("postgresql+asyncpg://", "postgresql://", 1)
    if value.startswith("postgresql://"):
        return value
    raise ValueError("CROSSPATCH_DATABASE_URL must use PostgreSQL")


async def capture_runtime(incident_id: str, evidence_id: str) -> dict[str, Any]:
    database_url = os.environ.get("CROSSPATCH_DATABASE_URL", "").strip()
    raw_root = Path(os.environ.get("CROSSPATCH_RAW_ARTIFACT_ROOT", ""))
    if not database_url or not str(raw_root):
        raise ValueError("runtime database and raw artifact root are required")

    connection = await asyncpg.connect(_asyncpg_dsn(database_url))
    try:
        async with connection.transaction(isolation="repeatable_read", readonly=True):
            record = await connection.fetchrow(
                """
                SELECT id, incident_id, provenance, raw_sha256,
                       sanitized_sha256, envelope_json
                  FROM evidence
                 WHERE incident_id = $1 AND id = $2
                """,
                incident_id,
                evidence_id,
            )
            events = await connection.fetch(
                """
                SELECT type, payload, event_hash
                  FROM timeline_events
                 WHERE incident_id = $1 AND type = ANY($2::text[])
                 ORDER BY sequence
                """,
                incident_id,
                list(_EVENT_TYPES),
            )
    finally:
        await connection.close()
    if record is None:
        raise ValueError("runtime evidence row is missing")
    record_dict = dict(record)
    raw = _read_private_blob(raw_root, incident_id, str(record_dict["raw_sha256"]))
    return build_runtime_attestation(record_dict, [dict(event) for event in events], raw)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incident-id", required=True)
    parser.add_argument("--evidence-id", required=True)
    arguments = parser.parse_args()
    try:
        attestation = asyncio.run(
            capture_runtime(arguments.incident_id, arguments.evidence_id)
        )
        payload = sign_runtime_attestation(
            attestation,
            _private_ed25519_key(),
            captured_at=_utc_now(),
        )
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, asyncpg.PostgresError) as error:
        print(f"C2 runtime provenance capture failed: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
