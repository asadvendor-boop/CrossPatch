"""Strict, no-extract verifier for CrossPatch case archives."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import stat
import struct
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from crosspatch.export.builder import (
    ALLOWED_ARTIFACT_KINDS,
    FORMAT,
    MANIFEST_NAME,
    SIGNATURE_NAME,
    CaseBinding,
    canonical_json_bytes,
)

_INCIDENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_HEX_40_OR_64 = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_READ_CHUNK = 64 * 1024
_EOCD_SIGNATURE = b"PK\x05\x06"
_EOCD_STRUCT = struct.Struct("<4s4H2LH")
_MAX_EOCD_SEARCH = _EOCD_STRUCT.size + 65_535


class ArchiveRejected(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class VerificationLimits:
    max_members: int = 256
    max_archive_bytes: int = 64 * 1024 * 1024
    max_member_bytes: int = 8 * 1024 * 1024
    max_total_bytes: int = 32 * 1024 * 1024
    max_central_directory_bytes: int = 2 * 1024 * 1024
    max_compression_ratio: float = 100.0

    def __post_init__(self) -> None:
        if (
            self.max_members < 3
            or self.max_archive_bytes < 1
            or self.max_member_bytes < 1
            or self.max_total_bytes < 1
            or self.max_central_directory_bytes < 1
            or self.max_compression_ratio < 1
        ):
            raise ValueError("verification limits must be positive")


@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    errors: tuple[str, ...]
    manifest: dict[str, Any] | None = None


def verify_export(
    archive: bytes | bytearray | memoryview | Path | str,
    pinned_public_key: bytes | Ed25519PublicKey,
    *,
    limits: VerificationLimits | None = None,
) -> VerificationResult:
    """Verify without extracting, and return only stable failure codes."""
    effective_limits = limits or VerificationLimits()
    try:
        archive_bytes = _archive_bytes(archive, effective_limits)
        public_key = _public_key(pinned_public_key)
        manifest = _verify_archive(archive_bytes, public_key, effective_limits)
    except ArchiveRejected as error:
        return VerificationResult(valid=False, errors=(error.code,))
    except (OSError, ValueError, TypeError, zipfile.BadZipFile, RuntimeError):
        return VerificationResult(valid=False, errors=("ARCHIVE_INVALID",))
    return VerificationResult(valid=True, errors=(), manifest=manifest)


def _archive_bytes(
    archive: bytes | bytearray | memoryview | Path | str,
    limits: VerificationLimits,
) -> bytes:
    if isinstance(archive, (Path, str)):
        path = Path(archive)
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limits.max_archive_bytes:
            raise ArchiveRejected("ARCHIVE_SIZE")
        value = path.read_bytes()
    elif isinstance(archive, (bytes, bytearray, memoryview)):
        value = bytes(archive)
    else:
        raise TypeError("archive must be bytes or a filesystem path")
    if len(value) > limits.max_archive_bytes:
        raise ArchiveRejected("ARCHIVE_SIZE")
    return value


def _public_key(value: bytes | Ed25519PublicKey) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    if not isinstance(value, bytes) or len(value) != 32:
        raise ArchiveRejected("PUBLIC_KEY_INVALID")
    try:
        return Ed25519PublicKey.from_public_bytes(value)
    except ValueError as error:
        raise ArchiveRejected("PUBLIC_KEY_INVALID") from error


def _verify_archive(
    archive: bytes,
    public_key: Ed25519PublicKey,
    limits: VerificationLimits,
) -> dict[str, Any]:
    _validate_central_directory_bounds(archive, limits)
    with zipfile.ZipFile(io.BytesIO(archive), mode="r") as source:
        infos = source.infolist()
        if len(infos) < 2 or len(infos) > limits.max_members:
            raise ArchiveRejected("MEMBER_COUNT")
        by_name = _validate_directory(infos, limits)
        if MANIFEST_NAME not in by_name or SIGNATURE_NAME not in by_name:
            raise ArchiveRejected("MANIFEST_MISSING")

        manifest_bytes = _read_bounded(source, by_name[MANIFEST_NAME], limits.max_member_bytes)
        signature_text = _read_bounded(source, by_name[SIGNATURE_NAME], 256)
        manifest = _parse_manifest(manifest_bytes)
        try:
            signature = base64.b64decode(signature_text, validate=True)
        except ValueError as error:
            raise ArchiveRejected("SIGNATURE_INVALID") from error
        if len(signature) != 64:
            raise ArchiveRejected("SIGNATURE_INVALID")
        try:
            public_key.verify(signature, manifest_bytes)
        except InvalidSignature as error:
            raise ArchiveRejected("SIGNATURE_INVALID") from error

        entries = _validate_manifest(manifest)
        expected_names = {MANIFEST_NAME, SIGNATURE_NAME, *(entry["path"] for entry in entries)}
        if set(by_name) != expected_names:
            raise ArchiveRejected("UNMANIFESTED_MEMBER")

        for entry in entries:
            info = by_name[entry["path"]]
            if info.file_size != entry["size_bytes"]:
                raise ArchiveRejected("MEMBER_SIZE_MISMATCH")
            payload = _read_bounded(source, info, limits.max_member_bytes)
            if hashlib.sha256(payload).hexdigest() != entry["sha256"]:
                raise ArchiveRejected("MEMBER_HASH_MISMATCH")
        return manifest


def _validate_central_directory_bounds(
    archive: bytes,
    limits: VerificationLimits,
) -> None:
    search_start = max(0, len(archive) - _MAX_EOCD_SEARCH)
    eocd_offset = archive.rfind(_EOCD_SIGNATURE, search_start)
    if eocd_offset < 0 or eocd_offset + _EOCD_STRUCT.size > len(archive):
        raise ArchiveRejected("ARCHIVE_INVALID")
    (
        _signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = _EOCD_STRUCT.unpack_from(archive, eocd_offset)
    if eocd_offset + _EOCD_STRUCT.size + comment_size != len(archive):
        raise ArchiveRejected("ARCHIVE_INVALID")
    if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
        raise ArchiveRejected("MULTIDISK_ARCHIVE")
    if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise ArchiveRejected("ZIP64_UNSUPPORTED")
    if total_entries < 2 or total_entries > limits.max_members:
        raise ArchiveRejected("MEMBER_COUNT")
    if central_size > limits.max_central_directory_bytes:
        raise ArchiveRejected("CENTRAL_DIRECTORY_SIZE")
    if central_offset + central_size > eocd_offset:
        raise ArchiveRejected("ARCHIVE_INVALID")


def _validate_directory(
    infos: list[zipfile.ZipInfo], limits: VerificationLimits
) -> dict[str, zipfile.ZipInfo]:
    by_name: dict[str, zipfile.ZipInfo] = {}
    normalized_names: set[str] = set()
    total = 0
    for info in infos:
        name = _safe_member_name(info.filename)
        collision_key = unicodedata.normalize("NFC", name).casefold()
        if name in by_name or collision_key in normalized_names:
            raise ArchiveRejected("DUPLICATE_MEMBER")
        by_name[name] = info
        normalized_names.add(collision_key)
        if info.flag_bits & 0x1:
            raise ArchiveRejected("ENCRYPTED_MEMBER")
        mode = info.external_attr >> 16
        file_type = stat.S_IFMT(mode)
        if info.is_dir() or file_type == stat.S_IFLNK or file_type not in {0, stat.S_IFREG}:
            raise ArchiveRejected("UNSAFE_MEMBER_TYPE")
        if info.file_size < 0 or info.file_size > limits.max_member_bytes:
            raise ArchiveRejected("MEMBER_SIZE")
        total += info.file_size
        if total > limits.max_total_bytes:
            raise ArchiveRejected("TOTAL_SIZE")
        if info.file_size:
            if info.compress_size <= 0:
                raise ArchiveRejected("COMPRESSION_RATIO")
            if info.file_size / info.compress_size > limits.max_compression_ratio:
                raise ArchiveRejected("COMPRESSION_RATIO")
    return by_name


def _safe_member_name(value: str) -> str:
    if not value or len(value) > 2048 or "\\" in value or "\x00" in value:
        raise ArchiveRejected("UNSAFE_MEMBER_NAME")
    if unicodedata.normalize("NFC", value) != value:
        raise ArchiveRejected("UNSAFE_MEMBER_NAME")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise ArchiveRejected("UNSAFE_MEMBER_NAME")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ArchiveRejected("UNSAFE_MEMBER_NAME")
    if path.parts and ":" in path.parts[0]:
        raise ArchiveRejected("UNSAFE_MEMBER_NAME")
    return value


def _read_bounded(source: zipfile.ZipFile, info: zipfile.ZipInfo, maximum: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    try:
        with source.open(info, mode="r") as member:
            while chunk := member.read(min(_READ_CHUNK, maximum - size + 1)):
                size += len(chunk)
                if size > maximum or size > info.file_size:
                    raise ArchiveRejected("MEMBER_SIZE")
                chunks.append(chunk)
    except (EOFError, RuntimeError, zipfile.BadZipFile) as error:
        raise ArchiveRejected("MEMBER_READ") from error
    if size != info.file_size:
        raise ArchiveRejected("MEMBER_SIZE")
    return b"".join(chunks)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArchiveRejected("MANIFEST_DUPLICATE_KEY")
        result[key] = value
    return result


def _parse_manifest(value: bytes) -> dict[str, Any]:
    try:
        decoded = value.decode("ascii")
        parsed = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArchiveRejected("MANIFEST_INVALID") from error
    if not isinstance(parsed, dict):
        raise ArchiveRejected("MANIFEST_INVALID")
    if canonical_json_bytes(parsed) != value:
        raise ArchiveRejected("MANIFEST_NONCANONICAL")
    return parsed


def _validate_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if set(manifest) != {"files", "format", "incident"} or manifest.get("format") != FORMAT:
        raise ArchiveRejected("MANIFEST_SCHEMA")
    incident = manifest.get("incident")
    files = manifest.get("files")
    expected_incident_keys = {
        "base_sha",
        "id",
        "receipt_sha256",
        "timeline_head",
        "verdict_sha256",
        "warrant_sha256",
    }
    proof_keys = {
        "counts",
        "execution_status",
        "plan_id",
        "plan_sha256",
        "response_statuses",
        "scenario",
        "trusted_observation_sha256",
    }
    if not isinstance(incident, dict):
        raise ArchiveRejected("MANIFEST_SCHEMA")
    incident_keys = frozenset(incident)
    if incident_keys not in {
        frozenset(expected_incident_keys),
        frozenset(expected_incident_keys | proof_keys),
    }:
        raise ArchiveRejected("MANIFEST_SCHEMA")
    incident_id = incident.get("id")
    if not isinstance(incident_id, str) or not _INCIDENT_ID.fullmatch(incident_id):
        raise ArchiveRejected("INCIDENT_BINDING")
    if not isinstance(incident.get("base_sha"), str) or not _HEX_40_OR_64.fullmatch(
        incident["base_sha"]
    ):
        raise ArchiveRejected("INCIDENT_BINDING")
    for key in ("receipt_sha256", "timeline_head", "verdict_sha256", "warrant_sha256"):
        if not isinstance(incident.get(key), str) or not _SHA256.fullmatch(incident[key]):
            raise ArchiveRejected("INCIDENT_BINDING")
    if proof_keys <= set(incident):
        response_statuses = incident.get("response_statuses")
        counts = incident.get("counts")
        if (
            not isinstance(response_statuses, list)
            or not isinstance(counts, dict)
            or set(counts) != {"receipts", "jobs", "deliveries"}
        ):
            raise ArchiveRejected("INCIDENT_BINDING")
        try:
            CaseBinding(
                incident_id=incident_id,
                base_sha=incident["base_sha"],
                verdict_sha256=incident["verdict_sha256"],
                warrant_sha256=incident["warrant_sha256"],
                receipt_sha256=incident["receipt_sha256"],
                timeline_head=incident["timeline_head"],
                scenario=incident.get("scenario"),
                plan_id=incident.get("plan_id"),
                plan_sha256=incident.get("plan_sha256"),
                execution_status=incident.get("execution_status"),
                response_statuses=tuple(response_statuses),
                counts=(counts["receipts"], counts["jobs"], counts["deliveries"]),
                trusted_observation_sha256=incident.get(
                    "trusted_observation_sha256"
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ArchiveRejected("INCIDENT_BINDING") from error
    if not isinstance(files, list):
        raise ArchiveRejected("MANIFEST_SCHEMA")

    expected_file_keys = {
        "incident_id",
        "kind",
        "path",
        "provenance",
        "sha256",
        "size_bytes",
    }
    validated: list[dict[str, Any]] = []
    previous_path = ""
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != expected_file_keys:
            raise ArchiveRejected("MANIFEST_SCHEMA")
        path = entry.get("path")
        kind = entry.get("kind")
        if not isinstance(path, str) or _safe_member_name(path) != path:
            raise ArchiveRejected("MANIFEST_SCHEMA")
        if path <= previous_path:
            raise ArchiveRejected("MANIFEST_ORDER")
        previous_path = path
        if entry.get("incident_id") != incident_id or not path.startswith(
            f"incidents/{incident_id}/"
        ):
            raise ArchiveRejected("CROSS_INCIDENT_MEMBER")
        relative_parts = PurePosixPath(path).parts[2:]
        if kind not in ALLOWED_ARTIFACT_KINDS or any(
            part.casefold().startswith("raw") for part in relative_parts
        ):
            raise ArchiveRejected("PRIVATE_MEMBER")
        if not isinstance(entry.get("provenance"), str) or not entry["provenance"]:
            raise ArchiveRejected("MANIFEST_SCHEMA")
        if not isinstance(entry.get("sha256"), str) or not _SHA256.fullmatch(entry["sha256"]):
            raise ArchiveRejected("MANIFEST_SCHEMA")
        size = entry.get("size_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ArchiveRejected("MANIFEST_SCHEMA")
        validated.append(entry)
    return validated
