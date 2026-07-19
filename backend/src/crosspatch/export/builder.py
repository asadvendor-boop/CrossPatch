"""Deterministic Ed25519-signed, sanitized-only case archive builder."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import stat
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FORMAT = "crosspatch-case-v1"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"
ALLOWED_ARTIFACT_KINDS = frozenset(
    {
        "agent_metadata",
        "receipt",
        "sanitized_evidence",
        "test",
        "timeline",
        "verdict",
        "warrant",
    }
)
_INCIDENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_HEX_40_OR_64 = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


@dataclass(frozen=True, slots=True)
class CaseBinding:
    incident_id: str
    base_sha: str
    verdict_sha256: str
    warrant_sha256: str
    receipt_sha256: str
    timeline_head: str
    scenario: str | None = None
    plan_id: str | None = None
    plan_sha256: str | None = None
    execution_status: str | None = None
    response_statuses: tuple[int, ...] | None = None
    counts: tuple[int, int, int] | None = None
    trusted_observation_sha256: str | None = None

    def __post_init__(self) -> None:
        if not _INCIDENT_ID.fullmatch(self.incident_id):
            raise ValueError("invalid incident identifier")
        if not _HEX_40_OR_64.fullmatch(self.base_sha):
            raise ValueError("base SHA must be lowercase 40- or 64-character hex")
        for name in (
            "verdict_sha256",
            "warrant_sha256",
            "receipt_sha256",
            "timeline_head",
        ):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"{name} must be a lowercase SHA-256")

        proof_fields = (
            self.scenario,
            self.plan_id,
            self.plan_sha256,
            self.execution_status,
            self.response_statuses,
            self.counts,
            self.trusted_observation_sha256,
        )
        if all(value is None for value in proof_fields):
            return
        if any(value is None for value in proof_fields):
            raise ValueError("typed scenario proof must be complete")
        if self.scenario != "webhook-payload-equivalence":
            raise ValueError("typed scenario proof has an unsupported scenario")
        if self.plan_id != "victim.payload-equivalence.candidate":
            raise ValueError("typed scenario proof has an unsupported plan")
        if not isinstance(self.plan_sha256, str) or not _SHA256.fullmatch(
            self.plan_sha256
        ):
            raise ValueError("plan_sha256 must be a lowercase SHA-256")
        if self.execution_status not in {"EXECUTED", "TEST_FAILED"}:
            raise ValueError("typed scenario proof has an invalid execution status")
        if (
            not isinstance(self.response_statuses, tuple)
            or not 1 <= len(self.response_statuses) <= 32
            or any(
                not isinstance(status, int)
                or isinstance(status, bool)
                or not 100 <= status <= 599
                for status in self.response_statuses
            )
        ):
            raise ValueError("typed scenario proof has invalid response statuses")
        if (
            not isinstance(self.counts, tuple)
            or len(self.counts) != 3
            or any(
                not isinstance(count, int) or isinstance(count, bool) or count < 0
                for count in self.counts
            )
        ):
            raise ValueError("typed scenario proof has invalid counts")
        if not isinstance(self.trusted_observation_sha256, str) or not _SHA256.fullmatch(
            self.trusted_observation_sha256
        ):
            raise ValueError("trusted_observation_sha256 must be a lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class ExportArtifact:
    path: str
    incident_id: str
    kind: str
    data: bytes
    provenance: str
    publicable: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("export artifact data must be immutable bytes")
        if not self.provenance or len(self.provenance) > 512:
            raise ValueError("export provenance is required and bounded")


class CaseExportBuilder:
    def __init__(self, signing_key: Ed25519PrivateKey) -> None:
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise TypeError("an Ed25519 private signing key is required")
        self._signing_key = signing_key

    def build(
        self,
        binding: CaseBinding,
        artifacts: tuple[ExportArtifact, ...],
    ) -> bytes:
        if not isinstance(binding, CaseBinding):
            raise TypeError("binding must be a CaseBinding")
        if not isinstance(artifacts, tuple):
            raise TypeError("artifacts must be an immutable tuple")

        entries: list[dict[str, object]] = []
        members: list[tuple[str, bytes]] = []
        seen: set[str] = set()
        for artifact in artifacts:
            member_path = _artifact_member(binding, artifact)
            if member_path in seen:
                raise ValueError("duplicate export artifact path")
            seen.add(member_path)
            entries.append(
                {
                    "incident_id": artifact.incident_id,
                    "kind": artifact.kind,
                    "path": member_path,
                    "provenance": artifact.provenance,
                    "sha256": hashlib.sha256(artifact.data).hexdigest(),
                    "size_bytes": len(artifact.data),
                }
            )
            members.append((member_path, artifact.data))

        entries.sort(key=lambda entry: str(entry["path"]))
        members.sort(key=lambda member: member[0])
        incident_manifest: dict[str, object] = {
            "base_sha": binding.base_sha,
            "id": binding.incident_id,
            "receipt_sha256": binding.receipt_sha256,
            "timeline_head": binding.timeline_head,
            "verdict_sha256": binding.verdict_sha256,
            "warrant_sha256": binding.warrant_sha256,
        }
        if binding.scenario is not None:
            assert binding.counts is not None
            assert binding.response_statuses is not None
            incident_manifest.update(
                {
                    "counts": {
                        "receipts": binding.counts[0],
                        "jobs": binding.counts[1],
                        "deliveries": binding.counts[2],
                    },
                    "execution_status": binding.execution_status,
                    "plan_id": binding.plan_id,
                    "plan_sha256": binding.plan_sha256,
                    "response_statuses": list(binding.response_statuses),
                    "scenario": binding.scenario,
                    "trusted_observation_sha256": (
                        binding.trusted_observation_sha256
                    ),
                }
            )
        manifest = {
            "files": entries,
            "format": FORMAT,
            "incident": incident_manifest,
        }
        manifest_bytes = canonical_json_bytes(manifest)
        signature = base64.b64encode(self._signing_key.sign(manifest_bytes))

        output = io.BytesIO()
        with zipfile.ZipFile(
            output,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            _write_member(archive, MANIFEST_NAME, manifest_bytes)
            _write_member(archive, SIGNATURE_NAME, signature)
            for path, data in members:
                _write_member(archive, path, data)
        return output.getvalue()


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _artifact_member(binding: CaseBinding, artifact: ExportArtifact) -> str:
    if not isinstance(artifact, ExportArtifact):
        raise TypeError("artifacts must contain ExportArtifact values")
    if artifact.incident_id != binding.incident_id:
        raise ValueError("cross-incident artifacts are forbidden")
    if not artifact.publicable:
        raise ValueError("unpublished artifacts cannot be exported")
    if artifact.kind not in ALLOWED_ARTIFACT_KINDS:
        raise ValueError("artifact kind is not publicable")
    relative = _safe_relative_path(artifact.path)
    if any(part.casefold().startswith("raw") for part in PurePosixPath(relative).parts):
        raise ValueError("raw artifacts cannot be exported")
    return f"incidents/{binding.incident_id}/{relative}"


def _safe_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError("artifact path must be a bounded relative path")
    if unicodedata.normalize("NFC", value) != value or "\\" in value or "\x00" in value:
        raise ValueError("artifact path is not canonical")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise ValueError("artifact path must be a canonical relative POSIX path")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("artifact path traversal is forbidden")
    if path.parts and ":" in path.parts[0]:
        raise ValueError("drive-qualified artifact paths are forbidden")
    return path.as_posix()


def _write_member(archive: zipfile.ZipFile, name: str, value: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    archive.writestr(info, value, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
