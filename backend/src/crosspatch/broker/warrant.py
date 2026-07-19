"""Canonical, versioned mutation-warrant documents.

The warrant is the complete deterministic input to the mutation broker.  The
human approval MAC covers these exact bytes; fields must never be reconstructed
from a model response at execution time.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from crosspatch.domain.hashing import canonical_json, sha256_hex
from crosspatch.runner.catalog import ExecutionPlan, OracleProfile

WARRANT_FORMAT = "crosspatch-warrant-v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class WarrantError(ValueError):
    """Base class for warrant-format failures."""


class DuplicateKey(WarrantError):
    """Raised when JSON contains an ambiguous repeated object key."""


class NonCanonicalWarrant(WarrantError):
    """Raised when serialized bytes are not the one canonical representation."""


class WarrantIntegrityError(WarrantError):
    """Raised when a derived binding disagrees with its source bytes."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BoundExecutionPlan(_FrozenModel):
    """Resolved immutable catalog entry captured at approval time."""

    plan_id: str = Field(min_length=1, max_length=128)
    argv: tuple[str, ...] = Field(min_length=1)
    working_directory: str = Field(min_length=1)
    timeout_seconds: int = Field(gt=0, le=900)
    expected_counts: tuple[int, int, int] | None = None
    expected_statuses: tuple[int, ...] | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    oracle_profile: OracleProfile | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    plan_sha256: str

    @field_validator("plan_sha256")
    @classmethod
    def _validate_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("plan_sha256 must be a lowercase SHA-256 digest")
        return value

    @classmethod
    def from_execution_plan(cls, plan: ExecutionPlan) -> Self:
        return cls(
            plan_id=plan.plan_id,
            argv=plan.argv,
            working_directory=plan.working_directory,
            timeout_seconds=plan.timeout_seconds,
            expected_counts=plan.expected_counts,
            expected_statuses=plan.expected_statuses,
            oracle_profile=plan.oracle_profile,
            plan_sha256=plan.sha256,
        )

    def as_execution_plan(self) -> ExecutionPlan:
        return ExecutionPlan(
            plan_id=self.plan_id,
            argv=self.argv,
            working_directory=self.working_directory,
            timeout_seconds=self.timeout_seconds,
            expected_counts=self.expected_counts,
            expected_statuses=self.expected_statuses,
            oracle_profile=self.oracle_profile,
        )

    def validate_binding(self) -> None:
        if self.as_execution_plan().sha256 != self.plan_sha256:
            raise WarrantIntegrityError(f"execution plan binding changed: {self.plan_id}")


class WarrantDocument(_FrozenModel):
    """All authority and execution material reviewed by the human approver."""

    format: str
    warrant_id: str
    incident_id: str
    repository_id: str
    verdict_id: str
    verdict_sha256: str
    candidate_id: str
    authority_snapshot_sha256: str
    reviewed_evidence_manifest_sha256: str
    reviewed_timeline_head: str
    base_sha: str
    repository_manifest_sha256: str
    patch_b64: str
    patch_sha256: str
    allowed_paths: tuple[str, ...] = Field(min_length=1)
    execution_plans: tuple[BoundExecutionPlan, ...] = Field(min_length=1)
    test_plan_sha256: str
    runner_digest: str
    environment_digest: str
    approver_identity: str = Field(min_length=1, max_length=256)
    issued_at: datetime
    expires_at: datetime
    approval_mac_key_id: str
    nonce: str

    @field_validator(
        "warrant_id",
        "incident_id",
        "repository_id",
        "verdict_id",
        "candidate_id",
        "approval_mac_key_id",
        "nonce",
    )
    @classmethod
    def _validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("identifier contains unsupported characters")
        return value

    @field_validator(
        "verdict_sha256",
        "authority_snapshot_sha256",
        "reviewed_evidence_manifest_sha256",
        "reviewed_timeline_head",
        "repository_manifest_sha256",
        "patch_sha256",
        "test_plan_sha256",
        "runner_digest",
        "environment_digest",
    )
    @classmethod
    def _validate_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("digest must be a lowercase SHA-256 value")
        return value

    @field_validator("base_sha")
    @classmethod
    def _validate_base_sha(cls, value: str) -> str:
        if not _GIT_SHA.fullmatch(value):
            raise ValueError("base_sha must be a lowercase Git object id")
        return value

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _validate_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("warrant timestamps must be timezone-aware")
        return value

    @field_validator("allowed_paths")
    @classmethod
    def _validate_declared_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("allowed_paths must not contain duplicates")
        if tuple(sorted(value)) != value:
            raise ValueError("allowed_paths must be sorted")
        return value

    @model_validator(mode="after")
    def _validate_document(self) -> Self:
        if self.format != WARRANT_FORMAT:
            raise ValueError(f"format must be {WARRANT_FORMAT}")
        if self.expires_at <= self.issued_at:
            raise ValueError("warrant expiry must follow issuance")
        plan_ids = tuple(plan.plan_id for plan in self.execution_plans)
        if len(plan_ids) != len(set(plan_ids)):
            raise ValueError("execution plan identifiers must be unique")
        return self

    @property
    def patch_bytes(self) -> bytes:
        try:
            decoded = base64.b64decode(self.patch_b64, validate=True)
        except (ValueError, binascii.Error) as error:
            raise WarrantIntegrityError("patch bytes are not strict base64") from error
        if base64.b64encode(decoded).decode("ascii") != self.patch_b64:
            raise WarrantIntegrityError("patch bytes are not canonically encoded")
        return decoded


def canonical_warrant_bytes(document: WarrantDocument) -> bytes:
    """Return the unique bytes displayed for, and bound by, approval."""
    return canonical_json(document)


def canonical_warrant_hash(document: WarrantDocument) -> str:
    return hashlib.sha256(canonical_warrant_bytes(document)).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_warrant_json(raw: bytes) -> WarrantDocument:
    """Parse only bytes already in CrossPatch's canonical JSON form."""
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except DuplicateKey:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WarrantError("invalid warrant JSON") from error
    try:
        document = WarrantDocument.model_validate(value)
    except ValueError as error:
        raise WarrantError("invalid warrant document") from error
    if raw != canonical_warrant_bytes(document):
        raise NonCanonicalWarrant("warrant JSON does not match its canonical bytes")
    return document


def validate_warrant_integrity(document: WarrantDocument) -> None:
    """Recompute every binding derivable without repository authority state."""
    patch = document.patch_bytes
    if not patch:
        raise WarrantIntegrityError("patch bytes must not be empty")
    if hashlib.sha256(patch).hexdigest() != document.patch_sha256:
        raise WarrantIntegrityError("patch bytes do not match patch_sha256")

    for plan in document.execution_plans:
        plan.validate_binding()
    if sha256_hex(document.execution_plans) != document.test_plan_sha256:
        raise WarrantIntegrityError("test plan does not match test_plan_sha256")
