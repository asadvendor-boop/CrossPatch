"""Server-authenticated, human-gated warrant approvals.

The MAC proves that CrossPatch received an approval for exact canonical bytes;
it is deliberately not described as a human digital signature.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from crosspatch.broker.warrant import (
    DuplicateKey,
    NonCanonicalWarrant,
    WarrantDocument,
    canonical_warrant_bytes,
    canonical_warrant_hash,
    validate_warrant_integrity,
)
from crosspatch.domain.hashing import canonical_json

_APPROVAL_DOMAIN = b"CROSSPATCH-APPROVAL-V1\x00"


class WarrantApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    warrant_id: str
    warrant_sha256: str
    approver_identity: str
    approved_at: datetime
    mac_key_id: str
    mac_sha256: str = Field(min_length=64, max_length=64)

    @field_validator("approved_at")
    @classmethod
    def _aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval timestamp must be timezone-aware")
        return value


def canonical_approval_bytes(approval: WarrantApproval) -> bytes:
    return canonical_json(approval)


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKey(f"duplicate approval JSON key: {key}")
        result[key] = value
    return result


def parse_approval_json(raw: bytes) -> WarrantApproval:
    try:
        value = json.loads(raw, object_pairs_hook=_strict_pairs)
        approval = WarrantApproval.model_validate(value)
    except DuplicateKey:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("invalid approval JSON") from error
    if raw != canonical_approval_bytes(approval):
        raise NonCanonicalWarrant("approval JSON does not match its canonical bytes")
    return approval


def _mac_input(document: WarrantDocument, approval: WarrantApproval) -> bytes:
    metadata = (
        f"{approval.warrant_sha256}\n"
        f"{approval.approver_identity}\n"
        f"{approval.approved_at.astimezone(UTC).isoformat(timespec='microseconds')}\n"
        f"{approval.mac_key_id}\n"
    ).encode()
    return _APPROVAL_DOMAIN + metadata + canonical_warrant_bytes(document)


class ApprovalService:
    """Issue and verify domain-separated HMAC approval envelopes."""

    def __init__(self, *, keys: Mapping[str, bytes]) -> None:
        self._keys = dict(keys)
        if not self._keys or any(len(key) < 32 for key in self._keys.values()):
            raise ValueError("approval MAC keys must contain at least 32 bytes")

    def approve(
        self,
        document: WarrantDocument,
        *,
        approved_at: datetime,
        approver_identity: str | None = None,
    ) -> WarrantApproval:
        validate_warrant_integrity(document)
        if approved_at.tzinfo is None or approved_at.utcoffset() is None:
            raise ValueError("approval timestamp must be timezone-aware")
        approved_at = approved_at.astimezone(UTC)
        if approved_at > document.expires_at.astimezone(UTC):
            raise ValueError("warrant is expired")
        if approved_at < document.issued_at.astimezone(UTC):
            raise ValueError("approval precedes warrant issuance")
        identity = approver_identity or document.approver_identity
        if not hmac.compare_digest(identity, document.approver_identity):
            raise ValueError("approver identity does not match the warrant")
        try:
            key = self._keys[document.approval_mac_key_id]
        except KeyError as error:
            raise ValueError("unknown approval MAC key") from error

        unsigned = WarrantApproval(
            warrant_id=document.warrant_id,
            warrant_sha256=canonical_warrant_hash(document),
            approver_identity=identity,
            approved_at=approved_at,
            mac_key_id=document.approval_mac_key_id,
            mac_sha256="0" * 64,
        )
        digest = hmac.new(key, _mac_input(document, unsigned), hashlib.sha256).hexdigest()
        return unsigned.model_copy(update={"mac_sha256": digest})

    def verify(self, document: WarrantDocument, approval: WarrantApproval) -> bool:
        try:
            validate_warrant_integrity(document)
            key = self._keys[approval.mac_key_id]
            expected_hash = canonical_warrant_hash(document)
            if not hmac.compare_digest(approval.warrant_id, document.warrant_id):
                return False
            if not hmac.compare_digest(approval.warrant_sha256, expected_hash):
                return False
            if not hmac.compare_digest(approval.approver_identity, document.approver_identity):
                return False
            if not hmac.compare_digest(approval.mac_key_id, document.approval_mac_key_id):
                return False
            unsigned = approval.model_copy(update={"mac_sha256": "0" * 64})
            expected_mac = hmac.new(key, _mac_input(document, unsigned), hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected_mac, approval.mac_sha256)
        except (KeyError, ValueError):
            return False
