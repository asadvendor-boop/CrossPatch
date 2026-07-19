"""Typed model-safe evidence envelopes shared by API, MCP, and agent surfaces."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from crosspatch.evidence.sanitizer import SanitizationTag, SanitizedEvidence, TagKind


class EvidenceKind(StrEnum):
    LOG = "log"
    TRACE = "trace"
    ISSUE = "issue"
    SOURCE = "source"
    COMMENT = "comment"
    DIFF = "diff"
    TEST_OUTPUT = "test_output"
    TIMELINE = "timeline"
    MCP_RESULT = "mcp_result"


class UntrustedEvidenceEnvelope(BaseModel):
    """The only evidence shape allowed across a model-facing boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    classification: Literal["UNTRUSTED_EVIDENCE"] = "UNTRUSTED_EVIDENCE"
    evidence_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    incident_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    kind: EvidenceKind
    provenance: str = Field(min_length=1, max_length=512)
    provenance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provenance_tags: tuple[TagKind, ...]
    text: str
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sanitized_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_size_bytes: int = Field(ge=0)
    sanitized_size_bytes: int = Field(ge=0)
    truncated: bool
    tags: tuple[SanitizationTag, ...]

    @classmethod
    def from_sanitized(
        cls,
        *,
        evidence_id: str | None = None,
        incident_id: str,
        kind: EvidenceKind,
        evidence: SanitizedEvidence,
    ) -> UntrustedEvidenceEnvelope:
        return cls(
            evidence_id=evidence_id or f"ev_{evidence.sanitized_sha256[:32]}",
            incident_id=incident_id,
            kind=kind,
            provenance=evidence.provenance,
            provenance_sha256=evidence.provenance_sha256,
            provenance_tags=evidence.provenance_tags,
            text=evidence.text,
            raw_sha256=evidence.raw_sha256,
            sanitized_sha256=evidence.sanitized_sha256,
            raw_size_bytes=evidence.raw_size_bytes,
            sanitized_size_bytes=evidence.sanitized_size_bytes,
            truncated=evidence.truncated,
            tags=evidence.tags,
        )
