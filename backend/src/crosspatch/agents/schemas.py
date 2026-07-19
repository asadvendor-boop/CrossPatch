"""Strict SDK input/output contracts and untrusted prior-output summaries."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from crosspatch.domain.enums import MechanismCode, ScenarioId, Seat
from crosspatch.domain.hashing import semantic_fingerprint, semantic_payload
from crosspatch.domain.schemas import (
    BailiffOutput,
    CounselOutput,
    InspectorOutput,
    MagistrateOutput,
    NoSupportedRival,
    ProsecutorOutput,
    SupportedRival,
    TestIntention,
)
from crosspatch.evidence.views import UntrustedEvidenceEnvelope

SeatOutput = InspectorOutput | ProsecutorOutput | CounselOutput | MagistrateOutput | BailiffOutput


class UntrustedAgentSummary(BaseModel):
    """Material structured fields only; prose never propagates between seats."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    classification: Literal["UNTRUSTED_EVIDENCE"] = "UNTRUSTED_EVIDENCE"
    kind: Literal["agent_output"] = "agent_output"
    source_classification: Literal["UNTRUSTED_AGENT_OUTPUT"] = "UNTRUSTED_AGENT_OUTPUT"
    seat: Seat
    semantic_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    material: dict[str, Any]


class AgentRunInput(BaseModel):
    """The complete model-visible dynamic input for an analysis seat."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol: Literal["crosspatch.agent-input.v1"] = "crosspatch.agent-input.v1"
    incident_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    scenario: ScenarioId
    candidate_plan_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    phase: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    evidence: tuple[UntrustedEvidenceEnvelope, ...] = ()
    citable_evidence_ids: tuple[str, ...] = Field(
        default=(),
        description=(
            "The only allowed evidence_ids for this run. Copy values from this list "
            "byte-for-byte; never invent, transform, or omit them."
        ),
    )
    prior_outputs: tuple[UntrustedAgentSummary, ...] = ()


class InspectorHandoffPayload(BaseModel):
    """Material Inspector finding transferred to Prosecutor without prose."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mechanism: MechanismCode
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    falsifiers: tuple[str, ...]

    def to_output(self) -> InspectorOutput:
        return InspectorOutput(
            mechanism=self.mechanism,
            evidence_ids=self.evidence_ids,
            falsifiers=self.falsifiers,
        )


class InspectorProsecutorResult(BaseModel):
    """Validated outputs from the single bounded SDK handoff."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    inspector: InspectorOutput
    prosecutor: ProsecutorOutput


class BailiffRunInput(BaseModel):
    """The Bailiff receives only an approved warrant identifier."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol: Literal["crosspatch.bailiff-input.v1"] = "crosspatch.bailiff-input.v1"
    warrant_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def summarize_output(seat: Seat, output: SeatOutput) -> UntrustedAgentSummary:
    return UntrustedAgentSummary(
        seat=seat,
        semantic_sha256=semantic_fingerprint(seat, output),
        material=semantic_payload(seat, output),
    )


__all__ = [
    "AgentRunInput",
    "BailiffOutput",
    "BailiffRunInput",
    "CounselOutput",
    "InspectorOutput",
    "InspectorHandoffPayload",
    "InspectorProsecutorResult",
    "MagistrateOutput",
    "NoSupportedRival",
    "ProsecutorOutput",
    "SeatOutput",
    "SupportedRival",
    "TestIntention",
    "UntrustedAgentSummary",
    "summarize_output",
]
