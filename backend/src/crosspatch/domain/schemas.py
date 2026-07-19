"""Strict structured-output schemas for all model-driven seats."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from crosspatch.domain.enums import MechanismCode, Seat, Verdict

_EVIDENCE_IDS_DESCRIPTION = (
    "One or more exact evidence_id values copied byte-for-byte from the typed "
    "UNTRUSTED_EVIDENCE entries supplied for this incident."
)


class StrictOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class InspectorOutput(StrictOutput):
    mechanism: MechanismCode
    evidence_ids: tuple[str, ...] = Field(
        min_length=1, description=_EVIDENCE_IDS_DESCRIPTION
    )
    falsifiers: tuple[str, ...]
    analysis: str = ""


class SupportedRival(StrictOutput):
    outcome: Literal["SUPPORTED_RIVAL"]
    rival_mechanism: MechanismCode
    counterexample_ids: tuple[str, ...] = Field(min_length=1)
    test_ids: tuple[str, ...] = Field(min_length=1)
    evidence_ids: tuple[str, ...] = Field(
        min_length=1, description=_EVIDENCE_IDS_DESCRIPTION
    )
    analysis: str = ""


class NoSupportedRival(StrictOutput):
    outcome: Literal["NO_SUPPORTED_RIVAL"]
    counterexample_ids: tuple[str, ...] = Field(min_length=1)
    test_ids: tuple[str, ...] = Field(min_length=1)
    evidence_ids: tuple[str, ...] = Field(
        min_length=1, description=_EVIDENCE_IDS_DESCRIPTION
    )
    analysis: str = ""


ProsecutorVariant = Annotated[
    SupportedRival | NoSupportedRival,
    Field(discriminator="outcome"),
]


class ProsecutorOutput(StrictOutput):
    """Object-shaped structured output with a discriminated rival finding."""

    root: ProsecutorVariant = Field(discriminator="outcome")


class TestIntention(StrictOutput):
    catalog_id: str = Field(min_length=1)
    purpose: str = Field(min_length=1)


class CounselOutput(StrictOutput):
    normalized_diff: str = Field(
        min_length=1,
        description=(
            "A complete canonical Git unified diff only: begin with `diff --git a/<path> "
            "b/<path>`, include matching `index`, `---`, `+++`, and text hunk lines, "
            "use LF line endings, and end with one LF. No Markdown fences or prose."
        ),
    )
    test_intentions: tuple[TestIntention, ...] = Field(min_length=1)
    evidence_ids: tuple[str, ...] = Field(
        min_length=1, description=_EVIDENCE_IDS_DESCRIPTION
    )
    analysis: str = ""


class RequiredChange(StrictOutput):
    code: str = Field(min_length=1)
    target: Seat | None = None
    action: str = ""


class MagistrateOutput(StrictOutput):
    verdict: Verdict
    finding_codes: tuple[str, ...]
    required_changes: tuple[RequiredChange, ...]
    remand_target: Seat | None = None
    evidence_ids: tuple[str, ...] = Field(
        min_length=1, description=_EVIDENCE_IDS_DESCRIPTION
    )
    analysis: str = ""


class BailiffOutput(StrictOutput):
    warrant_id: str = Field(min_length=1)
