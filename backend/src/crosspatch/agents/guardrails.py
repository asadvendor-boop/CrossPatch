"""Deterministic Agents SDK guardrails used only as defense in depth."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agents import (
    Agent,
    GuardrailFunctionOutput,
    RunContextWrapper,
    input_guardrail,
    output_guardrail,
)
from pydantic import ValidationError

from crosspatch.agents.schemas import (
    AgentRunInput,
    BailiffOutput,
    BailiffRunInput,
    CounselOutput,
    InspectorOutput,
    MagistrateOutput,
    ProsecutorOutput,
    SeatOutput,
)
from crosspatch.domain.enums import Seat, Verdict


@dataclass(slots=True, kw_only=True)
class SDKRunContext:
    """Application-owned bindings available to SDK guardrails for one run."""

    incident_id: str
    input_seat: Seat
    output_seat: Seat
    input_phase: str
    warrant_id: str | None = None


_OUTPUT_TYPES: dict[Seat, type[SeatOutput]] = {
    Seat.INSPECTOR: InspectorOutput,
    Seat.PROSECUTOR: ProsecutorOutput,
    Seat.COUNSEL: CounselOutput,
    Seat.MAGISTRATE: MagistrateOutput,
    Seat.BAILIFF: BailiffOutput,
}


def _guardrail_result(code: str, *, rejected: bool) -> GuardrailFunctionOutput:
    return GuardrailFunctionOutput(
        output_info={"code": code},
        tripwire_triggered=rejected,
    )


def _json_inputs(model_input: str | list[Any]) -> tuple[str, ...] | None:
    if isinstance(model_input, str):
        return (model_input,)
    if not model_input or not isinstance(model_input[-1], dict):
        return None
    if model_input[-1].get("role") != "user":
        return None
    serialized: list[str] = []
    for item in model_input:
        if not isinstance(item, dict) or item.get("role") != "user":
            continue
        content = item.get("content")
        if not isinstance(content, str):
            return None
        serialized.append(content)
    return tuple(serialized) or None


@input_guardrail(name="crosspatch_typed_model_input", run_in_parallel=False)
def typed_model_input_guardrail(
    context: RunContextWrapper[SDKRunContext],
    agent: Agent[Any],
    model_input: str | list[Any],
) -> GuardrailFunctionOutput:
    """Reject an unbound input before any model or tool can run."""

    binding = context.context
    if not isinstance(binding, SDKRunContext):
        return _guardrail_result("INVALID_RUN_CONTEXT", rejected=True)
    if agent.name != binding.input_seat.value:
        return _guardrail_result("INPUT_SEAT_MISMATCH", rejected=True)
    serialized_inputs = _json_inputs(model_input)
    if serialized_inputs is None:
        return _guardrail_result("INVALID_TYPED_INPUT", rejected=True)

    if binding.input_seat is Seat.BAILIFF:
        try:
            parsed_bailiff_inputs = tuple(
                BailiffRunInput.model_validate_json(item) for item in serialized_inputs
            )
        except ValidationError:
            return _guardrail_result("INVALID_TYPED_INPUT", rejected=True)
        parsed_bailiff = parsed_bailiff_inputs[-1]
        if binding.warrant_id is None or parsed_bailiff.warrant_id != binding.warrant_id:
            return _guardrail_result("WARRANT_INPUT_MISMATCH", rejected=True)
        return _guardrail_result("TYPED_INPUT_ACCEPTED", rejected=False)

    try:
        parsed_inputs = tuple(AgentRunInput.model_validate_json(item) for item in serialized_inputs)
    except ValidationError:
        return _guardrail_result("INVALID_TYPED_INPUT", rejected=True)
    if any(parsed.incident_id != binding.incident_id for parsed in parsed_inputs):
        return _guardrail_result("INCIDENT_INPUT_MISMATCH", rejected=True)
    if any(
        evidence.incident_id != binding.incident_id
        for parsed in parsed_inputs
        for evidence in parsed.evidence
    ):
        return _guardrail_result("CROSS_INCIDENT_EVIDENCE", rejected=True)
    parsed = parsed_inputs[-1]
    if parsed.phase != binding.input_phase:
        return _guardrail_result("INPUT_PHASE_MISMATCH", rejected=True)
    return _guardrail_result("TYPED_INPUT_ACCEPTED", rejected=False)


def _evidence_ids(output: SeatOutput) -> tuple[str, ...]:
    if isinstance(output, ProsecutorOutput):
        return output.root.evidence_ids
    return tuple(getattr(output, "evidence_ids", ()))


@output_guardrail(name="crosspatch_typed_model_output")
def typed_model_output_guardrail(
    context: RunContextWrapper[SDKRunContext],
    agent: Agent[Any],
    output: Any,
) -> GuardrailFunctionOutput:
    """Reject structurally inconsistent final output; never grant authority."""

    binding = context.context
    if not isinstance(binding, SDKRunContext):
        return _guardrail_result("INVALID_RUN_CONTEXT", rejected=True)
    if agent.name != binding.output_seat.value:
        return _guardrail_result("OUTPUT_SEAT_MISMATCH", rejected=True)
    expected_type = _OUTPUT_TYPES[binding.output_seat]
    if not isinstance(output, expected_type):
        return _guardrail_result("INVALID_OUTPUT_TYPE", rejected=True)

    if isinstance(output, BailiffOutput):
        if binding.warrant_id is None or output.warrant_id != binding.warrant_id:
            return _guardrail_result("WARRANT_OUTPUT_MISMATCH", rejected=True)
        return _guardrail_result("TYPED_OUTPUT_ACCEPTED", rejected=False)

    if not _evidence_ids(output):
        return _guardrail_result("MISSING_EVIDENCE_REFERENCES", rejected=True)

    if isinstance(output, MagistrateOutput):
        valid_remand_targets = {Seat.INSPECTOR, Seat.PROSECUTOR, Seat.COUNSEL}
        if output.verdict is Verdict.REMAND:
            if output.remand_target not in valid_remand_targets:
                return _guardrail_result("INVALID_REMAND_TARGET", rejected=True)
        elif output.remand_target is not None:
            return _guardrail_result("INCONSISTENT_VERDICT_SHAPE", rejected=True)

    return _guardrail_result("TYPED_OUTPUT_ACCEPTED", rejected=False)


__all__ = [
    "SDKRunContext",
    "typed_model_input_guardrail",
    "typed_model_output_guardrail",
]
