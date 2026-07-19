"""The single bounded analysis handoff used by CrossPatch."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from agents import Agent, RunContextWrapper, handoff
from agents.handoffs import Handoff, HandoffInputData

from crosspatch.agents.guardrails import SDKRunContext
from crosspatch.agents.schemas import (
    AgentRunInput,
    InspectorHandoffPayload,
    InspectorOutput,
    summarize_output,
)
from crosspatch.domain.enums import Seat
from crosspatch.orchestration.failures import SDKException

InspectorValidator = Callable[[InspectorOutput], Awaitable[InspectorOutput]]
INSPECTOR_PROSECUTOR_HANDOFF_TOOL = "transfer_inspector_finding_to_prosecutor"
PROSECUTOR_PHASE = "hypothesis-challenge"


@dataclass(slots=True, kw_only=True)
class InspectorProsecutorContext(SDKRunContext):
    request: AgentRunInput
    validate_inspector: InspectorValidator
    inspector_output: InspectorOutput | None = None


async def capture_validated_inspector_output(
    context: RunContextWrapper[Any],
    payload: InspectorHandoffPayload,
) -> None:
    """Validate the source finding before the target model receives it."""

    binding = context.context
    if not isinstance(binding, InspectorProsecutorContext):
        raise SDKException("Inspector handoff has an invalid run context")
    validated = await binding.validate_inspector(payload.to_output())
    if not isinstance(validated, InspectorOutput):
        raise SDKException("Inspector handoff validator changed the output type")
    binding.inspector_output = validated


def filtered_prosecutor_input(data: HandoffInputData) -> HandoffInputData:
    """Replace generated history with a fresh typed request and material summary."""

    run_context = data.run_context
    binding = run_context.context if run_context is not None else None
    if not isinstance(binding, InspectorProsecutorContext):
        raise SDKException("Inspector handoff filter has an invalid run context")
    if binding.inspector_output is None:
        raise SDKException("Inspector handoff was not validated before transfer")
    request = binding.request.model_copy(
        update={
            "phase": PROSECUTOR_PHASE,
            "prior_outputs": (
                *binding.request.prior_outputs,
                summarize_output(Seat.INSPECTOR, binding.inspector_output),
            ),
        }
    )
    return data.clone(
        input_history=request.model_dump_json(),
        pre_handoff_items=(),
        input_items=(),
    )


def inspector_to_prosecutor_handoff(target: Agent[Any]) -> Handoff[Any, Agent[Any]]:
    return handoff(
        target,
        tool_name_override=INSPECTOR_PROSECUTOR_HANDOFF_TOOL,
        tool_description_override=(
            "Transfer the material Inspector finding to Prosecutor for adversarial challenge."
        ),
        on_handoff=capture_validated_inspector_output,
        input_type=InspectorHandoffPayload,
        input_filter=filtered_prosecutor_input,
    )


__all__ = [
    "INSPECTOR_PROSECUTOR_HANDOFF_TOOL",
    "InspectorProsecutorContext",
    "InspectorValidator",
    "filtered_prosecutor_input",
    "inspector_to_prosecutor_handoff",
]
