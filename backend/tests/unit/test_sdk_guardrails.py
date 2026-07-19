from __future__ import annotations

import pytest
from agents import Agent, RunContextWrapper
from crosspatch.agents.guardrails import (
    SDKRunContext,
    typed_model_input_guardrail,
    typed_model_output_guardrail,
)
from crosspatch.agents.schemas import (
    AgentRunInput,
    BailiffOutput,
    BailiffRunInput,
    NoSupportedRival,
    ProsecutorOutput,
)
from crosspatch.domain.enums import Seat
from crosspatch.evidence.sanitizer import sanitize_evidence
from crosspatch.evidence.views import EvidenceKind, UntrustedEvidenceEnvelope
from pydantic import ValidationError


def context(
    *,
    input_seat: Seat = Seat.INSPECTOR,
    output_seat: Seat | None = None,
    warrant_id: str | None = None,
) -> SDKRunContext:
    return SDKRunContext(
        incident_id="inc-1",
        input_seat=input_seat,
        output_seat=output_seat or input_seat,
        input_phase="mechanism-analysis",
        warrant_id=warrant_id,
    )


def envelope(incident_id: str) -> UntrustedEvidenceEnvelope:
    return UntrustedEvidenceEnvelope.from_sanitized(
        incident_id=incident_id,
        kind=EvidenceKind.LOG,
        evidence=sanitize_evidence(b"duplicate delivery", "victim log"),
    )


@pytest.mark.asyncio
async def test_input_guardrail_blocks_before_model_and_accepts_exact_typed_envelope() -> None:
    assert typed_model_input_guardrail.run_in_parallel is False
    agent = Agent(name=Seat.INSPECTOR.value)
    run_context = RunContextWrapper(context())
    request = AgentRunInput(
        incident_id="inc-1",
        scenario="webhook-race",
        candidate_plan_id="victim.duplicate-race.candidate",
        phase="mechanism-analysis",
        evidence=(envelope("inc-1"),),
    )

    result = await typed_model_input_guardrail.run(
        agent,
        request.model_dump_json(),
        run_context,
    )

    assert result.output.tripwire_triggered is False
    assert result.output.output_info == {"code": "TYPED_INPUT_ACCEPTED"}


@pytest.mark.asyncio
async def test_input_guardrail_accepts_typed_current_request_after_typed_session_history() -> None:
    agent = Agent(name=Seat.INSPECTOR.value)
    run_context = RunContextWrapper(context())
    previous = AgentRunInput(
        incident_id="inc-1",
        scenario="webhook-race",
        candidate_plan_id="victim.duplicate-race.candidate",
        phase="earlier-analysis",
        evidence=(envelope("inc-1"),),
    )
    current = AgentRunInput(
        incident_id="inc-1",
        scenario="webhook-race",
        candidate_plan_id="victim.duplicate-race.candidate",
        phase="mechanism-analysis",
        evidence=(envelope("inc-1"),),
    )

    result = await typed_model_input_guardrail.run(
        agent,
        [
            {"role": "user", "content": previous.model_dump_json()},
            {"role": "assistant", "content": "persisted model output"},
            {"role": "user", "content": current.model_dump_json()},
        ],
        run_context,
    )

    assert result.output.tripwire_triggered is False
    assert result.output.output_info == {"code": "TYPED_INPUT_ACCEPTED"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("agent", "model_input", "run_context", "code"),
    (
        (
            Agent(name=Seat.PROSECUTOR.value),
            AgentRunInput(
                incident_id="inc-1",
                scenario="webhook-race",
                candidate_plan_id="victim.duplicate-race.candidate",
                phase="mechanism-analysis",
            ).model_dump_json(),
            RunContextWrapper(context()),
            "INPUT_SEAT_MISMATCH",
        ),
        (
            Agent(name=Seat.INSPECTOR.value),
            AgentRunInput(
                incident_id="inc-1",
                scenario="webhook-race",
                candidate_plan_id="victim.duplicate-race.candidate",
                phase="mechanism-analysis",
                evidence=(envelope("inc-2"),),
            ).model_dump_json(),
            RunContextWrapper(context()),
            "CROSS_INCIDENT_EVIDENCE",
        ),
        (
            Agent(name=Seat.INSPECTOR.value),
            '{"incident_id":"inc-1","phase":"mechanism-analysis","raw":"secret"}',
            RunContextWrapper(context()),
            "INVALID_TYPED_INPUT",
        ),
        (
            Agent(name=Seat.BAILIFF.value),
            BailiffRunInput(warrant_id="warrant-2").model_dump_json(),
            RunContextWrapper(
                context(
                    input_seat=Seat.BAILIFF,
                    output_seat=Seat.BAILIFF,
                    warrant_id="warrant-1",
                )
            ),
            "WARRANT_INPUT_MISMATCH",
        ),
    ),
)
async def test_input_guardrail_rejects_unbound_or_untyped_input(
    agent: Agent,
    model_input: str,
    run_context: RunContextWrapper[SDKRunContext],
    code: str,
) -> None:
    result = await typed_model_input_guardrail.run(agent, model_input, run_context)

    assert result.output.tripwire_triggered is True
    assert result.output.output_info == {"code": code}


@pytest.mark.asyncio
async def test_output_guardrail_is_seat_bound_and_requires_evidence_references() -> None:
    agent = Agent(name=Seat.PROSECUTOR.value)
    run_context = RunContextWrapper(
        context(input_seat=Seat.INSPECTOR, output_seat=Seat.PROSECUTOR)
    )
    valid = ProsecutorOutput(
        root=NoSupportedRival(
            outcome="NO_SUPPORTED_RIVAL",
            counterexample_ids=("counter-1",),
            test_ids=("victim.contract",),
            evidence_ids=("ev-1",),
        )
    )
    accepted = await typed_model_output_guardrail.run(run_context, agent, valid)

    assert accepted.output.tripwire_triggered is False
    assert accepted.output.output_info == {"code": "TYPED_OUTPUT_ACCEPTED"}
    with pytest.raises(ValidationError):
        NoSupportedRival(
            outcome="NO_SUPPORTED_RIVAL",
            counterexample_ids=("counter-1",),
            test_ids=("victim.contract",),
        )


@pytest.mark.asyncio
async def test_bailiff_output_guardrail_binds_receipt_to_approved_warrant() -> None:
    agent = Agent(name=Seat.BAILIFF.value)
    run_context = RunContextWrapper(
        context(
            input_seat=Seat.BAILIFF,
            output_seat=Seat.BAILIFF,
            warrant_id="warrant-1",
        )
    )

    result = await typed_model_output_guardrail.run(
        run_context,
        agent,
        BailiffOutput(warrant_id="warrant-2"),
    )

    assert result.output.tripwire_triggered is True
    assert result.output.output_info == {"code": "WARRANT_OUTPUT_MISMATCH"}
