from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from crosspatch.agents.schemas import (
    CounselOutput,
    InspectorOutput,
    InspectorProsecutorResult,
    MagistrateOutput,
    NoSupportedRival,
    ProsecutorOutput,
)
from crosspatch.agents.schemas import (
    TestIntention as AgentTestIntention,
)
from crosspatch.domain.enums import MechanismCode, Seat, Verdict
from crosspatch.orchestration.coordinator import Coordinator, IncidentInput
from crosspatch.orchestration.failures import (
    GuardrailStop,
    IncompleteResponse,
    InvalidSchema,
    MissingEvidenceReference,
    ModelRefusal,
    NetworkFailure,
    OutputCutoff,
    SDKException,
    TruncatedResponse,
    UnknownVerdict,
)


def output_for(seat: Seat):
    if seat is Seat.INSPECTOR:
        return InspectorOutput(
            mechanism=MechanismCode.CHECK_THEN_INSERT_RACE,
            evidence_ids=("ev-1",),
            falsifiers=("serialized delivery",),
        )
    if seat is Seat.PROSECUTOR:
        return ProsecutorOutput(
            root=NoSupportedRival(
                outcome="NO_SUPPORTED_RIVAL",
                counterexample_ids=("counter-1",),
                test_ids=("victim.contract",),
                evidence_ids=("ev-1",),
            )
        )
    if seat is Seat.COUNSEL:
        return CounselOutput(
            normalized_diff="--- a/victim.py\n+++ b/victim.py\n@@\n-old\n+new\n",
            test_intentions=(
                AgentTestIntention(catalog_id="victim.contract", purpose="prove one delivery"),
            ),
            evidence_ids=("ev-1",),
        )
    if seat is Seat.MAGISTRATE:
        return MagistrateOutput(
            verdict=Verdict.CLEAR,
            finding_codes=("CAUSE_SUPPORTED",),
            required_changes=(),
            evidence_ids=("ev-1",),
        )
    raise AssertionError(seat)


class Runtime:
    def __init__(
        self,
        failure: Exception | None = None,
        magistrate_output=None,
        handoff_failure: Exception | None = None,
    ) -> None:
        self.failure = failure
        self.magistrate_output = magistrate_output
        self.handoff_failure = handoff_failure
        self.calls: list[Seat] = []

    async def run_inspector_to_prosecutor(self, *, validate_inspector, **kwargs):
        self.calls.extend((Seat.INSPECTOR, Seat.PROSECUTOR))
        if self.handoff_failure is not None:
            raise self.handoff_failure
        inspector = await validate_inspector(output_for(Seat.INSPECTOR))
        return InspectorProsecutorResult(
            inspector=inspector,
            prosecutor=output_for(Seat.PROSECUTOR),
        )

    async def run_seat(self, *, seat: Seat, **kwargs):
        self.calls.append(seat)
        if seat is Seat.MAGISTRATE and self.failure is not None:
            raise self.failure
        if seat is Seat.MAGISTRATE and self.magistrate_output is not None:
            return self.magistrate_output
        return output_for(seat)

    async def execute_approved_warrant(self, **kwargs):
        self.calls.append(Seat.BAILIFF)
        raise AssertionError("Bailiff must not run in a failed review")


@dataclass
class Authority:
    events: list[tuple[str, dict]] = field(default_factory=list)
    warrants: list[str] = field(default_factory=list)
    approval_enabled: bool = False

    async def begin_review(self, incident_id: str) -> None:
        self.approval_enabled = False

    async def fail_closed_abstain(self, incident_id: str, *, reason: str) -> None:
        self.events.append(("ABSTAIN", {"reason": reason}))
        self.approval_enabled = False

    async def record_verdict(self, incident_id: str, output: MagistrateOutput) -> None:
        self.events.append((output.verdict.value, output.model_dump(mode="json")))

    async def open_approval(self, incident_id: str, output: MagistrateOutput, seat_outputs) -> str:
        self.warrants.append("warrant-1")
        self.approval_enabled = True
        return "warrant-1"

    async def record_escalation(self, incident_id: str, **kwargs) -> None:
        self.events.append(("ESCALATION", kwargs))

    async def approved_warrant(self, incident_id: str, warrant_id: str):
        return None


class Citations:
    def __init__(self, valid: frozenset[str] = frozenset({"ev-1"})) -> None:
        self.valid = valid

    async def contains_all(self, incident_id: str, evidence_ids: tuple[str, ...]) -> bool:
        return set(evidence_ids) <= self.valid


FAILURES = (
    ModelRefusal(),
    OutputCutoff(),
    TruncatedResponse(),
    IncompleteResponse(),
    TimeoutError(),
    NetworkFailure(),
    InvalidSchema(),
    MissingEvidenceReference(),
    SDKException(),
    GuardrailStop(),
    UnknownVerdict("OTHER"),
)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", FAILURES, ids=lambda failure: type(failure).__name__)
async def test_magistrate_failure_matrix_abstains_without_downstream_authority(
    failure: Exception,
) -> None:
    runtime = Runtime(failure=failure)
    authority = Authority()
    coordinator = Coordinator(runtime=runtime, authority=authority, citations=Citations())

    result = await coordinator.run_incident(
        IncidentInput(
            incident_id="inc-1",
            scenario="webhook-race",
            candidate_plan_id="victim.duplicate-race.candidate",
        )
    )

    assert result.verdict is Verdict.ABSTAIN
    assert authority.events[-1][0] == "ABSTAIN"
    assert authority.warrants == []
    assert authority.approval_enabled is False
    assert Seat.BAILIFF not in runtime.calls


@pytest.mark.asyncio
async def test_compromised_agent_cannot_forge_clear_with_cross_incident_citations() -> None:
    forged = MagistrateOutput(
        verdict=Verdict.CLEAR,
        finding_codes=("FORGED",),
        required_changes=(),
        evidence_ids=("other-incident:ev-9",),
    )
    runtime = Runtime(magistrate_output=forged)
    authority = Authority()
    coordinator = Coordinator(runtime=runtime, authority=authority, citations=Citations())

    result = await coordinator.run_incident(
        IncidentInput(
            incident_id="inc-1",
            scenario="webhook-race",
            candidate_plan_id="victim.duplicate-race.candidate",
        )
    )

    assert result.verdict is Verdict.ABSTAIN
    assert result.failure_reason == "missing_evidence_references"
    assert authority.warrants == []
    assert authority.approval_enabled is False
    assert Seat.BAILIFF not in runtime.calls


@pytest.mark.asyncio
async def test_sdk_handoff_guardrail_stop_abstains_before_warrant_or_bailiff() -> None:
    runtime = Runtime(handoff_failure=GuardrailStop())
    authority = Authority()
    coordinator = Coordinator(runtime=runtime, authority=authority, citations=Citations())

    result = await coordinator.run_incident(
        IncidentInput(
            incident_id="inc-1",
            scenario="webhook-race",
            candidate_plan_id="victim.duplicate-race.candidate",
        )
    )

    assert result.verdict is Verdict.ABSTAIN
    assert result.failure_reason == "guardrail_stop"
    assert authority.events == [("ABSTAIN", {"reason": "guardrail_stop"})]
    assert authority.warrants == []
    assert authority.approval_enabled is False
    assert runtime.calls == [Seat.INSPECTOR, Seat.PROSECUTOR]
    assert Seat.BAILIFF not in runtime.calls


@pytest.mark.asyncio
async def test_clear_with_remand_target_is_rejected_by_deterministic_authority() -> None:
    malformed = MagistrateOutput(
        verdict=Verdict.CLEAR,
        finding_codes=("INCONSISTENT_AUTHORITY",),
        required_changes=(),
        remand_target=Seat.COUNSEL,
        evidence_ids=("ev-1",),
    )
    runtime = Runtime(magistrate_output=malformed)
    authority = Authority()
    coordinator = Coordinator(runtime=runtime, authority=authority, citations=Citations())

    result = await coordinator.run_incident(
        IncidentInput(
            incident_id="inc-1",
            scenario="webhook-race",
            candidate_plan_id="victim.duplicate-race.candidate",
        )
    )

    assert result.verdict is Verdict.ABSTAIN
    assert result.failure_reason == "invalid_schema"
    assert authority.warrants == []
    assert authority.approval_enabled is False
    assert Seat.BAILIFF not in runtime.calls
