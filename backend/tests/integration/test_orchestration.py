from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from crosspatch.agents.schemas import (
    BailiffOutput,
    InspectorProsecutorResult,
    MagistrateOutput,
    summarize_output,
)
from crosspatch.domain.enums import Effort, Seat, Verdict
from crosspatch.domain.schemas import RequiredChange
from crosspatch.orchestration.coordinator import Coordinator, IncidentInput
from crosspatch.orchestration.escalation import ESCALATION_EXPLANATION
from crosspatch.runtime.scenarios import OPERATOR_SCENARIOS

from backend.tests.unit.test_fail_closed import Citations, output_for


class Runtime:
    def __init__(self) -> None:
        self.calls: list[tuple[Seat, Effort, str]] = []
        self.requests = []
        self.counsel_retry = False

    async def run_inspector_to_prosecutor(
        self,
        *,
        request,
        inspector_effort: Effort,
        prosecutor_effort: Effort,
        validate_inspector,
    ) -> InspectorProsecutorResult:
        self.calls.append((Seat.INSPECTOR, inspector_effort, "mechanism-analysis"))
        self.requests.append(request)
        inspector = await validate_inspector(output_for(Seat.INSPECTOR))
        prosecutor_request = request.model_copy(
            update={
                "phase": "hypothesis-challenge",
                "prior_outputs": (
                    *request.prior_outputs,
                    summarize_output(Seat.INSPECTOR, inspector),
                ),
            }
        )
        self.calls.append((Seat.PROSECUTOR, prosecutor_effort, "hypothesis-challenge"))
        self.requests.append(prosecutor_request)
        return InspectorProsecutorResult(
            inspector=inspector,
            prosecutor=output_for(Seat.PROSECUTOR),
        )

    async def run_seat(self, *, seat: Seat, effort: Effort, phase: str, request, **kwargs):
        self.calls.append((seat, effort, phase))
        self.requests.append(request)
        output = output_for(seat)
        if seat is Seat.COUNSEL and self.counsel_retry:
            output = output.model_copy(
                update={
                    "normalized_diff": (
                        "--- a/victim.py\n+++ b/victim.py\n@@\n-old\n+materially-safer\n"
                    )
                }
            )
        return output

    async def execute_approved_warrant(
        self,
        *,
        incident_id: str,
        warrant_id: str,
        approval_reference: str,
    ) -> BailiffOutput:
        self.calls.append((Seat.BAILIFF, Effort.NONE, "execute-approved"))
        return BailiffOutput(warrant_id=warrant_id)


@dataclass
class Authority:
    approval_enabled: bool = False
    warrant_id: str | None = None
    approval_reference: str | None = None
    events: list[tuple[str, dict]] = field(default_factory=list)

    async def begin_review(self, incident_id: str) -> None:
        self.approval_enabled = False

    async def fail_closed_abstain(self, incident_id: str, *, reason: str) -> None:
        self.events.append(("ABSTAIN", {"reason": reason}))
        self.approval_enabled = False

    async def record_verdict(self, incident_id: str, output: MagistrateOutput) -> None:
        self.events.append((output.verdict.value, output.model_dump(mode="json")))

    async def open_approval(self, incident_id: str, output: MagistrateOutput, seat_outputs) -> str:
        self.warrant_id = "warrant-1"
        self.approval_enabled = True
        return self.warrant_id

    async def record_escalation(self, incident_id: str, **kwargs) -> None:
        self.events.append(("ESCALATION", kwargs))

    async def approved_warrant(self, incident_id: str, warrant_id: str):
        if warrant_id == self.warrant_id and self.approval_reference:
            return self.approval_reference
        return None


@pytest.mark.parametrize(
    ("scenario", "candidate_plan_id"),
    tuple(
        (definition.scenario_id, definition.candidate_plan_id)
        for definition in OPERATOR_SCENARIOS.values()
    ),
)
def test_coordinator_request_copies_server_selected_scenario_and_plan(
    scenario: str,
    candidate_plan_id: str,
) -> None:
    coordinator = Coordinator(
        runtime=Runtime(),
        authority=Authority(),
        citations=Citations(),
    )
    incident = IncidentInput(
        incident_id=f"inc-{scenario}",
        scenario=scenario,
        candidate_plan_id=candidate_plan_id,
    )

    request = coordinator._request(incident, "mechanism-analysis", {})

    assert request.scenario == scenario
    assert request.candidate_plan_id == candidate_plan_id


@pytest.mark.asyncio
async def test_deterministic_seat_order_stops_at_human_gate_then_resumes_bailiff() -> None:
    runtime = Runtime()
    authority = Authority()
    coordinator = Coordinator(runtime=runtime, authority=authority, citations=Citations())

    result = await coordinator.run_incident(
        IncidentInput(
            incident_id="inc-1",
            scenario="webhook-race",
            candidate_plan_id="victim.duplicate-race.candidate",
        )
    )

    assert [seat for seat, _, _ in runtime.calls] == [
        Seat.INSPECTOR,
        Seat.PROSECUTOR,
        Seat.INSPECTOR,
        Seat.COUNSEL,
        Seat.PROSECUTOR,
        Seat.MAGISTRATE,
    ]
    assert result.verdict is Verdict.CLEAR
    assert result.pending_warrant_id == "warrant-1"
    assert authority.approval_enabled is True
    assert Seat.BAILIFF not in [seat for seat, _, _ in runtime.calls]
    assert runtime.requests[1].prior_outputs
    assert {
        summary.classification
        for request in runtime.requests[1:]
        for summary in request.prior_outputs
    } == {"UNTRUSTED_EVIDENCE"}

    with pytest.raises(PermissionError):
        await coordinator.resume_after_approval("inc-1", "warrant-1")
    assert Seat.BAILIFF not in [seat for seat, _, _ in runtime.calls]

    authority.approval_reference = "approval-1"
    bailiff = await coordinator.resume_after_approval("inc-1", "warrant-1")
    assert bailiff.warrant_id == "warrant-1"
    assert [seat for seat, _, _ in runtime.calls][-1] is Seat.BAILIFF


@pytest.mark.asyncio
async def test_failed_test_escalates_counsel_once_before_new_review() -> None:
    runtime = Runtime()
    authority = Authority()
    coordinator = Coordinator(runtime=runtime, authority=authority, citations=Citations())
    incident = IncidentInput(
        incident_id="inc-1",
        scenario="webhook-race",
        candidate_plan_id="victim.duplicate-race.candidate",
    )
    await coordinator.run_incident(incident)
    runtime.calls.clear()
    runtime.counsel_retry = True

    result = await coordinator.resume_after_test(incident, test_passed=False)

    assert result.verdict is Verdict.CLEAR
    assert runtime.calls[0] == (Seat.COUNSEL, Effort.HIGH, "test-failure-repair")
    assert [seat for seat, _, _ in runtime.calls] == [
        Seat.COUNSEL,
        Seat.PROSECUTOR,
        Seat.MAGISTRATE,
    ]
    escalation = [payload for event, payload in authority.events if event == "ESCALATION"][-1]
    assert escalation["message"] == ESCALATION_EXPLANATION


class RemandRuntime(Runtime):
    def __init__(self) -> None:
        super().__init__()
        self.magistrate_calls = 0

    async def run_seat(self, *, seat: Seat, effort: Effort, phase: str, request, **kwargs):
        if seat is Seat.MAGISTRATE:
            self.calls.append((seat, effort, phase))
            self.requests.append(request)
            self.magistrate_calls += 1
            if self.magistrate_calls == 1:
                return MagistrateOutput(
                    verdict=Verdict.REMAND,
                    finding_codes=("PATCH_TOO_BROAD",),
                    required_changes=(
                        RequiredChange(code="NARROW_PATCH", target=Seat.COUNSEL),
                    ),
                    remand_target=Seat.COUNSEL,
                    evidence_ids=("ev-1",),
                )
            return output_for(seat)
        if seat is Seat.COUNSEL and phase == "remand-revision":
            self.counsel_retry = True
        return await super().run_seat(
            seat=seat,
            effort=effort,
            phase=phase,
            request=request,
            **kwargs,
        )


@pytest.mark.asyncio
async def test_remand_escalates_only_target_one_level_and_requires_material_retry() -> None:
    runtime = RemandRuntime()
    authority = Authority()
    coordinator = Coordinator(runtime=runtime, authority=authority, citations=Citations())

    result = await coordinator.run_incident(
        IncidentInput(
            incident_id="inc-1",
            scenario="webhook-race",
            candidate_plan_id="victim.duplicate-race.candidate",
        )
    )

    assert result.verdict is Verdict.CLEAR
    assert runtime.calls[-3:] == [
        (Seat.COUNSEL, Effort.HIGH, "remand-revision"),
        (Seat.PROSECUTOR, Effort.LOW, "remand-challenge"),
        (Seat.MAGISTRATE, Effort.MEDIUM, "remand-review"),
    ]
    remand_events = [event for event, _ in authority.events]
    assert "REMAND" in remand_events
    assert "ESCALATION" in remand_events
