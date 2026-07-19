"""Application-owned seat order, citation checks, human gate, and fail closure."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from crosspatch.agents.schemas import (
    AgentRunInput,
    BailiffOutput,
    CounselOutput,
    InspectorOutput,
    InspectorProsecutorResult,
    MagistrateOutput,
    ProsecutorOutput,
    SeatOutput,
    summarize_output,
)
from crosspatch.domain.enums import Effort, ScenarioId, Seat, Verdict
from crosspatch.evidence.views import UntrustedEvidenceEnvelope
from crosspatch.orchestration.escalation import (
    DuplicateRetry,
    EscalationExhausted,
    EscalationTracker,
)
from crosspatch.orchestration.failures import (
    EscalationFailure,
    InvalidSchema,
    MissingEvidenceReference,
    UnknownVerdict,
    failure_reason,
)


@dataclass(frozen=True, slots=True)
class IncidentInput:
    incident_id: str
    scenario: ScenarioId
    candidate_plan_id: str
    evidence: tuple[UntrustedEvidenceEnvelope, ...] = ()


@dataclass(frozen=True, slots=True)
class CoordinatorResult:
    verdict: Verdict
    seat_outputs: dict[Seat, SeatOutput] = field(default_factory=dict)
    pending_warrant_id: str | None = None
    failure_reason: str | None = None


class AgentRuntime(Protocol):
    async def run_inspector_to_prosecutor(
        self,
        *,
        request: AgentRunInput,
        inspector_effort: Effort,
        prosecutor_effort: Effort,
        validate_inspector: Callable[[InspectorOutput], Awaitable[InspectorOutput]],
    ) -> InspectorProsecutorResult: ...

    async def run_seat(
        self,
        *,
        seat: Seat,
        effort: Effort,
        phase: str,
        request: AgentRunInput,
    ) -> Any: ...

    async def execute_approved_warrant(
        self,
        *,
        incident_id: str,
        warrant_id: str,
        approval_reference: str,
    ) -> BailiffOutput: ...


@runtime_checkable
class DeferredRetryRuntime(Protocol):
    """Persistence boundary for retries whose materiality is not yet known."""

    async def run_unpublished_retry(
        self,
        *,
        seat: Seat,
        effort: Effort,
        phase: str,
        request: AgentRunInput,
    ) -> Any: ...

    async def publish_accepted_retry(
        self,
        *,
        incident_id: str,
        seat: Seat,
        effort: Effort,
        phase: str,
        output: SeatOutput,
    ) -> None: ...

class AuthorityGateway(Protocol):
    async def begin_review(self, incident_id: str) -> None: ...

    async def fail_closed_abstain(self, incident_id: str, *, reason: str) -> None: ...

    async def record_verdict(self, incident_id: str, output: MagistrateOutput) -> None: ...

    async def open_approval(
        self,
        incident_id: str,
        output: MagistrateOutput,
        seat_outputs: dict[Seat, SeatOutput],
    ) -> str: ...

    async def record_escalation(
        self,
        incident_id: str,
        *,
        seat: Seat,
        effort: Effort,
        escalation_count: int,
        reason: str,
        message: str,
    ) -> None: ...

    async def reject_duplicate_retry(
        self,
        incident_id: str,
        *,
        seat: Seat,
        effort: Effort,
        phase: str,
        output: SeatOutput,
        reason: str,
    ) -> None: ...

    async def approved_warrant(self, incident_id: str, warrant_id: str) -> str | None: ...

    async def request_revision(
        self,
        *,
        warrant_id: str,
        warrant_sha256: str,
        guidance: UntrustedEvidenceEnvelope,
        actor: str,
    ) -> str: ...


class CitationAuthority(Protocol):
    async def contains_all(self, incident_id: str, evidence_ids: tuple[str, ...]) -> bool: ...


_OUTPUT_TYPES = {
    Seat.INSPECTOR: InspectorOutput,
    Seat.PROSECUTOR: ProsecutorOutput,
    Seat.COUNSEL: CounselOutput,
    Seat.MAGISTRATE: MagistrateOutput,
    Seat.BAILIFF: BailiffOutput,
}


class _DuplicateRetryAttempt(DuplicateRetry):
    def __init__(
        self,
        message: str,
        *,
        seat: Seat,
        effort: Effort,
        phase: str,
        output: SeatOutput,
    ) -> None:
        super().__init__(message)
        self.seat = seat
        self.effort = effort
        self.phase = phase
        self.output = output


class _RetryFailureAlreadyPersisted(EscalationFailure):
    """The atomic authority transaction already recorded the ABSTAIN outcome."""


class Coordinator:
    def __init__(
        self,
        *,
        runtime: AgentRuntime,
        authority: AuthorityGateway,
        citations: CitationAuthority,
        escalation: EscalationTracker | None = None,
    ) -> None:
        self._runtime = runtime
        self._authority = authority
        self._citations = citations
        self._escalation = escalation or EscalationTracker()
        self._incident_outputs: dict[str, dict[Seat, SeatOutput]] = {}
        self._incident_phases: dict[str, dict[Seat, str]] = {}

    def restore_incident_outputs(
        self,
        incident_id: str,
        outputs: dict[Seat, tuple[SeatOutput, Effort, int]],
        *,
        completed_phases: dict[Seat, str] | None = None,
        pending_retries: dict[Seat, str] | None = None,
    ) -> None:
        """Hydrate validated structured outputs and effort state from durable rows."""
        restored: dict[Seat, SeatOutput] = {}
        phases = dict(completed_phases or {})
        pending = dict(pending_retries or {})
        for seat, (output, effort, escalation_count) in outputs.items():
            expected = _OUTPUT_TYPES[seat]
            if not isinstance(output, expected):
                raise InvalidSchema(f"persisted {seat.value} output type changed")
            self._escalation.restore(
                incident_id,
                seat,
                output,
                effort=effort,
                escalation_count=escalation_count,
                retry_pending=seat in pending,
                pending_reason=pending.get(seat),
            )
            restored[seat] = output
        self._incident_outputs[incident_id] = restored
        self._incident_phases[incident_id] = phases

    @staticmethod
    def _evidence_ids(output: SeatOutput) -> tuple[str, ...]:
        if isinstance(output, ProsecutorOutput):
            return output.root.evidence_ids
        return tuple(getattr(output, "evidence_ids", ()))

    async def _validate(self, incident_id: str, seat: Seat, output: Any) -> SeatOutput:
        expected = _OUTPUT_TYPES[seat]
        if not isinstance(output, expected):
            if seat is Seat.MAGISTRATE and isinstance(output, dict):
                verdict = output.get("verdict")
                if isinstance(verdict, str) and verdict not in {item.value for item in Verdict}:
                    raise UnknownVerdict(verdict)
            raise InvalidSchema(f"{seat.value} did not return {expected.__name__}")
        if isinstance(output, MagistrateOutput):
            valid_remand_targets = {Seat.PROSECUTOR, Seat.INSPECTOR, Seat.COUNSEL}
            if output.verdict is Verdict.REMAND:
                if output.remand_target not in valid_remand_targets:
                    raise InvalidSchema("REMAND did not include a valid target")
            elif output.remand_target is not None:
                raise InvalidSchema("non-REMAND verdict included a remand target")
        evidence_ids = self._evidence_ids(output)
        if seat is not Seat.BAILIFF:
            if not evidence_ids:
                raise MissingEvidenceReference(f"{seat.value} returned no evidence citations")
            if not await self._citations.contains_all(incident_id, evidence_ids):
                raise MissingEvidenceReference(f"{seat.value} cited evidence outside the incident")
        return output

    def _request(
        self,
        incident: IncidentInput,
        phase: str,
        outputs: dict[Seat, SeatOutput],
    ) -> AgentRunInput:
        summaries = tuple(summarize_output(seat, output) for seat, output in outputs.items())
        return AgentRunInput(
            incident_id=incident.incident_id,
            scenario=incident.scenario,
            candidate_plan_id=incident.candidate_plan_id,
            phase=phase,
            evidence=incident.evidence,
            citable_evidence_ids=tuple(evidence.evidence_id for evidence in incident.evidence),
            prior_outputs=summaries,
        )

    async def _run_seat(
        self,
        incident: IncidentInput,
        outputs: dict[Seat, SeatOutput],
        *,
        seat: Seat,
        phase: str,
        effort: Effort | None = None,
        retry: bool = False,
    ) -> SeatOutput:
        selected_effort = effort or self._escalation.current_effort(incident.incident_id, seat)
        deferred_runtime = (
            self._runtime
            if retry and isinstance(self._runtime, DeferredRetryRuntime)
            else None
        )
        request = self._request(incident, phase, outputs)
        if deferred_runtime is None:
            output = await self._runtime.run_seat(
                seat=seat,
                effort=selected_effort,
                phase=phase,
                request=request,
            )
        else:
            output = await deferred_runtime.run_unpublished_retry(
                seat=seat,
                effort=selected_effort,
                phase=phase,
                request=request,
            )
        validated = await self._validate(incident.incident_id, seat, output)
        if retry:
            try:
                self._escalation.accept_retry(incident.incident_id, seat, validated)
            except DuplicateRetry as error:
                raise _DuplicateRetryAttempt(
                    str(error),
                    seat=seat,
                    effort=selected_effort,
                    phase=phase,
                    output=validated,
                ) from error
            if deferred_runtime is not None:
                await deferred_runtime.publish_accepted_retry(
                    incident_id=incident.incident_id,
                    seat=seat,
                    effort=selected_effort,
                    phase=phase,
                    output=validated,
                )
        else:
            self._escalation.record_initial(incident.incident_id, seat, validated)
        outputs[seat] = validated
        self._incident_phases.setdefault(incident.incident_id, {})[seat] = phase
        return validated

    async def _run_initial_handoff(
        self,
        incident: IncidentInput,
        outputs: dict[Seat, SeatOutput],
    ) -> None:
        """Accept one SDK handoff while retaining application-owned validation."""

        async def validate_inspector(output: InspectorOutput) -> InspectorOutput:
            validated = await self._validate(incident.incident_id, Seat.INSPECTOR, output)
            if not isinstance(validated, InspectorOutput):
                raise InvalidSchema("Inspector handoff changed output type")
            return validated

        result = await self._runtime.run_inspector_to_prosecutor(
            request=self._request(incident, "mechanism-analysis", outputs),
            inspector_effort=self._escalation.current_effort(
                incident.incident_id,
                Seat.INSPECTOR,
            ),
            prosecutor_effort=self._escalation.current_effort(
                incident.incident_id,
                Seat.PROSECUTOR,
            ),
            validate_inspector=validate_inspector,
        )
        if not isinstance(result, InspectorProsecutorResult):
            raise InvalidSchema("SDK handoff did not return the expected result")
        inspector = await validate_inspector(result.inspector)
        prosecutor = await self._validate(
            incident.incident_id,
            Seat.PROSECUTOR,
            result.prosecutor,
        )
        self._escalation.record_initial(incident.incident_id, Seat.INSPECTOR, inspector)
        self._escalation.record_initial(incident.incident_id, Seat.PROSECUTOR, prosecutor)
        outputs[Seat.INSPECTOR] = inspector
        outputs[Seat.PROSECUTOR] = prosecutor
        phases = self._incident_phases.setdefault(incident.incident_id, {})
        phases[Seat.INSPECTOR] = "mechanism-analysis"
        phases[Seat.PROSECUTOR] = "hypothesis-challenge"

    async def _fail_closed(
        self,
        incident_id: str,
        error: Exception,
        outputs: dict[Seat, SeatOutput],
    ) -> CoordinatorResult:
        reason = failure_reason(error)
        if not isinstance(error, _RetryFailureAlreadyPersisted):
            await self._authority.fail_closed_abstain(incident_id, reason=reason)
        self._incident_outputs[incident_id] = dict(outputs)
        return CoordinatorResult(
            verdict=Verdict.ABSTAIN,
            seat_outputs=dict(outputs),
            failure_reason=reason,
        )

    async def _escalate(
        self,
        incident: IncidentInput,
        outputs: dict[Seat, SeatOutput],
        *,
        seat: Seat,
        reason: str,
        phase: str,
    ) -> SeatOutput:
        decision = self._escalation.resume_pending_escalation(
            incident.incident_id,
            seat,
            reason=reason,
        )
        if decision is None:
            try:
                decision = self._escalation.begin_escalation(
                    incident.incident_id,
                    seat,
                    reason=reason,
                )
            except EscalationExhausted as error:
                raise EscalationFailure(str(error)) from error
            await self._authority.record_escalation(
                incident.incident_id,
                seat=seat,
                effort=decision.effort,
                escalation_count=decision.escalation_count,
                reason=reason,
                message=decision.explanation,
            )
        try:
            return await self._run_seat(
                incident,
                outputs,
                seat=seat,
                phase=phase,
                effort=decision.effort,
                retry=True,
            )
        except _DuplicateRetryAttempt as error:
            await self._authority.reject_duplicate_retry(
                incident.incident_id,
                seat=error.seat,
                effort=error.effort,
                phase=error.phase,
                output=error.output,
                reason=reason,
            )
            raise _RetryFailureAlreadyPersisted(str(error)) from error

    async def _resolve_verdict(
        self,
        incident: IncidentInput,
        outputs: dict[Seat, SeatOutput],
        magistrate: MagistrateOutput,
    ) -> CoordinatorResult:
        while magistrate.verdict is Verdict.REMAND:
            await self._authority.record_verdict(incident.incident_id, magistrate)
            target = magistrate.remand_target
            if target not in {Seat.PROSECUTOR, Seat.INSPECTOR, Seat.COUNSEL}:
                raise InvalidSchema("REMAND did not include a valid target")
            await self._escalate(
                incident,
                outputs,
                seat=target,
                reason="remand",
                phase="remand-revision",
            )
            if target is not Seat.COUNSEL:
                await self._run_seat(
                    incident,
                    outputs,
                    seat=Seat.COUNSEL,
                    phase="remand-patch",
                )
            await self._run_seat(
                incident,
                outputs,
                seat=Seat.PROSECUTOR,
                phase="remand-challenge",
            )
            magistrate = await self._run_seat(
                incident,
                outputs,
                seat=Seat.MAGISTRATE,
                phase="remand-review",
            )
            if not isinstance(magistrate, MagistrateOutput):
                raise InvalidSchema("Magistrate output type changed after remand")

        self._incident_outputs[incident.incident_id] = dict(outputs)
        if magistrate.verdict is Verdict.CLEAR:
            warrant_id = await self._authority.open_approval(
                incident.incident_id,
                magistrate,
                dict(outputs),
            )
            return CoordinatorResult(
                verdict=Verdict.CLEAR,
                seat_outputs=dict(outputs),
                pending_warrant_id=warrant_id,
            )
        await self._authority.record_verdict(incident.incident_id, magistrate)
        return CoordinatorResult(verdict=magistrate.verdict, seat_outputs=dict(outputs))

    async def run_incident(self, incident: IncidentInput) -> CoordinatorResult:
        outputs: dict[Seat, SeatOutput] = {}
        await self._authority.begin_review(incident.incident_id)
        try:
            await self._run_initial_handoff(incident, outputs)
            await self._run_seat(
                incident, outputs, seat=Seat.INSPECTOR, phase="mechanism-revision"
            )
            await self._run_seat(incident, outputs, seat=Seat.COUNSEL, phase="patch-proposal")
            await self._run_seat(
                incident, outputs, seat=Seat.PROSECUTOR, phase="patch-challenge"
            )
            magistrate = await self._run_seat(
                incident, outputs, seat=Seat.MAGISTRATE, phase="verdict-review"
            )
            if not isinstance(magistrate, MagistrateOutput):
                raise InvalidSchema("Magistrate output is invalid")
            return await self._resolve_verdict(incident, outputs, magistrate)
        except Exception as error:
            return await self._fail_closed(incident.incident_id, error, outputs)
    async def resume_after_approval(self, incident_id: str, warrant_id: str) -> BailiffOutput:
        approval_reference = await self._authority.approved_warrant(incident_id, warrant_id)
        if approval_reference is None:
            raise PermissionError("warrant does not have a valid human approval")
        result = await self._runtime.execute_approved_warrant(
            incident_id=incident_id,
            warrant_id=warrant_id,
            approval_reference=approval_reference,
        )
        if not isinstance(result, BailiffOutput) or result.warrant_id != warrant_id:
            raise InvalidSchema("Bailiff returned a different warrant identifier")
        return result

    async def resume_after_test(
        self,
        incident: IncidentInput,
        *,
        test_passed: bool,
    ) -> CoordinatorResult:
        outputs = dict(self._incident_outputs.get(incident.incident_id, {}))
        if not outputs:
            raise LookupError("incident has no resumable agent state")
        if test_passed:
            return CoordinatorResult(verdict=Verdict.CLEAR, seat_outputs=outputs)
        phases = self._incident_phases.setdefault(incident.incident_id, {})
        try:
            if phases.get(Seat.COUNSEL) != "test-failure-repair":
                await self._authority.begin_review(incident.incident_id)
                await self._escalate(
                    incident,
                    outputs,
                    seat=Seat.COUNSEL,
                    reason="test_failure",
                    phase="test-failure-repair",
                )
            if phases.get(Seat.PROSECUTOR) != "test-failure-challenge":
                await self._run_seat(
                    incident,
                    outputs,
                    seat=Seat.PROSECUTOR,
                    phase="test-failure-challenge",
                )
            if phases.get(Seat.MAGISTRATE) == "test-failure-review":
                magistrate = outputs.get(Seat.MAGISTRATE)
            else:
                magistrate = await self._run_seat(
                    incident,
                    outputs,
                    seat=Seat.MAGISTRATE,
                    phase="test-failure-review",
                )
            if not isinstance(magistrate, MagistrateOutput):
                raise InvalidSchema("Magistrate output is invalid")
            return await self._resolve_verdict(incident, outputs, magistrate)
        except Exception as error:
            return await self._fail_closed(incident.incident_id, error, outputs)

    async def resume_after_revision(self, incident: IncidentInput) -> CoordinatorResult:
        outputs = dict(self._incident_outputs.get(incident.incident_id, {}))
        if not outputs:
            raise LookupError("incident has no resumable agent state")
        try:
            await self._authority.begin_review(incident.incident_id)
            await self._escalate(
                incident,
                outputs,
                seat=Seat.COUNSEL,
                reason="human_revision",
                phase="human-revision-patch",
            )
            await self._run_seat(
                incident,
                outputs,
                seat=Seat.PROSECUTOR,
                phase="human-revision-challenge",
            )
            magistrate = await self._run_seat(
                incident,
                outputs,
                seat=Seat.MAGISTRATE,
                phase="human-revision-review",
            )
            if not isinstance(magistrate, MagistrateOutput):
                raise InvalidSchema("Magistrate output is invalid")
            return await self._resolve_verdict(incident, outputs, magistrate)
        except Exception as error:
            return await self._fail_closed(incident.incident_id, error, outputs)
