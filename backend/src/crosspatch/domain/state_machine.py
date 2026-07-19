"""Deterministic incident transition policy."""

import re
from dataclasses import dataclass, field
from typing import Any

from crosspatch.domain.enums import IncidentState, Seat, Verdict


class InvalidTransition(ValueError):
    """Raised when an event is not permitted from the current state."""


class EventChainCorrupted(RuntimeError):
    """Raised when incident chain metadata disagrees with durable events."""


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class Event:
    type: str
    payload: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def verdict(cls, verdict: Verdict, remand_target: Seat | None = None) -> "VerdictEvent":
        return VerdictEvent(verdict, remand_target)

    @classmethod
    def warrant_approved(
        cls,
        *,
        approval_id: str,
        warrant_sha256: str,
        approver_identity: str,
    ) -> "WarrantApprovedEvent":
        return WarrantApprovedEvent(approval_id, warrant_sha256, approver_identity)

    @classmethod
    def execution_started(cls, *, claim_id: str, warrant_id: str) -> "ExecutionStartedEvent":
        return ExecutionStartedEvent(claim_id, warrant_id)

    @classmethod
    def verified(cls, *, receipt_id: str, warrant_id: str) -> "VerifiedEvent":
        return VerifiedEvent(receipt_id, warrant_id)

    @classmethod
    def execution_failed(cls, *, warrant_id: str, error_code: str) -> "ExecutionFailedEvent":
        return ExecutionFailedEvent(warrant_id, error_code)

    @classmethod
    def warrant_expired(
        cls,
        *,
        warrant_id: str,
        warrant_sha256: str,
    ) -> "WarrantExpiredEvent":
        return WarrantExpiredEvent(warrant_id, warrant_sha256)

    @classmethod
    def revision_requested(
        cls,
        *,
        warrant_id: str,
        warrant_sha256: str,
        evidence_id: str,
    ) -> "RevisionRequestedEvent":
        return RevisionRequestedEvent(warrant_id, warrant_sha256, evidence_id)


class VerdictEvent(Event):
    verdict_value: Verdict
    remand_target: Seat | None

    def __init__(self, verdict: Verdict, remand_target: Seat | None = None) -> None:
        verdict = Verdict(verdict)
        if verdict is Verdict.REMAND:
            if remand_target not in {Seat.PROSECUTOR, Seat.INSPECTOR, Seat.COUNSEL}:
                raise ValueError("REMAND requires a valid Prosecutor, Inspector, or Counsel target")
        elif remand_target is not None:
            raise ValueError("only REMAND may include a remand target")
        payload: dict[str, Any] = {"verdict": verdict}
        if remand_target is not None:
            payload["remand_target"] = remand_target
        Event.__init__(self, type="VERDICT", payload=payload)
        object.__setattr__(self, "verdict_value", verdict)
        object.__setattr__(self, "remand_target", remand_target)


class WarrantApprovedEvent(Event):
    def __init__(self, approval_id: str, warrant_sha256: str, approver_identity: str) -> None:
        if not _IDENTIFIER.fullmatch(approval_id) or not _IDENTIFIER.fullmatch(approver_identity):
            raise ValueError("approval proof identifiers are invalid")
        if not _SHA256.fullmatch(warrant_sha256):
            raise ValueError("approval proof requires a canonical warrant SHA-256")
        Event.__init__(
            self,
            type="WARRANT_APPROVED",
            payload={
                "approval_id": approval_id,
                "warrant_sha256": warrant_sha256,
                "approver_identity": approver_identity,
            },
        )


class ExecutionStartedEvent(Event):
    def __init__(self, claim_id: str, warrant_id: str) -> None:
        if not _IDENTIFIER.fullmatch(claim_id) or not _IDENTIFIER.fullmatch(warrant_id):
            raise ValueError("execution claim proof is invalid")
        Event.__init__(
            self,
            type="EXECUTION_STARTED",
            payload={"claim_id": claim_id, "warrant_id": warrant_id},
        )


class VerifiedEvent(Event):
    def __init__(self, receipt_id: str, warrant_id: str) -> None:
        if not _IDENTIFIER.fullmatch(receipt_id) or not _IDENTIFIER.fullmatch(warrant_id):
            raise ValueError("verification receipt proof is invalid")
        Event.__init__(
            self,
            type="VERIFIED",
            payload={"receipt_id": receipt_id, "warrant_id": warrant_id},
        )


class ExecutionFailedEvent(Event):
    def __init__(self, warrant_id: str, error_code: str) -> None:
        if not _IDENTIFIER.fullmatch(warrant_id) or not _IDENTIFIER.fullmatch(error_code):
            raise ValueError("execution failure proof is invalid")
        Event.__init__(
            self,
            type="EXECUTION_FAILED",
            payload={"warrant_id": warrant_id, "error_code": error_code},
        )


class WarrantExpiredEvent(Event):
    def __init__(self, warrant_id: str, warrant_sha256: str) -> None:
        if not _IDENTIFIER.fullmatch(warrant_id) or not _SHA256.fullmatch(warrant_sha256):
            raise ValueError("expired warrant proof is invalid")
        Event.__init__(
            self,
            type="WARRANT_EXPIRED",
            payload={"warrant_id": warrant_id, "warrant_sha256": warrant_sha256},
        )


class RevisionRequestedEvent(Event):
    def __init__(self, warrant_id: str, warrant_sha256: str, evidence_id: str) -> None:
        if (
            not _IDENTIFIER.fullmatch(warrant_id)
            or not _IDENTIFIER.fullmatch(evidence_id)
            or not _SHA256.fullmatch(warrant_sha256)
        ):
            raise ValueError("revision request proof is invalid")
        Event.__init__(
            self,
            type="REVISION_REQUESTED",
            payload={
                "warrant_id": warrant_id,
                "warrant_sha256": warrant_sha256,
                "evidence_id": evidence_id,
            },
        )


FAIL_CLOSED_REASONS = frozenset(
    {
        "refusal",
        "cutoff",
        "truncated",
        "incomplete_response",
        "timeout",
        "network_failure",
        "invalid_schema",
        "missing_evidence_references",
        "sdk_exception",
        "guardrail_stop",
        "unknown_verdict",
    }
)


def verdict_for_failure(reason: str) -> Verdict:
    """Map all known and future model failures to the fail-closed verdict."""
    _ = reason
    return Verdict.ABSTAIN


def _transition_verdict(event: Event) -> IncidentState:
    if not isinstance(event, VerdictEvent):
        raise InvalidTransition("VERDICT requires a validated typed verdict event")
    verdict = event.verdict_value
    if verdict is Verdict.CLEAR:
        return IncidentState.APPROVAL_PENDING
    if verdict is Verdict.REMAND:
        target = event.remand_target
        return IncidentState.PATCHING if target == Seat.COUNSEL else IncidentState.ANALYZING
    if verdict is Verdict.BLOCK:
        return IncidentState.BLOCKED
    return IncidentState.HUMAN_ESCALATION


def transition_incident(state: IncidentState, event: Event) -> IncidentState:
    if event.type == "VERDICT":
        if (
            isinstance(event, VerdictEvent)
            and event.verdict_value is Verdict.ABSTAIN
            and state
            in {
                IncidentState.ANALYZING,
                IncidentState.PATCHING,
                IncidentState.REVIEWING,
                IncidentState.APPROVED,
                IncidentState.EXECUTING,
                IncidentState.TEST_FAILED,
            }
        ):
            return IncidentState.HUMAN_ESCALATION
        if state is not IncidentState.REVIEWING:
            raise InvalidTransition(f"VERDICT is not allowed from {state.value}")
        return _transition_verdict(event)

    if event.type == "WARRANT_APPROVED" and not isinstance(event, WarrantApprovedEvent):
        raise InvalidTransition("WARRANT_APPROVED requires validated approval proof")
    if event.type == "EXECUTION_STARTED" and not isinstance(event, ExecutionStartedEvent):
        raise InvalidTransition("EXECUTION_STARTED requires validated broker claim proof")
    if event.type == "VERIFIED" and not isinstance(event, VerifiedEvent):
        raise InvalidTransition("VERIFIED requires a validated test receipt")
    if event.type == "EXECUTION_FAILED" and not isinstance(event, ExecutionFailedEvent):
        raise InvalidTransition("EXECUTION_FAILED requires a validated broker failure")
    if event.type == "WARRANT_EXPIRED" and not isinstance(event, WarrantExpiredEvent):
        raise InvalidTransition("WARRANT_EXPIRED requires validated warrant proof")
    if event.type == "REVISION_REQUESTED" and not isinstance(
        event, RevisionRequestedEvent
    ):
        raise InvalidTransition("REVISION_REQUESTED requires validated revision proof")

    transitions = {
        (IncidentState.OPEN, "REPRODUCTION_STARTED"): IncidentState.REPRODUCING,
        (IncidentState.REPRODUCING, "EVIDENCE_CAPTURED"): IncidentState.EVIDENCE_READY,
        (IncidentState.EVIDENCE_READY, "REPRODUCTION_PASSED"): IncidentState.BLOCKED,
        (
            IncidentState.EVIDENCE_READY,
            "REPRODUCTION_INCONCLUSIVE",
        ): IncidentState.HUMAN_ESCALATION,
        (IncidentState.EVIDENCE_READY, "ANALYSIS_STARTED"): IncidentState.ANALYZING,
        (IncidentState.ANALYZING, "PATCH_REQUESTED"): IncidentState.PATCHING,
        (IncidentState.PATCHING, "PATCH_PROPOSED"): IncidentState.REVIEWING,
        (IncidentState.APPROVAL_PENDING, "WARRANT_APPROVED"): IncidentState.APPROVED,
        (IncidentState.APPROVAL_PENDING, "WARRANT_EXPIRED"): IncidentState.HUMAN_ESCALATION,
        (IncidentState.APPROVAL_PENDING, "REVISION_REQUESTED"): IncidentState.PATCHING,
        (IncidentState.APPROVED, "EXECUTION_STARTED"): IncidentState.EXECUTING,
        (IncidentState.EXECUTING, "TEST_FAILED"): IncidentState.TEST_FAILED,
        (IncidentState.TEST_FAILED, "RETRY_STARTED"): IncidentState.PATCHING,
        (IncidentState.EXECUTING, "VERIFIED"): IncidentState.VERIFIED,
        (IncidentState.OPEN, "BACKGROUND_TASK_FAILED"): IncidentState.HUMAN_ESCALATION,
        (IncidentState.REPRODUCING, "BACKGROUND_TASK_FAILED"): IncidentState.HUMAN_ESCALATION,
        (IncidentState.EVIDENCE_READY, "BACKGROUND_TASK_FAILED"): IncidentState.HUMAN_ESCALATION,
        (IncidentState.ANALYZING, "BACKGROUND_TASK_FAILED"): IncidentState.HUMAN_ESCALATION,
        (IncidentState.PATCHING, "BACKGROUND_TASK_FAILED"): IncidentState.HUMAN_ESCALATION,
        (IncidentState.REVIEWING, "BACKGROUND_TASK_FAILED"): IncidentState.HUMAN_ESCALATION,
        (IncidentState.APPROVED, "BACKGROUND_TASK_FAILED"): IncidentState.HUMAN_ESCALATION,
        (IncidentState.EXECUTING, "BACKGROUND_TASK_FAILED"): IncidentState.HUMAN_ESCALATION,
        (IncidentState.TEST_FAILED, "BACKGROUND_TASK_FAILED"): IncidentState.HUMAN_ESCALATION,
        (IncidentState.APPROVED, "EXECUTION_FAILED"): IncidentState.HUMAN_ESCALATION,
        (IncidentState.EXECUTING, "EXECUTION_FAILED"): IncidentState.HUMAN_ESCALATION,
    }
    try:
        return transitions[(state, event.type)]
    except KeyError as error:
        raise InvalidTransition(f"{event.type} is not allowed from {state.value}") from error


STATE_EVENT_TYPES = frozenset(
    {
        "REPRODUCTION_STARTED",
        "EVIDENCE_CAPTURED",
        "REPRODUCTION_PASSED",
        "REPRODUCTION_INCONCLUSIVE",
        "ANALYSIS_STARTED",
        "PATCH_REQUESTED",
        "PATCH_PROPOSED",
        "VERDICT",
        "WARRANT_APPROVED",
        "WARRANT_EXPIRED",
        "REVISION_REQUESTED",
        "EXECUTION_STARTED",
        "TEST_FAILED",
        "RETRY_STARTED",
        "VERIFIED",
        "BACKGROUND_TASK_FAILED",
        "EXECUTION_FAILED",
    }
)


def typed_event_from_payload(event_type: str, payload: dict[str, Any]) -> Event:
    """Validate persisted authority payloads before reducing incident state."""
    if event_type == "VERDICT":
        try:
            verdict = Verdict(payload["verdict"])
            target = payload.get("remand_target")
            remand_target = Seat(target) if target is not None else None
            return Event.verdict(verdict, remand_target)
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidTransition("malformed verdict payload") from error
    if event_type == "WARRANT_APPROVED":
        try:
            return Event.warrant_approved(
                approval_id=payload["approval_id"],
                warrant_sha256=payload["warrant_sha256"],
                approver_identity=payload["approver_identity"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidTransition("malformed approval proof") from error
    if event_type == "EXECUTION_STARTED":
        try:
            return Event.execution_started(
                claim_id=payload["claim_id"],
                warrant_id=payload["warrant_id"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidTransition("malformed execution claim proof") from error
    if event_type == "VERIFIED":
        try:
            return Event.verified(
                receipt_id=payload["receipt_id"],
                warrant_id=payload["warrant_id"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidTransition("malformed verification receipt") from error
    if event_type == "EXECUTION_FAILED":
        try:
            return Event.execution_failed(
                warrant_id=payload["warrant_id"],
                error_code=payload["error_code"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidTransition("malformed broker failure proof") from error
    if event_type == "WARRANT_EXPIRED":
        try:
            return Event.warrant_expired(
                warrant_id=payload["warrant_id"],
                warrant_sha256=payload["warrant_sha256"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidTransition("malformed expired warrant proof") from error
    if event_type == "REVISION_REQUESTED":
        try:
            return Event.revision_requested(
                warrant_id=payload["warrant_id"],
                warrant_sha256=payload["warrant_sha256"],
                evidence_id=payload["evidence_id"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidTransition("malformed revision request proof") from error
    return Event(type=event_type, payload=payload)
