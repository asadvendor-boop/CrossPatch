"""Per-incident effort escalation with semantic retry enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from crosspatch.domain.enums import Effort, Seat
from crosspatch.domain.hashing import semantic_fingerprint
from crosspatch.domain.seats import SEAT_SPECS

ESCALATION_EXPLANATION = "The room only thinks harder when the judge is unsatisfied."


class DuplicateRetry(RuntimeError):
    pass


class EscalationExhausted(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class EscalationDecision:
    effort: Effort
    escalation_count: int
    reason: str
    explanation: str = ESCALATION_EXPLANATION


@dataclass(slots=True)
class _SeatState:
    effort_index: int
    escalation_count: int
    fingerprint: str
    retry_pending: bool = False
    pending_reason: str | None = None


_SPEC_BY_SEAT = {spec.seat: spec for spec in SEAT_SPECS}


class EscalationTracker:
    def __init__(self) -> None:
        self._states: dict[tuple[str, Seat], _SeatState] = {}

    def record_initial(self, incident_id: str, seat: Seat, output: Any) -> None:
        spec = _SPEC_BY_SEAT[seat]
        key = (incident_id, seat)
        existing = self._states.get(key)
        self._states[key] = _SeatState(
            effort_index=0 if existing is None else existing.effort_index,
            escalation_count=0 if existing is None else existing.escalation_count,
            fingerprint=semantic_fingerprint(seat, output),
        )
        if spec.initial_effort != spec.effort_ladder[0]:
            raise RuntimeError("seat effort ladder is internally inconsistent")

    def restore(
        self,
        incident_id: str,
        seat: Seat,
        output: Any,
        *,
        effort: Effort,
        escalation_count: int,
        retry_pending: bool = False,
        pending_reason: str | None = None,
    ) -> None:
        """Restore only validated persisted policy state after a process restart."""
        spec = _SPEC_BY_SEAT[seat]
        try:
            effort_index = spec.effort_ladder.index(effort)
        except ValueError as error:
            raise ValueError("persisted effort is outside the seat policy") from error
        if escalation_count != effort_index or escalation_count > spec.max_escalations:
            raise ValueError("persisted escalation count disagrees with effort")
        if retry_pending and (escalation_count == 0 or not pending_reason):
            raise ValueError("pending retry requires a persisted escalation reason")
        if not retry_pending and pending_reason is not None:
            raise ValueError("completed retry cannot retain a pending reason")
        self._states[(incident_id, seat)] = _SeatState(
            effort_index=effort_index,
            escalation_count=escalation_count,
            fingerprint=semantic_fingerprint(seat, output),
            retry_pending=retry_pending,
            pending_reason=pending_reason,
        )

    def current_effort(self, incident_id: str, seat: Seat) -> Effort:
        spec = _SPEC_BY_SEAT[seat]
        state = self._states.get((incident_id, seat))
        return spec.effort_ladder[0 if state is None else state.effort_index]

    def begin_escalation(
        self,
        incident_id: str,
        seat: Seat,
        *,
        reason: str,
    ) -> EscalationDecision:
        key = (incident_id, seat)
        state = self._states.get(key)
        if state is None:
            raise ValueError("cannot escalate before an initial output is recorded")
        spec = _SPEC_BY_SEAT[seat]
        if state.retry_pending:
            raise RuntimeError("an escalation retry is already pending")
        if (
            state.escalation_count >= spec.max_escalations
            or state.effort_index + 1 >= len(spec.effort_ladder)
        ):
            raise EscalationExhausted(f"{seat.value} requires human escalation")
        state.effort_index += 1
        state.escalation_count += 1
        state.retry_pending = True
        state.pending_reason = reason
        return EscalationDecision(
            effort=spec.effort_ladder[state.effort_index],
            escalation_count=state.escalation_count,
            reason=reason,
        )

    def resume_pending_escalation(
        self,
        incident_id: str,
        seat: Seat,
        *,
        reason: str,
    ) -> EscalationDecision | None:
        state = self._states.get((incident_id, seat))
        if state is None or not state.retry_pending:
            return None
        if state.pending_reason != reason:
            raise ValueError("persisted escalation reason disagrees with recovery stage")
        spec = _SPEC_BY_SEAT[seat]
        return EscalationDecision(
            effort=spec.effort_ladder[state.effort_index],
            escalation_count=state.escalation_count,
            reason=reason,
        )

    def accept_retry(self, incident_id: str, seat: Seat, output: Any) -> str:
        state = self._states.get((incident_id, seat))
        if state is None or not state.retry_pending:
            raise ValueError("no escalation retry is pending")
        fingerprint = semantic_fingerprint(seat, output)
        state.retry_pending = False
        state.pending_reason = None
        if fingerprint == state.fingerprint:
            raise DuplicateRetry(f"{seat.value} retry is semantically duplicate")
        state.fingerprint = fingerprint
        return fingerprint
