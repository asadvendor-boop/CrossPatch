"""Credential-free reads of immutable, explicitly published case projections."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status

from crosspatch.api.dependencies import (
    PublicCaseReader,
    PublicCasesUnavailable,
    get_public_case_reader,
)
from crosspatch.api.models import (
    PublishedCaseDetailView,
    PublishedCaseListView,
    PublishedCaseSummaryView,
    PublishedCaseView,
    PublishedEvent,
    PublishedSeatSpendView,
    PublishedVerdictRecordView,
    RoomIncidentView,
    RoomWarrantHistoryView,
)
from crosspatch.domain.enums import Verdict
from crosspatch.domain.hashing import canonical_json
from crosspatch.mcp.published import publicable_for_incident
from crosspatch.public_titles import public_display_title

router = APIRouter(prefix="/api/public/cases", tags=["public cases"])

_REMAND_TARGETS = frozenset({"Prosecutor", "Inspector", "Counsel"})
_SEATS = frozenset({"Prosecutor", "Inspector", "Counsel", "Magistrate", "Bailiff"})
_EFFORTS = frozenset({"none", "low", "medium", "high", "xhigh"})


@dataclass(frozen=True, slots=True)
class _RecordedFacts:
    verdict_path: tuple[str, ...]
    recorded_cost_usd: float
    duration_seconds: float
    evidence_to_verified_seconds: float | None
    human_gate_dwell_seconds: float | None
    execution_verification_seconds: float | None
    seat_spend: tuple[PublishedSeatSpendView, ...]


def _case_view(value: object, *, expected_incident_id: str | None = None) -> PublishedCaseView:
    if not isinstance(value, Mapping):
        raise ValueError("published case envelope is malformed")
    incident_id = value.get("incident_id")
    if not isinstance(incident_id, str):
        raise ValueError("published case incident ID is malformed")
    if expected_incident_id is not None and incident_id != expected_incident_id:
        raise ValueError("published reader returned a different incident")
    normalized = publicable_for_incident(dict(value), incident_id)
    return PublishedCaseView.model_validate(normalized)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("published case timestamps must be timezone-aware")
    return value


def _elapsed_seconds(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    elapsed = (end - start).total_seconds()
    if not math.isfinite(elapsed) or elapsed < 0:
        return None
    return round(elapsed, 3)


def _recorded_facts(
    value: PublishedCaseView,
) -> _RecordedFacts:
    projection = value.projection
    raw_events = projection.get("events")
    if not isinstance(raw_events, list) or len(raw_events) < 2:
        raise ValueError("published case event record is incomplete")
    events = tuple(PublishedEvent.model_validate(item) for item in raw_events)
    if tuple(event.sequence for event in events) != tuple(range(1, len(events) + 1)):
        raise ValueError("published case event sequence is malformed")
    event_times = tuple(_aware(event.created_at) for event in events)
    if any(right < left for left, right in zip(event_times, event_times[1:])):
        raise ValueError("published case event timestamps are malformed")
    if events[0].type != "INCIDENT_OPENED":
        raise ValueError("published case event path does not start with the incident")

    raw_verdicts = projection.get("verdicts")
    if not isinstance(raw_verdicts, list) or not raw_verdicts:
        raise ValueError("published case verdict record is incomplete")
    verdicts = tuple(PublishedVerdictRecordView.model_validate(item) for item in raw_verdicts)
    if any(verdict.incident_id != value.incident_id for verdict in verdicts):
        raise ValueError("published case verdict belongs to a different incident")
    verdict_times = tuple(_aware(verdict.created_at) for verdict in verdicts)
    if any(right < left for left, right in zip(verdict_times, verdict_times[1:])):
        raise ValueError("published case verdict timestamps are malformed")

    event_verdicts: list[Verdict] = []
    event_verdict_times: list[datetime] = []
    verdict_event_indices: list[int] = []
    for index, event in enumerate(events):
        if event.type != "VERDICT":
            continue
        if event.actor != "Magistrate":
            raise ValueError("published verdict event has the wrong actor")
        try:
            verdict = Verdict(event.details["verdict"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("published verdict event is malformed") from error
        remand_target = event.details.get("remand_target")
        if verdict is Verdict.REMAND:
            if remand_target not in _REMAND_TARGETS:
                raise ValueError("published REMAND event has an invalid target")
        elif remand_target is not None:
            raise ValueError("only a REMAND event may include a target")
        event_verdicts.append(verdict)
        event_verdict_times.append(event.created_at)
        verdict_event_indices.append(index)

    verdict_path = tuple(Verdict(verdict.verdict) for verdict in verdicts)
    if tuple(event_verdicts) != verdict_path or tuple(event_verdict_times) != verdict_times:
        raise ValueError("published verdict records and events disagree")
    if verdict_path[-1] is not Verdict.CLEAR or any(
        verdict in {Verdict.BLOCK, Verdict.ABSTAIN} for verdict in verdict_path
    ):
        raise ValueError("published VERIFIED case has an impossible verdict path")

    verified_indices = [index for index, event in enumerate(events) if event.type == "VERIFIED"]
    terminal_clear_index = verdict_event_indices[-1] if verdict_event_indices else -1
    if (
        len(verified_indices) != 1
        or not verdict_event_indices
        or verified_indices[0] <= terminal_clear_index
        or any(
            event.type in {"VERDICT", "TEST_FAILED", "EXECUTION_FAILED"}
            for event in events[terminal_clear_index + 1 :]
        )
    ):
        raise ValueError("published VERIFIED case has an impossible terminal event path")

    costs: list[float] = []
    seat_spend: list[PublishedSeatSpendView] = []
    escalation_by_seat: dict[str, int] = {}
    for event in events:
        if event.type == "REASONING_ESCALATED":
            seat = event.details.get("seat")
            escalation_count = event.details.get("escalation_count")
            effort = event.details.get("effort")
            if (
                not isinstance(seat, str)
                or seat not in _SEATS
                or isinstance(escalation_count, bool)
                or not isinstance(escalation_count, int)
                or not 0 <= escalation_count <= 2
                or not isinstance(effort, str)
                or effort not in _EFFORTS
            ):
                raise ValueError("published reasoning escalation is malformed")
            escalation_by_seat[seat] = escalation_count
            continue
        if event.type != "MODEL_METRICS_RECORDED":
            continue
        cost = event.details.get("cost_usd")
        seat = event.details.get("seat")
        effort = event.details.get("effort")
        if (
            isinstance(cost, bool)
            or not isinstance(cost, (int, float))
            or not math.isfinite(cost)
            or cost < 0
            or not isinstance(seat, str)
            or seat not in _SEATS
            or not isinstance(effort, str)
            or effort not in _EFFORTS
        ):
            raise ValueError("published model spend is malformed")
        costs.append(float(cost))
        seat_spend.append(
            PublishedSeatSpendView(
                seat=seat,
                effort=effort,
                escalation_count=escalation_by_seat.get(seat, 0),
                cost_usd=float(cost),
            )
        )
    if not costs:
        raise ValueError("published case has no recorded model cost")

    duration_seconds = round((event_times[-1] - event_times[0]).total_seconds(), 3)
    if not math.isfinite(duration_seconds) or duration_seconds < 0:
        raise ValueError("published case duration is malformed")

    verified_event = events[verified_indices[0]]
    evidence_event = next(
        (event for event in events if event.type == "EVIDENCE_CAPTURED"),
        None,
    )
    verified_warrant_id = verified_event.details.get("warrant_id")
    execution_event = next(
        (
            event
            for event in events
            if event.type == "EXECUTION_STARTED"
            and isinstance(verified_warrant_id, str)
            and event.details.get("warrant_id") == verified_warrant_id
        ),
        None,
    )

    raw_warrants = projection.get("warrants")
    if not isinstance(raw_warrants, list):
        raise ValueError("published warrant history is malformed")
    warrants = tuple(RoomWarrantHistoryView.model_validate(item) for item in raw_warrants)
    human_gate_dwell_seconds: float | None = None
    for warrant in sorted(warrants, key=lambda item: item.created_at):
        approval = next(
            (
                event
                for event in events
                if event.type == "WARRANT_APPROVED"
                and (
                    event.details.get("warrant_id") == warrant.warrant_id
                    or event.details.get("warrant_sha256") == warrant.canonical_sha256
                )
            ),
            None,
        )
        measured = _elapsed_seconds(
            warrant.created_at,
            approval.created_at if approval is not None else None,
        )
        if measured is not None:
            human_gate_dwell_seconds = measured
            break

    return _RecordedFacts(
        verdict_path=tuple(verdict.value for verdict in verdict_path),
        recorded_cost_usd=round(math.fsum(costs), 12),
        duration_seconds=duration_seconds,
        evidence_to_verified_seconds=_elapsed_seconds(
            evidence_event.created_at if evidence_event is not None else None,
            verified_event.created_at,
        ),
        human_gate_dwell_seconds=human_gate_dwell_seconds,
        execution_verification_seconds=_elapsed_seconds(
            execution_event.created_at if execution_event is not None else None,
            verified_event.created_at,
        ),
        seat_spend=tuple(seat_spend),
    )


def _validate_case(
    value: object,
    *,
    expected_incident_id: str | None = None,
) -> tuple[PublishedCaseView, RoomIncidentView, _RecordedFacts]:
    """Validate the complete immutable publication contract for every read surface."""
    case = _case_view(value, expected_incident_id=expected_incident_id)
    incident = RoomIncidentView.model_validate(case.projection["incident"])
    recorded_facts = _recorded_facts(case)
    if incident.created_at > incident.updated_at:
        raise ValueError("published case incident timestamps are malformed")
    return case, incident, recorded_facts


def _summary(
    value: PublishedCaseView,
    incident: RoomIncidentView,
    recorded_facts: _RecordedFacts,
) -> PublishedCaseSummaryView:
    return PublishedCaseSummaryView(
        incident_id=value.incident_id,
        title=public_display_title(incident.title, incident.scenario),
        state=incident.state,
        scenario=incident.scenario,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        revision=value.revision,
        manifest_sha256=value.manifest_sha256,
        verdict_path=recorded_facts.verdict_path,
        recorded_cost_usd=recorded_facts.recorded_cost_usd,
        duration_seconds=recorded_facts.duration_seconds,
        evidence_to_verified_seconds=(
            recorded_facts.evidence_to_verified_seconds
        ),
        human_gate_dwell_seconds=recorded_facts.human_gate_dwell_seconds,
        execution_verification_seconds=(
            recorded_facts.execution_verification_seconds
        ),
        seat_spend=recorded_facts.seat_spend,
    )


@router.get("", response_model=PublishedCaseListView)
async def list_public_cases(
    reader: PublicCaseReader = Depends(get_public_case_reader),
) -> PublishedCaseListView:
    try:
        values = await reader.list_public_cases()
        if not isinstance(values, Sequence):
            raise ValueError("published case list is malformed")
        cases = tuple(_summary(*_validate_case(value)) for value in values)
        return PublishedCaseListView(cases=cases)
    except PublicCasesUnavailable:
        raise
    except Exception as error:
        raise PublicCasesUnavailable from error


@router.get("/{incident_id}", response_model=PublishedCaseDetailView)
async def get_public_case(
    incident_id: str,
    reader: PublicCaseReader = Depends(get_public_case_reader),
) -> PublishedCaseDetailView:
    try:
        value = await reader.get_public_case(incident_id)
    except LookupError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="case not found",
        ) from error
    except PublicCasesUnavailable:
        raise
    except Exception as error:
        raise PublicCasesUnavailable from error
    try:
        case, incident, _ = _validate_case(value, expected_incident_id=incident_id)
        return PublishedCaseDetailView.model_validate(
            {
                **case.model_dump(mode="python"),
                "display_title": public_display_title(incident.title, incident.scenario),
                "canonical_projection_json": canonical_json(case.projection).decode("utf-8"),
            }
        )
    except Exception as error:
        raise PublicCasesUnavailable from error
