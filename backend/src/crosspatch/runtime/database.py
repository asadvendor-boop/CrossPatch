"""Database lifecycle and durable runtime repositories."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from crosspatch.agents.schemas import CounselOutput, SeatOutput
from crosspatch.broker.broker import BrokerResult, BrokerStatus, WarrantState
from crosspatch.broker.paths import derive_patch_paths
from crosspatch.db.base import Base
from crosspatch.db.migrations import (
    configure_control_roles,
    ensure_published_case_boundary,
    install_append_only_guards,
    install_warrant_guards,
)
from crosspatch.db.models import (
    AgentRunRecord,
    ApiIncidentGrantRecord,
    ApiPrincipalRecord,
    ControlWarrantRecord,
    EvidenceRecord,
    IncidentRecord,
    PatchCandidateRecord,
    PublishedCaseRecord,
    RuntimeWorkRecord,
    TestRunRecord,
    TimelineEventRecord,
    VerdictRecord,
    WarrantRecord,
)
from crosspatch.domain.enums import Effort, IncidentState, Seat
from crosspatch.domain.hashing import canonical_json, semantic_fingerprint, sha256_hex
from crosspatch.domain.seats import SEAT_SPECS
from crosspatch.domain.state_machine import (
    STATE_EVENT_TYPES,
    EventChainCorrupted,
    transition_incident,
    typed_event_from_payload,
)
from crosspatch.evidence.sanitizer import sanitize_evidence
from crosspatch.evidence.views import UntrustedEvidenceEnvelope
from crosspatch.public_titles import require_publishable_title
from crosspatch.runner.results import ProcessReceipt
from crosspatch.runtime.projection import (
    published_event_details,
    published_specialist_summaries,
    published_trusted_observation,
    published_warrant_history,
)
from crosspatch.runtime.scenarios import require_operator_evidence_profile

ZERO_EVENT_HASH = "0" * 64
_SPEC_BY_SEAT = {spec.seat: spec for spec in SEAT_SPECS}

APPROVED_EXECUTION_WORK = "APPROVED_EXECUTION"
TEST_REPAIR_WORK = "TEST_REPAIR"


def execution_work_id(warrant_id: str) -> str:
    return f"execute:{warrant_id}"


def repair_work_id(warrant_id: str) -> str:
    return f"repair:{warrant_id}"


def broker_receipt_result(
    receipt: Any,
    *,
    warrant_id: str,
    evidence_id: str,
) -> dict[str, Any]:
    """Derive the only valid persisted test outcome from a broker receipt."""
    try:
        receipt_json = receipt.model_dump(mode="json")
    except (AttributeError, TypeError) as error:
        raise ValueError("broker receipt is not serializable") from error
    receipt = ProcessReceipt.model_validate(receipt_json)
    receipt_json = receipt.model_dump(mode="json")
    duration_ms = max(
        0,
        round(
            (aware_utc(receipt.finished_at) - aware_utc(receipt.started_at)).total_seconds() * 1000
        ),
    )
    return {
        "warrant_id": warrant_id,
        "state": "passed" if receipt.passed else "failed",
        "passed": receipt.passed,
        "duration_ms": duration_ms,
        "detail": receipt.verification_code,
        "evidence_id": evidence_id,
        "receipt_sha256": sha256_hex(receipt_json),
        "receipt": receipt_json,
    }


def _sanitize_projection_text(value: str, provenance: str) -> str:
    """Apply the evidence sanitizer before untrusted text enters a projection."""
    if not isinstance(value, str):
        raise ValueError("public projection text must be a string")
    return sanitize_evidence(value.encode("utf-8"), provenance).text


def aware_utc(value: datetime) -> datetime:
    """Normalize database timestamps, including SQLite's naive round-trip."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _sync_url(value: str) -> str:
    parsed = make_url(value)
    if parsed.drivername == "sqlite+aiosqlite":
        parsed = parsed.set(drivername="sqlite")
    elif parsed.drivername in {"postgresql+asyncpg", "postgresql"}:
        parsed = parsed.set(drivername="postgresql+psycopg")
    return parsed.render_as_string(hide_password=False)


def _async_url(value: str) -> str:
    parsed = make_url(value)
    if parsed.drivername == "sqlite":
        parsed = parsed.set(drivername="sqlite+aiosqlite")
    elif parsed.drivername in {"postgresql", "postgresql+psycopg"}:
        parsed = parsed.set(drivername="postgresql+asyncpg")
    return parsed.render_as_string(hide_password=False)


class RuntimeStore:
    """One transaction-oriented store shared by runtime service adapters."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def fail_closed_interrupted_incidents(self) -> int:
        """Make model/reproduction work lost to a process restart visibly terminal."""
        interrupted_states = {
            IncidentState.OPEN.value,
            IncidentState.REPRODUCING.value,
            IncidentState.EVIDENCE_READY.value,
            IncidentState.ANALYZING.value,
            IncidentState.PATCHING.value,
            IncidentState.REVIEWING.value,
        }
        now = datetime.now(UTC)
        active_runtime_work = (
            select(RuntimeWorkRecord.id)
            .where(RuntimeWorkRecord.incident_id == IncidentRecord.id)
            .where(RuntimeWorkRecord.status.in_({"PENDING", "RUNNING"}))
            .exists()
        )
        async with self.sessions() as session, session.begin():
            incidents = tuple(
                (
                    await session.scalars(
                        select(IncidentRecord)
                        .where(IncidentRecord.state.in_(interrupted_states))
                        .where(~active_runtime_work)
                        .order_by(IncidentRecord.created_at, IncidentRecord.id)
                        .with_for_update()
                    )
                ).all()
            )
            for incident in incidents:
                await self._append_locked(
                    session,
                    incident,
                    "BACKGROUND_TASK_FAILED",
                    "control-service",
                    {
                        "operation": "startup-reconciliation",
                        "failure_outcome": "PROCESS_RESTART",
                    },
                    now=now,
                )
                await self._publish_locked(session, incident.id, now)
            return len(incidents)

    async def _enqueue_runtime_work_locked(
        self,
        session: AsyncSession,
        *,
        incident_id: str,
        warrant_id: str,
        kind: str,
        now: datetime,
    ) -> RuntimeWorkRecord:
        if kind == APPROVED_EXECUTION_WORK:
            work_id = execution_work_id(warrant_id)
        elif kind == TEST_REPAIR_WORK:
            work_id = repair_work_id(warrant_id)
        else:
            raise ValueError("runtime work kind is invalid")
        existing = await session.get(RuntimeWorkRecord, work_id)
        if existing is not None:
            if (
                existing.incident_id != incident_id
                or existing.warrant_id != warrant_id
                or existing.kind != kind
            ):
                raise ValueError("runtime work binding changed")
            return existing
        record = RuntimeWorkRecord(
            id=work_id,
            incident_id=incident_id,
            warrant_id=warrant_id,
            kind=kind,
            status="PENDING",
            attempt_count=0,
            created_at=now,
            updated_at=now,
        )
        session.add(record)
        await session.flush()
        return record

    async def requeue_interrupted_runtime_work(self) -> None:
        """Release work owned by the previous, now-dead service process."""
        now = datetime.now(UTC)
        async with self.sessions() as session, session.begin():
            rows = tuple(
                (
                    await session.scalars(
                        select(RuntimeWorkRecord)
                        .where(RuntimeWorkRecord.status == "RUNNING")
                        .with_for_update()
                    )
                ).all()
            )
            for row in rows:
                incident = await session.scalar(
                    select(IncidentRecord)
                    .where(IncidentRecord.id == row.incident_id)
                    .with_for_update()
                )
                if incident is None:
                    raise LookupError(row.incident_id)
                if incident.state in {
                    IncidentState.HUMAN_ESCALATION.value,
                    IncidentState.BLOCKED.value,
                    IncidentState.VERIFIED.value,
                }:
                    row.status = "COMPLETED"
                    row.completed_at = now
                else:
                    row.status = "PENDING"
                row.owner_id = None
                row.updated_at = now

    async def pending_runtime_work(self) -> tuple[RuntimeWorkRecord, ...]:
        async with self.sessions() as session:
            return tuple(
                (
                    await session.scalars(
                        select(RuntimeWorkRecord)
                        .where(RuntimeWorkRecord.status == "PENDING")
                        .order_by(RuntimeWorkRecord.created_at, RuntimeWorkRecord.id)
                    )
                ).all()
            )

    async def claim_runtime_work(
        self,
        work_id: str,
        *,
        owner_id: str,
    ) -> RuntimeWorkRecord | None:
        now = datetime.now(UTC)
        async with self.sessions() as session, session.begin():
            work = await session.scalar(
                select(RuntimeWorkRecord).where(RuntimeWorkRecord.id == work_id).with_for_update()
            )
            if work is None or work.status != "PENDING":
                return None
            incident = await session.scalar(
                select(IncidentRecord)
                .where(IncidentRecord.id == work.incident_id)
                .with_for_update()
            )
            if incident is None:
                raise LookupError(work.incident_id)
            if work.kind == APPROVED_EXECUTION_WORK and incident.state != (
                IncidentState.APPROVED.value
            ):
                if incident.state in {
                    IncidentState.HUMAN_ESCALATION.value,
                    IncidentState.BLOCKED.value,
                    IncidentState.VERIFIED.value,
                }:
                    work.status = "COMPLETED"
                    work.owner_id = None
                    work.updated_at = now
                    work.completed_at = now
                    return None
                raise ValueError("approved execution work disagrees with incident state")
            work.status = "RUNNING"
            work.owner_id = owner_id
            work.attempt_count += 1
            work.updated_at = now
            await session.flush()
            return work

    async def fail_runtime_work(
        self,
        work_id: str,
        *,
        operation: str,
        failure_outcome: str,
    ) -> None:
        """Atomically publish fail-closed state and retire its delivery marker."""
        now = datetime.now(UTC)
        async with self.sessions() as session, session.begin():
            work = await session.scalar(
                select(RuntimeWorkRecord).where(RuntimeWorkRecord.id == work_id).with_for_update()
            )
            if work is None:
                raise LookupError(work_id)
            incident = await session.scalar(
                select(IncidentRecord)
                .where(IncidentRecord.id == work.incident_id)
                .with_for_update()
            )
            if incident is None:
                raise LookupError(work.incident_id)
            if work.status == "COMPLETED":
                if incident.state not in {
                    IncidentState.HUMAN_ESCALATION.value,
                    IncidentState.BLOCKED.value,
                    IncidentState.VERIFIED.value,
                }:
                    raise ValueError("completed failed work is not fail closed")
                return
            active = {
                IncidentState.OPEN.value,
                IncidentState.REPRODUCING.value,
                IncidentState.EVIDENCE_READY.value,
                IncidentState.ANALYZING.value,
                IncidentState.PATCHING.value,
                IncidentState.REVIEWING.value,
                IncidentState.APPROVED.value,
                IncidentState.EXECUTING.value,
                IncidentState.TEST_FAILED.value,
            }
            await self._append_locked(
                session,
                incident,
                (
                    "BACKGROUND_TASK_FAILED"
                    if incident.state in active
                    else "BACKGROUND_TASK_ERROR_REPORTED"
                ),
                "control-service",
                {
                    "operation": operation,
                    "failure_outcome": failure_outcome,
                },
                now=now,
            )
            work.status = "COMPLETED"
            work.owner_id = None
            work.updated_at = now
            work.completed_at = now
            await self._publish_locked(session, incident.id, now)

    async def complete_repair_work(
        self,
        incident_id: str,
        warrant_id: str,
    ) -> None:
        """A repair marker closes only after a durable authority outcome exists."""
        now = datetime.now(UTC)
        async with self.sessions() as session, session.begin():
            incident = await session.scalar(
                select(IncidentRecord).where(IncidentRecord.id == incident_id).with_for_update()
            )
            work = await session.scalar(
                select(RuntimeWorkRecord)
                .where(RuntimeWorkRecord.id == repair_work_id(warrant_id))
                .with_for_update()
            )
            if incident is None or work is None:
                raise LookupError(repair_work_id(warrant_id))
            if not await self._repair_has_durable_outcome_locked(
                session,
                incident,
                warrant_id,
            ):
                raise ValueError("repair work has no durable terminal authority outcome")
            work.status = "COMPLETED"
            work.owner_id = None
            work.updated_at = now
            work.completed_at = now

    async def _repair_has_durable_outcome_locked(
        self,
        session: AsyncSession,
        incident: IncidentRecord,
        warrant_id: str,
    ) -> bool:
        if incident.state in {
            IncidentState.HUMAN_ESCALATION.value,
            IncidentState.BLOCKED.value,
        }:
            return True
        latest = await session.scalar(
            select(ControlWarrantRecord)
            .where(ControlWarrantRecord.incident_id == incident.id)
            .order_by(
                ControlWarrantRecord.created_at.desc(),
                ControlWarrantRecord.id.desc(),
            )
            .limit(1)
        )
        # A different warrant can only be opened by the completed repair cycle.
        # Its later approval/execution/failure therefore remains terminal proof
        # for this older repair marker and must never rerun the old model work.
        return latest is not None and latest.id != warrant_id

    async def repair_has_durable_outcome(
        self,
        incident_id: str,
        warrant_id: str,
    ) -> bool:
        async with self.sessions() as session:
            incident = await session.get(IncidentRecord, incident_id)
            if incident is None:
                raise LookupError(incident_id)
            return await self._repair_has_durable_outcome_locked(
                session,
                incident,
                warrant_id,
            )

    async def create_incident(
        self,
        *,
        incident_id: str,
        title: str,
        scenario: str,
        state: IncidentState,
        base_sha: str,
        repository_manifest_sha256: str,
        catalog_sha256: str,
        actor: str,
        live_trial: bool = False,
        evidence_profile: str = "standard",
    ) -> IncidentRecord:
        profile = require_operator_evidence_profile(scenario, evidence_profile)
        now = datetime.now(UTC)
        record = IncidentRecord(
            id=incident_id,
            title=title,
            scenario=scenario,
            live_trial=live_trial,
            owner_subject=actor,
            state=state.value,
            base_sha=base_sha,
            repository_manifest_sha256=repository_manifest_sha256,
            catalog_sha256=catalog_sha256,
            next_event_sequence=1,
            created_at=now,
            updated_at=now,
        )
        async with self.sessions() as session, session.begin():
            session.add(record)
            await session.flush()
            await self._grant_incident(session, incident_id, actor, now)
            opening_payload = {"scenario": scenario}
            if profile != "standard":
                opening_payload["evidence_profile"] = profile
            await self._append_locked(
                session,
                record,
                "INCIDENT_OPENED",
                actor,
                opening_payload,
                now=now,
            )
            await self._publish_locked(session, incident_id, now)
        return record

    async def incident_evidence_profile(self, incident_id: str) -> str:
        async with self.sessions() as session:
            opening = await session.scalar(
                select(TimelineEventRecord).where(
                    TimelineEventRecord.incident_id == incident_id,
                    TimelineEventRecord.sequence == 1,
                    TimelineEventRecord.type == "INCIDENT_OPENED",
                )
            )
        if opening is None:
            raise EventChainCorrupted("incident opening event is unavailable")
        scenario = opening.payload.get("scenario")
        profile = opening.payload.get("evidence_profile", "standard")
        if not isinstance(scenario, str) or not isinstance(profile, str):
            raise EventChainCorrupted("incident opening evidence profile is malformed")
        try:
            return require_operator_evidence_profile(scenario, profile)
        except ValueError as error:
            raise EventChainCorrupted(
                "incident opening evidence profile is invalid"
            ) from error

    async def _grant_incident(
        self,
        session: AsyncSession,
        incident_id: str,
        actor: str,
        now: datetime,
    ) -> None:
        principals = tuple(
            (
                await session.scalars(
                    select(ApiPrincipalRecord).where(
                        (ApiPrincipalRecord.subject == actor)
                        | (ApiPrincipalRecord.role == "approver")
                        | (ApiPrincipalRecord.role == "read_only")
                    )
                )
            ).all()
        )
        for principal in principals:
            existing = await session.scalar(
                select(ApiIncidentGrantRecord).where(
                    ApiIncidentGrantRecord.subject == principal.subject,
                    ApiIncidentGrantRecord.incident_id == incident_id,
                )
            )
            if existing is None:
                session.add(
                    ApiIncidentGrantRecord(
                        id=f"grant_{uuid4().hex}",
                        subject=principal.subject,
                        incident_id=incident_id,
                        created_at=now,
                    )
                )

    async def get_incident_record(self, incident_id: str) -> IncidentRecord | None:
        async with self.sessions() as session:
            return await session.get(IncidentRecord, incident_id)

    async def incident_records(self, *, published_only: bool = False) -> tuple[IncidentRecord, ...]:
        del published_only  # Publication is represented by the projection row.
        async with self.sessions() as session:
            values = await session.scalars(
                select(IncidentRecord).order_by(IncidentRecord.created_at)
            )
            return tuple(values)

    async def append_event(
        self,
        incident_id: str,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
        *,
        published: bool = True,
    ) -> TimelineEventRecord:
        async with self.sessions() as session, session.begin():
            incident = await session.scalar(
                select(IncidentRecord).where(IncidentRecord.id == incident_id).with_for_update()
            )
            if incident is None:
                raise LookupError(incident_id)
            event = await self._append_locked(
                session,
                incident,
                event_type,
                actor,
                payload,
                published=published,
            )
            if published:
                await self._publish_locked(session, incident_id, event.created_at)
            return event

    async def _append_locked(
        self,
        session: AsyncSession,
        incident: IncidentRecord,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
        *,
        published: bool = True,
        now: datetime | None = None,
    ) -> TimelineEventRecord:
        last = await session.scalar(
            select(TimelineEventRecord)
            .where(TimelineEventRecord.incident_id == incident.id)
            .order_by(TimelineEventRecord.sequence.desc())
            .limit(1)
        )
        sequence = 1 if last is None else last.sequence + 1
        previous_hash = ZERO_EVENT_HASH if last is None else last.event_hash
        expected_head = None if last is None else last.event_hash
        if incident.next_event_sequence != sequence or incident.event_chain_head != expected_head:
            raise EventChainCorrupted("incident metadata disagrees with durable timeline")
        next_state: IncidentState | None = None
        if event_type in STATE_EVENT_TYPES:
            typed = typed_event_from_payload(event_type, payload)
            next_state = transition_incident(IncidentState(incident.state), typed)
        created_at = now or datetime.now(UTC)
        event_hash = sha256_hex(
            {
                "incident_id": incident.id,
                "sequence": sequence,
                "type": event_type,
                "actor": actor,
                "payload": payload,
                "previous_hash": previous_hash,
                "created_at": created_at,
            }
        )
        event = TimelineEventRecord(
            id=f"evt_{uuid4().hex}",
            incident_id=incident.id,
            sequence=sequence,
            type=event_type,
            actor=actor,
            payload=payload,
            previous_hash=previous_hash,
            event_hash=event_hash,
            published=published,
            created_at=created_at,
        )
        session.add(event)
        incident.next_event_sequence = sequence + 1
        incident.event_chain_head = event_hash
        incident.updated_at = created_at
        if next_state is not None:
            incident.state = next_state.value
        await session.flush()
        return event

    async def timeline_records(
        self,
        incident_id: str,
        *,
        after: int = 0,
        limit: int = 500,
        published_only: bool = False,
    ) -> tuple[TimelineEventRecord, ...]:
        statement = (
            select(TimelineEventRecord)
            .where(
                TimelineEventRecord.incident_id == incident_id,
                TimelineEventRecord.sequence > after,
            )
            .order_by(TimelineEventRecord.sequence)
            .limit(limit)
        )
        if published_only:
            statement = statement.where(TimelineEventRecord.published.is_(True))
        async with self.sessions() as session:
            return tuple((await session.scalars(statement)).all())

    async def record_evidence(
        self,
        evidence_id: str,
        envelope: UntrustedEvidenceEnvelope,
        *,
        published: bool,
    ) -> EvidenceRecord:
        now = datetime.now(UTC)
        encoded = canonical_json(envelope)
        record = EvidenceRecord(
            id=evidence_id,
            incident_id=envelope.incident_id,
            kind=envelope.kind.value,
            provenance=envelope.provenance,
            sanitized_text=envelope.text,
            raw_sha256=envelope.raw_sha256,
            sanitized_sha256=envelope.sanitized_sha256,
            envelope_json=encoded,
            tags=[tag.model_dump(mode="json") for tag in envelope.tags],
            published=published,
            created_at=now,
        )
        async with self.sessions() as session, session.begin():
            session.add(record)
            await session.flush()
            if published:
                await self._publish_locked(session, envelope.incident_id, now)
        return record

    async def evidence_records(
        self,
        incident_id: str,
        *,
        published_only: bool = True,
    ) -> tuple[EvidenceRecord, ...]:
        statement = select(EvidenceRecord).where(EvidenceRecord.incident_id == incident_id)
        if published_only:
            statement = statement.where(EvidenceRecord.published.is_(True))
        statement = statement.order_by(EvidenceRecord.created_at, EvidenceRecord.id)
        async with self.sessions() as session:
            return tuple((await session.scalars(statement)).all())

    async def get_evidence_record(
        self,
        incident_id: str,
        evidence_id: str,
        *,
        published_only: bool = True,
    ) -> EvidenceRecord | None:
        statement = select(EvidenceRecord).where(
            EvidenceRecord.id == evidence_id,
            EvidenceRecord.incident_id == incident_id,
        )
        if published_only:
            statement = statement.where(EvidenceRecord.published.is_(True))
        async with self.sessions() as session:
            return await session.scalar(statement)

    async def add_agent_run(self, record: AgentRunRecord) -> None:
        await self.add_agent_runs((record,))

    async def add_agent_runs(self, records: tuple[AgentRunRecord, ...]) -> None:
        if not records:
            raise ValueError("at least one agent run is required")
        incident_ids = {record.incident_id for record in records}
        if len(incident_ids) != 1:
            raise ValueError("agent runs must belong to one incident")
        async with self.sessions() as session, session.begin():
            session.add_all(records)
            await session.flush()
            await self._publish_locked(
                session,
                records[0].incident_id,
                max(record.created_at for record in records),
            )

    async def prepare_seat(self, incident_id: str, seat: Seat, phase: str) -> None:
        """Publish the real seat start and enter PATCHING only when Counsel begins."""
        async with self.sessions() as session, session.begin():
            incident = await session.scalar(
                select(IncidentRecord).where(IncidentRecord.id == incident_id).with_for_update()
            )
            if incident is None:
                raise LookupError(incident_id)
            if seat is Seat.COUNSEL and incident.state == IncidentState.ANALYZING.value:
                await self._append_locked(
                    session,
                    incident,
                    "PATCH_REQUESTED",
                    "orchestrator",
                    {"phase": phase},
                )
            await self._append_locked(
                session,
                incident,
                "SEAT_STARTED",
                seat.value,
                {"seat": seat.value, "phase": phase},
            )
            await self._publish_locked(session, incident_id, datetime.now(UTC))

    async def record_seat_output(
        self,
        *,
        incident_id: str,
        seat: Seat,
        effort: Effort,
        phase: str,
        output: SeatOutput,
        escalation_count: int = 0,
    ) -> AgentRunRecord:
        """Atomically persist a validated structured output and its timeline facts."""
        encoded = canonical_json(output)
        now = datetime.now(UTC)
        run = AgentRunRecord(
            id=f"run_{uuid4().hex}",
            incident_id=incident_id,
            seat=seat.value,
            model=_SPEC_BY_SEAT[seat].model,
            effort=effort.value,
            phase=phase,
            escalation_count=escalation_count,
            output_json=encoded,
            output_sha256=hashlib.sha256(encoded).hexdigest(),
            semantic_sha256=semantic_fingerprint(seat, output),
            schema_status="VALID",
            created_at=now,
        )
        async with self.sessions() as session, session.begin():
            incident = await session.scalar(
                select(IncidentRecord).where(IncidentRecord.id == incident_id).with_for_update()
            )
            if incident is None:
                raise LookupError(incident_id)
            session.add(run)
            await session.flush()
            candidate: PatchCandidateRecord | None = None
            if isinstance(output, CounselOutput):
                patch = output.normalized_diff.encode("utf-8")
                predecessor = await session.scalar(
                    select(PatchCandidateRecord)
                    .where(PatchCandidateRecord.incident_id == incident_id)
                    .order_by(
                        PatchCandidateRecord.created_at.desc(),
                        PatchCandidateRecord.id.desc(),
                    )
                    .limit(1)
                )
                candidate = PatchCandidateRecord(
                    id=f"candidate_{uuid4().hex}",
                    incident_id=incident_id,
                    agent_run_id=run.id,
                    patch_sha256=hashlib.sha256(patch).hexdigest(),
                    normalized_diff=output.normalized_diff,
                    allowed_paths=list(derive_patch_paths(patch)),
                    test_intentions=[
                        item.model_dump(mode="json") for item in output.test_intentions
                    ],
                    predecessor_id=(predecessor.id if predecessor is not None else None),
                    created_at=now,
                )
                session.add(candidate)
            await self._append_locked(
                session,
                incident,
                "AGENT_OUTPUT_RECORDED",
                seat.value,
                {
                    "seat": seat.value,
                    "phase": phase,
                    "effort": effort.value,
                    "output_sha256": run.output_sha256,
                    "semantic_sha256": run.semantic_sha256,
                },
                now=now,
            )
            if candidate is not None and incident.state == IncidentState.PATCHING.value:
                await self._append_locked(
                    session,
                    incident,
                    "PATCH_PROPOSED",
                    Seat.COUNSEL.value,
                    {
                        "candidate_id": candidate.id,
                        "patch_sha256": candidate.patch_sha256,
                    },
                    now=now,
                )
            await self._publish_locked(session, incident_id, now)
        return run

    async def add_patch_candidate(self, record: PatchCandidateRecord) -> None:
        async with self.sessions() as session, session.begin():
            session.add(record)

    async def add_verdict(self, record: VerdictRecord) -> None:
        async with self.sessions() as session, session.begin():
            session.add(record)

    async def record_test_run(
        self,
        record: TestRunRecord,
        *,
        event_type: str,
        event_payload: dict[str, Any],
    ) -> None:
        """Atomically publish a deterministic receipt and its typed outcome event."""
        async with self.sessions() as session, session.begin():
            incident = await session.scalar(
                select(IncidentRecord)
                .where(IncidentRecord.id == record.incident_id)
                .with_for_update()
            )
            if incident is None:
                raise LookupError(record.incident_id)
            session.add(record)
            await self._append_locked(
                session,
                incident,
                event_type,
                "deterministic-runner",
                event_payload,
                now=record.created_at,
            )
            await self._publish_locked(session, record.incident_id, record.created_at)

    async def control_warrant(self, warrant_id: str) -> ControlWarrantRecord | None:
        async with self.sessions() as session:
            return await session.get(ControlWarrantRecord, warrant_id)

    async def completed_broker_result_bytes(self, incident_id: str, warrant_id: str) -> bytes:
        async with self.sessions() as session:
            record = await session.scalar(
                select(WarrantRecord).where(
                    WarrantRecord.id == warrant_id,
                    WarrantRecord.incident_id == incident_id,
                    WarrantRecord.state == WarrantState.CONSUMED.value,
                    WarrantRecord.result_json.is_not(None),
                )
            )
            if record is None or record.result_json is None:
                raise LookupError(warrant_id)
            return bytes(record.result_json)

    async def latest_agent_runs(self, incident_id: str) -> tuple[AgentRunRecord, ...]:
        async with self.sessions() as session:
            rows = tuple(
                (
                    await session.scalars(
                        select(AgentRunRecord)
                        .where(
                            AgentRunRecord.incident_id == incident_id,
                            AgentRunRecord.schema_status == "VALID",
                        )
                        .order_by(AgentRunRecord.created_at, AgentRunRecord.id)
                    )
                ).all()
            )
        latest: dict[str, AgentRunRecord] = {}
        for row in rows:
            latest[row.seat] = row
        return tuple(latest[seat.value] for seat in Seat if seat.value in latest)

    async def latest_candidate(self, incident_id: str) -> PatchCandidateRecord | None:
        async with self.sessions() as session:
            return await session.scalar(
                select(PatchCandidateRecord)
                .where(PatchCandidateRecord.incident_id == incident_id)
                .order_by(
                    PatchCandidateRecord.created_at.desc(),
                    PatchCandidateRecord.id.desc(),
                )
                .limit(1)
            )

    async def evidence_manifest_sha256(self, incident_id: str) -> str:
        records = await self.evidence_records(incident_id)
        return sha256_hex(tuple((record.id, record.sanitized_sha256) for record in records))

    async def _projected_broker_result_locked(
        self,
        session: AsyncSession,
        incident: IncidentRecord,
        record: WarrantRecord,
        result: BrokerResult,
    ) -> BrokerResult | None:
        rows = tuple(
            (
                await session.scalars(
                    select(TestRunRecord)
                    .where(TestRunRecord.incident_id == incident.id)
                    .order_by(TestRunRecord.created_at, TestRunRecord.id)
                )
            ).all()
        )
        rows = tuple(row for row in rows if row.result.get("warrant_id") == record.id)
        if not rows:
            return None
        expected_state = (
            IncidentState.VERIFIED.value
            if result.status is BrokerStatus.EXECUTED
            else IncidentState.TEST_FAILED.value
        )
        receipts = tuple(result.receipts)
        by_plan = {(row.plan_id, row.plan_sha256): row for row in rows}
        evidence_ids = {
            row.result.get("evidence_id")
            for row in rows
            if isinstance(row.result.get("evidence_id"), str)
        }
        outcome_type = "VERIFIED" if result.status is BrokerStatus.EXECUTED else "TEST_FAILED"
        outcome_events = tuple(
            (
                await session.scalars(
                    select(TimelineEventRecord).where(
                        TimelineEventRecord.incident_id == incident.id,
                        TimelineEventRecord.type == outcome_type,
                    )
                )
            ).all()
        )
        outcome_events = tuple(
            event for event in outcome_events if event.payload.get("warrant_id") == record.id
        )
        work = await session.get(RuntimeWorkRecord, execution_work_id(record.id))
        repair = await session.get(RuntimeWorkRecord, repair_work_id(record.id))
        valid = (
            incident.state == expected_state
            and len(rows) == len(receipts) == len(by_plan)
            and len(evidence_ids) == 1
            and len(outcome_events) == 1
            and work is not None
            and work.status == "COMPLETED"
            and (
                result.status is BrokerStatus.EXECUTED
                or (repair is not None and repair.kind == TEST_REPAIR_WORK)
            )
        )
        if valid:
            evidence_id = next(iter(evidence_ids))
            event = outcome_events[0]
            outcome_row_id = event.payload.get(
                "receipt_id" if outcome_type == "VERIFIED" else "test_run_id"
            )
            valid = event.payload.get("evidence_id") == evidence_id and outcome_row_id in {
                row.id for row in rows
            }
            for receipt in receipts:
                row = by_plan.get((receipt.plan_id, receipt.plan_sha256))
                valid = bool(
                    valid
                    and row is not None
                    and row.result
                    == broker_receipt_result(
                        receipt,
                        warrant_id=record.id,
                        evidence_id=evidence_id,
                    )
                )
        if not valid:
            raise ValueError("persisted broker projection is contradictory")
        return result

    async def projected_broker_result(
        self,
        incident_id: str,
        warrant_id: str,
    ) -> BrokerResult | None:
        async with self.sessions() as session:
            incident = await session.get(IncidentRecord, incident_id)
            record = await session.get(WarrantRecord, warrant_id)
            if incident is None or record is None:
                raise LookupError(warrant_id)
            if record.result_json is None:
                return None
            result = BrokerResult.model_validate_json(record.result_json)
            return await self._projected_broker_result_locked(
                session,
                incident,
                record,
                result,
            )

    async def project_broker_result(
        self,
        incident_id: str,
        warrant_id: str,
        *,
        evidence_id: str,
    ) -> BrokerResult:
        """Project only the canonical broker-owned result into typed incident state."""
        now = datetime.now(UTC)
        async with self.sessions() as session, session.begin():
            incident = await session.scalar(
                select(IncidentRecord).where(IncidentRecord.id == incident_id).with_for_update()
            )
            record = await session.scalar(
                select(WarrantRecord).where(
                    WarrantRecord.id == warrant_id,
                    WarrantRecord.incident_id == incident_id,
                )
            )
            if incident is None or record is None:
                raise LookupError(warrant_id)
            if (
                record.state != WarrantState.CONSUMED.value
                or record.result_json is None
                or record.claimed_at is None
                or record.finished_at is None
            ):
                raise ValueError("broker result is not durably complete")
            result = BrokerResult.model_validate_json(record.result_json)
            if canonical_json(result) != record.result_json or result.warrant_id != warrant_id:
                raise ValueError("broker result canonical binding is invalid")
            if result.nonce_sha256 is None or not hmac.compare_digest(
                result.nonce_sha256, record.nonce_sha256
            ):
                raise ValueError("broker result nonce binding is invalid")
            if not result.receipts:
                raise ValueError("broker result has no trusted test receipt")
            passed = all(receipt.passed for receipt in result.receipts)
            if (result.status is BrokerStatus.EXECUTED) != passed:
                raise ValueError("broker status disagrees with trusted receipts")
            if result.status not in {BrokerStatus.EXECUTED, BrokerStatus.TEST_FAILED}:
                raise ValueError("broker result is not a projectable execution outcome")
            projected = await self._projected_broker_result_locked(
                session,
                incident,
                record,
                result,
            )
            if projected is not None:
                return projected

            claim_material = f"{warrant_id}:{aware_utc(record.claimed_at).isoformat()}".encode(
                "ascii"
            )
            claim_id = f"claim_{hashlib.sha256(claim_material).hexdigest()[:32]}"
            await self._append_locked(
                session,
                incident,
                "EXECUTION_STARTED",
                "broker",
                {"claim_id": claim_id, "warrant_id": warrant_id},
                now=now,
            )
            test_run_ids: list[str] = []
            for receipt in result.receipts:
                test_run_id = f"test_{uuid4().hex}"
                test_run_ids.append(test_run_id)
                session.add(
                    TestRunRecord(
                        id=test_run_id,
                        incident_id=incident_id,
                        plan_id=receipt.plan_id,
                        plan_sha256=receipt.plan_sha256,
                        result=broker_receipt_result(
                            receipt,
                            warrant_id=warrant_id,
                            evidence_id=evidence_id,
                        ),
                        created_at=now,
                    )
                )
            if passed:
                await self._append_locked(
                    session,
                    incident,
                    "VERIFIED",
                    "broker",
                    {
                        "receipt_id": test_run_ids[-1],
                        "warrant_id": warrant_id,
                        "evidence_id": evidence_id,
                    },
                    now=now,
                )
            else:
                await self._append_locked(
                    session,
                    incident,
                    "TEST_FAILED",
                    "broker",
                    {
                        "test_run_id": test_run_ids[-1],
                        "warrant_id": warrant_id,
                        "evidence_id": evidence_id,
                    },
                    now=now,
                )
            execution_work = await session.get(
                RuntimeWorkRecord,
                execution_work_id(warrant_id),
            )
            if (
                execution_work is None
                or execution_work.incident_id != incident_id
                or execution_work.warrant_id != warrant_id
                or execution_work.kind != APPROVED_EXECUTION_WORK
            ):
                raise ValueError("broker result has no matching durable execution work")
            execution_work.status = "COMPLETED"
            execution_work.owner_id = None
            execution_work.updated_at = now
            execution_work.completed_at = now
            if not passed:
                await self._enqueue_runtime_work_locked(
                    session,
                    incident_id=incident_id,
                    warrant_id=warrant_id,
                    kind=TEST_REPAIR_WORK,
                    now=now,
                )
            await self._publish_locked(session, incident_id, now)
            return result

    async def record_execution_failure(
        self,
        incident_id: str,
        warrant_id: str,
        *,
        error_code: str,
    ) -> None:
        now = datetime.now(UTC)
        async with self.sessions() as session, session.begin():
            incident = await session.scalar(
                select(IncidentRecord).where(IncidentRecord.id == incident_id).with_for_update()
            )
            work = await session.scalar(
                select(RuntimeWorkRecord)
                .where(RuntimeWorkRecord.id == execution_work_id(warrant_id))
                .with_for_update()
            )
            if incident is None or work is None:
                raise LookupError(warrant_id)
            await self._append_locked(
                session,
                incident,
                "EXECUTION_FAILED",
                "broker",
                {"warrant_id": warrant_id, "error_code": error_code},
                now=now,
            )
            work.status = "COMPLETED"
            work.owner_id = None
            work.updated_at = now
            work.completed_at = now
            await self._publish_locked(session, incident_id, now)

    async def published_projection(self, incident_id: str) -> dict[str, Any] | None:
        async with self.sessions() as session:
            record = await session.scalar(
                select(PublishedCaseRecord).where(
                    PublishedCaseRecord.incident_id == incident_id,
                    PublishedCaseRecord.published.is_(True),
                )
            )
            return None if record is None else dict(record.projection)

    async def read_projection(self, incident_id: str) -> dict[str, Any] | None:
        """Return the sanitized live projection to the incident-bound control API."""
        async with self.sessions() as session:
            record = await session.get(PublishedCaseRecord, incident_id)
            if record is None:
                return None
            projection = dict(record.projection)
            if record.published:
                incident = await session.get(IncidentRecord, incident_id)
                projected_incident = projection.get("incident")
                projected_state = (
                    projected_incident.get("state")
                    if isinstance(projected_incident, dict)
                    else None
                )
                if incident is None or incident.state != projected_state:
                    raise EventChainCorrupted(
                        "live incident state disagrees with published snapshot"
                    )
            return projection

    async def refresh_projection(self, incident_id: str) -> None:
        async with self.sessions() as session, session.begin():
            await self._publish_locked(session, incident_id, datetime.now(UTC))

    async def _publish_locked(
        self,
        session: AsyncSession,
        incident_id: str,
        now: datetime,
    ) -> None:
        incident = await session.get(IncidentRecord, incident_id)
        if incident is None:
            raise LookupError(incident_id)
        current = await session.get(PublishedCaseRecord, incident_id)
        published_snapshot = current is not None and current.published
        publishable = published_snapshot or (
            not incident.live_trial and incident.state == IncidentState.VERIFIED.value
        )
        if publishable and not published_snapshot:
            require_publishable_title(incident.title)
        projection_state = incident.state
        if published_snapshot:
            snapshot_incident = current.projection.get("incident")
            snapshot_state = (
                snapshot_incident.get("state") if isinstance(snapshot_incident, dict) else None
            )
            if snapshot_state != IncidentState.VERIFIED.value:
                raise RuntimeError("published operator snapshot is not VERIFIED")
            projection_state = snapshot_state
        evidence = tuple(
            (
                await session.scalars(
                    select(EvidenceRecord)
                    .where(
                        EvidenceRecord.incident_id == incident_id,
                        EvidenceRecord.published.is_(True),
                    )
                    .order_by(EvidenceRecord.created_at, EvidenceRecord.id)
                )
            ).all()
        )
        events = tuple(
            (
                await session.scalars(
                    select(TimelineEventRecord)
                    .where(
                        TimelineEventRecord.incident_id == incident_id,
                        TimelineEventRecord.published.is_(True),
                    )
                    .order_by(TimelineEventRecord.sequence)
                )
            ).all()
        )
        verdicts = tuple(
            (
                await session.scalars(
                    select(VerdictRecord)
                    .where(VerdictRecord.incident_id == incident_id)
                    .order_by(VerdictRecord.created_at, VerdictRecord.id)
                )
            ).all()
        )
        control_warrants = tuple(
            (
                await session.scalars(
                    select(ControlWarrantRecord)
                    .where(ControlWarrantRecord.incident_id == incident_id)
                    .order_by(
                        ControlWarrantRecord.created_at,
                        ControlWarrantRecord.id,
                    )
                )
            ).all()
        )
        broker_warrants = tuple(
            (
                await session.scalars(
                    select(WarrantRecord)
                    .where(WarrantRecord.incident_id == incident_id)
                    .order_by(WarrantRecord.created_at)
                )
            ).all()
        )
        tests = tuple(
            (
                await session.scalars(
                    select(TestRunRecord)
                    .where(TestRunRecord.incident_id == incident_id)
                    .order_by(TestRunRecord.created_at, TestRunRecord.id)
                )
            ).all()
        )
        agent_runs = tuple(
            (
                await session.scalars(
                    select(AgentRunRecord)
                    .where(AgentRunRecord.incident_id == incident_id)
                    .order_by(AgentRunRecord.created_at)
                )
            ).all()
        )
        candidates = tuple(
            (
                await session.scalars(
                    select(PatchCandidateRecord)
                    .where(PatchCandidateRecord.incident_id == incident_id)
                    .order_by(PatchCandidateRecord.created_at)
                )
            ).all()
        )
        latest_run = {row.seat: row for row in agent_runs}
        started = {
            row.payload.get("seat")
            for row in events
            if row.type == "SEAT_STARTED" and isinstance(row.payload.get("seat"), str)
        }
        projection = {
            "incident": {
                "id": incident.id,
                "title": _sanitize_projection_text(incident.title, "incident title"),
                "state": projection_state,
                "severity": "UNSET",
                "scenario": incident.scenario,
                "base_sha": incident.base_sha,
                "created_at": aware_utc(incident.created_at).isoformat(),
                "updated_at": aware_utc(incident.updated_at).isoformat(),
            },
            "seats": [
                {
                    "name": spec.seat.value,
                    "role": spec.role,
                    "model": spec.model,
                    "tier_rationale": spec.tier_rationale,
                    "effort": (
                        latest_run[spec.seat.value].effort
                        if spec.seat.value in latest_run
                        else spec.initial_effort.value
                    ),
                    "escalation_count": max(
                        (
                            int(row.payload.get("escalation_count", 0))
                            for row in events
                            if row.type == "REASONING_ESCALATED"
                            and row.payload.get("seat") == spec.seat.value
                        ),
                        default=(
                            latest_run[spec.seat.value].escalation_count
                            if spec.seat.value in latest_run
                            else 0
                        ),
                    ),
                    "state": (
                        "complete"
                        if spec.seat.value in latest_run
                        else "working"
                        if spec.seat.value in started
                        else "idle"
                    ),
                }
                for spec in SEAT_SPECS
            ],
            "events": [
                {
                    "id": row.id,
                    "incident_id": row.incident_id,
                    "sequence": row.sequence,
                    "type": row.type,
                    "actor": row.actor,
                    "summary": row.type.replace("_", " ").title(),
                    "details": published_event_details(row.type, row.payload),
                    "event_hash": row.event_hash,
                    "created_at": aware_utc(row.created_at).isoformat(),
                    "published": True,
                }
                for row in events
            ],
            "verdicts": [
                {
                    "id": row.id,
                    "incident_id": row.incident_id,
                    "verdict": row.verdict,
                    "verdict_sha256": row.verdict_sha256,
                    "source": row.source,
                    "created_at": aware_utc(row.created_at).isoformat(),
                }
                for row in verdicts
            ],
            "specialist_summaries": published_specialist_summaries(
                agent_runs,
                candidates,
            ),
            "warrants": published_warrant_history(
                control_warrants,
                broker_warrants,
                events,
                tests,
            ),
            "artifacts": {
                "evidence": [_published_evidence(row) for row in evidence],
                "diff": _published_patch(candidates[-1]) if candidates else None,
                "tests": [_published_test(row) for row in tests],
                # Full warrant bytes are available only on the authenticated
                # approval endpoint. Judge/public projections expose hashes in
                # ``warrants`` but never the canonical document or nonce.
                "warrant": None,
            },
            "pending_warrant": None,
        }
        manifest = hashlib.sha256(canonical_json(projection)).hexdigest()
        if current is None:
            session.add(
                PublishedCaseRecord(
                    incident_id=incident_id,
                    revision=1,
                    published=publishable,
                    projection=projection,
                    manifest_sha256=manifest,
                    updated_at=now,
                )
            )
        else:
            current.revision += 1
            current.published = publishable
            current.projection = projection
            current.manifest_sha256 = manifest
            current.updated_at = now


class RuntimeDatabase:
    """Own an async SQLAlchemy engine and the production runtime store."""

    def __init__(self, database_url: str) -> None:
        if not database_url:
            raise ValueError("database URL is required")
        self.database_url = _async_url(database_url)
        self.sync_url = _sync_url(self.database_url)
        self.engine: AsyncEngine = create_async_engine(self.database_url, pool_pre_ping=True)
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        self.store = RuntimeStore(self.sessions)

    async def bootstrap(self) -> None:
        if self.engine.dialect.name == "sqlite":
            async with self.engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
                await ensure_published_case_boundary(connection)
                await install_append_only_guards(connection)
            return
        if self.engine.dialect.name != "postgresql":
            raise RuntimeError("unsupported runtime database dialect")
        if not await self.health():
            raise RuntimeError("control database health check failed")

    async def migrate_control_schema(
        self,
        *,
        api_password: str,
        broker_password: str,
        evidence_password: str,
        judge_password: str,
    ) -> None:
        """Run owner-only DDL and install the production role boundary."""
        if self.engine.dialect.name != "postgresql":
            raise RuntimeError("control schema migration requires PostgreSQL")
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            await ensure_published_case_boundary(connection)
            await install_append_only_guards(connection)
            await install_warrant_guards(connection)
            await configure_control_roles(
                connection,
                api_password=api_password,
                broker_password=broker_password,
                evidence_password=evidence_password,
                judge_password=judge_password,
            )

    async def health(self) -> bool:
        async with self.sessions() as session:
            return (await session.scalar(text("SELECT 1"))) == 1

    async def close(self) -> None:
        await self.engine.dispose()


def _published_patch(record: PatchCandidateRecord) -> dict[str, Any]:
    """Sanitize model-authored diff text before the judge projection sees it."""
    sanitized = sanitize_evidence(
        record.normalized_diff.encode("utf-8"),
        "Counsel candidate diff",
    )
    return {
        "classification": "UNTRUSTED_EVIDENCE",
        "incident_id": record.incident_id,
        "candidate_id": record.id,
        "patch_sha256": record.patch_sha256,
        "text": sanitized.text,
        "sanitized_sha256": sanitized.sanitized_sha256,
        "tags": [tag.kind for tag in sanitized.tags],
        "created_at": aware_utc(record.created_at).isoformat(),
    }


def _published_test(record: TestRunRecord) -> dict[str, Any]:
    result = record.result
    projected = {
        "id": record.id,
        "label": record.plan_id,
        "plan_sha256": record.plan_sha256,
        "state": str(result.get("state", "pending")).lower(),
        "passed": result.get("passed"),
        "duration_ms": result.get("duration_ms"),
        "detail": (
            _sanitize_projection_text(result["detail"], "test result detail")
            if result.get("detail") is not None
            else None
        ),
        "warrant_id": result.get("warrant_id"),
        "evidence_id": result.get("evidence_id"),
        "receipt_sha256": result.get("receipt_sha256"),
    }
    observation = published_trusted_observation(
        result,
        expected_plan_id=record.plan_id,
        expected_plan_sha256=record.plan_sha256,
    )
    if observation is not None:
        projected.update(observation)
    return projected


_PRIVATE_EVIDENCE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "approval_mac",
        "approval_nonce",
        "approval_json",
        "authorization",
        "authority_json",
        "canonical_document",
        "document_json",
        "envelope_json",
        "nonce",
        "nonce_sha256",
        "patch_b64",
        "raw_artifact_path",
        "raw_bytes",
        "raw_path",
        "result_json",
        "secret",
        "server_mac",
        "token",
    }
)


def _canonical_public_key(value: str) -> str:
    """Apply the same camelCase/non-alphanumeric normalization as MCP DTOs."""
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^A-Za-z0-9]+", "_", snake).strip("_").lower()


def _is_private_evidence_key(value: str) -> bool:
    normalized = _canonical_public_key(value)
    key_parts = frozenset(normalized.split("_"))
    return (
        normalized in _PRIVATE_EVIDENCE_KEYS
        or "nonce" in key_parts
        or "secret" in key_parts
        or "authorization" in key_parts
        or "token" in key_parts
        or normalized.startswith("raw_")
    )


def _without_private_evidence_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _without_private_evidence_fields(item)
            for key, item in value.items()
            if not _is_private_evidence_key(str(key))
        }
    if isinstance(value, list):
        return [_without_private_evidence_fields(item) for item in value]
    return value


def _published_evidence(record: EvidenceRecord) -> dict[str, Any]:
    """Build a classified evidence DTO without embedded authority material."""
    text = record.sanitized_text
    tags = [tag.get("kind", "SANITIZED") for tag in record.tags]
    try:
        structured = json.loads(text)
    except (TypeError, ValueError):
        normalized = _canonical_public_key(text)
        if any(key in normalized for key in _PRIVATE_EVIDENCE_KEYS):
            text = "[PRIVATE_AUTHORITY_MATERIAL_REDACTED]"
            tags.append("PRIVATE_AUTHORITY_MATERIAL_REDACTED")
    else:
        redacted = _without_private_evidence_fields(structured)
        if redacted != structured:
            text = canonical_json(redacted).decode("utf-8")
            tags.append("PRIVATE_AUTHORITY_MATERIAL_REDACTED")
    return {
        "evidence_id": record.id,
        "incident_id": record.incident_id,
        "classification": "UNTRUSTED_EVIDENCE",
        "provenance": record.provenance,
        "kind": record.kind,
        "sanitized_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "captured_at": aware_utc(record.created_at).isoformat(),
        "text": text,
        "tags": tags,
    }
