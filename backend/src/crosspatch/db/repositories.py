"""Transactional repositories for incidents and append-only timeline events."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from crosspatch.db.models import IncidentRecord, TimelineEventRecord
from crosspatch.domain.enums import IncidentState
from crosspatch.domain.hashing import sha256_hex
from crosspatch.domain.state_machine import (
    STATE_EVENT_TYPES,
    EventChainCorrupted,
    transition_incident,
    typed_event_from_payload,
)

ZERO_EVENT_HASH = "0" * 64


class IncidentNotFound(LookupError):
    pass


class IncidentRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def create(
        self,
        incident_id: str,
        title: str,
        state: IncidentState = IncidentState.OPEN,
    ) -> IncidentRecord:
        now = datetime.now(UTC)
        incident = IncidentRecord(
            id=incident_id,
            title=title,
            state=state.value,
            next_event_sequence=1,
            created_at=now,
            updated_at=now,
        )
        async with self._sessions() as session, session.begin():
            session.add(incident)
        return incident


class EventRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions
        self._incident_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def append(
        self,
        incident_id: str,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
    ) -> TimelineEventRecord:
        async with self._incident_locks[incident_id]:
            async with self._sessions() as session, session.begin():
                incident = await session.scalar(
                    select(IncidentRecord).where(IncidentRecord.id == incident_id).with_for_update()
                )
                if incident is None:
                    raise IncidentNotFound(incident_id)

                last_event = await session.scalar(
                    select(TimelineEventRecord)
                    .where(TimelineEventRecord.incident_id == incident_id)
                    .order_by(TimelineEventRecord.sequence.desc())
                    .limit(1)
                )
                sequence = 1 if last_event is None else last_event.sequence + 1
                previous_hash = ZERO_EVENT_HASH if last_event is None else last_event.event_hash
                expected_head = None if last_event is None else last_event.event_hash
                if (
                    incident.next_event_sequence != sequence
                    or incident.event_chain_head != expected_head
                ):
                    raise EventChainCorrupted(
                        "incident chain metadata disagrees with durable timeline events"
                    )

                next_state: IncidentState | None = None
                if event_type in STATE_EVENT_TYPES:
                    typed_event = typed_event_from_payload(event_type, payload)
                    next_state = transition_incident(IncidentState(incident.state), typed_event)
                created_at = datetime.now(UTC)
                event_hash = sha256_hex(
                    {
                        "incident_id": incident_id,
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
                    incident_id=incident_id,
                    sequence=sequence,
                    type=event_type,
                    actor=actor,
                    payload=payload,
                    previous_hash=previous_hash,
                    event_hash=event_hash,
                    created_at=created_at,
                )
                session.add(event)
                incident.next_event_sequence = sequence + 1
                incident.event_chain_head = event_hash
                if next_state is not None:
                    incident.state = next_state.value
                incident.updated_at = created_at
            return event
