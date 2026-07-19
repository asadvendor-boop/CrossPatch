import asyncio

import pytest
import pytest_asyncio
from crosspatch.db.base import Base
from crosspatch.db.migrations import install_append_only_guards
from crosspatch.db.models import IncidentRecord, TimelineEventRecord
from crosspatch.db.repositories import EventRepository, IncidentRepository
from crosspatch.domain.enums import IncidentState
from crosspatch.domain.state_machine import EventChainCorrupted
from sqlalchemy import select, update
from sqlalchemy.exc import DatabaseError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


@pytest_asyncio.fixture
async def event_store(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'events.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        await install_append_only_guards(connection)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    incidents = IncidentRepository(sessions)
    events = EventRepository(sessions)
    await incidents.create("inc-1", "Webhook race", IncidentState.OPEN)
    try:
        yield sessions, events
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_event_rows_are_hash_chained_and_immutable(event_store):
    sessions, events = event_store
    first = await events.append("inc-1", "INCIDENT_OPENED", "operator", {"scenario": "race"})
    second = await events.append("inc-1", "ARTIFACT_RECORDED", "runner", {"artifact": "sha256:x"})

    assert first.sequence == 1
    assert second.sequence == 2
    assert second.previous_hash == first.event_hash

    async with sessions() as session:
        with pytest.raises(DatabaseError):
            await session.execute(
                update(TimelineEventRecord)
                .where(TimelineEventRecord.id == first.id)
                .values(payload={"type": "tampered"})
            )
            await session.commit()


@pytest.mark.asyncio
async def test_concurrent_appends_allocate_unique_monotonic_sequences(event_store):
    sessions, events = event_store

    await asyncio.gather(
        *(events.append("inc-1", "ARTIFACT_RECORDED", "runner", {"index": i}) for i in range(24))
    )

    async with sessions() as session:
        rows = (
            await session.scalars(
                select(TimelineEventRecord)
                .where(TimelineEventRecord.incident_id == "inc-1")
                .order_by(TimelineEventRecord.sequence)
            )
        ).all()
        incident = await session.get(IncidentRecord, "inc-1")

    assert [row.sequence for row in rows] == list(range(1, 25))
    assert len({row.event_hash for row in rows}) == 24
    assert all(rows[index].previous_hash == rows[index - 1].event_hash for index in range(1, 24))
    assert incident.next_event_sequence == 25
    assert incident.event_chain_head == rows[-1].event_hash


@pytest.mark.asyncio
async def test_state_event_updates_incident_state_in_same_transaction(event_store):
    sessions, events = event_store

    await events.append("inc-1", "REPRODUCTION_STARTED", "operator", {})

    async with sessions() as session:
        incident = await session.get(IncidentRecord, "inc-1")
    assert incident is not None
    assert incident.state == IncidentState.REPRODUCING.value


@pytest.mark.asyncio
async def test_tampered_chain_metadata_is_detected_not_trusted(event_store):
    sessions, events = event_store
    first = await events.append("inc-1", "INCIDENT_OPENED", "operator", {})
    async with sessions() as session, session.begin():
        incident = await session.get(IncidentRecord, "inc-1")
        assert incident is not None
        incident.next_event_sequence = 50
        incident.event_chain_head = "f" * 64

    with pytest.raises(EventChainCorrupted):
        await events.append("inc-1", "ARTIFACT_RECORDED", "runner", {})

    async with sessions() as session:
        rows = (
            await session.scalars(
                select(TimelineEventRecord).where(TimelineEventRecord.incident_id == "inc-1")
            )
        ).all()
    assert [row.id for row in rows] == [first.id]
