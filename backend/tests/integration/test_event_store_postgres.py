"""Real PostgreSQL row-lock and database-role acceptance gate."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import secrets
from collections.abc import Iterator
from queue import Empty

import pytest
from crosspatch.db.base import Base
from crosspatch.db.migrations import (
    ensure_login_role,
    grant_api_control_privileges,
    grant_evidence_reader_privileges,
    grant_judge_reader_privileges,
    grant_runtime_event_privileges,
    install_append_only_guards,
    install_warrant_guards,
)
from crosspatch.db.models import IncidentRecord, TimelineEventRecord
from crosspatch.db.repositories import EventRepository, IncidentRepository
from crosspatch.domain.enums import IncidentState
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

ADMIN_DSN_ENV = "CROSSPATCH_TEST_POSTGRES_DSN"


def _runtime_dsn(admin_dsn: str, role: str, password: str) -> str:
    scheme, remainder = admin_dsn.split("://", 1)
    host = remainder.split("@", 1)[1]
    return f"{scheme}://{role}:{password}@{host}"


async def _append_batch(dsn: str, incident_id: str, worker: int, count: int) -> None:
    engine = create_async_engine(dsn, pool_size=2)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    events = EventRepository(sessions)
    try:
        for index in range(count):
            await events.append(
                incident_id,
                "ARTIFACT_RECORDED",
                f"worker-{worker}",
                {"worker": worker, "index": index},
            )
    finally:
        await engine.dispose()


def _append_process(
    dsn: str,
    incident_id: str,
    worker: int,
    count: int,
    errors: multiprocessing.Queue,
) -> None:
    try:
        asyncio.run(_append_batch(dsn, incident_id, worker, count))
    except BaseException as error:  # pragma: no cover - returned to the parent process
        errors.put(repr(error))


@pytest.fixture
def postgres_admin_dsn() -> str:
    dsn = os.getenv(ADMIN_DSN_ENV)
    if not dsn:
        pytest.skip(f"{ADMIN_DSN_ENV} is required for the real PostgreSQL gate")
    return dsn


@pytest.fixture
def runtime_database(postgres_admin_dsn: str) -> Iterator[tuple[str, str, str]]:
    role = f"crosspatch_runtime_{secrets.token_hex(5)}"
    password = secrets.token_urlsafe(24)
    incident_id = f"inc-pg-{secrets.token_hex(8)}"

    async def prepare() -> None:
        engine = create_async_engine(postgres_admin_dsn)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            await install_append_only_guards(connection)
            await connection.execute(text(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'"))
            await grant_runtime_event_privileges(connection, role_name=role)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        await IncidentRepository(sessions).create(incident_id, "Postgres race", IncidentState.OPEN)
        await engine.dispose()

    asyncio.run(prepare())
    try:
        yield _runtime_dsn(postgres_admin_dsn, role, password), incident_id, role
    finally:

        async def cleanup() -> None:
            engine = create_async_engine(postgres_admin_dsn)
            async with engine.begin() as connection:
                await connection.execute(text(f'DROP OWNED BY "{role}"'))
                await connection.execute(text(f'DROP ROLE "{role}"'))
            await engine.dispose()

        asyncio.run(cleanup())


def test_multi_process_appends_use_postgres_row_lock_and_runtime_role(runtime_database):
    runtime_dsn, incident_id, role = runtime_database
    process_count = 4
    events_per_process = 8
    context = multiprocessing.get_context("spawn")
    errors = context.Queue()
    processes = [
        context.Process(
            target=_append_process,
            args=(runtime_dsn, incident_id, worker, events_per_process, errors),
        )
        for worker in range(process_count)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
        assert not process.is_alive(), "PostgreSQL append worker did not terminate"
        assert process.exitcode == 0
    try:
        error = errors.get_nowait()
    except Empty:
        error = None
    assert error is None

    async def verify() -> None:
        engine = create_async_engine(runtime_dsn)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as session:
            rows = (
                await session.scalars(
                    select(TimelineEventRecord)
                    .where(TimelineEventRecord.incident_id == incident_id)
                    .order_by(TimelineEventRecord.sequence)
                )
            ).all()
            incident = await session.get(IncidentRecord, incident_id)
            privileges = (
                await session.execute(
                    text(
                        """
                        SELECT privilege_type
                        FROM information_schema.table_privileges
                        WHERE grantee = :role AND table_name = 'timeline_events'
                        """
                    ),
                    {"role": role},
                )
            ).scalars()
            granted = set(privileges)
            assert "UPDATE" not in granted
            assert "DELETE" not in granted
            with pytest.raises(DBAPIError, match="permission denied|append-only"):
                await session.execute(
                    text(
                        "UPDATE timeline_events SET actor = 'tampered' "
                        "WHERE incident_id = :incident_id"
                    ),
                    {"incident_id": incident_id},
                )
                await session.commit()
        await engine.dispose()

        expected = process_count * events_per_process
        assert [row.sequence for row in rows] == list(range(1, expected + 1))
        assert all(
            rows[index].previous_hash == rows[index - 1].event_hash for index in range(1, expected)
        )
        assert incident is not None
        assert incident.next_event_sequence == expected + 1
        assert incident.event_chain_head == rows[-1].event_hash

    asyncio.run(verify())


@pytest.mark.postgres
def test_control_api_and_reader_roles_enforce_database_authority(postgres_admin_dsn: str) -> None:
    api_role = f"crosspatch_api_{secrets.token_hex(5)}"
    evidence_role = f"crosspatch_evidence_{secrets.token_hex(5)}"
    judge_role = f"crosspatch_judge_{secrets.token_hex(5)}"
    api_password = secrets.token_urlsafe(24)
    evidence_password = secrets.token_urlsafe(24)
    judge_password = secrets.token_urlsafe(24)
    incident_id = f"inc-role-{secrets.token_hex(8)}"

    async def prepare() -> None:
        engine = create_async_engine(postgres_admin_dsn)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            await install_append_only_guards(connection)
            await install_warrant_guards(connection)
            await ensure_login_role(
                connection, role_name=api_role, password=api_password
            )
            await ensure_login_role(
                connection, role_name=evidence_role, password=evidence_password
            )
            await ensure_login_role(
                connection, role_name=judge_role, password=judge_password
            )
            await grant_api_control_privileges(connection, role_name=api_role)
            await grant_evidence_reader_privileges(
                connection, role_name=evidence_role
            )
            await grant_judge_reader_privileges(connection, role_name=judge_role)
        await IncidentRepository(async_sessionmaker(engine, expire_on_commit=False)).create(
            incident_id,
            "Role boundary",
            IncidentState.OPEN,
        )
        await engine.dispose()

    async def verify() -> None:
        api_engine = create_async_engine(
            _runtime_dsn(postgres_admin_dsn, api_role, api_password)
        )
        evidence_engine = create_async_engine(
            _runtime_dsn(postgres_admin_dsn, evidence_role, evidence_password)
        )
        judge_engine = create_async_engine(
            _runtime_dsn(postgres_admin_dsn, judge_role, judge_password)
        )
        async with api_engine.begin() as connection:
            await connection.execute(
                text("UPDATE incidents SET updated_at = now() WHERE id = :incident_id"),
                {"incident_id": incident_id},
            )
            audit_privileges = set(
                (
                    await connection.execute(
                        text(
                            "SELECT privilege_type FROM information_schema.table_privileges "
                            "WHERE grantee = :role AND table_name = "
                            "'judge_token_audit_events'"
                        ),
                        {"role": api_role},
                    )
                ).scalars()
            )
            assert audit_privileges == {"INSERT", "SELECT"}
        async with api_engine.connect() as connection:
            with pytest.raises(DBAPIError, match="permission denied"):
                await connection.execute(
                    text("DELETE FROM incidents WHERE id = :incident_id"),
                    {"incident_id": incident_id},
                )
                await connection.commit()
            await connection.rollback()
        async with evidence_engine.connect() as connection:
            title = await connection.scalar(
                text("SELECT title FROM incidents WHERE id = :incident_id"),
                {"incident_id": incident_id},
            )
            assert title == "Role boundary"
            with pytest.raises(DBAPIError, match="permission denied"):
                await connection.execute(
                    text("UPDATE incidents SET title = 'reader-tamper' WHERE id = :incident_id"),
                    {"incident_id": incident_id},
                )
                await connection.commit()
            await connection.rollback()
            with pytest.raises(DBAPIError, match="permission denied"):
                await connection.execute(text("SELECT * FROM mutation_warrants"))
            await connection.rollback()
        async with judge_engine.connect() as connection:
            assert await connection.scalar(text("SELECT count(*) FROM published_cases")) >= 0
            assert await connection.scalar(text("SELECT count(*) FROM judge_tokens")) >= 0
            with pytest.raises(DBAPIError, match="permission denied"):
                await connection.execute(text("SELECT * FROM incidents"))
            await connection.rollback()
            with pytest.raises(DBAPIError, match="permission denied"):
                await connection.execute(text("SELECT * FROM mutation_authority"))
            await connection.rollback()
        await api_engine.dispose()
        await evidence_engine.dispose()
        await judge_engine.dispose()

    asyncio.run(prepare())
    try:
        asyncio.run(verify())
    finally:

        async def cleanup() -> None:
            engine = create_async_engine(postgres_admin_dsn)
            async with engine.begin() as connection:
                await connection.execute(
                    text("DELETE FROM incidents WHERE id = :incident_id"),
                    {"incident_id": incident_id},
                )
                for role in (api_role, evidence_role, judge_role):
                    await connection.execute(text(f'DROP OWNED BY "{role}"'))
                    await connection.execute(text(f'DROP ROLE "{role}"'))
            await engine.dispose()

        asyncio.run(cleanup())
