"""Real PostgreSQL least-privilege and token lifecycle regression gates."""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
from datetime import UTC, datetime

import pytest
from crosspatch.broker.broker import BrokerResult, BrokerStatus, WarrantState
from crosspatch.db.base import Base
from crosspatch.db.migrations import (
    ensure_login_role,
    grant_api_control_privileges,
    install_append_only_guards,
    install_warrant_guards,
)
from crosspatch.db.models import (
    AgentRunRecord,
    ControlWarrantRecord,
    EvidenceRecord,
    IncidentRecord,
    PatchCandidateRecord,
    PublishedCaseRecord,
    RuntimeWorkRecord,
    VerdictRecord,
    WarrantRecord,
)
from crosspatch.db.models import (
    TestRunRecord as DBTestRunRecord,
)
from crosspatch.db.repositories import IncidentRepository
from crosspatch.domain.enums import IncidentState
from crosspatch.domain.hashing import canonical_json
from crosspatch.runner.catalog import ExecutionCatalog
from crosspatch.runner.results import ProcessReceipt
from crosspatch.runtime.auth import JudgeTokenRepository
from crosspatch.runtime.database import RuntimeStore
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

ADMIN_DSN_ENV = "CROSSPATCH_TEST_POSTGRES_DSN"

_API_UPDATE_COLUMNS = {
    ("api_principals", "bearer_sha256"),
    ("api_principals", "csrf_sha256"),
    ("api_principals", "expires_at"),
    ("api_principals", "revoked"),
    ("api_principals", "role"),
    ("api_principals", "step_up_expires_at"),
    ("api_principals", "step_up_sha256"),
    ("api_principals", "updated_at"),
    ("control_warrants", "approval_id"),
    ("control_warrants", "status"),
    ("control_warrants", "updated_at"),
    ("incidents", "event_chain_head"),
    ("incidents", "next_event_sequence"),
    ("incidents", "pending_warrant_id"),
    ("incidents", "state"),
    ("incidents", "updated_at"),
    ("judge_tokens", "revoked"),
    ("judge_tokens", "revoked_at"),
    ("live_trial_budget", "reserved_microusd"),
    ("live_trial_budget", "spent_microusd"),
    ("live_trial_budget", "updated_at"),
    ("live_trial_credentials", "rate_count"),
    ("live_trial_credentials", "rate_window_started_at"),
    ("live_trial_credentials", "revoked_at"),
    ("live_trial_credentials", "revoked_by"),
    ("live_trial_credentials", "updated_at"),
    ("live_trial_reservations", "actual_microusd"),
    ("live_trial_reservations", "incident_id"),
    ("live_trial_reservations", "settled_at"),
    ("live_trial_reservations", "status"),
    ("mutation_authority", "snapshot_json"),
    ("mutation_authority", "updated_at"),
    ("mutation_authority", "version"),
    ("published_cases", "manifest_sha256"),
    ("published_cases", "published"),
    ("published_cases", "projection"),
    ("published_cases", "revision"),
    ("published_cases", "updated_at"),
    ("runtime_work", "attempt_count"),
    ("runtime_work", "completed_at"),
    ("runtime_work", "owner_id"),
    ("runtime_work", "status"),
    ("runtime_work", "updated_at"),
}


def _runtime_dsn(admin_dsn: str, role: str, password: str) -> str:
    scheme, remainder = admin_dsn.split("://", 1)
    host = remainder.split("@", 1)[1]
    return f"{scheme}://{role}:{password}@{host}"


async def _expect_database_rejection(
    engine: AsyncEngine,
    statement: str,
    parameters: dict[str, object],
    *,
    match: str,
) -> None:
    async with engine.connect() as connection:
        with pytest.raises(DBAPIError, match=match):
            await connection.execute(text(statement), parameters)
            await connection.commit()
        await connection.rollback()


async def _seed_historical_records(
    sessions: async_sessionmaker[AsyncSession],
    *,
    incident_id: str,
    suffix: str,
) -> dict[str, str]:
    now = datetime.now(UTC)
    identifiers = {
        "evidence": f"ev_{suffix}",
        "run": f"run_{suffix}",
        "candidate": f"candidate_{suffix}",
        "verdict": f"verdict_{suffix}",
        "test": f"test_{suffix}",
        "warrant": f"war_{suffix}",
    }
    async with sessions() as session, session.begin():
        session.add(
            EvidenceRecord(
                id=identifiers["evidence"],
                incident_id=incident_id,
                kind="log",
                provenance="postgres-hardening-test",
                sanitized_text="immutable artifact",
                raw_sha256="1" * 64,
                sanitized_sha256="2" * 64,
                envelope_json=b"{}",
                tags=[],
                published=True,
                created_at=now,
            )
        )
        session.add(
            AgentRunRecord(
                id=identifiers["run"],
                incident_id=incident_id,
                seat="Inspector",
                model="gpt-5.6-terra",
                effort="medium",
                phase="mechanism-analysis",
                escalation_count=0,
                output_json=b"{}",
                output_sha256="3" * 64,
                semantic_sha256="4" * 64,
                schema_status="VALID",
                created_at=now,
            )
        )
        await session.flush()
        session.add_all(
            (
                PatchCandidateRecord(
                    id=identifiers["candidate"],
                    incident_id=incident_id,
                    agent_run_id=identifiers["run"],
                    patch_sha256="5" * 64,
                    normalized_diff="diff --git a/a b/a\n",
                    allowed_paths=["a"],
                    test_intentions=[],
                    created_at=now,
                ),
                VerdictRecord(
                    id=identifiers["verdict"],
                    incident_id=incident_id,
                    agent_run_id=identifiers["run"],
                    verdict="CLEAR",
                    output_json=b"{}",
                    verdict_sha256="6" * 64,
                    source="Magistrate",
                    created_at=now,
                ),
                DBTestRunRecord(
                    id=identifiers["test"],
                    incident_id=incident_id,
                    plan_id="victim.duplicate-race.candidate",
                    plan_sha256="7" * 64,
                    result={"passed": True},
                    created_at=now,
                ),
                ControlWarrantRecord(
                    id=identifiers["warrant"],
                    incident_id=incident_id,
                    canonical_document=b'{"immutable":true}',
                    warrant_sha256="8" * 64,
                    authority_json=b'{"immutable":true}',
                    status="PENDING_APPROVAL",
                    expires_at=datetime(2026, 9, 1, 7, tzinfo=UTC),
                    created_at=now,
                    updated_at=now,
                ),
                PublishedCaseRecord(
                    incident_id=incident_id,
                    revision=1,
                    published=False,
                    projection={
                        "incident": {
                            "id": incident_id,
                            "state": IncidentState.OPEN.value,
                        }
                    },
                    manifest_sha256="9" * 64,
                    updated_at=now,
                ),
            )
        )
    return identifiers


@pytest.mark.postgres
def test_control_api_cannot_rewrite_history_bindings_or_token_lifecycle() -> None:
    admin_dsn = os.getenv(ADMIN_DSN_ENV)
    if not admin_dsn:
        pytest.skip(f"{ADMIN_DSN_ENV} is required for the real PostgreSQL gate")

    suffix = secrets.token_hex(8)
    role = f"crosspatch_api_{secrets.token_hex(5)}"
    password = secrets.token_urlsafe(24)
    incident_id = f"inc-hardening-{suffix}"
    token = f"judge-token-{secrets.token_urlsafe(32)}"
    token_id = f"judge-jti-{suffix}"
    expires_at = datetime(2026, 9, 1, 7, tzinfo=UTC)

    async def exercise() -> None:
        admin_engine = create_async_engine(admin_dsn)
        api_engine: AsyncEngine | None = None
        try:
            async with admin_engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
                await install_append_only_guards(connection)
                await install_warrant_guards(connection)
                await ensure_login_role(connection, role_name=role, password=password)
                await grant_api_control_privileges(connection, role_name=role)
            await IncidentRepository(
                async_sessionmaker(admin_engine, expire_on_commit=False)
            ).create(incident_id, "Immutable control history", IncidentState.OPEN)

            api_engine = create_async_engine(_runtime_dsn(admin_dsn, role, password))
            api_sessions = async_sessionmaker(api_engine, expire_on_commit=False)
            identifiers = await _seed_historical_records(
                api_sessions,
                incident_id=incident_id,
                suffix=suffix,
            )

            async with api_engine.begin() as connection:
                await connection.execute(
                    text("UPDATE incidents SET updated_at = now() WHERE id = :incident_id"),
                    {"incident_id": incident_id},
                )
                await connection.execute(
                    text(
                        "UPDATE control_warrants SET status = 'REJECTED', updated_at = now() "
                        "WHERE id = :warrant_id"
                    ),
                    {"warrant_id": identifiers["warrant"]},
                )
                update_columns = set(
                    (
                        await connection.execute(
                            text(
                                "SELECT table_name, column_name "
                                "FROM information_schema.column_privileges "
                                "WHERE grantee = :role AND privilege_type = 'UPDATE' "
                                "AND table_schema = 'public'"
                            ),
                            {"role": role},
                        )
                    ).tuples()
                )
                assert update_columns == _API_UPDATE_COLUMNS

            immutable_updates = (
                (
                    "UPDATE incidents SET title = 'tampered' WHERE id = :id",
                    incident_id,
                ),
                (
                    "UPDATE incidents SET live_trial = true WHERE id = :id",
                    incident_id,
                ),
                (
                    "UPDATE incidents SET owner_subject = 'tampered' WHERE id = :id",
                    incident_id,
                ),
                (
                    "UPDATE evidence SET sanitized_text = 'tampered' WHERE id = :id",
                    identifiers["evidence"],
                ),
                (
                    "UPDATE agent_runs SET output_sha256 = :tampered WHERE id = :id",
                    identifiers["run"],
                ),
                (
                    "UPDATE patch_candidates SET normalized_diff = 'tampered' WHERE id = :id",
                    identifiers["candidate"],
                ),
                (
                    "UPDATE verdicts SET verdict = 'BLOCK' WHERE id = :id",
                    identifiers["verdict"],
                ),
                (
                    "UPDATE test_runs SET plan_sha256 = :tampered WHERE id = :id",
                    identifiers["test"],
                ),
            )
            for statement, identifier in immutable_updates:
                await _expect_database_rejection(
                    api_engine,
                    statement,
                    {"id": identifier, "tampered": "0" * 64},
                    match="permission denied",
                )

            await _expect_database_rejection(
                api_engine,
                "UPDATE control_warrants SET canonical_document = :tampered WHERE id = :id",
                {"id": identifiers["warrant"], "tampered": b"tampered"},
                match="permission denied",
            )

            repository = JudgeTokenRepository(api_sessions)
            await repository.register(
                token,
                jti=token_id,
                expires_at=expires_at,
                actor="approver-issuer",
            )
            await _expect_database_rejection(
                admin_engine,
                "UPDATE judge_tokens SET expires_at = :expires_at WHERE jti = :token_id",
                {
                    "expires_at": datetime(2027, 1, 1, tzinfo=UTC),
                    "token_id": token_id,
                },
                match="identity and expiry are immutable",
            )
            await _expect_database_rejection(
                admin_engine,
                "UPDATE judge_tokens SET jti = :changed WHERE jti = :token_id",
                {"changed": f"changed-{token_id}", "token_id": token_id},
                match="identity and expiry are immutable",
            )
            await _expect_database_rejection(
                admin_engine,
                "DELETE FROM judge_tokens WHERE jti = :token_id",
                {"token_id": token_id},
                match="identities cannot be deleted",
            )
            await _expect_database_rejection(
                api_engine,
                "UPDATE judge_tokens SET revoked = true, revoked_at = now() "
                "WHERE jti = :token_id",
                {"token_id": token_id},
                match="matching append-only REVOKED audit",
            )

            revoked = await repository.revoke_by_token_id(
                token_id,
                actor="approver-revoker",
            )
            assert revoked is not None and revoked.revoked is True
            await _expect_database_rejection(
                api_engine,
                "UPDATE judge_tokens SET revoked = false, revoked_at = NULL "
                "WHERE jti = :token_id",
                {"token_id": token_id},
                match="revocation is irreversible",
            )

            persisted = (await repository.list_tokens())[-1]
            audit = tuple(
                event for event in await repository.audit_events() if event.token_id == token_id
            )
            assert persisted.token_id == token_id
            assert persisted.expires_at == expires_at
            assert persisted.revoked is True
            assert [event.action for event in audit] == ["ISSUED", "REVOKED"]

            async with api_engine.connect() as connection:
                evidence_text = await connection.scalar(
                    text("SELECT sanitized_text FROM evidence WHERE id = :id"),
                    {"id": identifiers["evidence"]},
                )
                canonical = await connection.scalar(
                    text("SELECT canonical_document FROM control_warrants WHERE id = :id"),
                    {"id": identifiers["warrant"]},
                )
            assert evidence_text == "immutable artifact"
            assert canonical == b'{"immutable":true}'

            async with admin_engine.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE incidents SET state = 'VERIFIED', live_trial = true "
                        "WHERE id = :incident_id"
                    ),
                    {"incident_id": incident_id},
                )
            await _expect_database_rejection(
                api_engine,
                "UPDATE incidents SET state = 'PATCHING' "
                "WHERE id = :incident_id",
                {"incident_id": incident_id},
                match="VERIFIED incidents are terminal",
            )
            await _expect_database_rejection(
                api_engine,
                "UPDATE published_cases SET published = true "
                "WHERE incident_id = :incident_id",
                {"incident_id": incident_id},
                match="publication requires a verified operator incident",
            )
        finally:
            if api_engine is not None:
                await api_engine.dispose()
            async with admin_engine.begin() as connection:
                await connection.execute(text(f'DROP OWNED BY "{role}"'))
                await connection.execute(text(f'DROP ROLE "{role}"'))
            await admin_engine.dispose()

    asyncio.run(exercise())


@pytest.mark.postgres
def test_api_projects_consumed_broker_result_with_select_only_warrant_access() -> None:
    admin_dsn = os.getenv(ADMIN_DSN_ENV)
    if not admin_dsn:
        pytest.skip(f"{ADMIN_DSN_ENV} is required for the real PostgreSQL gate")

    suffix = secrets.token_hex(8)
    role = f"crosspatch_api_{secrets.token_hex(5)}"
    password = secrets.token_urlsafe(24)
    incident_id = f"inc-projection-{suffix}"
    warrant_id = f"war-projection-{suffix}"
    now = datetime.now(UTC)

    async def exercise() -> None:
        admin_engine = create_async_engine(admin_dsn)
        api_engine: AsyncEngine | None = None
        try:
            async with admin_engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
                await install_append_only_guards(connection)
                await install_warrant_guards(connection)
                await ensure_login_role(connection, role_name=role, password=password)
                await grant_api_control_privileges(connection, role_name=role)

            plan = ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
            receipt = ProcessReceipt.for_test(plan=plan, exit_code=0)
            nonce_sha256 = hashlib.sha256(suffix.encode("ascii")).hexdigest()
            result = BrokerResult(
                warrant_id=warrant_id,
                status=BrokerStatus.EXECUTED,
                receipts=(receipt,),
                nonce_sha256=nonce_sha256,
            )
            admin_sessions = async_sessionmaker(admin_engine, expire_on_commit=False)
            async with admin_sessions() as session, session.begin():
                session.add_all(
                    (
                        IncidentRecord(
                            id=incident_id,
                            title="SELECT-only broker projection",
                            scenario="webhook-race",
                            state=IncidentState.APPROVED.value,
                            next_event_sequence=1,
                            event_chain_head=None,
                            created_at=now,
                            updated_at=now,
                        ),
                        WarrantRecord(
                            id=warrant_id,
                            incident_id=incident_id,
                            nonce_sha256=nonce_sha256,
                            document_json=b"{}",
                            approval_json=b"{}",
                            state=WarrantState.CONSUMED.value,
                            expires_at=datetime(2026, 9, 1, 7, tzinfo=UTC),
                            claimed_at=now,
                            nonce_consumed_at=now,
                            finished_at=now,
                            result_json=canonical_json(result),
                            created_at=now,
                            updated_at=now,
                        ),
                        RuntimeWorkRecord(
                            id=f"execute:{warrant_id}",
                            incident_id=incident_id,
                            warrant_id=warrant_id,
                            kind="APPROVED_EXECUTION",
                            status="RUNNING",
                            owner_id="projection-test",
                            attempt_count=1,
                            created_at=now,
                            updated_at=now,
                        ),
                    )
                )

            api_engine = create_async_engine(_runtime_dsn(admin_dsn, role, password))
            store = RuntimeStore(async_sessionmaker(api_engine, expire_on_commit=False))
            projected = await store.project_broker_result(
                incident_id,
                warrant_id,
                evidence_id=f"ev-projection-{suffix}",
            )
            assert projected.status is BrokerStatus.EXECUTED

            async with api_engine.connect() as connection:
                can_update_warrant = await connection.scalar(
                    text(
                        "SELECT has_table_privilege(current_user, "
                        "'mutation_warrants', 'UPDATE')"
                    )
                )
                state = await connection.scalar(
                    text("SELECT state FROM incidents WHERE id = :incident_id"),
                    {"incident_id": incident_id},
                )
            assert can_update_warrant is False
            assert state == IncidentState.VERIFIED.value
        finally:
            if api_engine is not None:
                await api_engine.dispose()
            async with admin_engine.begin() as connection:
                role_exists = await connection.scalar(
                    text("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :role)"),
                    {"role": role},
                )
                if role_exists:
                    await connection.execute(text(f'DROP OWNED BY "{role}"'))
                    await connection.execute(text(f'DROP ROLE "{role}"'))
            await admin_engine.dispose()

    asyncio.run(exercise())
