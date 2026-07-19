"""Real PostgreSQL multi-process single-use warrant claim gate."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import multiprocessing
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Empty

import pytest
from crosspatch.broker.approval import ApprovalService
from crosspatch.broker.broker import AuthoritySnapshot
from crosspatch.broker.store import PostgresWarrantStore
from crosspatch.broker.warrant import BoundExecutionPlan, WarrantDocument
from crosspatch.db.base import Base
from crosspatch.db.migrations import (
    grant_broker_warrant_privileges,
    install_warrant_guards,
)
from crosspatch.db.models import MutationAuthorityRecord, WarrantRecord
from crosspatch.domain.hashing import sha256_hex
from crosspatch.runner.catalog import ExecutionCatalog
from sqlalchemy import delete, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN_ENV = "CROSSPATCH_TEST_POSTGRES_DSN"
PATCH = b"""diff --git a/victim/src/victim/db.py b/victim/src/victim/db.py
index 1111111..2222222 100644
--- a/victim/src/victim/db.py
+++ b/victim/src/victim/db.py
@@ -1 +1 @@
-vulnerable = True
+vulnerable = False
"""


def _async_dsn(value: str) -> str:
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+asyncpg://", 1)
    return value


def _accept(document, approval, now, authority):
    del document, approval, now
    return authority


async def _claim_once(dsn: str, warrant_id: str) -> str:
    engine = create_async_engine(dsn, pool_size=1)
    store = PostgresWarrantStore(async_sessionmaker(engine, expire_on_commit=False))
    try:
        outcome = await store.claim_warrant(
            warrant_id,
            _accept,
            lambda _warrant_id: (_ for _ in ()).throw(
                AssertionError("PostgreSQL claim consulted an unlocked authority loader")
            ),
        )
        return "CLAIMED" if outcome.claimed is not None else str(outcome.rejection)
    finally:
        await engine.dispose()


def _claim_process(dsn: str, warrant_id: str, results: multiprocessing.Queue) -> None:
    try:
        results.put(asyncio.run(_claim_once(dsn, warrant_id)))
    except BaseException as error:  # pragma: no cover - returned to parent
        results.put(f"ERROR:{error!r}")


def _document(identifier: str, now: datetime) -> WarrantDocument:
    plan = BoundExecutionPlan.from_execution_plan(
        ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
    )
    return WarrantDocument(
        format="crosspatch-warrant-v1",
        warrant_id=f"war_pg_{identifier}",
        incident_id=f"inc_pg_{identifier}",
        repository_id="repo_01",
        verdict_id="ver_01",
        verdict_sha256="1" * 64,
        candidate_id="cand_01",
        authority_snapshot_sha256="2" * 64,
        reviewed_evidence_manifest_sha256="3" * 64,
        reviewed_timeline_head="4" * 64,
        base_sha="5" * 40,
        repository_manifest_sha256="6" * 64,
        patch_b64=base64.b64encode(PATCH).decode("ascii"),
        patch_sha256=hashlib.sha256(PATCH).hexdigest(),
        allowed_paths=("victim/src/victim/db.py",),
        execution_plans=(plan,),
        test_plan_sha256=sha256_hex((plan,)),
        runner_digest="7" * 64,
        environment_digest="8" * 64,
        approver_identity="approver-1",
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=15),
        approval_mac_key_id="approval-v1",
        nonce=f"nonce_pg_{identifier}",
    )


@pytest.mark.postgres
def test_postgres_row_lock_allows_exactly_one_multi_process_nonce_claim(tmp_path: Path):
    raw_dsn = os.getenv(DSN_ENV)
    if not raw_dsn:
        pytest.skip(f"{DSN_ENV} is required for the real PostgreSQL broker gate")
    dsn = _async_dsn(raw_dsn)
    identifier = secrets.token_hex(8)
    now = datetime.now(UTC)
    document = _document(identifier, now)
    approval = ApprovalService(keys={"approval-v1": b"k" * 32}).approve(
        document, approved_at=now
    )
    repository_root = tmp_path / "source"
    (repository_root / "victim/src/victim").mkdir(parents=True)
    (repository_root / "victim/src/victim/db.py").write_text(
        "vulnerable = True\n", encoding="utf-8"
    )
    authority = AuthoritySnapshot.from_warrant(document, repository_root=repository_root)
    broker_role = f"crosspatch_broker_{secrets.token_hex(5)}"
    broker_password = secrets.token_urlsafe(24)
    runtime_dsn = make_url(dsn).set(
        username=broker_role,
        password=broker_password,
    ).render_as_string(hide_password=False)

    async def prepare() -> None:
        engine = create_async_engine(dsn)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            await install_warrant_guards(connection)
            await connection.execute(
                text(f'CREATE ROLE "{broker_role}" LOGIN PASSWORD \'{broker_password}\'')
            )
            await grant_broker_warrant_privileges(connection, role_name=broker_role)
        store = PostgresWarrantStore(async_sessionmaker(engine, expire_on_commit=False))
        await store.add_approved(document, approval, authority)
        await engine.dispose()

    asyncio.run(prepare())
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    processes = [
        context.Process(
            target=_claim_process,
            args=(runtime_dsn, document.warrant_id, results),
        )
        for _ in range(6)
    ]
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=30)
            assert not process.is_alive()
            assert process.exitcode == 0
        observed: list[str] = []
        for _ in processes:
            try:
                observed.append(results.get(timeout=5))
            except Empty:
                pytest.fail("PostgreSQL claim worker returned no result")
        assert observed.count("CLAIMED") == 1
        assert observed.count("REPLAY_REJECTED") == len(processes) - 1
        assert not [result for result in observed if result.startswith("ERROR:")]

        async def verify() -> None:
            engine = create_async_engine(dsn)
            sessions = async_sessionmaker(engine, expire_on_commit=False)
            async with sessions() as session:
                row = await session.scalar(
                    select(WarrantRecord).where(WarrantRecord.id == document.warrant_id)
                )
                assert row is not None
                assert row.state == "CONSUMING"
                assert row.claimed_at is not None
                assert row.nonce_consumed_at is not None
            await engine.dispose()

        asyncio.run(verify())

        async def verify_role_boundary() -> None:
            engine = create_async_engine(runtime_dsn)
            async with engine.connect() as connection:
                with pytest.raises(DBAPIError, match="permission denied"):
                    await connection.execute(
                        text(
                            "UPDATE mutation_authority SET version = version + 1 "
                            "WHERE incident_id = :incident_id"
                        ),
                        {"incident_id": document.incident_id},
                    )
                    await connection.commit()
                await connection.rollback()
                with pytest.raises(DBAPIError, match="permission denied"):
                    await connection.execute(
                        text("DELETE FROM mutation_warrants WHERE id = :warrant_id"),
                        {"warrant_id": document.warrant_id},
                    )
                    await connection.commit()
                await connection.rollback()
            await engine.dispose()

        asyncio.run(verify_role_boundary())
    finally:

        async def cleanup() -> None:
            engine = create_async_engine(dsn)
            async with engine.begin() as connection:
                await connection.execute(
                    delete(WarrantRecord).where(WarrantRecord.id == document.warrant_id)
                )
                await connection.execute(
                    delete(MutationAuthorityRecord).where(
                        MutationAuthorityRecord.incident_id == document.incident_id
                    )
                )
                await connection.execute(text(f'DROP OWNED BY "{broker_role}"'))
                await connection.execute(text(f'DROP ROLE "{broker_role}"'))
            await engine.dispose()

        asyncio.run(cleanup())
