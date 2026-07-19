from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import pytest_asyncio
from crosspatch.broker.approval import canonical_approval_bytes, parse_approval_json
from crosspatch.broker.broker import BrokerResult, BrokerStatus, WarrantState
from crosspatch.broker.warrant import (
    BoundExecutionPlan,
    WarrantDocument,
    canonical_warrant_bytes,
    parse_warrant_json,
)
from crosspatch.db.models import (
    ControlWarrantRecord,
    IncidentRecord,
    PublishedCaseRecord,
    TimelineEventRecord,
    VerdictRecord,
    WarrantRecord,
)
from crosspatch.db.models import (
    TestRunRecord as DBTestRunRecord,
)
from crosspatch.domain.enums import Verdict
from crosspatch.domain.hashing import canonical_json, sha256_hex
from crosspatch.runner.catalog import ExecutionCatalog
from crosspatch.runner.results import ProcessReceipt
from crosspatch.runtime.control import DatabaseControlService
from crosspatch.runtime.database import RuntimeDatabase
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from backend.tests.runtime.test_failure_cycle_invariants import (
    _approve,
    _control_service,
    _prepared_incident,
)


@dataclass(slots=True)
class _CompletedCase:
    database: RuntimeDatabase
    authority: Any
    coordinator: Any
    incident: Any
    service: DatabaseControlService
    control: ControlWarrantRecord
    result_json: bytes


async def _complete_broker_result(
    database: RuntimeDatabase,
    warrant_id: str,
    *,
    passed: bool,
) -> bytes:
    plan = ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
    receipt = ProcessReceipt.for_test(plan=plan, exit_code=0 if passed else 1)
    now = datetime.now(UTC)
    async with database.sessions() as session, session.begin():
        broker = await session.get(WarrantRecord, warrant_id)
        assert broker is not None
        result = BrokerResult(
            warrant_id=warrant_id,
            status=BrokerStatus.EXECUTED if passed else BrokerStatus.TEST_FAILED,
            receipts=(receipt,),
            error_code=None if passed else "FIXED_TEST_PLAN_FAILED",
            nonce_sha256=broker.nonce_sha256,
        )
        broker.state = WarrantState.CONSUMED.value
        broker.claimed_at = now
        broker.nonce_consumed_at = now
        broker.finished_at = now
        broker.result_json = canonical_json(result)
        broker.updated_at = now
        result_json = bytes(broker.result_json)
    await database.store.project_broker_result(
        "inc-invariant-1",
        warrant_id,
        evidence_id="ev-invariant-1",
    )
    return result_json


async def _completed_case(tmp_path: Path, *, passed: bool) -> _CompletedCase:
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'export-atomic.db'}")
    await database.bootstrap()
    authority, coordinator, incident, _ = await _prepared_incident(
        database,
        duplicate_repair=False,
    )
    initial = await coordinator.run_incident(incident)
    assert initial.pending_warrant_id is not None
    control = await _approve(authority, initial.pending_warrant_id)
    result_json = await _complete_broker_result(
        database,
        control.id,
        passed=passed,
    )
    return _CompletedCase(
        database=database,
        authority=authority,
        coordinator=coordinator,
        incident=incident,
        service=_control_service(
            database,
            authority,
            Ed25519PrivateKey.generate(),
        ),
        control=control,
        result_json=result_json,
    )


@pytest_asyncio.fixture
async def completed_case(tmp_path: Path):
    completed = await _completed_case(tmp_path, passed=True)
    try:
        yield completed
    finally:
        await completed.database.close()


def _archive_members(archive_bytes: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


@pytest.mark.asyncio
async def test_postgres_export_uses_read_only_repeatable_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statements: list[str] = []

    class _Session:
        bind = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

        async def execute(self, statement):
            statements.append(str(statement))

        async def begin(self):
            statements.append("BEGIN")

        async def rollback(self):
            statements.append("ROLLBACK")

    session = _Session()

    class _Sessions:
        async def __aenter__(self):
            return session

        async def __aexit__(self, *args):
            return None

    service = object.__new__(DatabaseControlService)
    service._store = SimpleNamespace(sessions=lambda: _Sessions())

    async def load_snapshot(active_session, incident_id):
        assert active_session is session
        assert incident_id == "inc-export-snapshot"
        return "snapshot"

    monkeypatch.setattr(service, "_load_export_snapshot_locked", load_snapshot)
    monkeypatch.setattr(service, "_build_export", lambda snapshot, incident_id: b"case")

    assert await service.export_case("inc-export-snapshot") == b"case"
    assert statements == [
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
        "ROLLBACK",
    ]


@pytest.mark.asyncio
async def test_export_snapshot_queries_need_only_select_privilege() -> None:
    plan = BoundExecutionPlan.from_execution_plan(
        ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
    )
    patch = b"diff --git a/victim/src/victim/db.py b/victim/src/victim/db.py\n"
    now = datetime.now(UTC)
    document = WarrantDocument(
        format="crosspatch-warrant-v1",
        warrant_id="war_export_select_only",
        incident_id="inc-export-select-only",
        repository_id="crosspatch",
        verdict_id="verdict_export_select_only",
        verdict_sha256="1" * 64,
        candidate_id="candidate_export_select_only",
        authority_snapshot_sha256="2" * 64,
        reviewed_evidence_manifest_sha256="3" * 64,
        reviewed_timeline_head="4" * 64,
        base_sha="5" * 40,
        repository_manifest_sha256="6" * 64,
        patch_b64=base64.b64encode(patch).decode("ascii"),
        patch_sha256=hashlib.sha256(patch).hexdigest(),
        allowed_paths=("victim/src/victim/db.py",),
        execution_plans=(plan,),
        test_plan_sha256=sha256_hex((plan,)),
        runner_digest="7" * 64,
        environment_digest="8" * 64,
        approver_identity="approver-1",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        approval_mac_key_id="approval-v1",
        nonce="nonce_export_select_only",
    )
    incident = SimpleNamespace(event_chain_head="4" * 64)
    published = SimpleNamespace()
    control = SimpleNamespace(
        id=document.warrant_id,
        canonical_document=canonical_warrant_bytes(document),
    )
    verdict = SimpleNamespace()
    broker = SimpleNamespace(
        state=WarrantState.CONSUMED.value,
        result_json=b"{}",
        claimed_at=now,
        nonce_consumed_at=now,
        finished_at=now,
    )
    records = {
        IncidentRecord: incident,
        PublishedCaseRecord: published,
        ControlWarrantRecord: control,
        VerdictRecord: verdict,
        WarrantRecord: broker,
    }

    class _Rows:
        def all(self):
            return []

    class _SelectOnlySession:
        async def scalar(self, statement):
            assert statement._for_update_arg is None
            return records[statement.column_descriptions[0]["entity"]]

        async def scalars(self, statement):
            assert statement._for_update_arg is None
            assert statement.column_descriptions[0]["entity"] in {
                DBTestRunRecord,
                TimelineEventRecord,
            }
            return _Rows()

    snapshot = await DatabaseControlService._load_export_snapshot_locked(
        object(),
        _SelectOnlySession(),
        document.incident_id,
    )
    assert snapshot.incident is incident
    assert snapshot.verdict is verdict
    assert snapshot.broker is broker


@pytest.mark.asyncio
async def test_export_contains_exact_canonical_broker_result_and_receipt_rows(
    completed_case: _CompletedCase,
) -> None:
    archive_bytes = await completed_case.service.export_case("inc-invariant-1")
    members = _archive_members(archive_bytes)
    result_path = "incidents/inc-invariant-1/receipts/broker-result.json"
    receipt_paths = sorted(
        name
        for name in members
        if name.startswith("incidents/inc-invariant-1/receipts/test_")
    )
    assert members[result_path] == completed_case.result_json
    assert len(receipt_paths) == 1

    broker_result = BrokerResult.model_validate_json(completed_case.result_json)
    receipt_row = json.loads(members[receipt_paths[0]])
    expected_receipt = broker_result.receipts[0].model_dump(mode="json")
    assert receipt_row["warrant_id"] == completed_case.control.id
    assert receipt_row["plan_id"] == broker_result.receipts[0].plan_id
    assert receipt_row["plan_sha256"] == broker_result.receipts[0].plan_sha256
    assert receipt_row["result"] == {
        "detail": broker_result.receipts[0].verification_code,
        "duration_ms": round(
            (
                broker_result.receipts[0].finished_at
                - broker_result.receipts[0].started_at
            ).total_seconds()
            * 1000
        ),
        "evidence_id": "ev-invariant-1",
        "passed": True,
        "receipt": expected_receipt,
        "receipt_sha256": sha256_hex(expected_receipt),
        "state": "passed",
        "warrant_id": completed_case.control.id,
    }
    assert receipt_row["receipt"] == expected_receipt
    assert receipt_row["receipt_sha256"] == sha256_hex(expected_receipt)

    manifest = json.loads(members["manifest.json"])
    assert manifest["incident"]["receipt_sha256"] == hashlib.sha256(
        completed_case.result_json
    ).hexdigest()


@pytest.mark.asyncio
async def test_export_rejects_broker_nonce_that_is_not_derived_from_document(
    completed_case: _CompletedCase,
) -> None:
    async with completed_case.database.sessions() as session, session.begin():
        broker = await session.get(WarrantRecord, completed_case.control.id)
        assert broker is not None and broker.result_json is not None
        result = BrokerResult.model_validate_json(broker.result_json)
        forged_nonce_sha256 = "f" * 64
        broker.nonce_sha256 = forged_nonce_sha256
        broker.result_json = canonical_json(
            result.model_copy(update={"nonce_sha256": forged_nonce_sha256})
        )

    with pytest.raises(ValueError, match="bindings disagree"):
        await completed_case.service.export_case("inc-invariant-1")


@pytest.mark.asyncio
async def test_export_rejects_noncanonical_result_bytes(
    completed_case: _CompletedCase,
) -> None:
    async with completed_case.database.sessions() as session, session.begin():
        broker = await session.get(WarrantRecord, completed_case.control.id)
        assert broker is not None and broker.result_json is not None
        parsed = json.loads(broker.result_json)
        broker.result_json = json.dumps(parsed, indent=2, sort_keys=False).encode()

    with pytest.raises(ValueError, match="completed broker result"):
        await completed_case.service.export_case("inc-invariant-1")


@pytest.mark.asyncio
async def test_export_rejects_nonconsumed_broker(
    completed_case: _CompletedCase,
) -> None:
    async with completed_case.database.sessions() as session, session.begin():
        broker = await session.get(WarrantRecord, completed_case.control.id)
        assert broker is not None
        broker.state = WarrantState.APPROVED.value

    with pytest.raises(ValueError, match="completed broker result"):
        await completed_case.service.export_case("inc-invariant-1")


@pytest.mark.asyncio
async def test_export_rejects_invalid_canonical_approval_proof(
    completed_case: _CompletedCase,
) -> None:
    async with completed_case.database.sessions() as session, session.begin():
        broker = await session.get(WarrantRecord, completed_case.control.id)
        assert broker is not None
        approval = parse_approval_json(broker.approval_json)
        broker.approval_json = canonical_approval_bytes(
            approval.model_copy(update={"mac_sha256": "0" * 64})
        )

    with pytest.raises(ValueError, match="approval proof"):
        await completed_case.service.export_case("inc-invariant-1")


@pytest.mark.asyncio
async def test_export_rejects_empty_or_status_inconsistent_receipts(
    completed_case: _CompletedCase,
) -> None:
    async with completed_case.database.sessions() as session, session.begin():
        broker = await session.get(WarrantRecord, completed_case.control.id)
        assert broker is not None and broker.result_json is not None
        result = BrokerResult.model_validate_json(broker.result_json)
        broker.result_json = canonical_json(result.model_copy(update={"receipts": ()}))

    with pytest.raises(ValueError, match="status and receipts disagree"):
        await completed_case.service.export_case("inc-invariant-1")


@pytest.mark.asyncio
async def test_export_rejects_receipt_row_that_disagrees_with_broker_result(
    completed_case: _CompletedCase,
) -> None:
    async with completed_case.database.sessions() as session, session.begin():
        test_run = await session.scalar(
            select(DBTestRunRecord).where(
                DBTestRunRecord.incident_id == "inc-invariant-1"
            )
        )
        assert test_run is not None
        test_run.result = {**test_run.result, "receipt_sha256": "0" * 64}

    with pytest.raises(ValueError, match="receipt rows disagree"):
        await completed_case.service.export_case("inc-invariant-1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "forged"),
    (
        ("state", "failed"),
        ("passed", False),
        ("duration_ms", 999_999),
        ("detail", "FORGED_OUTCOME"),
        ("evidence_id", "ev-forged"),
    ),
)
async def test_export_rejects_persisted_test_outcome_that_disagrees_with_receipt(
    completed_case: _CompletedCase,
    field: str,
    forged: object,
) -> None:
    async with completed_case.database.sessions() as session, session.begin():
        test_run = await session.scalar(
            select(DBTestRunRecord).where(
                DBTestRunRecord.incident_id == "inc-invariant-1"
            )
        )
        assert test_run is not None
        test_run.result = {**test_run.result, field: forged}

    with pytest.raises(ValueError, match="receipt rows disagree"):
        await completed_case.service.export_case("inc-invariant-1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("attribute", "forged"),
    (
        ("plan_id", "forged.plan"),
        ("plan_sha256", "0" * 64),
    ),
)
async def test_export_rejects_persisted_test_binding_that_disagrees_with_receipt(
    completed_case: _CompletedCase,
    attribute: str,
    forged: str,
) -> None:
    async with completed_case.database.sessions() as session, session.begin():
        test_run = await session.scalar(
            select(DBTestRunRecord).where(
                DBTestRunRecord.incident_id == "inc-invariant-1"
            )
        )
        assert test_run is not None
        setattr(test_run, attribute, forged)

    with pytest.raises(ValueError, match="receipt rows disagree"):
        await completed_case.service.export_case("inc-invariant-1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "forged"),
    (
        ("label", "forged.plan"),
        ("plan_sha256", "0" * 64),
        ("state", "failed"),
        ("passed", False),
        ("duration_ms", 999_999),
        ("detail", "FORGED_OUTCOME"),
        ("evidence_id", "ev-forged"),
    ),
)
async def test_export_rejects_projected_test_outcome_that_disagrees_with_receipt(
    completed_case: _CompletedCase,
    field: str,
    forged: object,
) -> None:
    async with completed_case.database.sessions() as session, session.begin():
        published = await session.get(PublishedCaseRecord, "inc-invariant-1")
        assert published is not None
        projection = json.loads(json.dumps(published.projection))
        tests = projection["artifacts"]["tests"]
        assert len(tests) == 1
        tests[0][field] = forged
        published.projection = projection
        published.manifest_sha256 = hashlib.sha256(canonical_json(projection)).hexdigest()

    with pytest.raises(ValueError, match="receipt rows disagree"):
        await completed_case.service.export_case("inc-invariant-1")


@pytest.mark.asyncio
async def test_export_rejects_contradictory_duplicate_projected_test_id(
    completed_case: _CompletedCase,
) -> None:
    async with completed_case.database.sessions() as session, session.begin():
        published = await session.get(PublishedCaseRecord, "inc-invariant-1")
        assert published is not None
        projection = json.loads(json.dumps(published.projection))
        tests = projection["artifacts"]["tests"]
        assert len(tests) == 1
        forged = {**tests[0], "state": "failed", "passed": False}
        tests.insert(0, forged)
        published.projection = projection
        published.manifest_sha256 = hashlib.sha256(canonical_json(projection)).hexdigest()

    with pytest.raises(ValueError, match="receipt rows disagree"):
        await completed_case.service.export_case("inc-invariant-1")


@pytest.mark.asyncio
async def test_export_requires_clear_verdict_semantics(
    completed_case: _CompletedCase,
) -> None:
    async with completed_case.database.sessions() as session, session.begin():
        verdict = await session.scalar(
            select(VerdictRecord).where(
                VerdictRecord.id
                == parse_warrant_json(
                    completed_case.control.canonical_document
                ).verdict_id
            )
        )
        assert verdict is not None
        verdict.verdict = Verdict.BLOCK.value

    with pytest.raises(ValueError, match="verdict semantics"):
        await completed_case.service.export_case("inc-invariant-1")


@pytest.mark.asyncio
async def test_export_remains_unavailable_until_repair_publishes_v2(
    tmp_path: Path,
) -> None:
    completed = await _completed_case(tmp_path, passed=False)
    new_warrant_id: str | None = None

    async def publish_v2() -> None:
        nonlocal new_warrant_id
        revised = await completed.coordinator.resume_after_test(
            completed.incident,
            test_passed=False,
        )
        assert revised.pending_warrant_id is not None
        new_warrant_id = revised.pending_warrant_id
        await _approve(completed.authority, revised.pending_warrant_id)
        await _complete_broker_result(
            completed.database,
            revised.pending_warrant_id,
            passed=True,
        )

    try:
        with pytest.raises(
            ValueError,
            match="persisted verdict, warrant, and broker receipt",
        ):
            await completed.service.export_case("inc-invariant-1")
        await publish_v2()
        archive_bytes = await completed.service.export_case("inc-invariant-1")
        members = _archive_members(archive_bytes)
        manifest = json.loads(members["manifest.json"])
        case_file = json.loads(
            members["incidents/inc-invariant-1/case-file.json"]
        )
        latest_exported = case_file["warrants"][-1]
        assert latest_exported["warrant_id"] == new_warrant_id
        assert latest_exported["canonical_sha256"] == manifest["incident"][
            "warrant_sha256"
        ]
        assert case_file["events"][-1]["event_hash"] == manifest["incident"][
            "timeline_head"
        ]

        async with completed.database.sessions() as session:
            newest = await session.scalar(
                select(ControlWarrantRecord)
                .where(ControlWarrantRecord.incident_id == "inc-invariant-1")
                .order_by(
                    ControlWarrantRecord.created_at.desc(),
                    ControlWarrantRecord.id.desc(),
                )
                .limit(1)
            )
        assert newest is not None and newest.id == new_warrant_id
        assert newest.id != completed.control.id
    finally:
        await completed.database.close()
