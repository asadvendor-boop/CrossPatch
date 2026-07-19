from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from crosspatch.broker.broker import BrokerResult, BrokerStatus, WarrantState
from crosspatch.db.models import (
    RuntimeWorkRecord,
    WarrantRecord,
)
from crosspatch.db.models import (
    TestRunRecord as DBTestRunRecord,
)
from crosspatch.domain.enums import Effort, IncidentState, Seat
from crosspatch.domain.hashing import canonical_json
from crosspatch.mcp.auth import TokenIssuer
from crosspatch.orchestration.coordinator import Coordinator
from crosspatch.runner.catalog import ExecutionCatalog
from crosspatch.runner.results import ProcessReceipt
from crosspatch.runtime.auth import JudgeTokenRepository
from crosspatch.runtime.authority import PersistingAgentRuntime
from crosspatch.runtime.control import DatabaseControlService
from crosspatch.runtime.database import RuntimeDatabase
from crosspatch.runtime.incidents import BundledIncidentLauncher
from crosspatch.runtime.readers import DatabaseCitationAuthority
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from backend.tests.runtime.test_failure_cycle_invariants import (
    PATCH_V2,
    _approve,
    _counsel,
    _judge_config,
    _NoopLauncher,
    _prepared_incident,
    _ScriptedRuntime,
)


async def _consumed_result_without_projection(
    database: RuntimeDatabase,
    warrant_id: str,
    *,
    passed: bool,
) -> BrokerResult:
    plan = ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
    receipt = ProcessReceipt.for_test(plan=plan, exit_code=0 if passed else 1)
    now = datetime.now(UTC)
    async with database.sessions() as session, session.begin():
        warrant = await session.get(WarrantRecord, warrant_id)
        assert warrant is not None
        result = BrokerResult(
            warrant_id=warrant_id,
            status=BrokerStatus.EXECUTED if passed else BrokerStatus.TEST_FAILED,
            receipts=(receipt,),
            error_code=None if passed else "FIXED_TEST_PLAN_FAILED",
            nonce_sha256=warrant.nonce_sha256,
        )
        warrant.state = WarrantState.CONSUMED.value
        warrant.claimed_at = now
        warrant.nonce_consumed_at = now
        warrant.finished_at = now
        warrant.result_json = canonical_json(result)
        warrant.updated_at = now
    return result


class _NeverReplayBailiff:
    async def resume_after_approval(self, *_args, **_kwargs):
        raise AssertionError("durably consumed broker work must not replay Bailiff")


class _NeverResumeCompletedRepair:
    def restore_incident_outputs(self, *_args, **_kwargs) -> None:
        raise AssertionError("a repair with a durable successor must not replay")


class _RecoveredRepair:
    def __init__(self, authority) -> None:
        self.authority = authority
        self.outputs = None
        self.resume_calls = 0

    def restore_incident_outputs(self, _incident_id: str, outputs, **_kwargs) -> None:
        self.outputs = outputs

    async def resume_after_test(self, incident, *, test_passed: bool):
        assert self.outputs is not None
        assert test_passed is False
        _output, effort, escalation_count = self.outputs[Seat.COUNSEL]
        assert (effort, escalation_count) == (Effort.HIGH, 1)
        self.resume_calls += 1
        await self.authority.fail_closed_abstain(
            incident.incident_id,
            reason="sdk_exception",
            failure_code="TEST_RECOVERY_TERMINAL",
        )


class _RecordingRecoveryRuntime(_ScriptedRuntime):
    def __init__(self) -> None:
        super().__init__(duplicate_repair=False)
        self.calls: list[tuple[Seat, str]] = []

    async def run_seat(self, *, seat, effort, phase, request):
        self.calls.append((seat, phase))
        return await super().run_seat(
            seat=seat,
            effort=effort,
            phase=phase,
            request=request,
        )


def _service(
    database: RuntimeDatabase,
    authority,
    *,
    approval_resumer=None,
    repair_resumer=None,
) -> DatabaseControlService:
    return DatabaseControlService(
        store=database.store,
        authority=authority,
        launcher=_NoopLauncher(),
        judge_tokens=JudgeTokenRepository(database.sessions),
        judge_issuer=TokenIssuer(_judge_config()),
        judge_token_expires_at=datetime(2026, 9, 1, 7, tzinfo=UTC),
        export_signing_key=Ed25519PrivateKey.generate(),
        approval_resumer=approval_resumer,
        repair_resumer=repair_resumer,
    )


@pytest.mark.asyncio
async def test_approval_commits_a_pending_execution_work_item_atomically(
    tmp_path: Path,
) -> None:
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'approval-work.db'}")
    await database.bootstrap()
    try:
        authority, coordinator, incident, _ = await _prepared_incident(
            database,
            duplicate_repair=False,
        )
        initial = await coordinator.run_incident(incident)
        assert initial.pending_warrant_id is not None
        control = await _approve(authority, initial.pending_warrant_id)

        async with database.sessions() as session:
            work = await session.get(RuntimeWorkRecord, f"execute:{control.id}")
        assert work is not None
        assert work.incident_id == incident.incident_id
        assert work.warrant_id == control.id
        assert work.kind == "APPROVED_EXECUTION"
        assert work.status == "PENDING"
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_approval_and_execution_work_roll_back_together(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'approval-atomic.db'}")
    await database.bootstrap()
    try:
        authority, coordinator, incident, _ = await _prepared_incident(
            database,
            duplicate_repair=False,
        )
        initial = await coordinator.run_incident(incident)
        assert initial.pending_warrant_id is not None
        warrant = await authority.get_warrant(initial.pending_warrant_id)
        assert warrant is not None

        async def crash_before_commit(*_args, **_kwargs) -> None:
            raise RuntimeError("simulated approval commit loss")

        monkeypatch.setattr(database.store, "_publish_locked", crash_before_commit)
        with pytest.raises(RuntimeError, match="simulated approval commit loss"):
            await authority.decide_warrant(
                warrant_id=warrant.id,
                approve=True,
                warrant_sha256=warrant.warrant_sha256,
                actor="approver-1",
            )

        async with database.sessions() as session:
            control = await authority.store.control_warrant(warrant.id)
            broker = await session.get(WarrantRecord, warrant.id)
            work = await session.get(RuntimeWorkRecord, f"execute:{warrant.id}")
        assert control is not None and control.status == "PENDING_APPROVAL"
        assert broker is None
        assert work is None
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_startup_projects_consumed_result_without_replaying_bailiff(
    tmp_path: Path,
) -> None:
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'consumed.db'}")
    await database.bootstrap()
    try:
        authority, coordinator, incident, _ = await _prepared_incident(
            database,
            duplicate_repair=False,
        )
        initial = await coordinator.run_incident(incident)
        assert initial.pending_warrant_id is not None
        control = await _approve(authority, initial.pending_warrant_id)
        await _consumed_result_without_projection(database, control.id, passed=True)
        abandoned = await database.store.claim_runtime_work(
            f"execute:{control.id}",
            owner_id="dead-control-process",
        )
        assert abandoned is not None and abandoned.status == "RUNNING"

        launcher = BundledIncidentLauncher(
            store=database.store,
            authority=authority,
            coordinator=_NeverReplayBailiff(),  # type: ignore[arg-type]
            reproduction_factories={"webhook-race": lambda: None},  # type: ignore[dict-item]
            raw_artifact_root=tmp_path / "raw",
            sanitized_artifact_root=tmp_path / "sanitized",
            openai_api_key="configured",
        )
        service = _service(
            database,
            authority,
            approval_resumer=launcher.execute_approved_only,
        )

        assert await service.reconcile_runtime_work() == 1
        await service.wait_for_runtime_work()
        assert await service.reconcile_runtime_work() == 0
        await service.wait_for_runtime_work()
        recovered_result = await database.store.project_broker_result(
            incident.incident_id,
            control.id,
            evidence_id="ev-must-not-create-a-second-projection",
        )
        assert recovered_result.status is BrokerStatus.EXECUTED

        async with database.sessions() as session:
            work = await session.get(RuntimeWorkRecord, f"execute:{control.id}")
            tests = tuple(
                (
                    await session.scalars(
                        select(DBTestRunRecord).where(
                            DBTestRunRecord.incident_id == incident.incident_id
                        )
                    )
                ).all()
            )
        persisted = await database.store.get_incident_record(incident.incident_id)
        assert work is not None and work.status == "COMPLETED"
        assert len(tests) == 1
        assert persisted is not None and persisted.state == IncidentState.VERIFIED.value
        await service.close()
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_failed_projection_and_repair_work_roll_back_together(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'projection-atomic.db'}")
    await database.bootstrap()
    try:
        authority, coordinator, incident, _ = await _prepared_incident(
            database,
            duplicate_repair=False,
        )
        initial = await coordinator.run_incident(incident)
        assert initial.pending_warrant_id is not None
        control = await _approve(authority, initial.pending_warrant_id)
        await _consumed_result_without_projection(database, control.id, passed=False)

        original_publish = database.store._publish_locked

        async def crash_before_commit(*_args, **_kwargs) -> None:
            raise RuntimeError("simulated projection commit loss")

        monkeypatch.setattr(database.store, "_publish_locked", crash_before_commit)
        with pytest.raises(RuntimeError, match="simulated projection commit loss"):
            await database.store.project_broker_result(
                incident.incident_id,
                control.id,
                evidence_id="ev-invariant-1",
            )

        async with database.sessions() as session:
            execution = await session.get(RuntimeWorkRecord, f"execute:{control.id}")
            repair = await session.get(RuntimeWorkRecord, f"repair:{control.id}")
            tests = tuple(
                (
                    await session.scalars(
                        select(DBTestRunRecord).where(
                            DBTestRunRecord.incident_id == incident.incident_id
                        )
                    )
                ).all()
            )
        persisted = await database.store.get_incident_record(incident.incident_id)
        assert execution is not None and execution.status == "PENDING"
        assert repair is None
        assert tests == ()
        assert persisted is not None and persisted.state == IncidentState.APPROVED.value

        monkeypatch.setattr(database.store, "_publish_locked", original_publish)
        await database.store.project_broker_result(
            incident.incident_id,
            control.id,
            evidence_id="ev-invariant-1",
        )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_recovery_exception_fails_closed_and_does_not_redeliver(
    tmp_path: Path,
) -> None:
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'failed-work.db'}")
    await database.bootstrap()
    calls = 0

    async def fail_delivery(_incident_id: str, _warrant_id: str) -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("simulated runtime failure")

    try:
        authority, coordinator, incident, _ = await _prepared_incident(
            database,
            duplicate_repair=False,
        )
        initial = await coordinator.run_incident(incident)
        assert initial.pending_warrant_id is not None
        control = await _approve(authority, initial.pending_warrant_id)
        service = _service(
            database,
            authority,
            approval_resumer=fail_delivery,
        )

        assert await service.reconcile_runtime_work() == 1
        await service.wait_for_runtime_work()
        assert await service.reconcile_runtime_work() == 0

        async with database.sessions() as session:
            work = await session.get(RuntimeWorkRecord, f"execute:{control.id}")
        persisted = await database.store.get_incident_record(incident.incident_id)
        assert calls == 1
        assert work is not None and work.status == "COMPLETED"
        assert (
            persisted is not None
            and persisted.state == IncidentState.HUMAN_ESCALATION.value
        )
        await service.close()
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_background_failure_and_work_completion_are_one_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'failed-atomic.db'}")
    await database.bootstrap()
    try:
        authority, coordinator, incident, _ = await _prepared_incident(
            database,
            duplicate_repair=False,
        )
        initial = await coordinator.run_incident(incident)
        assert initial.pending_warrant_id is not None
        control = await _approve(authority, initial.pending_warrant_id)
        work_id = f"execute:{control.id}"
        claimed = await database.store.claim_runtime_work(
            work_id,
            owner_id="crashing-control",
        )
        assert claimed is not None and claimed.status == "RUNNING"
        original_publish = database.store._publish_locked

        async def crash_before_commit(*_args, **_kwargs) -> None:
            raise RuntimeError("simulated failure-outcome commit loss")

        monkeypatch.setattr(database.store, "_publish_locked", crash_before_commit)
        with pytest.raises(RuntimeError, match="simulated failure-outcome commit loss"):
            await database.store.fail_runtime_work(
                work_id,
                operation="runtime-work:approved_execution",
                failure_outcome="RuntimeError",
            )

        persisted = await database.store.get_incident_record(incident.incident_id)
        async with database.sessions() as session:
            work = await session.get(RuntimeWorkRecord, work_id)
        assert persisted is not None and persisted.state == IncidentState.APPROVED.value
        assert work is not None and work.status == "RUNNING"

        monkeypatch.setattr(database.store, "_publish_locked", original_publish)
        await database.store.fail_runtime_work(
            work_id,
            operation="runtime-work:approved_execution",
            failure_outcome="RuntimeError",
        )
        persisted = await database.store.get_incident_record(incident.incident_id)
        async with database.sessions() as session:
            work = await session.get(RuntimeWorkRecord, work_id)
        assert (
            persisted is not None
            and persisted.state == IncidentState.HUMAN_ESCALATION.value
        )
        assert work is not None and work.status == "COMPLETED"
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_old_repair_does_not_replay_after_successor_warrant_is_approved(
    tmp_path: Path,
) -> None:
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'successor.db'}")
    await database.bootstrap()
    try:
        authority, coordinator, incident, _ = await _prepared_incident(
            database,
            duplicate_repair=False,
        )
        initial = await coordinator.run_incident(incident)
        assert initial.pending_warrant_id is not None
        first = await _approve(authority, initial.pending_warrant_id)
        await _consumed_result_without_projection(database, first.id, passed=False)
        await database.store.project_broker_result(
            incident.incident_id,
            first.id,
            evidence_id="ev-invariant-1",
        )
        revised = await coordinator.resume_after_test(incident, test_passed=False)
        assert revised.pending_warrant_id is not None
        second = await _approve(authority, revised.pending_warrant_id)

        launcher = BundledIncidentLauncher(
            store=database.store,
            authority=authority,
            coordinator=_NeverResumeCompletedRepair(),  # type: ignore[arg-type]
            reproduction_factories={"webhook-race": lambda: None},  # type: ignore[dict-item]
            raw_artifact_root=tmp_path / "raw-successor",
            sanitized_artifact_root=tmp_path / "sanitized-successor",
            openai_api_key="configured",
        )
        await launcher.repair_failed(incident.incident_id, first.id)

        async with database.sessions() as session:
            old_repair = await session.get(RuntimeWorkRecord, f"repair:{first.id}")
        persisted = await database.store.get_incident_record(incident.incident_id)
        assert old_repair is not None and old_repair.status == "COMPLETED"
        assert persisted is not None and persisted.state == IncidentState.APPROVED.value
        assert second.id != first.id
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_restart_continues_after_accepted_repair_without_repatching(
    tmp_path: Path,
) -> None:
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'repair-stage.db'}")
    await database.bootstrap()
    try:
        authority, coordinator, incident, _ = await _prepared_incident(
            database,
            duplicate_repair=False,
        )
        initial = await coordinator.run_incident(incident)
        assert initial.pending_warrant_id is not None
        first = await _approve(authority, initial.pending_warrant_id)
        await _consumed_result_without_projection(database, first.id, passed=False)
        await database.store.project_broker_result(
            incident.incident_id,
            first.id,
            evidence_id="ev-invariant-1",
        )
        await authority.begin_review(incident.incident_id)
        await authority.record_escalation(
            incident.incident_id,
            seat=Seat.COUNSEL,
            effort=Effort.HIGH,
            escalation_count=1,
            reason="test_failure",
            message="reserved accepted repair",
        )
        await database.store.record_seat_output(
            incident_id=incident.incident_id,
            seat=Seat.COUNSEL,
            effort=Effort.HIGH,
            phase="test-failure-repair",
            output=_counsel(PATCH_V2),
            escalation_count=1,
        )

        runtime = _RecordingRecoveryRuntime()
        citations = DatabaseCitationAuthority(database.sessions)
        recovered = Coordinator(
            runtime=PersistingAgentRuntime(
                runtime,
                database.store,
                citations=citations,
            ),
            authority=authority,
            citations=citations,
        )
        launcher = BundledIncidentLauncher(
            store=database.store,
            authority=authority,
            coordinator=recovered,
            reproduction_factories={"webhook-race": lambda: None},  # type: ignore[dict-item]
            raw_artifact_root=tmp_path / "raw-stage",
            sanitized_artifact_root=tmp_path / "sanitized-stage",
            openai_api_key="configured",
        )
        await launcher.repair_failed(incident.incident_id, first.id)

        assert (Seat.COUNSEL, "test-failure-repair") not in runtime.calls
        assert (Seat.PROSECUTOR, "test-failure-challenge") in runtime.calls
        assert (Seat.MAGISTRATE, "test-failure-review") in runtime.calls
        persisted = await database.store.get_incident_record(incident.incident_id)
        async with database.sessions() as session:
            repair = await session.get(RuntimeWorkRecord, f"repair:{first.id}")
        assert (
            persisted is not None
            and persisted.state == IncidentState.APPROVAL_PENDING.value
        )
        assert repair is not None and repair.status == "COMPLETED"
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_startup_restores_outputs_before_resuming_durable_repair(
    tmp_path: Path,
) -> None:
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'repair.db'}")
    await database.bootstrap()
    try:
        authority, coordinator, incident, _ = await _prepared_incident(
            database,
            duplicate_repair=False,
        )
        initial = await coordinator.run_incident(incident)
        assert initial.pending_warrant_id is not None
        control = await _approve(authority, initial.pending_warrant_id)
        await _consumed_result_without_projection(database, control.id, passed=False)
        await database.store.project_broker_result(
            incident.incident_id,
            control.id,
            evidence_id="ev-invariant-1",
        )
        await authority.begin_review(incident.incident_id)
        await authority.record_escalation(
            incident.incident_id,
            seat=Seat.COUNSEL,
            effort=Effort.HIGH,
            escalation_count=1,
            reason="test_failure",
            message="attempt reserved before process loss",
        )
        abandoned = await database.store.claim_runtime_work(
            f"repair:{control.id}",
            owner_id="dead-control-process",
        )
        assert abandoned is not None and abandoned.status == "RUNNING"

        recovered = _RecoveredRepair(authority)
        launcher = BundledIncidentLauncher(
            store=database.store,
            authority=authority,
            coordinator=recovered,  # type: ignore[arg-type]
            reproduction_factories={"webhook-race": lambda: None},  # type: ignore[dict-item]
            raw_artifact_root=tmp_path / "raw-repair",
            sanitized_artifact_root=tmp_path / "sanitized-repair",
            openai_api_key="configured",
        )
        service = _service(
            database,
            authority,
            repair_resumer=launcher.repair_failed,
        )

        assert await service.reconcile_runtime_work() == 1
        await service.wait_for_runtime_work()
        assert await service.reconcile_runtime_work() == 0
        await service.wait_for_runtime_work()

        async with database.sessions() as session:
            work = await session.get(RuntimeWorkRecord, f"repair:{control.id}")
        persisted = await database.store.get_incident_record(incident.incident_id)
        assert recovered.resume_calls == 1
        assert work is not None and work.status == "COMPLETED"
        assert (
            persisted is not None
            and persisted.state == IncidentState.HUMAN_ESCALATION.value
        )
        await service.close()
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_missing_runtime_resumer_fails_closed_on_the_bound_incident(
    tmp_path: Path,
) -> None:
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'missing-resumer.db'}")
    await database.bootstrap()
    try:
        authority, coordinator, incident, _ = await _prepared_incident(
            database,
            duplicate_repair=False,
        )
        initial = await coordinator.run_incident(incident)
        assert initial.pending_warrant_id is not None
        await _approve(authority, initial.pending_warrant_id)
        service = _service(database, authority)

        assert await service.reconcile_runtime_work() == 1
        await service.wait_for_runtime_work()

        persisted = await database.store.get_incident_record(incident.incident_id)
        events = await database.store.timeline_records(incident.incident_id)
        assert persisted is not None
        assert persisted.state == IncidentState.HUMAN_ESCALATION.value
        assert events[-1].type == "BACKGROUND_TASK_FAILED"
        assert events[-1].payload == {
            "operation": "runtime-work:approved_execution",
            "failure_outcome": "RuntimeError",
        }
        await service.close()
    finally:
        await database.close()


@pytest.mark.parametrize(
    "interrupted_state",
    (
        IncidentState.OPEN,
        IncidentState.REPRODUCING,
        IncidentState.EVIDENCE_READY,
        IncidentState.ANALYZING,
        IncidentState.PATCHING,
        IncidentState.REVIEWING,
    ),
)
@pytest.mark.asyncio
async def test_startup_reconciliation_fails_closed_interrupted_incident_work(
    tmp_path: Path,
    interrupted_state: IncidentState,
) -> None:
    database = RuntimeDatabase(
        f"sqlite+aiosqlite:///{tmp_path / f'interrupted-{interrupted_state.value}.db'}"
    )
    await database.bootstrap()
    incident_id = f"inc-interrupted-{interrupted_state.value.lower()}"
    try:
        await database.store.create_incident(
            incident_id=incident_id,
            title="Interrupted incident work",
            scenario="webhook-race",
            state=interrupted_state,
            base_sha="1" * 40,
            repository_manifest_sha256="2" * 64,
            catalog_sha256="3" * 64,
            actor="operator-1",
        )
        service = _service(database, object())

        assert await service.reconcile_runtime_work() == 0
        assert await service.reconcile_runtime_work() == 0

        persisted = await database.store.get_incident_record(incident_id)
        events = await database.store.timeline_records(incident_id)
        failures = [event for event in events if event.type == "BACKGROUND_TASK_FAILED"]
        assert persisted is not None
        assert persisted.state == IncidentState.HUMAN_ESCALATION.value
        assert len(failures) == 1
        assert failures[0].payload == {
            "operation": "startup-reconciliation",
            "failure_outcome": "PROCESS_RESTART",
        }
        await service.close()
    finally:
        await database.close()
