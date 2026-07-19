from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from crosspatch.agents.schemas import (
    BailiffOutput,
    CounselOutput,
    InspectorOutput,
    MagistrateOutput,
)
from crosspatch.agents.schemas import (
    TestIntention as AgentTestIntention,
)
from crosspatch.broker.approval import ApprovalService, parse_approval_json
from crosspatch.broker.broker import BrokerResult, BrokerStatus
from crosspatch.broker.warrant import parse_warrant_json
from crosspatch.db.models import (
    AgentRunRecord,
    ControlWarrantRecord,
    PatchCandidateRecord,
    RuntimeWorkRecord,
    VerdictRecord,
    WarrantRecord,
)
from crosspatch.db.models import (
    TestRunRecord as DBTestRunRecord,
)
from crosspatch.domain.enums import Effort, IncidentState, MechanismCode, Seat, Verdict
from crosspatch.domain.hashing import canonical_json
from crosspatch.domain.state_machine import Event, transition_incident
from crosspatch.evidence.sanitizer import sanitize_evidence
from crosspatch.evidence.views import EvidenceKind, UntrustedEvidenceEnvelope
from crosspatch.runner.catalog import ExecutionCatalog
from crosspatch.runner.results import ProcessReceipt
from crosspatch.runner.worktree import repository_manifest_sha256
from crosspatch.runtime.authority import (
    AuthorityPolicy,
    DatabaseAuthorityGateway,
    PersistingAgentRuntime,
    WarrantDecisionConflict,
)
from crosspatch.runtime.database import RuntimeDatabase
from crosspatch.runtime.incidents import BundledIncidentLauncher
from crosspatch.runtime.scenarios import OPERATOR_SCENARIOS
from sqlalchemy import select

REPOSITORY_ROOT = Path(__file__).parents[3]
PATCH = """diff --git a/victim/src/victim/db.py b/victim/src/victim/db.py
index 1111111..2222222 100644
--- a/victim/src/victim/db.py
+++ b/victim/src/victim/db.py
@@ -1,1 +1,1 @@
-from __future__ import annotations
+from __future__ import annotations
"""
PAYLOAD_PATCH = """diff --git a/victim/src/victim/webhooks.py b/victim/src/victim/webhooks.py
index 3333333..4444444 100644
--- a/victim/src/victim/webhooks.py
+++ b/victim/src/victim/webhooks.py
@@ -1,1 +1,1 @@
-\"\"\"Signed webhook parsing and business response mapping.\"\"\"
+\"\"\"Signed webhook parsing and business response mapping.\"\"\"
"""


def _policy() -> AuthorityPolicy:
    return AuthorityPolicy(
        repository_root=REPOSITORY_ROOT,
        repository_id="crosspatch",
        approver_identity="approver-1",
        approval_mac_key_id="approval-v1",
        approval_service=ApprovalService(keys={"approval-v1": b"k" * 32}),
        runner_digest="7" * 64,
        environment_digest="8" * 64,
        warrant_ttl=timedelta(minutes=15),
    )


@pytest_asyncio.fixture
async def database(tmp_path):
    runtime = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'authority.db'}")
    await runtime.bootstrap()
    try:
        yield runtime
    finally:
        await runtime.close()


async def _reviewing_incident(
    database: RuntimeDatabase,
    *,
    actor: str = "operator-1",
    live_trial: bool = False,
    scenario: str = "webhook-race",
) -> UntrustedEvidenceEnvelope:
    base_sha = subprocess.run(
        ["git", "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    await database.store.create_incident(
        incident_id="inc-authority-1",
        title="Webhook duplicate delivery",
        scenario=scenario,
        state=IncidentState.OPEN,
        base_sha=base_sha,
        repository_manifest_sha256=repository_manifest_sha256(REPOSITORY_ROOT, base_sha),
        catalog_sha256=hashlib.sha256(
            json.dumps(ExecutionCatalog.default().plan_ids).encode()
        ).hexdigest(),
        actor=actor,
        live_trial=live_trial,
    )
    sanitized = sanitize_evidence(
        b"duplicate race counts: receipts=1 jobs=2 deliveries=2",
        "deterministic reproduction",
    )
    envelope = UntrustedEvidenceEnvelope.from_sanitized(
        incident_id="inc-authority-1",
        kind=EvidenceKind.TEST_OUTPUT,
        evidence=sanitized,
    )
    await database.store.record_evidence("ev-runtime-1", envelope, published=True)
    await database.store.append_event("inc-authority-1", "REPRODUCTION_STARTED", "runner", {})
    await database.store.append_event(
        "inc-authority-1", "EVIDENCE_CAPTURED", "runner", {"evidence_id": "ev-runtime-1"}
    )
    await database.store.append_event("inc-authority-1", "ANALYSIS_STARTED", "orchestrator", {})
    await database.store.append_event("inc-authority-1", "PATCH_REQUESTED", "orchestrator", {})
    await database.store.append_event(
        "inc-authority-1", "PATCH_PROPOSED", "Counsel", {"candidate_id": "candidate-1"}
    )
    return envelope


def _clear_outputs(
    plan_ids: tuple[str, ...],
    *,
    patch: str = PATCH,
) -> tuple[CounselOutput, MagistrateOutput]:
    counsel = CounselOutput(
        normalized_diff=patch,
        test_intentions=tuple(
            AgentTestIntention(
                catalog_id=plan_id,
                purpose="run the server-owned scenario candidate plan",
            )
            for plan_id in plan_ids
        ),
        evidence_ids=("ev-runtime-1",),
    )
    magistrate = MagistrateOutput(
        verdict=Verdict.CLEAR,
        finding_codes=("CAUSAL_AND_SCOPED",),
        required_changes=(),
        evidence_ids=("ev-runtime-1",),
    )
    return counsel, magistrate


@pytest.mark.parametrize(
    "state",
    (IncidentState.ANALYZING, IncidentState.PATCHING, IncidentState.REVIEWING),
)
def test_abstain_is_a_typed_fail_closed_transition_from_model_running_states(state) -> None:
    assert (
        transition_incident(state, Event.verdict(Verdict.ABSTAIN)) is IncidentState.HUMAN_ESCALATION
    )


@pytest.mark.asyncio
async def test_fail_closed_abstain_is_atomic_and_never_materializes_a_warrant(database) -> None:
    await _reviewing_incident(database)
    authority = DatabaseAuthorityGateway(database.store, _policy())

    await authority.fail_closed_abstain("inc-authority-1", reason="refusal")

    incident = await database.store.get_incident_record("inc-authority-1")
    events = await database.store.timeline_records("inc-authority-1")
    assert incident.state == IncidentState.HUMAN_ESCALATION.value
    assert events[-1].type == "VERDICT"
    assert events[-1].payload == {"verdict": "ABSTAIN", "reason": "refusal"}
    async with database.sessions() as session:
        assert await session.scalar(select(ControlWarrantRecord)) is None
        assert await session.scalar(select(WarrantRecord)) is None


@pytest.mark.parametrize(
    ("scenario", "patch"),
    (
        ("webhook-race", PATCH),
        ("webhook-payload-equivalence", PAYLOAD_PATCH),
    ),
)
@pytest.mark.asyncio
async def test_approval_accepts_only_the_plan_bound_to_the_persisted_scenario(
    database,
    scenario: str,
    patch: str,
) -> None:
    await _reviewing_incident(database, scenario=scenario)
    definition = OPERATOR_SCENARIOS[scenario]
    counsel, magistrate = _clear_outputs(
        (definition.candidate_plan_id,),
        patch=patch,
    )
    authority = DatabaseAuthorityGateway(database.store, _policy())

    warrant_id = await authority.open_approval(
        "inc-authority-1",
        magistrate,
        {Seat.COUNSEL: counsel, Seat.MAGISTRATE: magistrate},
    )

    async with database.sessions() as session:
        control = await session.get(ControlWarrantRecord, warrant_id)
        broker = await session.get(WarrantRecord, warrant_id)
    assert control is not None
    assert broker is None


@pytest.mark.parametrize(
    ("scenario", "wrong_plan_id", "patch"),
    (
        (
            "webhook-race",
            "victim.payload-equivalence.candidate",
            PATCH,
        ),
        (
            "webhook-payload-equivalence",
            "victim.duplicate-race.candidate",
            PAYLOAD_PATCH,
        ),
    ),
)
@pytest.mark.asyncio
async def test_swapped_scenario_plan_is_rejected_before_any_warrant_row(
    database,
    scenario: str,
    wrong_plan_id: str,
    patch: str,
) -> None:
    await _reviewing_incident(database, scenario=scenario)
    counsel, magistrate = _clear_outputs((wrong_plan_id,), patch=patch)
    authority = DatabaseAuthorityGateway(database.store, _policy())

    with pytest.raises(
        ValueError,
        match="approval plan does not match incident scenario",
    ):
        await authority.open_approval(
            "inc-authority-1",
            magistrate,
            {Seat.COUNSEL: counsel, Seat.MAGISTRATE: magistrate},
        )

    async with database.sessions() as session:
        assert await session.scalar(select(ControlWarrantRecord)) is None
        assert await session.scalar(select(WarrantRecord)) is None


@pytest.mark.parametrize(
    "plan_ids",
    (
        (
            "victim.duplicate-race.candidate",
            "victim.payload-equivalence.candidate",
        ),
        ("victim.unknown.candidate",),
    ),
)
@pytest.mark.asyncio
async def test_multiple_or_unknown_plans_are_rejected_before_any_warrant_row(
    database,
    plan_ids: tuple[str, ...],
) -> None:
    await _reviewing_incident(database, scenario="webhook-race")
    counsel, magistrate = _clear_outputs(plan_ids)
    authority = DatabaseAuthorityGateway(database.store, _policy())

    with pytest.raises(
        ValueError,
        match="approval plan does not match incident scenario",
    ):
        await authority.open_approval(
            "inc-authority-1",
            magistrate,
            {Seat.COUNSEL: counsel, Seat.MAGISTRATE: magistrate},
        )

    async with database.sessions() as session:
        assert await session.scalar(select(ControlWarrantRecord)) is None
        assert await session.scalar(select(WarrantRecord)) is None


@pytest.mark.asyncio
async def test_structured_seat_output_survives_runtime_restart(database) -> None:
    envelope = await _reviewing_incident(database)

    class Runtime:
        async def run_seat(self, **_kwargs):
            return InspectorOutput(
                mechanism=MechanismCode.CHECK_THEN_INSERT_RACE,
                evidence_ids=("ev-runtime-1",),
                falsifiers=("victim.worker-retry",),
                analysis="Cited mechanism",
            )

    runtime = PersistingAgentRuntime(Runtime(), database.store)
    output = await runtime.run_seat(
        seat=Seat.INSPECTOR,
        effort=Effort.MEDIUM,
        phase="mechanism-analysis",
        request=type("Request", (), {"incident_id": envelope.incident_id})(),
    )
    assert output.evidence_ids == ("ev-runtime-1",)

    async with database.sessions() as session:
        row = await session.scalar(select(AgentRunRecord))
    assert row is not None
    assert row.seat == Seat.INSPECTOR.value
    assert InspectorOutput.model_validate_json(row.output_json) == output
    assert row.output_sha256 == hashlib.sha256(row.output_json).hexdigest()


@pytest.mark.asyncio
async def test_counsel_candidate_is_complete_and_immutable_before_approval(database) -> None:
    await _reviewing_incident(database)
    counsel = CounselOutput(
        normalized_diff=PATCH,
        test_intentions=(
            AgentTestIntention(
                catalog_id="victim.duplicate-race.candidate",
                purpose="prove exactly once under the duplicate race",
            ),
        ),
        evidence_ids=("ev-runtime-1",),
    )
    magistrate = MagistrateOutput(
        verdict=Verdict.CLEAR,
        finding_codes=("CAUSAL_AND_SCOPED",),
        required_changes=(),
        evidence_ids=("ev-runtime-1",),
    )
    run = await database.store.record_seat_output(
        incident_id="inc-authority-1",
        seat=Seat.COUNSEL,
        effort=Effort.MEDIUM,
        phase="patch-proposal",
        output=counsel,
    )

    async with database.sessions() as session:
        before = await session.scalar(
            select(PatchCandidateRecord).where(PatchCandidateRecord.agent_run_id == run.id)
        )
        assert before is not None
        candidate_id = before.id
        created_at = before.created_at
        assert before.allowed_paths == ["victim/src/victim/db.py"]

    authority = DatabaseAuthorityGateway(database.store, _policy())
    await authority.open_approval(
        "inc-authority-1",
        magistrate,
        {Seat.COUNSEL: counsel, Seat.MAGISTRATE: magistrate},
    )

    async with database.sessions() as session:
        candidates = tuple((await session.scalars(select(PatchCandidateRecord))).all())
    assert len(candidates) == 1
    assert candidates[0].id == candidate_id
    assert candidates[0].created_at == created_at
    assert candidates[0].allowed_paths == ["victim/src/victim/db.py"]


@pytest.mark.asyncio
async def test_pending_warrant_has_no_broker_authority_until_exact_human_approval(database) -> None:
    await _reviewing_incident(database)
    authority = DatabaseAuthorityGateway(database.store, _policy())
    counsel = CounselOutput(
        normalized_diff=PATCH,
        test_intentions=(
            AgentTestIntention(
                catalog_id="victim.duplicate-race.candidate",
                purpose="prove exactly once under the duplicate race",
            ),
        ),
        evidence_ids=("ev-runtime-1",),
    )
    magistrate = MagistrateOutput(
        verdict=Verdict.CLEAR,
        finding_codes=("CAUSAL_AND_SCOPED",),
        required_changes=(),
        evidence_ids=("ev-runtime-1",),
    )

    warrant_id = await authority.open_approval(
        "inc-authority-1",
        magistrate,
        {Seat.COUNSEL: counsel, Seat.MAGISTRATE: magistrate},
    )
    pending = await authority.get_warrant(warrant_id)
    assert pending.status == "PENDING_APPROVAL"
    async with database.sessions() as session:
        assert await session.get(WarrantRecord, warrant_id) is None

    approved = await authority.decide_warrant(
        warrant_id=warrant_id,
        approve=True,
        warrant_sha256=pending.warrant_sha256,
        actor="approver-1",
    )
    assert approved.status == "APPROVED"

    async with database.sessions() as session:
        broker_record = await session.get(WarrantRecord, warrant_id)
        control_record = await session.get(ControlWarrantRecord, warrant_id)
    assert broker_record is not None
    assert control_record is not None
    document = parse_warrant_json(broker_record.document_json)
    approval = parse_approval_json(broker_record.approval_json)
    assert document.warrant_id == warrant_id
    assert _policy().approval_service.verify(document, approval)
    assert control_record.approval_id == approval.warrant_id.replace("war_", "apr_", 1)


@pytest.mark.asyncio
async def test_live_trial_warrant_binds_approval_to_its_credential_owner(database) -> None:
    owner = "live-trial-owner"
    await _reviewing_incident(database, actor=owner, live_trial=True)
    authority = DatabaseAuthorityGateway(database.store, _policy())
    counsel = CounselOutput(
        normalized_diff=PATCH,
        test_intentions=(
            AgentTestIntention(
                catalog_id="victim.duplicate-race.candidate",
                purpose="prove exactly once under the duplicate race",
            ),
        ),
        evidence_ids=("ev-runtime-1",),
    )
    magistrate = MagistrateOutput(
        verdict=Verdict.CLEAR,
        finding_codes=("CAUSAL_AND_SCOPED",),
        required_changes=(),
        evidence_ids=("ev-runtime-1",),
    )

    warrant_id = await authority.open_approval(
        "inc-authority-1",
        magistrate,
        {Seat.COUNSEL: counsel, Seat.MAGISTRATE: magistrate},
    )
    pending = await authority.get_warrant(warrant_id)
    assert pending is not None
    assert parse_warrant_json(pending.canonical_document.encode()).approver_identity == owner
    approved = await authority.decide_warrant(
        warrant_id=warrant_id,
        approve=True,
        warrant_sha256=pending.warrant_sha256,
        actor=owner,
    )
    assert approved.status == "APPROVED"


@pytest.mark.asyncio
async def test_expired_approval_persists_terminal_state_before_typed_conflict(database) -> None:
    await _reviewing_incident(database)
    authority = DatabaseAuthorityGateway(database.store, _policy())
    counsel = CounselOutput(
        normalized_diff=PATCH,
        test_intentions=(
            AgentTestIntention(
                catalog_id="victim.duplicate-race.candidate",
                purpose="prove exactly once under the duplicate race",
            ),
        ),
        evidence_ids=("ev-runtime-1",),
    )
    magistrate = MagistrateOutput(
        verdict=Verdict.CLEAR,
        finding_codes=("CAUSAL_AND_SCOPED",),
        required_changes=(),
        evidence_ids=("ev-runtime-1",),
    )
    warrant_id = await authority.open_approval(
        "inc-authority-1",
        magistrate,
        {Seat.COUNSEL: counsel, Seat.MAGISTRATE: magistrate},
    )
    pending = await authority.get_warrant(warrant_id)
    assert pending is not None
    async with database.sessions() as session, session.begin():
        control = await session.get(ControlWarrantRecord, warrant_id)
        assert control is not None
        control.expires_at = datetime(2000, 1, 1, tzinfo=UTC)

    with pytest.raises(WarrantDecisionConflict, match="warrant is expired") as failure:
        await authority.decide_warrant(
            warrant_id=warrant_id,
            approve=True,
            warrant_sha256=pending.warrant_sha256,
            actor="approver-1",
        )

    incident = await database.store.get_incident_record("inc-authority-1")
    events = await database.store.timeline_records("inc-authority-1")
    async with database.sessions() as session:
        control = await session.get(ControlWarrantRecord, warrant_id)
        broker = await session.get(WarrantRecord, warrant_id)
        work = await session.scalar(select(RuntimeWorkRecord))
    assert failure.value.code == "WARRANT_EXPIRED"
    assert control is not None and control.status == "EXPIRED"
    assert broker is None and work is None
    assert incident is not None
    assert incident.pending_warrant_id is None
    assert incident.state == IncidentState.HUMAN_ESCALATION.value
    assert events[-1].type == "WARRANT_EXPIRED"
    assert events[-1].payload == {
        "warrant_id": warrant_id,
        "warrant_sha256": pending.warrant_sha256,
    }


async def _approved_runtime_warrant(
    database: RuntimeDatabase,
) -> tuple[DatabaseAuthorityGateway, str]:
    await _reviewing_incident(database)
    authority = DatabaseAuthorityGateway(database.store, _policy())
    counsel = CounselOutput(
        normalized_diff=PATCH,
        test_intentions=(
            AgentTestIntention(
                catalog_id="victim.duplicate-race.candidate",
                purpose="prove exactly once under the duplicate race",
            ),
        ),
        evidence_ids=("ev-runtime-1",),
    )
    magistrate = MagistrateOutput(
        verdict=Verdict.CLEAR,
        finding_codes=("CAUSAL_AND_SCOPED",),
        required_changes=(),
        evidence_ids=("ev-runtime-1",),
    )
    warrant_id = await authority.open_approval(
        "inc-authority-1",
        magistrate,
        {Seat.COUNSEL: counsel, Seat.MAGISTRATE: magistrate},
    )
    pending = await authority.get_warrant(warrant_id)
    assert pending is not None
    await authority.decide_warrant(
        warrant_id=warrant_id,
        approve=True,
        warrant_sha256=pending.warrant_sha256,
        actor="approver-1",
    )
    return authority, warrant_id


@pytest.mark.asyncio
async def test_execute_approved_projects_only_persisted_broker_receipt(database, tmp_path) -> None:
    authority, warrant_id = await _approved_runtime_warrant(database)
    plan = ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
    receipt = ProcessReceipt.for_test(plan=plan)
    now = datetime.now(UTC)
    async with database.sessions() as session, session.begin():
        record = await session.get(WarrantRecord, warrant_id)
        assert record is not None
        result = BrokerResult(
            warrant_id=warrant_id,
            status=BrokerStatus.EXECUTED,
            receipts=(receipt,),
            nonce_sha256=record.nonce_sha256,
        )
        record.state = "CONSUMED"
        record.claimed_at = now
        record.nonce_consumed_at = now
        record.finished_at = now
        record.result_json = canonical_json(result)
        record.updated_at = now

    class Coordinator:
        async def resume_after_approval(self, incident_id: str, selected: str):
            assert incident_id == "inc-authority-1"
            assert selected == warrant_id
            return BailiffOutput(warrant_id=selected)

    launcher = BundledIncidentLauncher(
        store=database.store,
        authority=authority,
        coordinator=Coordinator(),  # type: ignore[arg-type]
        reproduction_factories={"webhook-race": lambda: None},  # type: ignore[dict-item]
        raw_artifact_root=tmp_path / "raw",
        sanitized_artifact_root=tmp_path / "sanitized",
        openai_api_key="configured",
    )
    await launcher.execute_approved("inc-authority-1", warrant_id)

    incident = await database.store.get_incident_record("inc-authority-1")
    events = await database.store.timeline_records("inc-authority-1")
    async with database.sessions() as session:
        test_run = await session.scalar(select(DBTestRunRecord))
    assert incident is not None and incident.state == IncidentState.VERIFIED.value
    assert [event.type for event in events[-3:]] == [
        "EXECUTION_STARTED",
        "VERIFIED",
        "BAILIFF_COMPLETED",
    ]
    assert test_run is not None and test_run.result["passed"] is True


@pytest.mark.asyncio
async def test_execute_approved_fails_closed_when_broker_result_is_absent(
    database, tmp_path
) -> None:
    authority, warrant_id = await _approved_runtime_warrant(database)

    class Coordinator:
        async def resume_after_approval(self, _incident_id: str, selected: str):
            return BailiffOutput(warrant_id=selected)

    launcher = BundledIncidentLauncher(
        store=database.store,
        authority=authority,
        coordinator=Coordinator(),  # type: ignore[arg-type]
        reproduction_factories={"webhook-race": lambda: None},  # type: ignore[dict-item]
        raw_artifact_root=tmp_path / "raw",
        sanitized_artifact_root=tmp_path / "sanitized",
        openai_api_key="configured",
    )
    await launcher.execute_approved("inc-authority-1", warrant_id)

    incident = await database.store.get_incident_record("inc-authority-1")
    events = await database.store.timeline_records("inc-authority-1")
    async with database.sessions() as session:
        test_run = await session.scalar(select(DBTestRunRecord))
    assert incident is not None and incident.state == IncidentState.HUMAN_ESCALATION.value
    assert events[-1].type == "EXECUTION_FAILED"
    assert events[-1].payload["error_code"] == "BROKER_RESULT_INVALID"
    assert test_run is None


@pytest.mark.asyncio
async def test_failed_test_repair_exception_records_abstain_without_invalid_transition(
    database, tmp_path
) -> None:
    authority, warrant_id = await _approved_runtime_warrant(database)
    plan = ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
    receipt = ProcessReceipt.for_test(plan=plan, exit_code=1)
    now = datetime.now(UTC)
    async with database.sessions() as session, session.begin():
        record = await session.get(WarrantRecord, warrant_id)
        assert record is not None
        result = BrokerResult(
            warrant_id=warrant_id,
            status=BrokerStatus.TEST_FAILED,
            receipts=(receipt,),
            error_code="FIXED_TEST_PLAN_FAILED",
            nonce_sha256=record.nonce_sha256,
        )
        record.state = "CONSUMED"
        record.claimed_at = now
        record.nonce_consumed_at = now
        record.finished_at = now
        record.result_json = canonical_json(result)
        record.updated_at = now

    class Coordinator:
        async def resume_after_approval(self, _incident_id: str, selected: str):
            return BailiffOutput(warrant_id=selected)

        def restore_incident_outputs(
            self, _incident_id: str, _outputs: object, **_kwargs: object
        ) -> None:
            return None

        async def resume_after_test(self, _incident: object, *, test_passed: bool):
            assert test_passed is False
            raise RuntimeError("simulated SDK repair failure")

    launcher = BundledIncidentLauncher(
        store=database.store,
        authority=authority,
        coordinator=Coordinator(),  # type: ignore[arg-type]
        reproduction_factories={"webhook-race": lambda: None},  # type: ignore[dict-item]
        raw_artifact_root=tmp_path / "raw",
        sanitized_artifact_root=tmp_path / "sanitized",
        openai_api_key="configured",
    )

    await launcher.execute_approved("inc-authority-1", warrant_id)

    incident = await database.store.get_incident_record("inc-authority-1")
    events = await database.store.timeline_records("inc-authority-1")
    async with database.sessions() as session:
        verdict = await session.scalar(
            select(VerdictRecord).where(VerdictRecord.verdict == Verdict.ABSTAIN.value)
        )
    assert incident is not None and incident.state == IncidentState.HUMAN_ESCALATION.value
    assert [event.type for event in events[-2:]] == ["REPAIR_CYCLE_FAILED", "VERDICT"]
    assert events[-2].payload["error_code"] == "REPAIR_RUNTIMEERROR"
    assert events[-1].payload["verdict"] == Verdict.ABSTAIN.value
    assert verdict is not None and verdict.verdict == Verdict.ABSTAIN.value
