from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from crosspatch.agents.schemas import CounselOutput
from crosspatch.agents.schemas import TestIntention as AgentTestIntention
from crosspatch.broker.approval import ApprovalService
from crosspatch.db.models import AgentRunRecord, VerdictRecord
from crosspatch.domain.enums import Effort, IncidentState, Seat, Verdict
from crosspatch.orchestration.escalation import EscalationExhausted, EscalationTracker
from crosspatch.runner.worktree import repository_manifest_sha256
from crosspatch.runtime.authority import AuthorityPolicy, DatabaseAuthorityGateway
from crosspatch.runtime.database import RuntimeDatabase
from crosspatch.runtime.incidents import BundledIncidentLauncher
from sqlalchemy import select

REPOSITORY_ROOT = Path(__file__).parents[3]
PATCH = """diff --git a/victim/src/victim/db.py b/victim/src/victim/db.py
index 1111111..2222222 100644
--- a/victim/src/victim/db.py
+++ b/victim/src/victim/db.py
@@ -1 +1 @@
-old
+new
"""


def _counsel() -> CounselOutput:
    return CounselOutput(
        normalized_diff=PATCH,
        test_intentions=(
            AgentTestIntention(
                catalog_id="victim.duplicate-race.candidate",
                purpose="prove duplicate delivery is serialized",
            ),
        ),
        evidence_ids=("ev-retry-1",),
        analysis="The receipt and outbox write share one transaction.",
    )


async def _database(tmp_path: Path, name: str) -> RuntimeDatabase:
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / name}")
    await database.bootstrap()
    return database


async def _create_incident(
    database: RuntimeDatabase,
    *,
    incident_id: str,
    state: IncidentState,
) -> None:
    import subprocess

    base_sha = subprocess.run(
        ["git", "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    await database.store.create_incident(
        incident_id=incident_id,
        title="Retry durability",
        scenario="webhook-race",
        state=state,
        base_sha=base_sha,
        repository_manifest_sha256=repository_manifest_sha256(
            REPOSITORY_ROOT,
            base_sha,
        ),
        catalog_sha256=hashlib.sha256(b"catalog").hexdigest(),
        actor="operator-1",
    )


class _RestoredCoordinator:
    def __init__(self) -> None:
        self.outputs = None
        self.completed_phases = None
        self.pending_retries = None

    def restore_incident_outputs(
        self,
        _incident_id: str,
        outputs,
        *,
        completed_phases=None,
        pending_retries=None,
    ) -> None:
        self.outputs = outputs
        self.completed_phases = completed_phases
        self.pending_retries = pending_retries


@pytest.mark.asyncio
async def test_restart_restores_valid_output_but_spends_durable_attempt_effort(
    tmp_path: Path,
) -> None:
    database = await _database(tmp_path, "restore.db")
    try:
        await _create_incident(
            database,
            incident_id="inc-retry-restore",
            state=IncidentState.ANALYZING,
        )
        await database.store.record_seat_output(
            incident_id="inc-retry-restore",
            seat=Seat.COUNSEL,
            effort=Effort.MEDIUM,
            phase="patch-proposal",
            output=_counsel(),
        )
        await database.store.append_event(
            "inc-retry-restore",
            "REASONING_ESCALATED",
            Seat.COUNSEL.value,
            {
                "seat": Seat.COUNSEL.value,
                "effort": Effort.HIGH.value,
                "escalation_count": 1,
                "reason": "test_failure",
                "message": "attempt reserved before model execution",
            },
        )

        restored = _RestoredCoordinator()
        launcher = BundledIncidentLauncher(
            store=database.store,
            authority=object(),  # type: ignore[arg-type]
            coordinator=restored,  # type: ignore[arg-type]
            reproduction_factories={"webhook-race": lambda: None},  # type: ignore[dict-item]
            raw_artifact_root=tmp_path / "raw",
            sanitized_artifact_root=tmp_path / "sanitized",
            openai_api_key="configured",
            source_root=REPOSITORY_ROOT,
        )

        await launcher._restore_outputs("inc-retry-restore")

        assert restored.outputs is not None
        assert restored.completed_phases[Seat.COUNSEL] == "patch-proposal"
        assert restored.pending_retries == {Seat.COUNSEL: "test_failure"}
        output, effort, count = restored.outputs[Seat.COUNSEL]
        assert output == _counsel()
        assert (effort, count) == (Effort.HIGH, 1)
        tracker = EscalationTracker()
        tracker.restore(
            "inc-retry-restore",
            Seat.COUNSEL,
            output,
            effort=effort,
            escalation_count=count,
            retry_pending=True,
            pending_reason="test_failure",
        )
        next_attempt = tracker.resume_pending_escalation(
            "inc-retry-restore",
            Seat.COUNSEL,
            reason="test_failure",
        )
        assert next_attempt is not None
        assert (next_attempt.effort, next_attempt.escalation_count) == (
            Effort.HIGH,
            1,
        )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_restart_restores_durable_cap_and_cannot_run_a_third_attempt(
    tmp_path: Path,
) -> None:
    database = await _database(tmp_path, "cap.db")
    try:
        await _create_incident(
            database,
            incident_id="inc-retry-cap",
            state=IncidentState.ANALYZING,
        )
        output = _counsel()
        await database.store.record_seat_output(
            incident_id="inc-retry-cap",
            seat=Seat.COUNSEL,
            effort=Effort.MEDIUM,
            phase="patch-proposal",
            output=output,
        )
        for count, effort in ((1, Effort.HIGH), (2, Effort.XHIGH)):
            await database.store.append_event(
                "inc-retry-cap",
                "REASONING_ESCALATED",
                Seat.COUNSEL.value,
                {
                    "seat": Seat.COUNSEL.value,
                    "effort": effort.value,
                    "escalation_count": count,
                    "reason": "test_failure",
                    "message": "attempt reserved before model execution",
                },
            )

        restored = _RestoredCoordinator()
        launcher = BundledIncidentLauncher(
            store=database.store,
            authority=object(),  # type: ignore[arg-type]
            coordinator=restored,  # type: ignore[arg-type]
            reproduction_factories={"webhook-race": lambda: None},  # type: ignore[dict-item]
            raw_artifact_root=tmp_path / "raw-cap",
            sanitized_artifact_root=tmp_path / "sanitized-cap",
            openai_api_key="configured",
            source_root=REPOSITORY_ROOT,
        )
        await launcher._restore_outputs("inc-retry-cap")
        assert restored.outputs is not None
        restored_output, effort, count = restored.outputs[Seat.COUNSEL]
        assert (effort, count) == (Effort.XHIGH, 2)

        tracker = EscalationTracker()
        tracker.restore(
            "inc-retry-cap",
            Seat.COUNSEL,
            restored_output,
            effort=effort,
            escalation_count=count,
        )
        with pytest.raises(EscalationExhausted, match="human escalation"):
            tracker.begin_escalation(
                "inc-retry-cap",
                Seat.COUNSEL,
                reason="restart",
            )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_rejected_retry_and_abstain_roll_back_as_one_atomic_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = await _database(tmp_path, "atomic.db")
    try:
        await _create_incident(
            database,
            incident_id="inc-retry-atomic",
            state=IncidentState.PATCHING,
        )
        authority = DatabaseAuthorityGateway(
            database.store,
            AuthorityPolicy(
                repository_root=REPOSITORY_ROOT,
                repository_id="crosspatch",
                approver_identity="approver-1",
                approval_mac_key_id="approval-v1",
                approval_service=ApprovalService(keys={"approval-v1": b"k" * 32}),
                runner_digest="7" * 64,
                environment_digest="8" * 64,
            ),
        )
        publish = database.store._publish_locked

        async def crash_before_commit(*_args, **_kwargs) -> None:
            raise RuntimeError("simulated process loss before commit")

        monkeypatch.setattr(database.store, "_publish_locked", crash_before_commit)
        with pytest.raises(RuntimeError, match="simulated process loss"):
            await authority.reject_duplicate_retry(
                "inc-retry-atomic",
                seat=Seat.COUNSEL,
                effort=Effort.HIGH,
                phase="test-failure-repair",
                output=_counsel(),
                reason="test_failure",
            )

        incident = await database.store.get_incident_record("inc-retry-atomic")
        events = await database.store.timeline_records("inc-retry-atomic")
        async with database.sessions() as session:
            rejected = tuple((await session.scalars(select(AgentRunRecord))).all())
            verdicts = tuple((await session.scalars(select(VerdictRecord))).all())
        assert incident is not None and incident.state == IncidentState.PATCHING.value
        assert not rejected
        assert not verdicts
        assert all(event.type != "FAILED_RETRY_DUPLICATE" for event in events)
        assert all(event.type != "VERDICT" for event in events)

        monkeypatch.setattr(database.store, "_publish_locked", publish)
        await authority.reject_duplicate_retry(
            "inc-retry-atomic",
            seat=Seat.COUNSEL,
            effort=Effort.HIGH,
            phase="test-failure-repair",
            output=_counsel(),
            reason="test_failure",
        )

        incident = await database.store.get_incident_record("inc-retry-atomic")
        events = await database.store.timeline_records("inc-retry-atomic")
        async with database.sessions() as session:
            rejected = tuple((await session.scalars(select(AgentRunRecord))).all())
            verdicts = tuple((await session.scalars(select(VerdictRecord))).all())
        assert incident is not None and incident.state == IncidentState.HUMAN_ESCALATION.value
        assert len(rejected) == 1
        assert rejected[0].schema_status == "REJECTED_DUPLICATE"
        assert rejected[0].effort == Effort.HIGH.value
        assert len(verdicts) == 1 and verdicts[0].verdict == Verdict.ABSTAIN.value
        assert [event.type for event in events[-2:]] == [
            "FAILED_RETRY_DUPLICATE",
            "VERDICT",
        ]
    finally:
        await database.close()
