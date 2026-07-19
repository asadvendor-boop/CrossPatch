"""Concrete durable control-plane service shared by HTTP and CLI clients."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import subprocess
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, text

from crosspatch.agents.schemas import MagistrateOutput
from crosspatch.api.dependencies import Principal, Role
from crosspatch.api.models import (
    EvidenceView,
    IncidentRoomView,
    IncidentView,
    JudgeTokenListView,
    JudgeTokenMetadataView,
    JudgeTokenView,
    LiveTrialCredentialView,
    PublishedEvent,
    RoomArtifactsView,
    RoomDiffView,
    RoomEvidenceView,
    RoomIncidentView,
    RoomSeatView,
    RoomTestView,
    WarrantView,
)
from crosspatch.broker.approval import parse_approval_json
from crosspatch.broker.broker import BrokerResult, BrokerStatus, WarrantState
from crosspatch.broker.warrant import canonical_warrant_hash, parse_warrant_json
from crosspatch.db.models import (
    AgentRunRecord,
    ControlWarrantRecord,
    IncidentRecord,
    PatchCandidateRecord,
    PublishedCaseRecord,
    TestRunRecord,
    TimelineEventRecord,
    VerdictRecord,
    WarrantRecord,
)
from crosspatch.domain.enums import IncidentState, Verdict
from crosspatch.domain.hashing import canonical_json, sha256_hex
from crosspatch.domain.seats import SEAT_SPECS
from crosspatch.evidence.sanitizer import sanitize_evidence
from crosspatch.export import CaseBinding, CaseExportBuilder, ExportArtifact
from crosspatch.mcp.auth import TokenIssuer
from crosspatch.runner.catalog import ExecutionCatalog
from crosspatch.runner.results import ProcessReceipt
from crosspatch.runner.worktree import repository_manifest_sha256
from crosspatch.runtime.auth import JudgeTokenRepository
from crosspatch.runtime.authority import DatabaseAuthorityGateway
from crosspatch.runtime.database import (
    APPROVED_EXECUTION_WORK,
    TEST_REPAIR_WORK,
    RuntimeStore,
    _published_evidence,
    _published_patch,
    aware_utc,
    broker_receipt_result,
    execution_work_id,
)
from crosspatch.runtime.incidents import BundledScenarioBindingError
from crosspatch.runtime.live_trials import LiveTrialRepository
from crosspatch.runtime.projection import (
    published_event_details,
    published_trusted_observation,
)
from crosspatch.runtime.scenarios import (
    require_live_trial_scenario,
    require_operator_evidence_profile,
    require_operator_scenario,
)


class IncidentLauncher(Protocol):
    async def launch(self, incident_id: str) -> None: ...

    async def prepare_revision(
        self,
        *,
        incident_id: str,
        warrant_id: str,
        warrant_sha256: str,
        comment: str,
        actor: str,
    ) -> None: ...

    async def resume_revision(self, incident_id: str) -> Any: ...


ApprovalResumer = Callable[[str, str], Awaitable[Any]]
RepairResumer = Callable[[str, str], Awaitable[Any]]


@dataclass(frozen=True, slots=True)
class _ExportSnapshot:
    incident: IncidentRecord
    published: PublishedCaseRecord
    control: ControlWarrantRecord
    verdict: VerdictRecord
    broker: WarrantRecord
    test_runs: tuple[TestRunRecord, ...]
    timeline_events: tuple[TimelineEventRecord, ...]


class DatabaseControlService:
    """A restart-readable control service with no in-memory source of truth."""

    def __init__(
        self,
        *,
        store: RuntimeStore,
        authority: DatabaseAuthorityGateway,
        launcher: IncidentLauncher,
        judge_tokens: JudgeTokenRepository,
        judge_issuer: TokenIssuer,
        judge_token_expires_at: datetime,
        export_signing_key: Ed25519PrivateKey,
        approval_resumer: ApprovalResumer | None = None,
        repair_resumer: RepairResumer | None = None,
        model_runtime: str = "abstain_only",
        live_trials: LiveTrialRepository | None = None,
        live_trial_token_expires_at: datetime | None = None,
        live_trial_run_reservation_usd: Decimal | int | str = Decimal("4"),
    ) -> None:
        if judge_token_expires_at.tzinfo is None or judge_token_expires_at.utcoffset() is None:
            raise ValueError("judge token expiry must be timezone-aware")
        self._store = store
        self._authority = authority
        self._launcher = launcher
        self._judge_tokens = judge_tokens
        self._judge_issuer = judge_issuer
        self._judge_token_expires_at = judge_token_expires_at.astimezone(UTC)
        self._exporter = CaseExportBuilder(export_signing_key)
        self._approval_resumer = approval_resumer
        self._repair_resumer = repair_resumer
        self._live_trials = live_trials
        self._live_trial_token_expires_at = (
            None
            if live_trial_token_expires_at is None
            else live_trial_token_expires_at.astimezone(UTC)
        )
        try:
            self._live_trial_run_reservation_usd = Decimal(str(live_trial_run_reservation_usd))
        except InvalidOperation as error:
            raise ValueError("live-trial run reservation must be a decimal") from error
        if (
            not self._live_trial_run_reservation_usd.is_finite()
            or self._live_trial_run_reservation_usd <= 0
        ):
            raise ValueError("live-trial run reservation must be positive")
        if model_runtime not in {"abstain_only", "configured"}:
            raise ValueError("model runtime health state is invalid")
        self._model_runtime = model_runtime
        self._incident_tasks: dict[str, asyncio.Task[None]] = {}
        self._approval_tasks: set[asyncio.Task[Any]] = set()
        self._runtime_work_tasks: dict[str, asyncio.Task[Any]] = {}
        self._runtime_work_owner = f"control_{uuid4().hex}"
        self._runtime_recovery_initialized = False

    def _schedule_runtime_work(self, work_id: str) -> bool:
        existing = self._runtime_work_tasks.get(work_id)
        if existing is not None and not existing.done():
            return False
        task = asyncio.create_task(
            self._run_runtime_work(work_id),
            name=f"crosspatch-work-{work_id}",
        )
        self._runtime_work_tasks[work_id] = task

        def discard(done: asyncio.Task[Any]) -> None:
            if self._runtime_work_tasks.get(work_id) is done:
                self._runtime_work_tasks.pop(work_id, None)

        task.add_done_callback(discard)
        return True

    async def _run_runtime_work(self, work_id: str) -> None:
        work = await self._store.claim_runtime_work(
            work_id,
            owner_id=self._runtime_work_owner,
        )
        if work is None:
            return
        operation = f"runtime-work:{work.kind.lower()}"
        try:
            await self._dispatch_runtime_work(work)
        except Exception as error:
            await self._store.fail_runtime_work(
                work.id,
                operation=operation,
                failure_outcome=type(error).__name__,
            )
        for pending in await self._store.pending_runtime_work():
            self._schedule_runtime_work(pending.id)

    async def _dispatch_runtime_work(self, work) -> None:
        if work.kind == APPROVED_EXECUTION_WORK:
            if self._approval_resumer is None:
                raise RuntimeError("approved execution resumer is unavailable")
            await self._approval_resumer(work.incident_id, work.warrant_id)
        elif work.kind == TEST_REPAIR_WORK:
            if self._repair_resumer is None:
                raise RuntimeError("test repair resumer is unavailable")
            await self._repair_resumer(work.incident_id, work.warrant_id)
        else:
            raise ValueError("durable runtime work kind is invalid")

    async def reconcile_runtime_work(self) -> int:
        """Requeue persisted work once at startup; repeated calls are idempotent."""
        if not self._runtime_recovery_initialized:
            await self._store.fail_closed_interrupted_incidents()
            await self._store.requeue_interrupted_runtime_work()
            self._runtime_recovery_initialized = True
        scheduled = 0
        for work in await self._store.pending_runtime_work():
            if self._schedule_runtime_work(work.id):
                scheduled += 1
        return scheduled

    async def wait_for_runtime_work(self) -> None:
        while self._runtime_work_tasks:
            tasks = tuple(self._runtime_work_tasks.values())
            await asyncio.gather(*tasks)

    async def _guard_background(
        self,
        incident_id: str,
        operation: str,
        awaitable: Awaitable[Any],
    ) -> bool:
        try:
            await awaitable
            return True
        except BundledScenarioBindingError:
            return False
        except Exception as error:
            incident = await self._store.get_incident_record(incident_id)
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
            await self._store.append_event(
                incident_id,
                (
                    "BACKGROUND_TASK_FAILED"
                    if incident is not None and incident.state in active
                    else "BACKGROUND_TASK_ERROR_REPORTED"
                ),
                "control-service",
                {
                    "operation": operation,
                    "failure_outcome": type(error).__name__,
                },
            )
            return False

    async def health(self) -> dict[str, str]:
        async with self._store.sessions() as session:
            database_ok = (await session.scalar(text("SELECT 1"))) == 1
        return {
            "status": "ok" if database_ok else "unavailable",
            "database": "ok" if database_ok else "failed",
            "model_runtime": self._model_runtime,
        }

    @staticmethod
    def _incident_view(record) -> IncidentView:
        return IncidentView(
            id=record.id,
            title=record.title,
            scenario=record.scenario,
            state=record.state,
            timeline_head=record.event_chain_head,
            pending_warrant_id=record.pending_warrant_id,
        )

    async def open_incident(
        self,
        *,
        scenario: str,
        title: str | None,
        actor: str,
        evidence_profile: str = "standard",
    ) -> IncidentView:
        definition = require_operator_scenario(scenario)
        profile = require_operator_evidence_profile(
            definition.scenario_id,
            evidence_profile,
        )
        record = await self._create_incident(
            scenario=definition.scenario_id,
            title=title if title is not None else definition.default_title,
            actor=actor,
            live_trial=False,
            evidence_profile=profile,
        )
        self._schedule_incident_launch(record.id, self._launcher.launch(record.id))
        return self._incident_view(record)

    async def _create_incident(
        self,
        *,
        scenario: str,
        title: str,
        actor: str,
        live_trial: bool,
        evidence_profile: str = "standard",
    ):
        repository_root = self._authority.policy.repository_root

        def bindings() -> tuple[str, str]:
            base_sha = subprocess.run(
                ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            return base_sha, repository_manifest_sha256(repository_root, base_sha)

        base_sha, manifest_sha256 = await asyncio.to_thread(bindings)
        incident_id = f"inc_{uuid4().hex}"
        record = await self._store.create_incident(
            incident_id=incident_id,
            title=title,
            scenario=scenario,
            state=IncidentState.OPEN,
            base_sha=base_sha,
            repository_manifest_sha256=manifest_sha256,
            catalog_sha256=sha256_hex(ExecutionCatalog.default().plan_ids),
            actor=actor,
            live_trial=live_trial,
            evidence_profile=evidence_profile,
        )
        return record

    def _schedule_incident_launch(
        self,
        incident_id: str,
        awaitable: Awaitable[Any],
    ) -> None:
        task = asyncio.create_task(
            self._guard_background(
                incident_id,
                "incident-launch",
                awaitable,
            ),
            name=f"crosspatch-incident-{incident_id}",
        )
        self._incident_tasks[incident_id] = task

    async def open_live_trial(
        self,
        *,
        scenario: str,
        title: str | None,
        actor: str,
    ) -> IncidentView:
        definition = require_live_trial_scenario(scenario)
        if self._live_trials is None:
            raise RuntimeError("live trials are unavailable")
        reservation_id = await self._live_trials.reserve(
            actor,
            amount_usd=self._live_trial_run_reservation_usd,
            operation="initial-run",
        )
        try:
            record = await self._create_incident(
                scenario=definition.scenario_id,
                title=title if title is not None else "Webhook race live trial",
                actor=actor,
                live_trial=True,
            )
            await self._live_trials.bind_incident(
                reservation_id,
                subject=actor,
                incident_id=record.id,
            )
        except BaseException:
            await self._live_trials.settle(reservation_id, actual_usd=0)
            raise
        self._schedule_incident_launch(
            record.id,
            self._launch_and_settle_live_trial(record.id, reservation_id),
        )
        return self._incident_view(record)

    async def _launch_and_settle_live_trial(
        self,
        incident_id: str,
        reservation_id: str,
    ) -> None:
        try:
            await self._launcher.launch(incident_id)
        finally:
            actual = await self._recorded_model_spend(incident_id)
            repository = self._live_trials
            if repository is None:
                raise RuntimeError("live trials are unavailable")
            await repository.settle(
                reservation_id,
                actual_usd=actual,
            )

    async def _recorded_model_spend(self, incident_id: str) -> Decimal:
        total = Decimal("0")
        records = await self._store.timeline_records(incident_id, published_only=False)
        for record in records:
            if record.type != "MODEL_METRICS_RECORDED":
                continue
            try:
                amount = Decimal(str(record.payload["cost_usd"]))
            except (InvalidOperation, KeyError):
                return self._live_trial_run_reservation_usd
            if not amount.is_finite() or amount < 0:
                return self._live_trial_run_reservation_usd
            total += amount
        return total

    async def wait_for_incident(self, incident_id: str) -> None:
        task = self._incident_tasks.get(incident_id)
        if task is not None:
            await task
            return
        if await self._store.get_incident_record(incident_id) is None:
            raise LookupError(incident_id)

    async def get_incident(self, incident_id: str) -> IncidentView | None:
        record = await self._store.get_incident_record(incident_id)
        return None if record is None else self._incident_view(record)

    @staticmethod
    def _tag_names(tags: list[dict[str, Any]]) -> tuple[str, ...]:
        return tuple(str(tag.get("kind", "SANITIZED")) for tag in tags if isinstance(tag, dict))

    async def list_evidence(self, incident_id: str) -> tuple[EvidenceView, ...]:
        records = await self._store.evidence_records(incident_id, published_only=True)
        published = tuple(_published_evidence(record) for record in records)
        return tuple(
            EvidenceView(
                id=str(item["evidence_id"]),
                incident_id=str(item["incident_id"]),
                kind=str(item["kind"]),
                provenance=str(item["provenance"]),
                text=str(item["text"]),
                sanitized_sha256=str(item["sanitized_sha256"]),
                tags=tuple(str(tag) for tag in item["tags"]),
                published=True,
            )
            for item in published
        )

    @staticmethod
    def _event(record) -> PublishedEvent:
        return PublishedEvent(
            id=record.id,
            incident_id=record.incident_id,
            sequence=record.sequence,
            type=record.type,
            actor=record.actor,
            summary=f"{record.type} by {record.actor}",
            details=published_event_details(record.type, record.payload),
            event_hash=record.event_hash,
            created_at=aware_utc(record.created_at),
            published=record.published,
        )

    async def list_events(
        self,
        incident_id: str,
        *,
        after: int,
        limit: int,
    ) -> tuple[PublishedEvent, ...]:
        records = await self._store.timeline_records(
            incident_id,
            after=after,
            limit=limit,
            published_only=True,
        )
        return tuple(self._event(record) for record in records)

    async def stream_events(
        self,
        incident_id: str,
        *,
        after: int,
    ) -> AsyncIterator[PublishedEvent]:
        previous = after
        while True:
            values = await self.list_events(incident_id, after=previous, limit=100)
            for event in values:
                previous = event.sequence
                yield event
            incident = await self._store.get_incident_record(incident_id)
            if incident is None:
                return
            if not values and IncidentState(incident.state) in {
                IncidentState.HUMAN_ESCALATION,
                IncidentState.BLOCKED,
                IncidentState.VERIFIED,
            }:
                return
            await asyncio.sleep(0.25)

    async def _warrant_record(
        self,
        incident_id: str,
    ) -> ControlWarrantRecord | None:
        async with self._store.sessions() as session:
            return await session.scalar(
                select(ControlWarrantRecord)
                .where(ControlWarrantRecord.incident_id == incident_id)
                .order_by(ControlWarrantRecord.created_at.desc())
                .limit(1)
            )

    async def get_room(
        self,
        incident_id: str,
        principal: Principal,
    ) -> IncidentRoomView | None:
        if not principal.can_access(incident_id):
            return None
        incident = await self._store.get_incident_record(incident_id)
        if incident is None:
            return None
        async with self._store.sessions() as session:
            runs = tuple(
                (
                    await session.scalars(
                        select(AgentRunRecord)
                        .where(AgentRunRecord.incident_id == incident_id)
                        .order_by(AgentRunRecord.created_at)
                    )
                ).all()
            )
            candidate = await session.scalar(
                select(PatchCandidateRecord)
                .where(PatchCandidateRecord.incident_id == incident_id)
                .order_by(PatchCandidateRecord.created_at.desc())
                .limit(1)
            )
            test_runs = tuple(
                (
                    await session.scalars(
                        select(TestRunRecord)
                        .where(TestRunRecord.incident_id == incident_id)
                        .order_by(TestRunRecord.created_at)
                    )
                ).all()
            )
        latest = {run.seat: run for run in runs}
        seats: list[RoomSeatView] = []
        for spec in SEAT_SPECS:
            run = latest.get(spec.seat.value)
            state = "idle"
            if run is not None:
                state = "complete" if run.schema_status == "VALID" else "failed"
            elif (
                spec.seat.value == "Magistrate"
                and incident.state == IncidentState.HUMAN_ESCALATION.value
            ):
                state = "abstained"
            seats.append(
                RoomSeatView(
                    name=spec.seat.value,
                    role=spec.role,
                    model=spec.model,
                    tier_rationale=spec.tier_rationale,
                    effort=run.effort if run is not None else spec.initial_effort.value,
                    escalation_count=run.escalation_count if run is not None else 0,
                    state=state,
                )
            )

        evidence_records = await self._store.evidence_records(incident_id, published_only=True)
        evidence = tuple(self._room_evidence(row) for row in evidence_records)
        tests = tuple(self._room_test(row) for row in test_runs)
        control = await self._warrant_record(incident_id)
        may_review_exact_warrant = principal.role in {
            Role.OPERATOR,
            Role.APPROVER,
            Role.LIVE_TRIAL,
        }
        warrant = (
            None
            if control is None or not may_review_exact_warrant
            else await self._authority.get_warrant(control.id)
        )
        pending = warrant if warrant is not None and warrant.status == "PENDING_APPROVAL" else None
        events = await self.list_events(incident_id, after=0, limit=500)
        published = await self._store.read_projection(incident_id)
        if published is None:
            raise RuntimeError("incident has no sanitized published projection")
        return IncidentRoomView(
            viewer_role=principal.role.value,
            incident=RoomIncidentView(
                id=incident.id,
                title=sanitize_evidence(
                    incident.title.encode("utf-8"),
                    "incident title",
                ).text,
                state=incident.state,
                severity="UNSET",
                scenario=incident.scenario,
                base_sha=incident.base_sha or "0" * 40,
                created_at=aware_utc(incident.created_at),
                updated_at=aware_utc(incident.updated_at),
            ),
            seats=tuple(seats),
            events=events,
            specialist_summaries=tuple(published.get("specialist_summaries", ())),
            warrants=tuple(published.get("warrants", ())),
            artifacts=RoomArtifactsView(
                evidence=evidence,
                diff=(
                    None
                    if candidate is None
                    else RoomDiffView.model_validate(_published_patch(candidate))
                ),
                tests=tests,
                warrant=warrant,
            ),
            pending_warrant=pending,
        )

    @staticmethod
    def _room_evidence(record) -> RoomEvidenceView:
        published = _published_evidence(record)
        return RoomEvidenceView(
            id=str(published["evidence_id"]),
            incident_id=str(published["incident_id"]),
            provenance=str(published["provenance"]),
            kind=str(published["kind"]),
            sanitized_sha256=str(published["sanitized_sha256"]),
            captured_at=published["captured_at"],
            text=str(published["text"]),
            tags=tuple(str(tag) for tag in published["tags"]),
        )

    @staticmethod
    def _room_test(record: TestRunRecord) -> RoomTestView:
        result = record.result
        trusted_observation = published_trusted_observation(
            result,
            expected_plan_id=record.plan_id,
            expected_plan_sha256=record.plan_sha256,
        )
        passed = bool(result.get("passed")) or result.get("status") == "PASSED"
        failed = result.get("status") == "FAILED" or result.get("passed") is False
        state = "passed" if passed else "failed" if failed else "pending"
        duration = result.get("duration_ms")
        detail = result.get("detail")
        return RoomTestView(
            id=record.id,
            label=record.plan_id,
            state=state,
            duration_ms=duration if isinstance(duration, int) else None,
            detail=detail if isinstance(detail, str) else None,
            receipt_sha256=(
                str(result["receipt_sha256"])
                if isinstance(result.get("receipt_sha256"), str)
                else None
            ),
            **(trusted_observation or {}),
        )

    async def get_warrant_for_principal(
        self,
        warrant_id: str,
        principal: Principal,
    ) -> WarrantView | None:
        warrant = await self._authority.get_warrant(warrant_id)
        if warrant is None or not principal.can_access(warrant.incident_id):
            return None
        return warrant

    async def decide_warrant(
        self,
        *,
        warrant_id: str,
        approve: bool,
        warrant_sha256: str,
        actor: str,
        reason: str | None = None,
    ) -> WarrantView:
        warrant = await self._authority.decide_warrant(
            warrant_id=warrant_id,
            approve=approve,
            warrant_sha256=warrant_sha256,
            actor=actor,
            reason=reason,
        )
        if approve:
            self._schedule_runtime_work(execution_work_id(warrant.id))
        return warrant

    async def decide_live_trial_warrant(
        self,
        *,
        warrant_id: str,
        approve: bool,
        warrant_sha256: str,
        actor: str,
        reason: str | None = None,
    ) -> WarrantView:
        if self._live_trials is None:
            raise RuntimeError("live trials are unavailable")
        warrant = await self._authority.get_warrant(warrant_id)
        if warrant is None or not await self._live_trials.owns(actor, warrant.incident_id):
            raise LookupError(warrant_id)
        sanitized_reason = (
            None
            if reason is None
            else sanitize_evidence(
                reason.encode("utf-8"),
                "live-trial rejection reason",
            ).text
        )
        return await self.decide_warrant(
            warrant_id=warrant_id,
            approve=approve,
            warrant_sha256=warrant_sha256,
            actor=actor,
            reason=sanitized_reason,
        )

    async def request_live_trial_revision(
        self,
        *,
        warrant_id: str,
        warrant_sha256: str,
        comment: str,
        actor: str,
    ) -> IncidentView:
        repository = self._live_trials
        if repository is None:
            raise RuntimeError("live trials are unavailable")
        warrant = await self._authority.get_warrant(warrant_id)
        if warrant is None or not await repository.owns(actor, warrant.incident_id):
            raise LookupError(warrant_id)
        reservation_id = await repository.reserve(
            actor,
            amount_usd=self._live_trial_run_reservation_usd,
            operation="revision",
        )
        baseline_spend = await self._recorded_model_spend(warrant.incident_id)
        try:
            await self._launcher.prepare_revision(
                incident_id=warrant.incident_id,
                warrant_id=warrant_id,
                warrant_sha256=warrant_sha256,
                comment=comment,
                actor=actor,
            )
        except BaseException:
            await repository.settle(reservation_id, actual_usd=0)
            raise
        self._schedule_incident_launch(
            warrant.incident_id,
            self._resume_and_settle_revision(
                warrant.incident_id,
                reservation_id,
                baseline_spend,
            ),
        )
        incident = await self._store.get_incident_record(warrant.incident_id)
        if incident is None:
            raise LookupError(warrant.incident_id)
        return self._incident_view(incident)

    async def _resume_and_settle_revision(
        self,
        incident_id: str,
        reservation_id: str,
        baseline_spend: Decimal,
    ) -> None:
        try:
            await self._launcher.resume_revision(incident_id)
        finally:
            repository = self._live_trials
            if repository is None:
                raise RuntimeError("live trials are unavailable")
            total = await self._recorded_model_spend(incident_id)
            actual = max(Decimal("0"), total - baseline_spend)
            await repository.settle(reservation_id, actual_usd=actual)

    async def export_case(self, incident_id: str) -> bytes:
        async with self._store.sessions() as session:
            if session.bind is None:
                raise RuntimeError("export transaction has no database binding")
            if session.bind.dialect.name == "sqlite":
                # SQLite ignores SELECT FOR UPDATE. BEGIN IMMEDIATE makes the
                # read snapshot stable against a concurrent V2 publisher.
                await session.execute(text("BEGIN IMMEDIATE"))
            else:
                # Export is a pure read.  PostgreSQL REPEATABLE READ gives every
                # query below one immutable snapshot without requiring UPDATE
                # privilege merely to take row locks on append-only history.
                await session.execute(
                    text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                )
            try:
                snapshot = await self._load_export_snapshot_locked(
                    session,
                    incident_id,
                )
                archive = self._build_export(snapshot, incident_id)
            except BaseException:
                await session.rollback()
                raise
            await session.rollback()
            return archive

    async def _load_export_snapshot_locked(
        self,
        session,
        incident_id: str,
    ) -> _ExportSnapshot:
        """Load every byte that can influence one signed export snapshot."""
        incident = await session.scalar(
            select(IncidentRecord).where(IncidentRecord.id == incident_id)
        )
        published = await session.scalar(
            select(PublishedCaseRecord).where(
                PublishedCaseRecord.incident_id == incident_id,
                PublishedCaseRecord.published.is_(True),
            )
        )
        if incident is None or incident.event_chain_head is None:
            raise LookupError(incident_id)
        if published is None:
            raise ValueError(
                "case export requires a persisted verdict, warrant, and broker receipt"
            )
        control = await session.scalar(
            select(ControlWarrantRecord)
            .where(ControlWarrantRecord.incident_id == incident_id)
            .order_by(
                ControlWarrantRecord.created_at.desc(),
                ControlWarrantRecord.id.desc(),
            )
            .limit(1)
        )
        if control is None:
            raise ValueError(
                "case export requires a persisted verdict, warrant, and broker receipt"
            )
        document = parse_warrant_json(bytes(control.canonical_document))
        verdict = await session.scalar(
            select(VerdictRecord).where(
                VerdictRecord.id == document.verdict_id,
                VerdictRecord.incident_id == incident_id,
            )
        )
        broker = await session.scalar(
            select(WarrantRecord).where(
                WarrantRecord.id == control.id,
                WarrantRecord.incident_id == incident_id,
            )
        )
        test_runs = tuple(
            (
                await session.scalars(
                    select(TestRunRecord)
                    .where(TestRunRecord.incident_id == incident_id)
                    .order_by(TestRunRecord.created_at, TestRunRecord.id)
                )
            ).all()
        )
        timeline_events = tuple(
            (
                await session.scalars(
                    select(TimelineEventRecord)
                    .where(TimelineEventRecord.incident_id == incident_id)
                    .order_by(TimelineEventRecord.sequence)
                )
            ).all()
        )
        if verdict is None:
            raise ValueError(
                "case export requires a persisted verdict, warrant, and broker receipt"
            )
        if (
            broker is None
            or broker.state != WarrantState.CONSUMED.value
            or broker.result_json is None
            or broker.claimed_at is None
            or broker.nonce_consumed_at is None
            or broker.finished_at is None
        ):
            raise ValueError(
                "case export requires the latest warrant's matching completed broker result"
            )
        return _ExportSnapshot(
            incident=incident,
            published=published,
            control=control,
            verdict=verdict,
            broker=broker,
            test_runs=test_runs,
            timeline_events=timeline_events,
        )

    def _build_export(self, snapshot: _ExportSnapshot, incident_id: str) -> bytes:
        incident = snapshot.incident
        control = snapshot.control
        verdict = snapshot.verdict
        broker = snapshot.broker
        projection = dict(snapshot.published.projection)
        document = parse_warrant_json(bytes(control.canonical_document))
        try:
            result = BrokerResult.model_validate_json(broker.result_json)
            verdict_output = MagistrateOutput.model_validate_json(verdict.output_json)
            approval = parse_approval_json(bytes(broker.approval_json))
        except ValueError as error:
            raise ValueError("case export contains malformed typed proof") from error
        if canonical_json(result) != bytes(broker.result_json):
            raise ValueError(
                "case export requires the latest warrant's matching completed broker result"
            )
        if (
            verdict.verdict != Verdict.CLEAR.value
            or verdict_output.verdict is not Verdict.CLEAR
            or verdict.source != "Magistrate"
            or canonical_json(verdict_output) != bytes(verdict.output_json)
        ):
            raise ValueError("case export verdict semantics are not CLEAR")

        warrant_hash = canonical_warrant_hash(document)
        verdict_hash = hashlib.sha256(verdict.output_json).hexdigest()
        document_nonce_sha256 = hashlib.sha256(document.nonce.encode("utf-8")).hexdigest()
        approval_valid = (
            self._authority.policy.approval_service.verify(document, approval)
            and approval.warrant_id == document.warrant_id == broker.id
            and control.approval_id == document.warrant_id.replace("war_", "apr_", 1)
            and hmac.compare_digest(approval.warrant_sha256, warrant_hash)
            and hmac.compare_digest(
                approval.approver_identity,
                document.approver_identity,
            )
            and hmac.compare_digest(
                approval.mac_key_id,
                document.approval_mac_key_id,
            )
            and document.issued_at <= approval.approved_at <= document.expires_at
            and aware_utc(approval.approved_at) == aware_utc(broker.created_at)
            and aware_utc(approval.approved_at) == aware_utc(control.updated_at)
        )
        if not approval_valid:
            raise ValueError("case export approval proof is invalid")
        correlated = (
            document.incident_id == incident_id
            and document.warrant_id == control.id == broker.id
            and document.verdict_id == verdict.id
            and control.status == "APPROVED"
            and control.approval_id is not None
            and hmac.compare_digest(control.warrant_sha256, warrant_hash)
            and hmac.compare_digest(document.verdict_sha256, verdict.verdict_sha256)
            and hmac.compare_digest(verdict.verdict_sha256, verdict_hash)
            and bytes(broker.document_json) == bytes(control.canonical_document)
            and result.warrant_id == broker.id
            and result.nonce_sha256 is not None
            and hmac.compare_digest(broker.nonce_sha256, document_nonce_sha256)
            and hmac.compare_digest(result.nonce_sha256, document_nonce_sha256)
        )
        if not correlated:
            raise ValueError("case export warrant, verdict, and receipt bindings disagree")

        receipts = tuple(result.receipts)
        expected_plans = tuple(
            (plan.plan_id, plan.plan_sha256) for plan in document.execution_plans
        )
        actual_plans = tuple((receipt.plan_id, receipt.plan_sha256) for receipt in receipts)
        passed = bool(receipts) and all(receipt.passed for receipt in receipts)
        status_consistent = (
            result.status in {BrokerStatus.EXECUTED, BrokerStatus.TEST_FAILED}
            and (result.status is BrokerStatus.EXECUTED) is passed
            and all(receipt.supervisor_verified for receipt in receipts)
            and expected_plans == actual_plans
            and (
                (result.status is BrokerStatus.EXECUTED and result.error_code is None)
                or (
                    result.status is BrokerStatus.TEST_FAILED
                    and isinstance(result.error_code, str)
                    and bool(result.error_code)
                )
            )
        )
        if not receipts or not status_consistent:
            raise ValueError("case export broker status and receipts disagree")

        receipt_rows = tuple(
            row for row in snapshot.test_runs if row.result.get("warrant_id") == control.id
        )
        receipt_artifacts: list[ExportArtifact] = []
        if len(receipt_rows) != len(receipts):
            raise ValueError("case export receipt rows disagree with broker result")
        receipt_rows_by_plan = {(row.plan_id, row.plan_sha256): row for row in receipt_rows}
        if len(receipt_rows_by_plan) != len(receipt_rows):
            raise ValueError("case export receipt rows disagree with broker result")
        projection_artifacts = projection.get("artifacts")
        if not isinstance(projection_artifacts, dict):
            raise ValueError("case export projection and timeline head disagree")
        projected_tests = projection_artifacts.get("tests")
        if not isinstance(projected_tests, list):
            raise ValueError("case export projection and timeline head disagree")
        if not all(isinstance(item, dict) for item in projected_tests):
            raise ValueError("case export receipt rows disagree with broker result")
        projected_test_ids = [item.get("id") for item in projected_tests]
        persisted_test_ids = {row.id for row in snapshot.test_runs}
        if (
            len(projected_tests) != len(snapshot.test_runs)
            or len(set(projected_test_ids)) != len(projected_test_ids)
            or set(projected_test_ids) != persisted_test_ids
        ):
            raise ValueError("case export receipt rows disagree with broker result")
        projected_by_id = {
            item.get("id"): item for item in projected_tests if isinstance(item, dict)
        }
        projected_receipts = [
            item for item in projected_tests if item.get("warrant_id") == control.id
        ]
        projected_receipt_ids = {item.get("id") for item in projected_receipts}
        if len(projected_receipts) != len(receipt_rows) or projected_receipt_ids != {
            row.id for row in receipt_rows
        }:
            raise ValueError("case export receipt rows disagree with broker result")
        expected_outcome_type = (
            "VERIFIED" if result.status is BrokerStatus.EXECUTED else "TEST_FAILED"
        )
        outcome_events = tuple(
            event
            for event in snapshot.timeline_events
            if event.type == expected_outcome_type and event.payload.get("warrant_id") == control.id
        )
        if len(outcome_events) != 1:
            raise ValueError("case export receipt rows disagree with broker result")
        outcome_event = outcome_events[0]
        outcome_receipt_id = outcome_event.payload.get(
            "receipt_id" if expected_outcome_type == "VERIFIED" else "test_run_id"
        )
        evidence_id = outcome_event.payload.get("evidence_id")
        if (
            outcome_receipt_id not in {row.id for row in receipt_rows}
            or not isinstance(evidence_id, str)
            or not evidence_id
        ):
            raise ValueError("case export receipt rows disagree with broker result")
        for receipt in receipts:
            row = receipt_rows_by_plan.get((receipt.plan_id, receipt.plan_sha256))
            if row is None:
                raise ValueError("case export receipt rows disagree with broker result")
            try:
                row_receipt = ProcessReceipt.model_validate(row.result.get("receipt"))
            except ValueError as error:
                raise ValueError("case export receipt rows disagree with broker result") from error
            receipt_json = receipt.model_dump(mode="json")
            receipt_sha256 = sha256_hex(receipt_json)
            projected = projected_by_id.get(row.id)
            expected_result = broker_receipt_result(
                receipt,
                warrant_id=control.id,
                evidence_id=evidence_id,
            )
            expected_projected = {
                "id": row.id,
                "label": receipt.plan_id,
                "plan_sha256": receipt.plan_sha256,
                "state": expected_result["state"],
                "passed": expected_result["passed"],
                "duration_ms": expected_result["duration_ms"],
                "detail": expected_result["detail"],
                "warrant_id": control.id,
                "evidence_id": evidence_id,
                "receipt_sha256": receipt_sha256,
            }
            trusted_observation = published_trusted_observation(
                expected_result,
                expected_plan_id=receipt.plan_id,
                expected_plan_sha256=receipt.plan_sha256,
            )
            if trusted_observation is not None:
                expected_projected.update(trusted_observation)
            row_correlated = (
                row.plan_id == receipt.plan_id
                and row.plan_sha256 == receipt.plan_sha256
                and row_receipt == receipt
                and row.result == expected_result
                and isinstance(projected, dict)
                and projected == expected_projected
            )
            if not row_correlated:
                raise ValueError("case export receipt rows disagree with broker result")
            receipt_artifacts.append(
                ExportArtifact(
                    path=f"receipts/{row.id}.json",
                    incident_id=incident_id,
                    kind="receipt",
                    data=canonical_json(
                        {
                            "id": row.id,
                            "incident_id": incident_id,
                            "plan_id": row.plan_id,
                            "plan_sha256": row.plan_sha256,
                            "warrant_id": control.id,
                            "receipt_sha256": receipt_sha256,
                            "receipt": receipt_json,
                            "result": row.result,
                        }
                    ),
                    provenance="deterministic runner receipt row",
                )
            )

        projection_hash = hashlib.sha256(canonical_json(projection)).hexdigest()
        projection_incident = projection.get("incident")
        projection_events = projection.get("events")
        projection_verdicts = projection.get("verdicts")
        projection_warrants = projection.get("warrants")
        latest_projected_verdict = (
            projection_verdicts[-1]
            if isinstance(projection_verdicts, list)
            and projection_verdicts
            and isinstance(projection_verdicts[-1], dict)
            else None
        )
        latest_projected_warrant = (
            projection_warrants[-1]
            if isinstance(projection_warrants, list)
            and projection_warrants
            and isinstance(projection_warrants[-1], dict)
            else None
        )
        projected_binding_hashes = (
            latest_projected_warrant.get("binding_hashes")
            if latest_projected_warrant is not None
            else None
        )
        expected_binding_hashes = {
            "authority_snapshot_sha256": document.authority_snapshot_sha256,
            "base_sha": document.base_sha,
            "environment_digest": document.environment_digest,
            "patch_sha256": document.patch_sha256,
            "repository_manifest_sha256": document.repository_manifest_sha256,
            "reviewed_evidence_manifest_sha256": (document.reviewed_evidence_manifest_sha256),
            "reviewed_timeline_head": document.reviewed_timeline_head,
            "runner_digest": document.runner_digest,
            "test_plan_sha256": document.test_plan_sha256,
            "verdict_sha256": document.verdict_sha256,
        }
        projection_correlated = (
            snapshot.published.revision > 0
            and hmac.compare_digest(snapshot.published.manifest_sha256, projection_hash)
            and isinstance(projection_incident, dict)
            and projection_incident.get("id") == incident_id
            and projection_incident.get("state") == incident.state
            and projection_incident.get("base_sha") == incident.base_sha == document.base_sha
            and isinstance(projection_events, list)
            and bool(projection_events)
            and projection_events[-1].get("event_hash") == incident.event_chain_head
            and latest_projected_verdict is not None
            and latest_projected_verdict.get("id") == verdict.id
            and latest_projected_verdict.get("verdict") == Verdict.CLEAR.value
            and latest_projected_verdict.get("verdict_sha256") == verdict.verdict_sha256
            and latest_projected_warrant is not None
            and latest_projected_warrant.get("warrant_id") == control.id
            and latest_projected_warrant.get("canonical_sha256") == control.warrant_sha256
            and latest_projected_warrant.get("approval_status") == "APPROVED"
            and latest_projected_warrant.get("approval_id") == control.approval_id
            and latest_projected_warrant.get("consumption_status") == WarrantState.CONSUMED.value
            and latest_projected_warrant.get("execution_status") == result.status.value
            and latest_projected_warrant.get("receipt_ids") == [row.id for row in receipt_rows]
            and projected_binding_hashes == expected_binding_hashes
        )
        if not projection_correlated:
            raise ValueError("case export projection and timeline head disagree")

        case_bytes = canonical_json(projection)
        artifacts: list[ExportArtifact] = [
            ExportArtifact(
                path="case-file.json",
                incident_id=incident_id,
                kind="timeline",
                data=case_bytes,
                provenance="transactionally published CrossPatch case projection",
            ),
            ExportArtifact(
                path="receipts/broker-result.json",
                incident_id=incident_id,
                kind="receipt",
                data=bytes(broker.result_json),
                provenance="canonical deterministic broker result",
            ),
            *receipt_artifacts,
        ]
        artifact_projection = projection.get("artifacts", {})
        evidence_projection = (
            artifact_projection.get("evidence", []) if isinstance(artifact_projection, dict) else []
        )
        for item in evidence_projection:
            if not isinstance(item, dict) or item.get("classification") != "UNTRUSTED_EVIDENCE":
                raise ValueError("published evidence projection is malformed")
            evidence_id = str(item["evidence_id"])
            artifacts.append(
                ExportArtifact(
                    path=f"evidence/{evidence_id}.json",
                    incident_id=incident_id,
                    kind="sanitized_evidence",
                    data=canonical_json(item),
                    provenance="sanitized evidence projection",
                )
            )
        binding_extensions: dict[str, object] = {}
        if incident.scenario == "webhook-payload-equivalence":
            if len(receipt_rows) != 1:
                raise ValueError(
                    "payload-equivalence export requires one bound trusted observation"
                )
            receipt_row = receipt_rows[0]
            trusted = published_trusted_observation(
                receipt_row.result,
                expected_plan_id=receipt_row.plan_id,
                expected_plan_sha256=receipt_row.plan_sha256,
            )
            if trusted is None:
                raise ValueError(
                    "payload-equivalence export requires one bound trusted observation"
                )
            observation = trusted["trusted_observation"]
            counts = observation["counts"]
            binding_extensions = {
                "scenario": incident.scenario,
                "plan_id": receipt_row.plan_id,
                "plan_sha256": receipt_row.plan_sha256,
                "execution_status": result.status.value,
                "response_statuses": tuple(observation["response_statuses"]),
                "counts": (
                    counts["receipts"],
                    counts["jobs"],
                    counts["deliveries"],
                ),
                "trusted_observation_sha256": trusted["trusted_observation_sha256"],
            }
        return self._exporter.build(
            CaseBinding(
                incident_id=incident_id,
                base_sha=incident.base_sha or "0" * 40,
                verdict_sha256=verdict.verdict_sha256,
                warrant_sha256=control.warrant_sha256,
                receipt_sha256=hashlib.sha256(bytes(broker.result_json)).hexdigest(),
                timeline_head=incident.event_chain_head,
                **binding_extensions,
            ),
            tuple(artifacts),
        )

    async def rotate_judge_token(
        self, *, actor: str, incident_id: str | None = None
    ) -> JudgeTokenView:
        now = datetime.now(UTC)
        jti = f"judge-{uuid4().hex}"
        token = self._judge_issuer.issue(
            subject="judge-client",
            jti=jti,
            issued_at=now,
            expires_at=self._judge_token_expires_at,
            incident_id=incident_id,
        )
        await self._judge_tokens.register(
            token,
            jti=jti,
            expires_at=self._judge_token_expires_at,
            actor=actor,
        )
        return JudgeTokenView(token=token, expires_at=self._judge_token_expires_at)

    async def rotate_live_trial_credential(
        self,
        *,
        actor: str,
    ) -> LiveTrialCredentialView:
        if self._live_trials is None or self._live_trial_token_expires_at is None:
            raise RuntimeError("live-trial credentials are unavailable")
        issued = await self._live_trials.issue(
            actor=actor,
            expires_at=self._live_trial_token_expires_at,
        )
        budget = await self._live_trials.global_budget()
        return LiveTrialCredentialView(
            token=issued.token,
            subject=issued.subject,
            expires_at=issued.expires_at,
            global_budget_cap_usd=budget.cap_usd,
        )

    async def revoke_live_trial_credential(
        self,
        subject: str,
        *,
        actor: str,
    ) -> None:
        if self._live_trials is None:
            raise RuntimeError("live-trial credentials are unavailable")
        await self._live_trials.revoke(subject, actor=actor)

    @staticmethod
    def _judge_token_metadata(status) -> JudgeTokenMetadataView:
        return JudgeTokenMetadataView(
            token_id=status.token_id,
            expires_at=status.expires_at,
            revoked=status.revoked,
            created_at=status.created_at,
            revoked_at=status.revoked_at,
        )

    async def list_judge_tokens(self) -> JudgeTokenListView:
        statuses = await self._judge_tokens.list_tokens()
        return JudgeTokenListView(
            tokens=tuple(self._judge_token_metadata(status) for status in statuses)
        )

    async def revoke_judge_token(
        self,
        token_id: str,
        *,
        actor: str,
    ) -> JudgeTokenMetadataView:
        status = await self._judge_tokens.revoke_by_token_id(token_id, actor=actor)
        if status is None:
            raise LookupError(token_id)
        return self._judge_token_metadata(status)

    async def close(self) -> None:
        tasks = (
            tuple(self._incident_tasks.values())
            + tuple(self._approval_tasks)
            + tuple(self._runtime_work_tasks.values())
        )
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
