"""Database-backed orchestration authority and approval boundary."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel
from sqlalchemy import select, text

from crosspatch.agents.schemas import (
    BailiffOutput,
    CounselOutput,
    InspectorProsecutorResult,
    MagistrateOutput,
    SeatOutput,
)
from crosspatch.api.models import WarrantView
from crosspatch.broker.approval import ApprovalService, canonical_approval_bytes
from crosspatch.broker.broker import AuthoritySnapshot, WarrantState
from crosspatch.broker.paths import (
    PatchFormatViolation,
    PathPolicyViolation,
    derive_patch_paths,
    validate_patch_paths,
)
from crosspatch.broker.store import canonical_authority_bytes
from crosspatch.broker.warrant import (
    WARRANT_FORMAT,
    BoundExecutionPlan,
    WarrantDocument,
    canonical_warrant_bytes,
    canonical_warrant_hash,
)
from crosspatch.db.models import (
    AgentRunRecord,
    ControlWarrantRecord,
    EvidenceRecord,
    IncidentRecord,
    MutationAuthorityRecord,
    PatchCandidateRecord,
    VerdictRecord,
    WarrantRecord,
)
from crosspatch.domain.enums import Effort, IncidentState, Seat, Verdict
from crosspatch.domain.hashing import canonical_json, semantic_fingerprint, sha256_hex
from crosspatch.domain.seats import SEAT_SPECS
from crosspatch.evidence.views import UntrustedEvidenceEnvelope
from crosspatch.orchestration.failures import InvalidSchema, MissingEvidenceReference
from crosspatch.runner.catalog import ExecutionCatalog
from crosspatch.runtime.database import (
    APPROVED_EXECUTION_WORK,
    RuntimeStore,
    aware_utc,
)
from crosspatch.runtime.scenarios import require_operator_scenario

_SPEC_BY_SEAT = {spec.seat: spec for spec in SEAT_SPECS}


class WarrantDecisionConflict(RuntimeError):
    """A durable warrant decision conflict safe to map to HTTP 409."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class AuthorityPolicy:
    repository_root: Path
    repository_id: str
    approver_identity: str
    approval_mac_key_id: str
    approval_service: ApprovalService
    runner_digest: str
    environment_digest: str
    warrant_ttl: timedelta = timedelta(minutes=15)
    catalog: ExecutionCatalog = ExecutionCatalog.default()

    def __post_init__(self) -> None:
        root = Path(self.repository_root).resolve(strict=True)
        object.__setattr__(self, "repository_root", root)
        if not self.repository_id or not self.approver_identity or not self.approval_mac_key_id:
            raise ValueError("authority identity fields are required")
        if len(self.runner_digest) != 64 or len(self.environment_digest) != 64:
            raise ValueError("runner and environment digests must be SHA-256 values")
        if self.warrant_ttl <= timedelta(0):
            raise ValueError("warrant TTL must be positive")


class DatabaseAuthorityGateway:
    def __init__(self, store: RuntimeStore, policy: AuthorityPolicy) -> None:
        self.store = store
        self.policy = policy

    async def begin_review(self, incident_id: str) -> None:
        incident = await self.store.get_incident_record(incident_id)
        if incident is None:
            raise LookupError(incident_id)
        state = IncidentState(incident.state)
        if state is IncidentState.EVIDENCE_READY:
            await self.store.append_event(incident_id, "ANALYSIS_STARTED", "orchestrator", {})
        elif state is IncidentState.TEST_FAILED:
            await self.store.append_event(incident_id, "RETRY_STARTED", "orchestrator", {})
        elif state not in {IncidentState.ANALYZING, IncidentState.PATCHING}:
            raise ValueError(f"incident cannot begin review from {state.value}")

    async def fail_closed_abstain(
        self,
        incident_id: str,
        *,
        reason: str,
        failure_code: str | None = None,
    ) -> None:
        payload: dict[str, Any] = {"verdict": Verdict.ABSTAIN.value, "reason": reason}
        if failure_code is not None:
            payload["failure_code"] = failure_code
        now = datetime.now(UTC)
        encoded = canonical_json(payload)
        async with self.store.sessions() as session, session.begin():
            incident = await session.scalar(
                select(IncidentRecord).where(IncidentRecord.id == incident_id).with_for_update()
            )
            if incident is None:
                raise LookupError(incident_id)
            session.add(
                VerdictRecord(
                    id=f"verdict_{uuid4().hex}",
                    incident_id=incident_id,
                    agent_run_id=None,
                    verdict=Verdict.ABSTAIN.value,
                    output_json=encoded,
                    verdict_sha256=hashlib.sha256(encoded).hexdigest(),
                    source=Seat.MAGISTRATE.value,
                    created_at=now,
                )
            )
            await self.store._append_locked(
                session,
                incident,
                "VERDICT",
                Seat.MAGISTRATE.value,
                payload,
                now=now,
            )
            await self.store._publish_locked(session, incident_id, now)

    async def record_verdict(self, incident_id: str, output: MagistrateOutput) -> None:
        encoded = canonical_json(output)
        now = datetime.now(UTC)
        record = VerdictRecord(
            id=f"verdict_{uuid4().hex}",
            incident_id=incident_id,
            agent_run_id=None,
            verdict=output.verdict.value,
            output_json=encoded,
            verdict_sha256=hashlib.sha256(encoded).hexdigest(),
            source="Magistrate",
            created_at=now,
        )
        async with self.store.sessions() as session, session.begin():
            session.add(record)
            incident = await session.scalar(
                select(IncidentRecord).where(IncidentRecord.id == incident_id).with_for_update()
            )
            if incident is None:
                raise LookupError(incident_id)
            payload = output.model_dump(mode="json")
            await self.store._append_locked(
                session, incident, "VERDICT", "Magistrate", payload, now=now
            )
            await self.store._publish_locked(session, incident_id, now)

    async def record_escalation(
        self,
        incident_id: str,
        *,
        seat: Seat,
        effort: Effort,
        escalation_count: int,
        reason: str,
        message: str,
    ) -> None:
        await self.store.append_event(
            incident_id,
            "REASONING_ESCALATED",
            seat.value,
            {
                "seat": seat.value,
                "effort": effort.value,
                "escalation_count": escalation_count,
                "reason": reason,
                "message": message,
            },
        )

    async def reject_duplicate_retry(
        self,
        incident_id: str,
        *,
        seat: Seat,
        effort: Effort,
        phase: str,
        output: SeatOutput,
        reason: str,
    ) -> None:
        """Atomically retain the rejected attempt and enter human escalation."""
        spec = _SPEC_BY_SEAT[seat]
        try:
            escalation_count = spec.effort_ladder.index(effort)
        except ValueError as error:
            raise ValueError("rejected retry effort is outside the seat policy") from error
        if escalation_count == 0 or escalation_count > spec.max_escalations:
            raise ValueError("rejected retry did not consume a valid escalation step")

        now = datetime.now(UTC)
        encoded_output = canonical_json(output)
        output_sha256 = hashlib.sha256(encoded_output).hexdigest()
        semantic_sha256 = semantic_fingerprint(seat, output)
        abstain_payload = {
            "verdict": Verdict.ABSTAIN.value,
            "reason": "escalation_exhausted",
            "failure_code": "FAILED_RETRY_DUPLICATE",
        }
        encoded_abstain = canonical_json(abstain_payload)
        async with self.store.sessions() as session, session.begin():
            incident = await session.scalar(
                select(IncidentRecord)
                .where(IncidentRecord.id == incident_id)
                .with_for_update()
            )
            if incident is None:
                raise LookupError(incident_id)
            session.add(
                AgentRunRecord(
                    id=f"run_{uuid4().hex}",
                    incident_id=incident_id,
                    seat=seat.value,
                    model=spec.model,
                    effort=effort.value,
                    phase=phase,
                    escalation_count=escalation_count,
                    output_json=encoded_output,
                    output_sha256=output_sha256,
                    semantic_sha256=semantic_sha256,
                    schema_status="REJECTED_DUPLICATE",
                    failure_reason="FAILED_RETRY_DUPLICATE",
                    created_at=now,
                )
            )
            await self.store._append_locked(
                session,
                incident,
                "FAILED_RETRY_DUPLICATE",
                seat.value,
                {
                    "seat": seat.value,
                    "effort": effort.value,
                    "escalation_count": escalation_count,
                    "phase": phase,
                    "reason": reason,
                    "output_sha256": output_sha256,
                    "semantic_sha256": semantic_sha256,
                },
                now=now,
            )
            session.add(
                VerdictRecord(
                    id=f"verdict_{uuid4().hex}",
                    incident_id=incident_id,
                    agent_run_id=None,
                    verdict=Verdict.ABSTAIN.value,
                    output_json=encoded_abstain,
                    verdict_sha256=hashlib.sha256(encoded_abstain).hexdigest(),
                    source=Seat.MAGISTRATE.value,
                    created_at=now,
                )
            )
            await self.store._append_locked(
                session,
                incident,
                "VERDICT",
                Seat.MAGISTRATE.value,
                abstain_payload,
                now=now,
            )
            await self.store._publish_locked(session, incident_id, now)

    async def _persist_output_locked(
        self,
        session,
        incident_id: str,
        seat: Seat,
        phase: str,
        effort: Effort,
        output: SeatOutput,
        now: datetime,
    ) -> AgentRunRecord:
        encoded = canonical_json(output)
        record = AgentRunRecord(
            id=f"run_{uuid4().hex}",
            incident_id=incident_id,
            seat=seat.value,
            model=_SPEC_BY_SEAT[seat].model,
            effort=effort.value,
            phase=phase,
            escalation_count=0,
            output_json=encoded,
            output_sha256=hashlib.sha256(encoded).hexdigest(),
            semantic_sha256=semantic_fingerprint(seat, output),
            schema_status="VALID",
            created_at=now,
        )
        session.add(record)
        await session.flush()
        return record

    async def open_approval(
        self,
        incident_id: str,
        output: MagistrateOutput,
        seat_outputs: dict[Seat, SeatOutput],
    ) -> str:
        if output.verdict is not Verdict.CLEAR:
            raise ValueError("only a CLEAR verdict can open human approval")
        counsel = seat_outputs.get(Seat.COUNSEL)
        if not isinstance(counsel, CounselOutput):
            raise ValueError("CLEAR requires a structured Counsel patch")
        patch = counsel.normalized_diff.encode("utf-8")
        allowed_paths = derive_patch_paths(patch)
        validate_patch_paths(self.policy.repository_root, allowed_paths)
        plan_ids = tuple(intention.catalog_id for intention in counsel.test_intentions)
        now = datetime.now(UTC)
        warrant_id = f"war_{uuid4().hex}"
        verdict_id = f"verdict_{uuid4().hex}"
        nonce = f"nonce_{secrets.token_hex(24)}"

        async with self.store.sessions() as session, session.begin():
            incident = await session.scalar(
                select(IncidentRecord).where(IncidentRecord.id == incident_id).with_for_update()
            )
            if incident is None:
                raise LookupError(incident_id)
            if IncidentState(incident.state) is not IncidentState.REVIEWING:
                raise ValueError("approval can open only from REVIEWING")
            if not incident.base_sha or not incident.repository_manifest_sha256:
                raise ValueError("incident repository bindings are incomplete")
            definition = require_operator_scenario(incident.scenario)
            if plan_ids != (definition.candidate_plan_id,):
                raise ValueError("approval plan does not match incident scenario")
            plans = tuple(
                BoundExecutionPlan.from_execution_plan(self.policy.catalog.resolve(plan_id))
                for plan_id in plan_ids
            )
            test_plan_sha256 = sha256_hex(plans)
            evidence = tuple(
                (
                    await session.scalars(
                        select(EvidenceRecord)
                        .where(
                            EvidenceRecord.incident_id == incident_id,
                            EvidenceRecord.published.is_(True),
                        )
                        .order_by(EvidenceRecord.id)
                    )
                ).all()
            )
            evidence_manifest = sha256_hex(
                tuple((row.id, row.sanitized_sha256) for row in evidence)
            )
            reviewed_head = incident.event_chain_head
            if reviewed_head is None:
                raise ValueError("incident timeline has no review head")
            counsel_bytes = canonical_json(counsel)
            counsel_sha256 = hashlib.sha256(counsel_bytes).hexdigest()
            counsel_run = await session.scalar(
                select(AgentRunRecord)
                .where(
                    AgentRunRecord.incident_id == incident_id,
                    AgentRunRecord.seat == Seat.COUNSEL.value,
                    AgentRunRecord.output_sha256 == counsel_sha256,
                    AgentRunRecord.schema_status == "VALID",
                )
                .order_by(AgentRunRecord.created_at.desc(), AgentRunRecord.id.desc())
                .limit(1)
            )
            if counsel_run is None:
                counsel_run = await self._persist_output_locked(
                    session,
                    incident_id,
                    Seat.COUNSEL,
                    "patch-proposal",
                    _SPEC_BY_SEAT[Seat.COUNSEL].initial_effort,
                    counsel,
                    now,
                )
            patch_sha256 = hashlib.sha256(patch).hexdigest()
            candidate = await session.scalar(
                select(PatchCandidateRecord)
                .where(
                    PatchCandidateRecord.incident_id == incident_id,
                    PatchCandidateRecord.agent_run_id == counsel_run.id,
                    PatchCandidateRecord.patch_sha256 == patch_sha256,
                )
                .order_by(PatchCandidateRecord.created_at.desc())
                .limit(1)
            )
            if candidate is None:
                predecessor = await session.scalar(
                    select(PatchCandidateRecord)
                    .where(PatchCandidateRecord.incident_id == incident_id)
                    .order_by(
                        PatchCandidateRecord.created_at.desc(),
                        PatchCandidateRecord.id.desc(),
                    )
                    .limit(1)
                )
                candidate = PatchCandidateRecord(
                    id=f"candidate_{uuid4().hex}",
                    incident_id=incident_id,
                    agent_run_id=counsel_run.id,
                    patch_sha256=patch_sha256,
                    normalized_diff=counsel.normalized_diff,
                    allowed_paths=list(allowed_paths),
                    test_intentions=[
                        item.model_dump(mode="json") for item in counsel.test_intentions
                    ],
                    predecessor_id=(predecessor.id if predecessor is not None else None),
                    created_at=now,
                )
                session.add(candidate)
            elif tuple(candidate.allowed_paths) != allowed_paths:
                raise ValueError("persisted patch candidate paths changed")
            candidate_id = candidate.id

            magistrate_bytes = canonical_json(output)
            magistrate_sha256 = hashlib.sha256(magistrate_bytes).hexdigest()
            magistrate_run = await session.scalar(
                select(AgentRunRecord)
                .where(
                    AgentRunRecord.incident_id == incident_id,
                    AgentRunRecord.seat == Seat.MAGISTRATE.value,
                    AgentRunRecord.output_sha256 == magistrate_sha256,
                    AgentRunRecord.schema_status == "VALID",
                )
                .order_by(AgentRunRecord.created_at.desc(), AgentRunRecord.id.desc())
                .limit(1)
            )
            if magistrate_run is None:
                magistrate_run = await self._persist_output_locked(
                    session,
                    incident_id,
                    Seat.MAGISTRATE,
                    "verdict-review",
                    _SPEC_BY_SEAT[Seat.MAGISTRATE].initial_effort,
                    output,
                    now,
                )
            verdict_bytes = canonical_json(output)
            verdict_sha256 = hashlib.sha256(verdict_bytes).hexdigest()
            authority_digest = sha256_hex(
                {
                    "warrant_id": warrant_id,
                    "incident_id": incident_id,
                    "verdict_id": verdict_id,
                    "verdict_sha256": verdict_sha256,
                    "candidate_id": candidate_id,
                    "evidence_manifest": evidence_manifest,
                    "timeline_head": reviewed_head,
                    "patch_sha256": patch_sha256,
                    "allowed_paths": allowed_paths,
                    "test_plan_sha256": test_plan_sha256,
                }
            )
            approver_identity = self.policy.approver_identity
            if incident.live_trial:
                if not incident.owner_subject:
                    raise ValueError("live-trial incident has no credential owner")
                approver_identity = incident.owner_subject
            document = WarrantDocument(
                format=WARRANT_FORMAT,
                warrant_id=warrant_id,
                incident_id=incident_id,
                repository_id=self.policy.repository_id,
                verdict_id=verdict_id,
                verdict_sha256=verdict_sha256,
                candidate_id=candidate_id,
                authority_snapshot_sha256=authority_digest,
                reviewed_evidence_manifest_sha256=evidence_manifest,
                reviewed_timeline_head=reviewed_head,
                base_sha=incident.base_sha,
                repository_manifest_sha256=incident.repository_manifest_sha256,
                patch_b64=base64.b64encode(patch).decode("ascii"),
                patch_sha256=patch_sha256,
                allowed_paths=allowed_paths,
                execution_plans=plans,
                test_plan_sha256=test_plan_sha256,
                runner_digest=self.policy.runner_digest,
                environment_digest=self.policy.environment_digest,
                approver_identity=approver_identity,
                issued_at=now,
                expires_at=now + self.policy.warrant_ttl,
                approval_mac_key_id=self.policy.approval_mac_key_id,
                nonce=nonce,
            )
            authority = AuthoritySnapshot.from_warrant(
                document, repository_root=self.policy.repository_root
            )
            session.add(
                VerdictRecord(
                    id=verdict_id,
                    incident_id=incident_id,
                    agent_run_id=magistrate_run.id,
                    verdict=Verdict.CLEAR.value,
                    output_json=verdict_bytes,
                    verdict_sha256=verdict_sha256,
                    source=Seat.MAGISTRATE.value,
                    created_at=now,
                )
            )
            canonical = canonical_warrant_bytes(document)
            session.add(
                ControlWarrantRecord(
                    id=warrant_id,
                    incident_id=incident_id,
                    canonical_document=canonical,
                    warrant_sha256=canonical_warrant_hash(document),
                    authority_json=canonical_authority_bytes(authority),
                    status="PENDING_APPROVAL",
                    expires_at=document.expires_at,
                    created_at=now,
                    updated_at=now,
                )
            )
            incident.pending_warrant_id = warrant_id
            await self.store._append_locked(
                session,
                incident,
                "VERDICT",
                Seat.MAGISTRATE.value,
                output.model_dump(mode="json"),
                now=now,
            )
            await self.store._publish_locked(session, incident_id, now)
        return warrant_id

    async def get_warrant(self, warrant_id: str) -> WarrantView | None:
        record = await self.store.control_warrant(warrant_id)
        if record is None:
            return None
        return WarrantView(
            id=record.id,
            incident_id=record.incident_id,
            status=record.status,
            canonical_document=record.canonical_document.decode("utf-8"),
            warrant_sha256=record.warrant_sha256,
            expires_at=aware_utc(record.expires_at),
        )

    async def _expire_warrant_if_needed(
        self,
        *,
        warrant_id: str,
        warrant_sha256: str,
        actor: str,
        reason: str | None = None,
        now: datetime,
    ) -> bool:
        async with self.store.sessions() as session, session.begin():
            control = await session.scalar(
                select(ControlWarrantRecord)
                .where(ControlWarrantRecord.id == warrant_id)
                .with_for_update()
            )
            if control is None:
                raise LookupError(warrant_id)
            if control.status != "PENDING_APPROVAL":
                raise WarrantDecisionConflict(
                    "WARRANT_NOT_PENDING",
                    "warrant is not pending approval",
                )
            if not hmac.compare_digest(control.warrant_sha256, warrant_sha256):
                raise WarrantDecisionConflict(
                    "WARRANT_HASH_CHANGED",
                    "canonical warrant hash changed",
                )
            if now <= aware_utc(control.expires_at):
                return False
            incident = await session.scalar(
                select(IncidentRecord)
                .where(IncidentRecord.id == control.incident_id)
                .with_for_update()
            )
            if incident is None:
                raise LookupError(control.incident_id)
            control.status = "EXPIRED"
            control.updated_at = now
            incident.pending_warrant_id = None
            await self.store._append_locked(
                session,
                incident,
                "WARRANT_EXPIRED",
                actor,
                {"warrant_id": warrant_id, "warrant_sha256": warrant_sha256},
                now=now,
            )
            await self.store._publish_locked(session, incident.id, now)
            return True

    async def decide_warrant(
        self,
        *,
        warrant_id: str,
        approve: bool,
        warrant_sha256: str,
        actor: str,
        reason: str | None = None,
    ) -> WarrantView:
        now = datetime.now(UTC)
        if approve and await self._expire_warrant_if_needed(
            warrant_id=warrant_id,
            warrant_sha256=warrant_sha256,
            actor=actor,
            now=now,
        ):
            raise WarrantDecisionConflict("WARRANT_EXPIRED", "warrant is expired")
        async with self.store.sessions() as session, session.begin():
            control = await session.scalar(
                select(ControlWarrantRecord)
                .where(ControlWarrantRecord.id == warrant_id)
                .with_for_update()
            )
            if control is None:
                raise LookupError(warrant_id)
            if control.status != "PENDING_APPROVAL":
                raise WarrantDecisionConflict(
                    "WARRANT_NOT_PENDING",
                    "warrant is not pending approval",
                )
            if not hmac.compare_digest(control.warrant_sha256, warrant_sha256):
                raise WarrantDecisionConflict(
                    "WARRANT_HASH_CHANGED",
                    "canonical warrant hash changed",
                )
            document = WarrantDocument.model_validate_json(control.canonical_document)
            incident = await session.scalar(
                select(IncidentRecord)
                .where(IncidentRecord.id == control.incident_id)
                .with_for_update()
            )
            if incident is None:
                raise LookupError(control.incident_id)
            if not approve:
                control.status = "REJECTED"
                control.updated_at = now
                incident.pending_warrant_id = None
                incident.state = IncidentState.BLOCKED.value
                payload = {"warrant_id": warrant_id, "warrant_sha256": warrant_sha256}
                if reason is not None:
                    payload["reason"] = reason
                await self.store._append_locked(
                    session,
                    incident,
                    "WARRANT_REJECTED",
                    actor,
                    payload,
                    now=now,
                )
                await self.store._publish_locked(session, incident.id, now)
            else:
                if now > aware_utc(control.expires_at):
                    raise RuntimeError("warrant expiry changed during locked approval")
                approval = self.policy.approval_service.approve(
                    document,
                    approved_at=now,
                    approver_identity=actor,
                )
                AuthoritySnapshot.model_validate_json(control.authority_json)
                if session.bind is not None and session.bind.dialect.name == "postgresql":
                    await session.execute(
                        text(
                            "SELECT pg_advisory_xact_lock("
                            "hashtextextended(:incident_id, 435276111))"
                        ),
                        {"incident_id": incident.id},
                    )
                current_authority = await session.scalar(
                    select(MutationAuthorityRecord)
                    .where(MutationAuthorityRecord.incident_id == incident.id)
                    .with_for_update()
                )
                if current_authority is None:
                    session.add(
                        MutationAuthorityRecord(
                            incident_id=incident.id,
                            snapshot_json=control.authority_json,
                            version=1,
                            updated_at=now,
                        )
                    )
                else:
                    current_authority.snapshot_json = control.authority_json
                    current_authority.version += 1
                    current_authority.updated_at = now
                session.add(
                    WarrantRecord(
                        id=warrant_id,
                        incident_id=incident.id,
                        nonce_sha256=hashlib.sha256(document.nonce.encode()).hexdigest(),
                        document_json=control.canonical_document,
                        approval_json=canonical_approval_bytes(approval),
                        state=WarrantState.APPROVED.value,
                        expires_at=document.expires_at,
                        created_at=now,
                        updated_at=now,
                    )
                )
                control.status = "APPROVED"
                control.approval_id = warrant_id.replace("war_", "apr_", 1)
                control.updated_at = now
                incident.pending_warrant_id = None
                await self.store._append_locked(
                    session,
                    incident,
                    "WARRANT_APPROVED",
                    actor,
                    {
                        "approval_id": control.approval_id,
                        "warrant_sha256": warrant_sha256,
                        "approver_identity": actor,
                    },
                    now=now,
                )
                await self.store._enqueue_runtime_work_locked(
                    session,
                    incident_id=incident.id,
                    warrant_id=warrant_id,
                    kind=APPROVED_EXECUTION_WORK,
                    now=now,
                )
                await self.store._publish_locked(session, incident.id, now)
        result = await self.get_warrant(warrant_id)
        assert result is not None
        return result

    async def request_revision(
        self,
        *,
        warrant_id: str,
        warrant_sha256: str,
        guidance: UntrustedEvidenceEnvelope,
        actor: str,
    ) -> str:
        now = datetime.now(UTC)
        async with self.store.sessions() as session, session.begin():
            control = await session.scalar(
                select(ControlWarrantRecord)
                .where(ControlWarrantRecord.id == warrant_id)
                .with_for_update()
            )
            if control is None:
                raise LookupError(warrant_id)
            if control.status != "PENDING_APPROVAL":
                raise WarrantDecisionConflict(
                    "WARRANT_NOT_PENDING",
                    "warrant is not pending approval",
                )
            if not hmac.compare_digest(control.warrant_sha256, warrant_sha256):
                raise WarrantDecisionConflict(
                    "WARRANT_HASH_CHANGED",
                    "canonical warrant hash changed",
                )
            if now > aware_utc(control.expires_at):
                raise WarrantDecisionConflict("WARRANT_EXPIRED", "warrant is expired")
            incident = await session.scalar(
                select(IncidentRecord)
                .where(IncidentRecord.id == control.incident_id)
                .with_for_update()
            )
            if (
                incident is None
                or not incident.live_trial
                or incident.owner_subject != actor
                or guidance.incident_id != incident.id
            ):
                raise PermissionError("revision is not authorized for this live trial")
            evidence_id = guidance.evidence_id
            session.add(
                EvidenceRecord(
                    id=evidence_id,
                    incident_id=guidance.incident_id,
                    kind=guidance.kind.value,
                    provenance=guidance.provenance,
                    sanitized_text=guidance.text,
                    raw_sha256=guidance.raw_sha256,
                    sanitized_sha256=guidance.sanitized_sha256,
                    envelope_json=canonical_json(guidance),
                    tags=[tag.model_dump(mode="json") for tag in guidance.tags],
                    published=True,
                    created_at=now,
                )
            )
            control.status = "REJECTED"
            control.updated_at = now
            incident.pending_warrant_id = None
            await self.store._append_locked(
                session,
                incident,
                "REVISION_REQUESTED",
                actor,
                {
                    "warrant_id": warrant_id,
                    "warrant_sha256": warrant_sha256,
                    "evidence_id": evidence_id,
                },
                now=now,
            )
            await self.store._publish_locked(session, incident.id, now)
        return control.incident_id

    async def approved_warrant(self, incident_id: str, warrant_id: str) -> str | None:
        async with self.store.sessions() as session:
            record = await session.scalar(
                select(ControlWarrantRecord).where(
                    ControlWarrantRecord.id == warrant_id,
                    ControlWarrantRecord.incident_id == incident_id,
                    ControlWarrantRecord.status == "APPROVED",
                )
            )
            return None if record is None else record.approval_id


class PersistingAgentRuntime:
    """Persist citation-validated seat outputs and their visible state transitions."""

    def __init__(
        self,
        runtime: Any,
        store: RuntimeStore,
        *,
        citations: Any | None = None,
    ) -> None:
        self._runtime = runtime
        self._store = store
        self._citations = citations

    @staticmethod
    def _evidence_ids(output: SeatOutput) -> tuple[str, ...]:
        root = getattr(output, "root", None)
        if root is not None:
            return tuple(getattr(root, "evidence_ids", ()))
        return tuple(getattr(output, "evidence_ids", ()))

    async def _persist(
        self,
        *,
        incident_id: str,
        seat: Seat,
        effort: Effort,
        phase: str,
        output: SeatOutput,
    ) -> None:
        if self._citations is not None and seat is not Seat.BAILIFF:
            evidence_ids = self._evidence_ids(output)
            if not evidence_ids or not await self._citations.contains_all(
                incident_id, evidence_ids
            ):
                raise MissingEvidenceReference(
                    f"{seat.value} returned invalid evidence citations"
                )
        try:
            await self._store.record_seat_output(
                incident_id=incident_id,
                seat=seat,
                effort=effort,
                phase=phase,
                output=output,
                escalation_count=_SPEC_BY_SEAT[seat].effort_ladder.index(effort),
            )
        except (PatchFormatViolation, PathPolicyViolation) as error:
            # A model-proposed diff is structured output; malformed patch syntax is
            # an invalid schema result, never a generic SDK failure or a relaxation
            # of the broker's canonical-diff boundary.
            raise InvalidSchema(f"Counsel returned an invalid canonical diff: {error}") from error

    async def run_inspector_to_prosecutor(
        self,
        *,
        request: Any,
        inspector_effort: Effort,
        prosecutor_effort: Effort,
        validate_inspector: Any,
    ) -> InspectorProsecutorResult:
        await self._store.prepare_seat(request.incident_id, Seat.INSPECTOR, "mechanism-analysis")
        await self._store.prepare_seat(request.incident_id, Seat.PROSECUTOR, "hypothesis-challenge")
        result = await self._runtime.run_inspector_to_prosecutor(
            request=request,
            inspector_effort=inspector_effort,
            prosecutor_effort=prosecutor_effort,
            validate_inspector=validate_inspector,
        )
        if not isinstance(result, InspectorProsecutorResult):
            raise TypeError("agent runtime returned an invalid handoff result")
        await self._persist(
            incident_id=request.incident_id,
            seat=Seat.INSPECTOR,
            effort=inspector_effort,
            phase="mechanism-analysis",
            output=result.inspector,
        )
        await self._persist(
            incident_id=request.incident_id,
            seat=Seat.PROSECUTOR,
            effort=prosecutor_effort,
            phase="hypothesis-challenge",
            output=result.prosecutor,
        )
        return result

    async def run_seat(
        self,
        *,
        seat: Seat,
        effort: Effort,
        phase: str,
        request: Any,
    ) -> SeatOutput:
        await self._store.prepare_seat(request.incident_id, seat, phase)
        output = await self._runtime.run_seat(
            seat=seat,
            effort=effort,
            phase=phase,
            request=request,
        )
        if not isinstance(output, BaseModel):
            raise TypeError("agent runtime returned an unstructured output")
        await self._persist(
            incident_id=request.incident_id,
            seat=seat,
            effort=effort,
            phase=phase,
            output=output,
        )
        return output

    async def run_unpublished_retry(
        self,
        *,
        seat: Seat,
        effort: Effort,
        phase: str,
        request: Any,
    ) -> SeatOutput:
        """Run a retry without publishing it before semantic acceptance."""
        await self._store.prepare_seat(request.incident_id, seat, phase)
        output = await self._runtime.run_seat(
            seat=seat,
            effort=effort,
            phase=phase,
            request=request,
        )
        if not isinstance(output, BaseModel):
            raise TypeError("agent runtime returned an unstructured output")
        return output

    async def publish_accepted_retry(
        self,
        *,
        incident_id: str,
        seat: Seat,
        effort: Effort,
        phase: str,
        output: SeatOutput,
    ) -> None:
        await self._persist(
            incident_id=incident_id,
            seat=seat,
            effort=effort,
            phase=phase,
            output=output,
        )

    async def execute_approved_warrant(
        self,
        *,
        incident_id: str,
        warrant_id: str,
        approval_reference: str,
    ) -> BailiffOutput:
        await self._store.prepare_seat(incident_id, Seat.BAILIFF, "execute-approved")
        result = await self._runtime.execute_approved_warrant(
            incident_id=incident_id,
            warrant_id=warrant_id,
            approval_reference=approval_reference,
        )
        await self._persist(
            incident_id=incident_id,
            seat=Seat.BAILIFF,
            effort=Effort.NONE,
            phase="execute-approved",
            output=result,
        )
        return result
