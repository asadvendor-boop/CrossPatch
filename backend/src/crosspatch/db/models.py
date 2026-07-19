"""Core append-only incident persistence models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from crosspatch.db.base import Base
from crosspatch.domain.enums import IncidentState


class IncidentRecord(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    scenario: Mapped[str] = mapped_column(String(128), nullable=False, default="webhook-race")
    live_trial: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    owner_subject: Mapped[str | None] = mapped_column(String(128), nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default=IncidentState.OPEN.value)
    base_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    repository_manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    catalog_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pending_warrant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    next_event_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    event_chain_head: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    events: Mapped[list[TimelineEventRecord]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="TimelineEventRecord.sequence",
    )


class TimelineEventRecord(Base):
    __tablename__ = "timeline_events"
    __table_args__ = (
        UniqueConstraint("incident_id", "sequence", name="uq_incident_event_sequence"),
        Index("ix_timeline_events_incident_sequence", "incident_id", "sequence"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    incident: Mapped[IncidentRecord] = relationship(back_populates="events")


class MutationAuthorityRecord(Base):
    """The current, transaction-lockable selection/evidence authority snapshot."""

    __tablename__ = "mutation_authority"

    incident_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    snapshot_json: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class WarrantRecord(Base):
    """Canonical approval bytes and their irreversible single-use state."""

    __tablename__ = "mutation_warrants"
    __table_args__ = (
        UniqueConstraint("nonce_sha256", name="uq_mutation_warrant_nonce"),
        CheckConstraint(
            "state IN ('APPROVED','CONSUMING','CONSUMED','REJECTED','EXPIRED')",
            name="ck_mutation_warrant_state",
        ),
        Index("ix_mutation_warrants_incident_state", "incident_id", "state"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    document_json: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    approval_json: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    nonce_consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result_json: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EvidenceRecord(Base):
    """Private evidence metadata plus the sanitized model-visible envelope."""

    __tablename__ = "evidence"
    __table_args__ = (Index("ix_evidence_incident_created", "incident_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance: Mapped[str] = mapped_column(String(512), nullable=False)
    sanitized_text: Mapped[str] = mapped_column(Text, nullable=False)
    raw_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sanitized_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    envelope_json: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    tags: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AgentRunRecord(Base):
    """Durable structured output and exact model policy for one seat run."""

    __tablename__ = "agent_runs"
    __table_args__ = (Index("ix_agent_runs_incident_created", "incident_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False
    )
    seat: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(64), nullable=False)
    effort: Mapped[str] = mapped_column(String(16), nullable=False)
    phase: Mapped[str] = mapped_column(String(64), nullable=False)
    escalation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_json: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    output_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    semantic_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    response_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    trace_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    schema_status: Mapped[str] = mapped_column(String(32), nullable=False, default="VALID")
    failure_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PatchCandidateRecord(Base):
    __tablename__ = "patch_candidates"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False
    )
    agent_run_id: Mapped[str] = mapped_column(
        ForeignKey("agent_runs.id", ondelete="RESTRICT"), nullable=False
    )
    patch_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    normalized_diff: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    test_intentions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    predecessor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class VerdictRecord(Base):
    __tablename__ = "verdicts"
    __table_args__ = (Index("ix_verdicts_incident_created", "incident_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False
    )
    agent_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("agent_runs.id", ondelete="RESTRICT"), nullable=True
    )
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    output_json: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    verdict_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ControlWarrantRecord(Base):
    """Human-review state; broker authority is materialized only after approval."""

    __tablename__ = "control_warrants"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING_APPROVAL','APPROVED','REJECTED','EXPIRED')",
            name="ck_control_warrant_status",
        ),
        Index("ix_control_warrants_incident_status", "incident_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False
    )
    canonical_document: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    warrant_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    authority_json: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    approval_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ApiPrincipalRecord(Base):
    """Configured API bearer identity; bearer material is never stored."""

    __tablename__ = "api_principals"

    subject: Mapped[str] = mapped_column(String(128), primary_key=True)
    bearer_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    csrf_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    step_up_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    step_up_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ApiIncidentGrantRecord(Base):
    __tablename__ = "api_incident_grants"
    __table_args__ = (UniqueConstraint("subject", "incident_id", name="uq_api_subject_incident"),)

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    subject: Mapped[str] = mapped_column(
        ForeignKey("api_principals.subject", ondelete="RESTRICT"), nullable=False
    )
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LiveTrialCredentialRecord(Base):
    """Rate state for one digest-only live-trial API principal."""

    __tablename__ = "live_trial_credentials"

    subject: Mapped[str] = mapped_column(
        ForeignKey("api_principals.subject", ondelete="RESTRICT"), primary_key=True
    )
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    rate_window_started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    rate_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LiveTrialBudgetRecord(Base):
    """Singleton hard ceiling shared by every live-trial credential."""

    __tablename__ = "live_trial_budget"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cap_microusd: Mapped[int] = mapped_column(Integer, nullable=False)
    spent_microusd: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reserved_microusd: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LiveTrialReservationRecord(Base):
    __tablename__ = "live_trial_reservations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('RESERVED','SETTLED')",
            name="ck_live_trial_reservation_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    subject: Mapped[str] = mapped_column(
        ForeignKey("live_trial_credentials.subject", ondelete="RESTRICT"), nullable=False
    )
    incident_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    reserved_microusd: Mapped[int] = mapped_column(Integer, nullable=False)
    actual_microusd: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class JudgeTokenRecord(Base):
    """Shared revocation registry containing only bearer digests."""

    __tablename__ = "judge_tokens"

    token_sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    jti: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class JudgeTokenAuditRecord(Base):
    """Append-only actor attribution for judge-token issuance and revocation."""

    __tablename__ = "judge_token_audit_events"
    __table_args__ = (
        CheckConstraint(
            "action IN ('ISSUED','REVOKED')",
            name="ck_judge_token_audit_action",
        ),
        Index("ix_judge_token_audit_token_created", "token_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    token_id: Mapped[str] = mapped_column(
        ForeignKey("judge_tokens.jti", ondelete="RESTRICT"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PublishedCaseRecord(Base):
    """Transactionally replaced sanitized projection consumed by judge MCP only."""

    __tablename__ = "published_cases"

    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), primary_key=True
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    projection: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TestRunRecord(Base):
    __tablename__ = "test_runs"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False
    )
    plan_id: Mapped[str] = mapped_column(String(128), nullable=False)
    plan_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RuntimeWorkRecord(Base):
    """Durable control-plane work; in-memory tasks are only delivery attempts."""

    __tablename__ = "runtime_work"
    __table_args__ = (
        UniqueConstraint("kind", "warrant_id", name="uq_runtime_work_kind_warrant"),
        CheckConstraint(
            "kind IN ('APPROVED_EXECUTION','TEST_REPAIR')",
            name="ck_runtime_work_kind",
        ),
        CheckConstraint(
            "status IN ('PENDING','RUNNING','COMPLETED')",
            name="ck_runtime_work_status",
        ),
        Index("ix_runtime_work_status_created", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(160), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False
    )
    warrant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    owner_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
