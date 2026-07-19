"""Single-use deterministic mutation broker.

All approval, authority, catalog, patch, and deployment bindings are checked in
the store's atomic claim critical section.  Workspace creation and process
execution are impossible until that claim has committed.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

import anyio
from pydantic import BaseModel, ConfigDict

from crosspatch.broker.approval import ApprovalService, WarrantApproval
from crosspatch.broker.paths import (
    PatchFormatViolation,
    PathPolicyViolation,
    validate_declared_patch_paths,
)
from crosspatch.broker.warrant import (
    WARRANT_FORMAT,
    BoundExecutionPlan,
    WarrantDocument,
    WarrantIntegrityError,
    validate_warrant_integrity,
)
from crosspatch.domain.hashing import canonical_json
from crosspatch.runner.catalog import (
    CANDIDATE_PLAN_IDS,
    ExecutionCatalog,
    UnknownExecutionPlan,
)
from crosspatch.runner.results import ProcessReceipt
from crosspatch.runner.supervisor import is_trusted_process_supervisor


class BrokerStatus(StrEnum):
    EXECUTED = "EXECUTED"
    TEST_FAILED = "TEST_FAILED"
    TAMPER_REJECTED = "TAMPER_REJECTED"
    POLICY_REJECTED = "POLICY_REJECTED"
    EXPIRED = "EXPIRED"
    REPLAY_REJECTED = "REPLAY_REJECTED"
    INFRA_FAILED = "INFRA_FAILED"
    NOT_FOUND = "NOT_FOUND"


class WarrantState(StrEnum):
    APPROVED = "APPROVED"
    CONSUMING = "CONSUMING"
    CONSUMED = "CONSUMED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class BrokerResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    warrant_id: str
    status: BrokerStatus
    receipts: tuple[ProcessReceipt, ...] = ()
    error_code: str | None = None
    nonce_sha256: str | None = None


class AuthoritySnapshot(BaseModel):
    """Current DB-authoritative selection reviewed by the Magistrate."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    warrant_id: str
    incident_id: str
    repository_id: str
    verdict_id: str
    verdict_sha256: str
    candidate_id: str
    authority_snapshot_sha256: str
    reviewed_evidence_manifest_sha256: str
    reviewed_timeline_head: str
    base_sha: str
    repository_manifest_sha256: str
    patch_sha256: str
    allowed_paths: tuple[str, ...]
    test_plan_sha256: str
    repository_root: Path

    @classmethod
    def from_warrant(
        cls, document: WarrantDocument, *, repository_root: str | Path
    ) -> AuthoritySnapshot:
        return cls(
            warrant_id=document.warrant_id,
            incident_id=document.incident_id,
            repository_id=document.repository_id,
            verdict_id=document.verdict_id,
            verdict_sha256=document.verdict_sha256,
            candidate_id=document.candidate_id,
            authority_snapshot_sha256=document.authority_snapshot_sha256,
            reviewed_evidence_manifest_sha256=document.reviewed_evidence_manifest_sha256,
            reviewed_timeline_head=document.reviewed_timeline_head,
            base_sha=document.base_sha,
            repository_manifest_sha256=document.repository_manifest_sha256,
            patch_sha256=document.patch_sha256,
            allowed_paths=document.allowed_paths,
            test_plan_sha256=document.test_plan_sha256,
            repository_root=Path(repository_root).resolve(),
        )


class AuthorityProvider(Protocol):
    def read_for_claim(self, warrant_id: str) -> AuthoritySnapshot: ...


class WorktreeContext(Protocol):
    async def __aenter__(self) -> Path: ...

    async def __aexit__(self, exc_type, exc, traceback) -> None: ...


class WorktreeFactory(Protocol):
    def create(
        self, document: WarrantDocument, authority: AuthoritySnapshot
    ) -> WorktreeContext: ...


class ProcessRunner(Protocol):
    async def run(self, workspace: Path, plan) -> ProcessReceipt: ...


class TamperRejected(ValueError):
    pass


class PolicyRejected(ValueError):
    pass


class _StoredWarrant:
    __slots__ = ("approval", "document", "result", "state")

    def __init__(self, document: WarrantDocument, approval: WarrantApproval) -> None:
        self.document = document
        self.approval = approval
        self.state = WarrantState.APPROVED
        self.result: BrokerResult | None = None


class _ClaimedWarrant(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    document: WarrantDocument
    approval: WarrantApproval
    authority: AuthoritySnapshot


class _ClaimOutcome(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    claimed: _ClaimedWarrant | None = None
    rejection: BrokerStatus | None = None
    error_code: str | None = None


ClaimValidator = Callable[
    [WarrantDocument, WarrantApproval, datetime, AuthoritySnapshot], AuthoritySnapshot
]
AuthorityLoader = Callable[[str], AuthoritySnapshot]


class WarrantStore(Protocol):
    async def claim_warrant(
        self,
        warrant_id: str,
        validator: ClaimValidator,
        authority_loader: AuthorityLoader,
    ) -> _ClaimOutcome: ...

    async def finish(self, warrant_id: str, result: BrokerResult) -> None: ...


class InMemoryWarrantStore:
    """Lock-backed test/local store with the same one-way claim semantics as SQL."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = asyncio.Lock()
        self._records: dict[str, _StoredWarrant] = {}

    async def add_approved(self, document: WarrantDocument, approval: WarrantApproval) -> None:
        async with self._lock:
            if document.warrant_id in self._records:
                raise ValueError("warrant id already exists")
            self._records[document.warrant_id] = _StoredWarrant(document, approval)

    async def claim_warrant(
        self,
        warrant_id: str,
        validator: ClaimValidator,
        authority_loader: AuthorityLoader,
    ) -> _ClaimOutcome:
        async with self._lock:
            record = self._records.get(warrant_id)
            if record is None:
                return _ClaimOutcome(
                    rejection=BrokerStatus.NOT_FOUND, error_code="WARRANT_NOT_FOUND"
                )
            if record.state is not WarrantState.APPROVED:
                return _ClaimOutcome(
                    rejection=BrokerStatus.REPLAY_REJECTED,
                    error_code="WARRANT_ALREADY_CLAIMED",
                )
            now = self._clock()
            if now.tzinfo is None or now.utcoffset() is None:
                raise RuntimeError("broker database clock must be timezone-aware")
            now = now.astimezone(UTC)
            if now > record.document.expires_at.astimezone(UTC):
                record.state = WarrantState.EXPIRED
                return _ClaimOutcome(rejection=BrokerStatus.EXPIRED, error_code="WARRANT_EXPIRED")
            try:
                locked_authority = authority_loader(record.document.warrant_id)
                authority = validator(record.document, record.approval, now, locked_authority)
            except PolicyRejected as error:
                record.state = WarrantState.REJECTED
                return _ClaimOutcome(
                    rejection=BrokerStatus.POLICY_REJECTED,
                    error_code=str(error) or "PATCH_POLICY_REJECTED",
                )
            except (TamperRejected, ValueError) as error:
                record.state = WarrantState.REJECTED
                return _ClaimOutcome(
                    rejection=BrokerStatus.TAMPER_REJECTED,
                    error_code=str(error) or "WARRANT_TAMPER_REJECTED",
                )
            record.state = WarrantState.CONSUMING
            return _ClaimOutcome(
                claimed=_ClaimedWarrant(
                    document=record.document,
                    approval=record.approval,
                    authority=authority,
                )
            )

    async def finish(self, warrant_id: str, result: BrokerResult) -> None:
        async with self._lock:
            record = self._records[warrant_id]
            if record.state is not WarrantState.CONSUMING:
                raise RuntimeError("only a consuming warrant can finish")
            record.result = result
            record.state = WarrantState.CONSUMED

    async def unsafe_replace_for_test(
        self,
        warrant_id: str,
        *,
        document: WarrantDocument | None = None,
        approval: WarrantApproval | None = None,
    ) -> None:
        """Corrupt persisted fields for negative tests; never expose in an API."""
        async with self._lock:
            record = self._records[warrant_id]
            if document is not None:
                record.document = document
            if approval is not None:
                record.approval = approval


def _same(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


class Broker:
    _BROKER_EXECUTABLE_PLAN_IDS = CANDIDATE_PLAN_IDS

    def __init__(
        self,
        *,
        store: WarrantStore,
        approvals: ApprovalService,
        authority: AuthorityProvider,
        worktrees: WorktreeFactory,
        process_runner: ProcessRunner,
        catalog: ExecutionCatalog,
        runner_digest: str,
        environment_digest: str,
    ) -> None:
        self._store = store
        self._approvals = approvals
        self._authority = authority
        self._worktrees = worktrees
        self._process_runner = process_runner
        self._catalog = catalog
        self._runner_digest = runner_digest
        self._environment_digest = environment_digest
        if not is_trusted_process_supervisor(process_runner):
            raise ValueError("mutation broker requires a trusted process supervisor")

    def _validate_claim(
        self,
        document: WarrantDocument,
        approval: WarrantApproval,
        now: datetime,
        authority: AuthoritySnapshot,
    ) -> AuthoritySnapshot:
        try:
            validate_warrant_integrity(document)
        except WarrantIntegrityError as error:
            raise TamperRejected("WARRANT_DERIVED_BINDING_CHANGED") from error
        if document.format != WARRANT_FORMAT:
            raise TamperRejected("WARRANT_FORMAT_CHANGED")
        if document.issued_at.astimezone(UTC) > now:
            raise TamperRejected("WARRANT_ISSUED_IN_FUTURE")
        if approval.approved_at.astimezone(UTC) > now:
            raise TamperRejected("APPROVAL_TIMESTAMP_IN_FUTURE")
        if approval.approved_at < document.issued_at or approval.approved_at > document.expires_at:
            raise TamperRejected("APPROVAL_TIMESTAMP_OUTSIDE_WARRANT_WINDOW")
        if not self._approvals.verify(document, approval):
            raise TamperRejected("APPROVAL_MAC_OR_CANONICAL_BYTES_CHANGED")

        bound_pairs = (
            (document.warrant_id, authority.warrant_id),
            (document.incident_id, authority.incident_id),
            (document.repository_id, authority.repository_id),
            (document.verdict_id, authority.verdict_id),
            (document.verdict_sha256, authority.verdict_sha256),
            (document.candidate_id, authority.candidate_id),
            (document.authority_snapshot_sha256, authority.authority_snapshot_sha256),
            (
                document.reviewed_evidence_manifest_sha256,
                authority.reviewed_evidence_manifest_sha256,
            ),
            (document.reviewed_timeline_head, authority.reviewed_timeline_head),
            (document.base_sha, authority.base_sha),
            (document.repository_manifest_sha256, authority.repository_manifest_sha256),
            (document.patch_sha256, authority.patch_sha256),
            (document.test_plan_sha256, authority.test_plan_sha256),
        )
        if not all(_same(left, right) for left, right in bound_pairs):
            raise TamperRejected("CURRENT_AUTHORITY_SNAPSHOT_CHANGED")
        if not hmac.compare_digest(
            canonical_json(document.allowed_paths), canonical_json(authority.allowed_paths)
        ):
            raise TamperRejected("CURRENT_ALLOWED_PATHS_CHANGED")
        if not _same(document.runner_digest, self._runner_digest):
            raise TamperRejected("RUNNER_DIGEST_CHANGED")
        if not _same(document.environment_digest, self._environment_digest):
            raise TamperRejected("ENVIRONMENT_DIGEST_CHANGED")

        try:
            for bound in document.execution_plans:
                if bound.plan_id not in self._BROKER_EXECUTABLE_PLAN_IDS:
                    raise TamperRejected("PLAN_NOT_BROKER_EXECUTABLE")
                expected = BoundExecutionPlan.from_execution_plan(
                    self._catalog.resolve(bound.plan_id)
                )
                if not hmac.compare_digest(canonical_json(bound), canonical_json(expected)):
                    raise TamperRejected("RESOLVED_EXECUTION_PLAN_CHANGED")
        except UnknownExecutionPlan as error:
            raise TamperRejected("UNKNOWN_EXECUTION_PLAN") from error

        try:
            validate_declared_patch_paths(
                authority.repository_root,
                document.patch_bytes,
                document.allowed_paths,
            )
        except (PatchFormatViolation, PathPolicyViolation) as error:
            raise PolicyRejected("PATCH_POLICY_REJECTED") from error
        return authority

    async def execute_warrant(self, warrant_id: str) -> BrokerResult:
        """Claim once, then create a snapshot and run only catalog-owned argv."""
        outcome = await self._store.claim_warrant(
            warrant_id,
            self._validate_claim,
            self._authority.read_for_claim,
        )
        if outcome.claimed is None:
            assert outcome.rejection is not None
            return BrokerResult(
                warrant_id=warrant_id,
                status=outcome.rejection,
                error_code=outcome.error_code,
            )

        document = outcome.claimed.document
        nonce_sha256 = hashlib.sha256(document.nonce.encode("utf-8")).hexdigest()
        receipts: list[ProcessReceipt] = []
        try:
            async with self._worktrees.create(document, outcome.claimed.authority) as workspace:
                for bound in document.execution_plans:
                    plan = self._catalog.resolve(bound.plan_id)
                    receipt = await self._process_runner.run(workspace, plan)
                    receipts.append(receipt)
                    if not receipt.passed:
                        result = BrokerResult(
                            warrant_id=warrant_id,
                            status=BrokerStatus.TEST_FAILED,
                            receipts=tuple(receipts),
                            error_code="FIXED_TEST_PLAN_FAILED",
                            nonce_sha256=nonce_sha256,
                        )
                        break
                else:
                    result = BrokerResult(
                        warrant_id=warrant_id,
                        status=BrokerStatus.EXECUTED,
                        receipts=tuple(receipts),
                        nonce_sha256=nonce_sha256,
                    )
        except BaseException as error:
            if isinstance(error, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
                # Consumption is still finalized before cancellation is propagated.
                result = BrokerResult(
                    warrant_id=warrant_id,
                    status=BrokerStatus.INFRA_FAILED,
                    receipts=tuple(receipts),
                    error_code="BROKER_CANCELLED_AFTER_CLAIM",
                    nonce_sha256=nonce_sha256,
                )
                # Streamable HTTP servers execute inside an AnyIO cancel scope.
                # Once authority is consumed, durable finalization must survive
                # transport cancellation and complete before it propagates.
                with anyio.CancelScope(shield=True):
                    await self._store.finish(warrant_id, result)
                raise
            result = BrokerResult(
                warrant_id=warrant_id,
                status=BrokerStatus.INFRA_FAILED,
                receipts=tuple(receipts),
                error_code="WORKTREE_OR_RUNNER_FAILURE",
                nonce_sha256=nonce_sha256,
            )
        await self._store.finish(warrant_id, result)
        return result
