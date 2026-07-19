from __future__ import annotations

import asyncio
import base64
import hashlib
import os
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
import pytest
from crosspatch.broker.approval import ApprovalService
from crosspatch.broker.broker import (
    AuthoritySnapshot,
    Broker,
    BrokerStatus,
    InMemoryWarrantStore,
    WarrantState,
)
from crosspatch.broker.warrant import BoundExecutionPlan, WarrantDocument
from crosspatch.domain.hashing import sha256_hex
from crosspatch.runner.catalog import ExecutionCatalog, OracleProfile
from crosspatch.runner.results import ProcessReceipt
from crosspatch.runner.supervisor import TrustedProcessSupervisor

PATCH = b"""diff --git a/victim/src/victim/db.py b/victim/src/victim/db.py
index 1111111..2222222 100644
--- a/victim/src/victim/db.py
+++ b/victim/src/victim/db.py
@@ -1 +1 @@
-vulnerable = True
+vulnerable = False
"""


def _bound_plan(
    plan_id: str = "victim.duplicate-race.candidate",
) -> BoundExecutionPlan:
    return BoundExecutionPlan.from_execution_plan(
        ExecutionCatalog.default().resolve(plan_id)
    )


def _document(
    patch: bytes = PATCH,
    *,
    plan_id: str = "victim.duplicate-race.candidate",
    **updates: Any,
) -> WarrantDocument:
    plan = _bound_plan(plan_id)
    issued = datetime(2026, 7, 14, 2, tzinfo=UTC)
    values: dict[str, Any] = {
        "format": "crosspatch-warrant-v1",
        "warrant_id": "war_01",
        "incident_id": "inc_01",
        "repository_id": "repo_01",
        "verdict_id": "ver_01",
        "verdict_sha256": "1" * 64,
        "candidate_id": "cand_01",
        "authority_snapshot_sha256": "2" * 64,
        "reviewed_evidence_manifest_sha256": "3" * 64,
        "reviewed_timeline_head": "4" * 64,
        "base_sha": "5" * 40,
        "repository_manifest_sha256": "6" * 64,
        "patch_b64": base64.b64encode(patch).decode("ascii"),
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "allowed_paths": ("victim/src/victim/db.py",),
        "execution_plans": (plan,),
        "test_plan_sha256": sha256_hex((plan,)),
        "runner_digest": "7" * 64,
        "environment_digest": "8" * 64,
        "approver_identity": "approver-1",
        "issued_at": issued,
        "expires_at": issued + timedelta(minutes=15),
        "approval_mac_key_id": "approval-v1",
        "nonce": "nonce_01",
    }
    values.update(updates)
    return WarrantDocument(**values)


class StaticAuthority:
    def __init__(self, snapshot: AuthoritySnapshot) -> None:
        self.snapshot = snapshot

    def read_for_claim(self, warrant_id: str) -> AuthoritySnapshot:
        assert warrant_id
        return self.snapshot


class WorktreeSpy:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls = 0

    @asynccontextmanager
    async def create(self, document: WarrantDocument, authority: AuthoritySnapshot):
        self.calls += 1
        assert document.repository_id == authority.repository_id
        yield self.root


class _IsolatedTestExecutor:
    candidate_uid = 10002
    pid_namespace_isolated = True
    workspace_read_only = True
    context_capability_absent = True
    external_receipt_authority = True


class _UnusedTestVerifier:
    pass


class RunnerSpy(TrustedProcessSupervisor):

    def __init__(self, *, exit_code: int = 0, hold: asyncio.Event | None = None) -> None:
        super().__init__(
            executor=_IsolatedTestExecutor(),  # type: ignore[arg-type]
            verifier=_UnusedTestVerifier(),  # type: ignore[arg-type]
            supervisor_uid=os.geteuid(),
        )
        self.exit_code = exit_code
        self.hold = hold
        self.calls = 0

    async def run(self, workspace: Path, plan) -> ProcessReceipt:
        self.calls += 1
        if self.hold is not None:
            await self.hold.wait()
        return ProcessReceipt.for_test(plan=plan, exit_code=self.exit_code)


class ForgedTrustedMarker:
    trusted_supervisor = True


def _authority(root: Path, document: WarrantDocument) -> AuthoritySnapshot:
    return AuthoritySnapshot.from_warrant(document, repository_root=root)


async def _harness(
    tmp_path: Path,
    *,
    document: WarrantDocument | None = None,
    runner: RunnerSpy | None = None,
    clock: Callable[[], datetime] | None = None,
):
    document = document or _document()
    target = tmp_path / "victim/src/victim/db.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("vulnerable = True\n", encoding="utf-8")
    approval_service = ApprovalService(keys={"approval-v1": b"k" * 32})
    approval = approval_service.approve(
        document, approved_at=datetime(2026, 7, 14, 2, 1, tzinfo=UTC)
    )
    store = InMemoryWarrantStore(clock=clock or (lambda: datetime(2026, 7, 14, 2, 2, tzinfo=UTC)))
    await store.add_approved(document, approval)
    worktrees = WorktreeSpy(tmp_path)
    runner = runner or RunnerSpy()
    authority = StaticAuthority(_authority(tmp_path, document))
    broker = Broker(
        store=store,
        approvals=approval_service,
        authority=authority,
        worktrees=worktrees,
        process_runner=runner,
        catalog=ExecutionCatalog.default(),
        runner_digest="7" * 64,
        environment_digest="8" * 64,
    )
    return broker, store, approval, authority, worktrees, runner


def _change(document: WarrantDocument, field: str, value: Any) -> WarrantDocument:
    return document.model_copy(update={field: value})


def _tamper_patch_bytes(document: WarrantDocument) -> WarrantDocument:
    altered = PATCH.replace(b"False", b"None ")
    return document.model_copy(
        update={
            "patch_b64": base64.b64encode(altered).decode("ascii"),
            "patch_sha256": hashlib.sha256(altered).hexdigest(),
        }
    )


def _tamper_plan(document: WarrantDocument, field: str, value: Any) -> WarrantDocument:
    plan = document.execution_plans[0].model_copy(update={field: value})
    plans = (plan,)
    return document.model_copy(
        update={"execution_plans": plans, "test_plan_sha256": sha256_hex(plans)}
    )


DOCUMENT_TAMPERS: list[tuple[str, Callable[[WarrantDocument], WarrantDocument]]] = [
    ("format-version", lambda d: _change(d, "format", "crosspatch-warrant-v2")),
    ("warrant-id", lambda d: _change(d, "warrant_id", "war_other")),
    ("incident-id", lambda d: _change(d, "incident_id", "inc_other")),
    ("repository-id", lambda d: _change(d, "repository_id", "repo_other")),
    ("verdict-id", lambda d: _change(d, "verdict_id", "ver_other")),
    ("verdict-hash", lambda d: _change(d, "verdict_sha256", "a" * 64)),
    ("candidate-id", lambda d: _change(d, "candidate_id", "cand_other")),
    ("authority-snapshot", lambda d: _change(d, "authority_snapshot_sha256", "a" * 64)),
    (
        "evidence-manifest",
        lambda d: _change(d, "reviewed_evidence_manifest_sha256", "a" * 64),
    ),
    ("timeline-head", lambda d: _change(d, "reviewed_timeline_head", "a" * 64)),
    ("base-sha", lambda d: _change(d, "base_sha", "a" * 40)),
    ("repository-manifest", lambda d: _change(d, "repository_manifest_sha256", "a" * 64)),
    ("actual-patch-bytes", _tamper_patch_bytes),
    ("patch-hash", lambda d: _change(d, "patch_sha256", "a" * 64)),
    ("allowed-paths", lambda d: _change(d, "allowed_paths", ("victim/src/victim/web.py",))),
    ("plan-id", lambda d: _tamper_plan(d, "plan_id", "victim.single-delivery")),
    ("resolved-argv", lambda d: _tamper_plan(d, "argv", ("/bin/sh", "-c", "id"))),
    ("working-directory", lambda d: _tamper_plan(d, "working_directory", "/tmp")),
    ("timeout", lambda d: _tamper_plan(d, "timeout_seconds", 899)),
    (
        "oracle-profile",
        lambda d: _tamper_plan(d, "oracle_profile", OracleProfile.PAYLOAD_EQUIVALENCE),
    ),
    ("expected-statuses", lambda d: _tamper_plan(d, "expected_statuses", (202, 409, 409))),
    ("plan-digest", lambda d: _tamper_plan(d, "plan_sha256", "a" * 64)),
    ("test-plan", lambda d: _change(d, "test_plan_sha256", "a" * 64)),
    ("expiry", lambda d: _change(d, "expires_at", d.expires_at + timedelta(minutes=1))),
    ("approver", lambda d: _change(d, "approver_identity", "other-approver")),
    ("issued-at", lambda d: _change(d, "issued_at", d.issued_at + timedelta(seconds=1))),
    ("mac-key-id", lambda d: _change(d, "approval_mac_key_id", "other-key")),
    ("nonce", lambda d: _change(d, "nonce", "nonce_other")),
    ("runner-digest", lambda d: _change(d, "runner_digest", "a" * 64)),
    ("environment-digest", lambda d: _change(d, "environment_digest", "a" * 64)),
]


def test_broker_rejects_an_object_that_only_claims_to_be_trusted() -> None:
    with pytest.raises(ValueError, match="trusted process supervisor"):
        Broker(
            store=None,  # type: ignore[arg-type]
            approvals=None,  # type: ignore[arg-type]
            authority=None,  # type: ignore[arg-type]
            worktrees=None,  # type: ignore[arg-type]
            process_runner=ForgedTrustedMarker(),  # type: ignore[arg-type]
            catalog=ExecutionCatalog.default(),
            runner_digest="7" * 64,
            environment_digest="8" * 64,
        )


@pytest.mark.asyncio
@pytest.mark.adversarial_eval_broker_tamper
@pytest.mark.parametrize(
    "name,tamper", DOCUMENT_TAMPERS, ids=[item[0] for item in DOCUMENT_TAMPERS]
)
async def test_every_bound_field_and_actual_patch_tamper_rejects_before_side_effects(
    tmp_path: Path,
    name: str,
    tamper: Callable[[WarrantDocument], WarrantDocument],
):
    del name
    original = _document()
    broker, store, _approval, _authority_provider, worktrees, runner = await _harness(
        tmp_path, document=original
    )
    await store.unsafe_replace_for_test(original.warrant_id, document=tamper(original))

    result = await broker.execute_warrant(original.warrant_id)

    assert result.status is BrokerStatus.TAMPER_REJECTED
    assert worktrees.calls == 0
    assert runner.calls == 0


@pytest.mark.asyncio
@pytest.mark.adversarial_eval_broker_tamper
@pytest.mark.parametrize(
    "field,value",
    [
        ("oracle_profile", OracleProfile.DUPLICATE_RACE),
        ("expected_statuses", (202, 409, 409)),
    ],
)
async def test_approved_self_consistent_oracle_plan_drift_rejects_before_side_effects(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    catalog_plan = ExecutionCatalog.default().resolve(
        "victim.payload-equivalence.candidate"
    )
    changed_plan = replace(catalog_plan, **{field: value})
    changed_bound = BoundExecutionPlan.from_execution_plan(changed_plan)
    document = _document(
        plan_id="victim.payload-equivalence.candidate",
        execution_plans=(changed_bound,),
        test_plan_sha256=sha256_hex((changed_bound,)),
    )
    broker, _store, _approval, _authority, worktrees, runner = await _harness(
        tmp_path,
        document=document,
    )

    result = await broker.execute_warrant(document.warrant_id)

    assert result.status is BrokerStatus.TAMPER_REJECTED
    assert result.error_code == "RESOLVED_EXECUTION_PLAN_CHANGED"
    assert worktrees.calls == 0
    assert runner.calls == 0


@pytest.mark.asyncio
async def test_payload_equivalence_candidate_is_broker_executable_when_exactly_bound(
    tmp_path: Path,
) -> None:
    document = _document(plan_id="victim.payload-equivalence.candidate")
    broker, _store, _approval, _authority, worktrees, runner = await _harness(
        tmp_path,
        document=document,
    )

    result = await broker.execute_warrant(document.warrant_id)

    assert result.status is BrokerStatus.EXECUTED
    assert result.receipts[0].plan_id == "victim.payload-equivalence.candidate"
    assert worktrees.calls == runner.calls == 1


@pytest.mark.asyncio
@pytest.mark.adversarial_eval_broker_tamper
async def test_approval_mac_tamper_rejects_before_side_effects(tmp_path: Path):
    document = _document()
    broker, store, approval, _authority_provider, worktrees, runner = await _harness(
        tmp_path, document=document
    )
    tampered = approval.model_copy(update={"mac_sha256": "a" * 64})
    await store.unsafe_replace_for_test(document.warrant_id, approval=tampered)

    result = await broker.execute_warrant(document.warrant_id)

    assert result.status is BrokerStatus.TAMPER_REJECTED
    assert worktrees.calls == runner.calls == 0


@pytest.mark.asyncio
@pytest.mark.adversarial_eval_broker_tamper
async def test_changed_authority_snapshot_after_clear_rejects_before_side_effects(tmp_path: Path):
    document = _document()
    broker, _store, _approval, authority, worktrees, runner = await _harness(
        tmp_path, document=document
    )
    authority.snapshot = authority.snapshot.model_copy(update={"candidate_id": "cand_other"})

    result = await broker.execute_warrant(document.warrant_id)

    assert result.status is BrokerStatus.TAMPER_REJECTED
    assert worktrees.calls == runner.calls == 0


@pytest.mark.asyncio
@pytest.mark.adversarial_eval_broker_reuse
async def test_concurrent_execution_consumes_nonce_once_and_failure_stays_consumed(tmp_path: Path):
    release = asyncio.Event()
    runner = RunnerSpy(exit_code=1, hold=release)
    document = _document()
    broker, _store, _approval, _authority, worktrees, _runner = await _harness(
        tmp_path, document=document, runner=runner
    )

    first = asyncio.create_task(broker.execute_warrant(document.warrant_id))
    while worktrees.calls == 0:
        await asyncio.sleep(0)
    second = await broker.execute_warrant(document.warrant_id)
    release.set()
    first_result = await first
    third = await broker.execute_warrant(document.warrant_id)

    assert first_result.status is BrokerStatus.TEST_FAILED
    assert second.status is BrokerStatus.REPLAY_REJECTED
    assert third.status is BrokerStatus.REPLAY_REJECTED
    assert runner.calls == 1


@pytest.mark.asyncio
async def test_anyio_cancellation_after_claim_is_finalized_before_propagation(
    tmp_path: Path,
) -> None:
    hold = asyncio.Event()
    runner = RunnerSpy(hold=hold)
    document = _document()
    broker, store, _approval, _authority, worktrees, _runner = await _harness(
        tmp_path,
        document=document,
        runner=runner,
    )
    original_finish = store.finish

    async def checkpointing_finish(warrant_id, result) -> None:
        # PostgreSQL completion necessarily crosses an async I/O checkpoint.
        await anyio.sleep(0)
        await original_finish(warrant_id, result)

    store.finish = checkpointing_finish  # type: ignore[method-assign]
    scope_ready = asyncio.Event()
    scope_holder: list[anyio.CancelScope] = []

    async def execute_in_transport_scope() -> None:
        with anyio.CancelScope() as scope:
            scope_holder.append(scope)
            scope_ready.set()
            await broker.execute_warrant(document.warrant_id)

    task = asyncio.create_task(execute_in_transport_scope())
    await scope_ready.wait()
    while worktrees.calls == 0:
        await asyncio.sleep(0)
    scope_holder[0].cancel()
    await task

    record = store._records[document.warrant_id]
    assert record.state is WarrantState.CONSUMED
    assert record.result is not None
    assert record.result.status is BrokerStatus.INFRA_FAILED
    assert record.result.error_code == "BROKER_CANCELLED_AFTER_CLAIM"


@pytest.mark.asyncio
@pytest.mark.adversarial_eval_broker_expiry
async def test_claim_time_expiry_rejects_without_worktree_or_process(tmp_path: Path):
    document = _document()
    broker, _store, _approval, _authority, worktrees, runner = await _harness(
        tmp_path,
        document=document,
        clock=lambda: document.expires_at + timedelta(microseconds=1),
    )

    result = await broker.execute_warrant(document.warrant_id)

    assert result.status is BrokerStatus.EXPIRED
    assert worktrees.calls == runner.calls == 0


@pytest.mark.asyncio
async def test_success_runs_only_the_catalog_bound_plan(tmp_path: Path):
    document = _document()
    broker, _store, _approval, _authority, worktrees, runner = await _harness(
        tmp_path, document=document
    )

    result = await broker.execute_warrant(document.warrant_id)

    assert result.status is BrokerStatus.EXECUTED
    assert result.nonce_sha256 == hashlib.sha256(document.nonce.encode()).hexdigest()
    assert worktrees.calls == runner.calls == 1
    assert result.receipts[0].plan_id == "victim.duplicate-race.candidate"


HOSTILE_PATCH = b"""diff --git a/victim/src/victim/db.py b/victim/src/victim/db.py
index 1111111..2222222 100644
--- a/victim/src/victim/db.py
+++ b/victim/src/victim/db.py
@@ -1 +1 @@
-vulnerable = True
+vulnerable = False
diff --git a/compose.yaml b/compose.yaml
index 1111111..2222222 100644
--- a/compose.yaml
+++ b/compose.yaml
@@ -1 +1 @@
-safe: true
+safe: false
"""


@pytest.mark.asyncio
async def test_approved_hostile_patch_is_policy_rejected_before_worktree(tmp_path: Path):
    document = _document(
        patch=HOSTILE_PATCH,
        allowed_paths=("compose.yaml", "victim/src/victim/db.py"),
    )
    broker, _store, _approval, _authority, worktrees, runner = await _harness(
        tmp_path, document=document
    )

    result = await broker.execute_warrant(document.warrant_id)

    assert result.status is BrokerStatus.POLICY_REJECTED
    assert worktrees.calls == runner.calls == 0
