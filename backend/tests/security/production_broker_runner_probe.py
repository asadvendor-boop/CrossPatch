"""Executable production probe for Broker -> worktree -> trusted runner.

This file intentionally uses only runtime dependencies so it can run inside
the hardened broker-mcp image without installing pytest.
"""

from __future__ import annotations

import asyncio
import base64
import difflib
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from crosspatch.broker.approval import ApprovalService
from crosspatch.broker.broker import (
    AuthoritySnapshot,
    Broker,
    BrokerStatus,
    InMemoryWarrantStore,
)
from crosspatch.broker.warrant import BoundExecutionPlan, WarrantDocument
from crosspatch.domain.hashing import sha256_hex
from crosspatch.runner.catalog import ExecutionCatalog
from crosspatch.runner.runner_service import build_runner_service_client_from_environment
from crosspatch.runner.worktree import EphemeralWorktreeFactory, repository_manifest_sha256

_RELATIVE_PATH = "victim/src/victim/db.py"
_OLD = '''            existing = connection.execute(
                """
                SELECT payload_sha256
                  FROM webhook_receipts
                 WHERE provider = %s AND event_id = %s
                """,
                (event.provider, event.event_id),
            ).fetchone()
            if existing is not None:
                if existing["payload_sha256"].strip() != event.payload_sha256:
                    return IngestDisposition.PAYLOAD_MISMATCH
                return IngestDisposition.DUPLICATE

            # Deliberately vulnerable ordering: two transactions can both pass
            # the check and enqueue work before either publishes its receipt.
'''
_NEW = '''            inserted = connection.execute(
                """
                INSERT INTO webhook_receipts (provider, event_id, payload_sha256)
                VALUES (%s, %s, %s)
                ON CONFLICT (provider, event_id) DO NOTHING
                RETURNING payload_sha256
                """,
                (event.provider, event.event_id, event.payload_sha256),
            ).fetchone()
            if inserted is None:
                existing = connection.execute(
                    """
                    SELECT payload_sha256
                      FROM webhook_receipts
                     WHERE provider = %s AND event_id = %s
                    """,
                    (event.provider, event.event_id),
                ).fetchone()
                if existing is None:
                    raise RuntimeError("conflicting webhook receipt disappeared")
                if existing["payload_sha256"].strip() != event.payload_sha256:
                    return IngestDisposition.PAYLOAD_MISMATCH
                return IngestDisposition.DUPLICATE

            # Receipt ownership precedes the one allowed outbox insert.
'''
_OLD_RECEIPT = '''            connection.execute(
                """
                INSERT INTO webhook_receipts (provider, event_id, payload_sha256)
                VALUES (%s, %s, %s)
                ON CONFLICT (provider, event_id) DO NOTHING
                """,
                (event.provider, event.event_id, event.payload_sha256),
            )
'''


class _StaticAuthority:
    def __init__(self, snapshot: AuthoritySnapshot) -> None:
        self._snapshot = snapshot

    def read_for_claim(self, warrant_id: str) -> AuthoritySnapshot:
        if warrant_id != self._snapshot.warrant_id:
            raise LookupError(warrant_id)
        return self._snapshot


def _git(repository: Path, *args: str, input_bytes: bytes | None = None) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repository), *args],
        input=input_bytes,
        check=True,
        capture_output=True,
    ).stdout.decode("ascii").strip()


def _patch(repository: Path) -> bytes:
    baseline = (repository / _RELATIVE_PATH).read_text(encoding="utf-8")
    if baseline.count(_OLD) != 1 or baseline.count(_OLD_RECEIPT) != 1:
        raise RuntimeError("production probe baseline no longer matches the approved fixture")
    candidate = baseline.replace(_OLD, _NEW).replace(_OLD_RECEIPT, "")
    old_blob = _git(repository, "hash-object", "--stdin", input_bytes=baseline.encode())
    new_blob = _git(repository, "hash-object", "--stdin", input_bytes=candidate.encode())
    body = "".join(
        difflib.unified_diff(
            baseline.splitlines(keepends=True),
            candidate.splitlines(keepends=True),
            fromfile=f"a/{_RELATIVE_PATH}",
            tofile=f"b/{_RELATIVE_PATH}",
        )
    )
    patch = (
        f"diff --git a/{_RELATIVE_PATH} b/{_RELATIVE_PATH}\n"
        f"index {old_blob[:12]}..{new_blob[:12]} 100644\n"
        f"{body}"
    ).encode()
    if not patch.endswith(b"\n"):
        patch += b"\n"
    return patch


async def _run() -> dict[str, object]:
    repository = Path(os.environ.get("CROSSPATCH_REPOSITORY_ROOT", "/app/repository"))
    repository = repository.resolve(strict=True)
    jobs_root = Path(os.environ["CROSSPATCH_RUNNER_JOBS_ROOT"]).resolve(strict=True)
    workspaces_root = Path(
        os.environ["CROSSPATCH_RUNNER_WORKSPACES_ROOT"]
    ).resolve(strict=True)
    before_jobs = {path.name for path in jobs_root.iterdir()}
    before_workspaces = {path.name for path in workspaces_root.iterdir()}
    base_sha = _git(repository, "rev-parse", "HEAD")
    patch = _patch(repository)
    plan = BoundExecutionPlan.from_execution_plan(
        ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
    )
    now = datetime.now(UTC)
    document = WarrantDocument(
        format="crosspatch-warrant-v1",
        warrant_id="war_live_runner_probe",
        incident_id="inc_live_runner_probe",
        repository_id="crosspatch",
        verdict_id="ver_live_runner_probe",
        verdict_sha256="1" * 64,
        candidate_id="cand_live_runner_probe",
        authority_snapshot_sha256="2" * 64,
        reviewed_evidence_manifest_sha256="3" * 64,
        reviewed_timeline_head="4" * 64,
        base_sha=base_sha,
        repository_manifest_sha256=repository_manifest_sha256(repository, base_sha),
        patch_b64=base64.b64encode(patch).decode("ascii"),
        patch_sha256=hashlib.sha256(patch).hexdigest(),
        allowed_paths=(_RELATIVE_PATH,),
        execution_plans=(plan,),
        test_plan_sha256=sha256_hex((plan,)),
        runner_digest=os.environ["CROSSPATCH_RUNNER_DIGEST"],
        environment_digest=os.environ["CROSSPATCH_ENVIRONMENT_DIGEST"],
        approver_identity="production-probe",
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
        approval_mac_key_id="probe-v1",
        nonce="nonce_live_runner_probe",
    )
    approval_service = ApprovalService(keys={"probe-v1": b"p" * 32})
    approval = approval_service.approve(document, approved_at=now)
    store = InMemoryWarrantStore(clock=lambda: now)
    await store.add_approved(document, approval)
    broker = Broker(
        store=store,
        approvals=approval_service,
        authority=_StaticAuthority(
            AuthoritySnapshot.from_warrant(document, repository_root=repository)
        ),
        worktrees=EphemeralWorktreeFactory(
            jobs_root=jobs_root,
            workspaces_root=workspaces_root,
        ),
        process_runner=build_runner_service_client_from_environment(),
        catalog=ExecutionCatalog.default(),
        runner_digest=document.runner_digest,
        environment_digest=document.environment_digest,
    )
    result = await broker.execute_warrant(document.warrant_id)
    if result.status is not BrokerStatus.EXECUTED or len(result.receipts) != 1:
        raise RuntimeError(f"production broker probe failed: {result.model_dump_json()}")
    receipt = result.receipts[0]
    if not receipt.passed or result.nonce_sha256 != hashlib.sha256(
        document.nonce.encode()
    ).hexdigest():
        raise RuntimeError("production broker receipt binding failed")
    if {path.name for path in jobs_root.iterdir()} != before_jobs:
        raise RuntimeError("trusted runner job cleanup failed")
    if {path.name for path in workspaces_root.iterdir()} != before_workspaces:
        raise RuntimeError("candidate workspace cleanup failed")
    return {
        "argv_sha256": receipt.argv_sha256,
        "job_provenance_sha256": receipt.job_provenance_sha256,
        "nonce_sha256": result.nonce_sha256,
        "plan_sha256": receipt.plan_sha256,
        "runner_service_identity_sha256": receipt.runner_service_identity_sha256,
        "status": result.status.value,
        "workspace_provenance_sha256": receipt.workspace_provenance_sha256,
    }


if __name__ == "__main__":
    print(json.dumps(asyncio.run(_run()), separators=(",", ":"), sort_keys=True))
