import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from crosspatch.broker.approval import ApprovalService
from crosspatch.broker.warrant import (
    BoundExecutionPlan,
    DuplicateKey,
    NonCanonicalWarrant,
    WarrantDocument,
    WarrantIntegrityError,
    canonical_warrant_bytes,
    canonical_warrant_hash,
    parse_warrant_json,
    validate_warrant_integrity,
)
from crosspatch.domain.hashing import sha256_hex
from crosspatch.runner.catalog import ExecutionCatalog, ExecutionPlan, OracleProfile

PATCH = b"""diff --git a/victim/src/victim/db.py b/victim/src/victim/db.py
index 1111111111111111111111111111111111111111..2222222222222222222222222222222222222222 100644
--- a/victim/src/victim/db.py
+++ b/victim/src/victim/db.py
@@ -1 +1 @@
-vulnerable = True
+vulnerable = False
"""


def _document(
    *,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    approver_identity: str = "approver-1",
) -> WarrantDocument:
    plan = ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
    bound = BoundExecutionPlan.from_execution_plan(plan)
    issued = issued_at or datetime(2026, 7, 14, 2, tzinfo=UTC)
    return WarrantDocument(
        format="crosspatch-warrant-v1",
        warrant_id="war_01",
        incident_id="inc_01",
        repository_id="repo_01",
        verdict_id="ver_01",
        verdict_sha256="1" * 64,
        candidate_id="cand_01",
        authority_snapshot_sha256="2" * 64,
        reviewed_evidence_manifest_sha256="3" * 64,
        reviewed_timeline_head="4" * 64,
        base_sha="5" * 40,
        repository_manifest_sha256="6" * 64,
        patch_b64=base64.b64encode(PATCH).decode("ascii"),
        patch_sha256=hashlib.sha256(PATCH).hexdigest(),
        allowed_paths=("victim/src/victim/db.py",),
        execution_plans=(bound,),
        test_plan_sha256=sha256_hex((bound,)),
        runner_digest="7" * 64,
        environment_digest="8" * 64,
        approver_identity=approver_identity,
        issued_at=issued,
        expires_at=expires_at or issued + timedelta(minutes=15),
        approval_mac_key_id="approval-v1",
        nonce="nonce_01",
    )


def test_canonical_warrant_golden_vector_normalizes_unicode_and_time():
    utc = _document(approver_identity="approv\u00e9r")
    offset = _document(
        issued_at=datetime(2026, 7, 14, 7, tzinfo=timezone(timedelta(hours=5))),
        expires_at=datetime(2026, 7, 14, 7, 15, tzinfo=timezone(timedelta(hours=5))),
        approver_identity="approve\u0301r",
    )

    assert canonical_warrant_bytes(utc) == canonical_warrant_bytes(offset)
    assert canonical_warrant_hash(utc) == canonical_warrant_hash(offset)
    assert canonical_warrant_hash(utc) == (
        "a8873e79abf146ba1e0dd75c252d72e3fd1f104183299fd91a3120349fab27b2"
    )


def test_parser_rejects_duplicate_keys_and_noncanonical_json():
    with pytest.raises(DuplicateKey):
        parse_warrant_json(b'{"format":"a","format":"b"}')

    pretty = json.dumps(_document().model_dump(mode="json"), indent=2).encode()
    with pytest.raises(NonCanonicalWarrant):
        parse_warrant_json(pretty)


def test_integrity_recomputes_actual_patch_and_every_derived_binding():
    document = _document()
    validate_warrant_integrity(document)

    altered_patch = bytearray(PATCH)
    altered_patch[-2] ^= 1
    tampered = document.model_copy(
        update={"patch_b64": base64.b64encode(altered_patch).decode("ascii")}
    )
    with pytest.raises(WarrantIntegrityError, match="patch bytes"):
        validate_warrant_integrity(tampered)

    tampered_plan = document.model_copy(update={"test_plan_sha256": "9" * 64})
    with pytest.raises(WarrantIntegrityError, match="test plan"):
        validate_warrant_integrity(tampered_plan)


def test_bound_plan_round_trip_preserves_oracle_profile_and_statuses() -> None:
    plan = ExecutionCatalog.default().resolve("victim.payload-equivalence.candidate")

    bound = BoundExecutionPlan.from_execution_plan(plan)

    assert bound.oracle_profile is OracleProfile.PAYLOAD_EQUIVALENCE
    assert bound.expected_statuses == (202, 200, 409)
    assert bound.as_execution_plan() == plan
    bound.validate_binding()


def test_legacy_canonical_warrant_without_oracle_fields_round_trips_exactly() -> None:
    current = ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
    legacy_plan = ExecutionPlan(
        plan_id=current.plan_id,
        argv=current.argv,
        working_directory=current.working_directory,
        timeout_seconds=current.timeout_seconds,
        expected_counts=current.expected_counts,
    )
    legacy_bound = BoundExecutionPlan.from_execution_plan(legacy_plan)
    legacy_document = _document().model_copy(
        update={
            "execution_plans": (legacy_bound,),
            "test_plan_sha256": sha256_hex((legacy_bound,)),
        }
    )
    legacy_bytes = canonical_warrant_bytes(legacy_document)

    assert b'"oracle_profile"' not in legacy_bytes
    assert b'"expected_statuses"' not in legacy_bytes
    parsed = parse_warrant_json(legacy_bytes)
    validate_warrant_integrity(parsed)
    assert canonical_warrant_bytes(parsed) == legacy_bytes
    assert parsed.execution_plans[0].oracle_profile is None
    assert parsed.execution_plans[0].expected_statuses is None


def test_approval_mac_is_domain_separated_and_binds_exact_canonical_bytes():
    service = ApprovalService(keys={"approval-v1": b"k" * 32})
    document = _document()
    approval = service.approve(document, approved_at=datetime(2026, 7, 14, 2, 1, tzinfo=UTC))

    assert service.verify(document, approval) is True
    assert service.verify(document.model_copy(update={"base_sha": "a" * 40}), approval) is False
    assert service.verify(
        document,
        approval.model_copy(update={"approver_identity": "different-approver"}),
    ) is False


def test_approval_rejects_expired_warrant_and_wrong_approver():
    service = ApprovalService(keys={"approval-v1": b"k" * 32})
    document = _document(expires_at=datetime(2026, 7, 14, 2, 2, tzinfo=UTC))

    with pytest.raises(ValueError, match="expired"):
        service.approve(document, approved_at=datetime(2026, 7, 14, 2, 3, tzinfo=UTC))
    with pytest.raises(ValueError, match="approver"):
        service.approve(
            document,
            approved_at=datetime(2026, 7, 14, 2, 1, tzinfo=UTC),
            approver_identity="someone-else",
        )
