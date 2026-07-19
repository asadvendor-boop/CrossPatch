from __future__ import annotations

import hashlib
import json

import pytest
from crosspatch.api.models import PublishedCaseView
from crosspatch.domain.hashing import canonical_json, sha256_hex
from crosspatch.publication_policy import is_forbidden_public_key
from pydantic import ValidationError


def test_publication_policy_allows_only_the_one_way_nonce_digest() -> None:
    assert is_forbidden_public_key("nonce_sha256") is False
    assert is_forbidden_public_key("nonce") is True
    assert is_forbidden_public_key("approval_nonce") is True
    assert is_forbidden_public_key("nonce_value") is True


def _published_projection() -> dict[str, object]:
    nonce_sha256 = "1" * 64
    warrant = {
        "allowed_paths": ["victim/src/victim/db.py"],
        "approver_identity": "approver-1",
        "authority_snapshot_sha256": "a" * 64,
        "base_sha": "2" * 40,
        "canonical_warrant_sha256": "3" * 64,
        "environment_digest": "b" * 64,
        "expires_at": "2026-07-16T12:15:00+00:00",
        "format": "crosspatch-public-warrant-anatomy-v1",
        "incident_id": "inc-public-1",
        "nonce_sha256": nonce_sha256,
        "patch_sha256": "4" * 64,
        "plan_ids": ["victim.duplicate-race.candidate"],
        "repository_manifest_sha256": "c" * 64,
        "reviewed_evidence_manifest_sha256": "5" * 64,
        "reviewed_timeline_head": "6" * 64,
        "runner_digest": "7" * 64,
        "test_plan_sha256": "8" * 64,
        "verdict_sha256": "9" * 64,
        "warrant_id": "war-public-1",
    }
    public_bytes = canonical_json(warrant).decode("utf-8")
    return {
        "incident": {
            "id": "inc-public-1",
            "scenario": "webhook-race",
            "state": "VERIFIED",
        },
        "seats": [],
        "events": [],
        "verdicts": [],
        "specialist_summaries": [],
        "warrants": [{
            "warrant_id": "war-public-1",
            "canonical_sha256": "3" * 64,
            "public_warrant_bytes": public_bytes,
            "public_warrant_sha256": hashlib.sha256(public_bytes.encode()).hexdigest(),
            "nonce_sha256": nonce_sha256,
            "binding_hashes": {
                "authority_snapshot_sha256": "a" * 64,
                "base_sha": "2" * 40,
                "environment_digest": "b" * 64,
                "patch_sha256": "4" * 64,
                "repository_manifest_sha256": "c" * 64,
                "reviewed_evidence_manifest_sha256": "5" * 64,
                "reviewed_timeline_head": "6" * 64,
                "runner_digest": "7" * 64,
                "test_plan_sha256": "8" * 64,
                "verdict_sha256": "9" * 64,
            },
            "approval_status": "APPROVED",
            "approval_id": "apr-public-1",
            "consumption_status": "CONSUMED",
            "execution_status": "EXECUTED",
            "receipt_ids": ["receipt-public-1"],
            "created_at": "2026-07-16T12:00:00+00:00",
            "expires_at": "2026-07-16T12:15:00+00:00",
            "consumed_at": "2026-07-16T12:01:00+00:00",
        }],
        "artifacts": {"evidence": [], "diff": None, "tests": [], "warrant": None},
        "pending_warrant": None,
    }


def test_published_case_validates_each_nested_public_warrant_document() -> None:
    projection = _published_projection()
    PublishedCaseView(
        incident_id="inc-public-1",
        revision=1,
        manifest_sha256=sha256_hex(projection),
        projection=projection,
    )

    history = projection["warrants"]
    assert isinstance(history, list)
    history[0]["public_warrant_sha256"] = "f" * 64

    with pytest.raises(ValidationError, match="public warrant anatomy hash mismatch"):
        PublishedCaseView(
            incident_id="inc-public-1",
            revision=1,
            manifest_sha256=sha256_hex(projection),
            projection=projection,
        )


def test_published_case_binds_each_public_warrant_to_the_published_incident() -> None:
    projection = _published_projection()
    history = projection["warrants"]
    assert isinstance(history, list)
    public_warrant = json.loads(history[0]["public_warrant_bytes"])
    public_warrant["incident_id"] = "inc-other"
    public_bytes = canonical_json(public_warrant).decode("utf-8")
    history[0]["public_warrant_bytes"] = public_bytes
    history[0]["public_warrant_sha256"] = hashlib.sha256(public_bytes.encode()).hexdigest()

    with pytest.raises(ValidationError, match="matching incident"):
        PublishedCaseView(
            incident_id="inc-public-1",
            revision=1,
            manifest_sha256=sha256_hex(projection),
            projection=projection,
        )
