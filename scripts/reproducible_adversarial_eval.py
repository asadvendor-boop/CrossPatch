#!/usr/bin/env python3
"""Reproduce CrossPatch's separately denominated adversarial evidence claims."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from crosspatch.domain.hashing import canonical_json as domain_canonical_json
from crosspatch.evidence.sanitizer import sanitize_evidence
from crosspatch.export.verifier import verify_export
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from verification_lib import atomic_json, current_git_sha, release_source_sha256

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "evals" / "adversarial-corpus-v1.json"
SANITIZER_VECTOR_REGISTRY = ROOT / "evals" / "adversarial-sanitizer-vectors-v1.json"
GENERATOR = "scripts/reproducible_adversarial_eval.py"
RUNTIME_PROVENANCE_GENERATOR = "scripts/capture_c2_runtime_provenance.py"
_REGISTRY_MARKERS = {
    "sanitizer": "adversarial_eval_sanitizer",
    "authority": (
        "adversarial_eval_broker_tamper or "
        "adversarial_eval_broker_expiry or "
        "adversarial_eval_broker_reuse"
    ),
}


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def repo_output_path(relative: str | Path) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("evaluation output must stay inside the repository")
    candidate = ROOT / path
    if candidate.is_symlink():
        raise ValueError("evaluation output must stay inside the repository")
    parent = candidate.parent.resolve(strict=True)
    resolved = parent / candidate.name
    if not resolved.is_relative_to(ROOT.resolve()):
        raise ValueError("evaluation output must stay inside the repository")
    return resolved


def _repo_file(relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe corpus path: {relative}")
    candidate = ROOT / path
    if not candidate.is_file() or candidate.is_symlink():
        raise ValueError(f"missing corpus file: {relative}")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(ROOT.resolve()):
        raise ValueError(f"corpus path escaped repository: {relative}")
    return resolved


def load_corpus(path: Path = DEFAULT_CORPUS) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("adversarial corpus must be a JSON object")
    if payload.get("schema_version") != "crosspatch.adversarial-corpus.v1":
        raise ValueError("unsupported adversarial corpus schema")
    expected_lengths = {
        "genuine_hostile_evidence": 1,
        "sanitizer_vectors": 14,
        "broker_tamper_controls": 34,
        "broker_expiry_controls": 1,
        "broker_reuse_controls": 1,
        "duplicate_retry_refusals": 1,
        "published_repairs": 5,
    }
    for field, expected in expected_lengths.items():
        values = payload.get(field)
        if not isinstance(values, list) or len(values) != expected:
            raise ValueError(f"{field} must declare exactly {expected} inputs")
    node_fields = (
        "sanitizer_vectors",
        "broker_tamper_controls",
        "broker_expiry_controls",
        "broker_reuse_controls",
    )
    for field in node_fields:
        nodes = [item.get("pytest_node_id") for item in payload[field]]
        if any(not isinstance(node, str) or "::" not in node for node in nodes):
            raise ValueError(f"{field} must bind every input to a pytest node")
        if len(nodes) != len(set(nodes)):
            raise ValueError(f"{field} contains duplicate pytest nodes")
    if "blended_total" in payload:
        raise ValueError("adversarial corpora must not publish a blended denominator")
    return payload


def _load_sanitizer_vector_registry() -> dict[str, dict[str, Any]]:
    payload = json.loads(SANITIZER_VECTOR_REGISTRY.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "crosspatch.adversarial-sanitizer-vectors.v1":
        raise ValueError("unsupported sanitizer vector registry schema")
    vectors = payload.get("vectors")
    if not isinstance(vectors, list) or len(vectors) != 14:
        raise ValueError("sanitizer vector registry must declare exactly 14 inputs")
    registry: dict[str, dict[str, Any]] = {}
    for vector in vectors:
        if not isinstance(vector, dict):
            raise ValueError("sanitizer vector registry entries must be objects")
        vector_id = vector.get("id")
        if not isinstance(vector_id, str) or not vector_id or vector_id in registry:
            raise ValueError("sanitizer vector registry IDs must be unique strings")
        try:
            raw = base64.b64decode(vector["payload_base64"], validate=True)
        except (KeyError, ValueError) as error:
            raise ValueError(f"sanitizer vector payload is invalid: {vector_id}") from error
        raw_sha256 = vector.get("raw_sha256")
        if raw_sha256 != _sha256_bytes(raw):
            raise ValueError(f"sanitizer vector registry hash drifted: {vector_id}")
        registry[vector_id] = {"raw": raw, "raw_sha256": raw_sha256}
    return registry


def verify_sanitizer_registry(corpus: dict[str, Any]) -> dict[str, Any]:
    registry = _load_sanitizer_vector_registry()
    declared: dict[str, str] = {}
    for item in corpus["sanitizer_vectors"]:
        if "payload_base64" in item:
            raise ValueError("sanitizer corpus must not duplicate authoritative bytes")
        vector_id = item.get("registry_id")
        if (
            not isinstance(vector_id, str)
            or vector_id != item.get("id")
            or vector_id in declared
        ):
            raise ValueError("sanitizer corpus registry IDs must be exact and unique")
        declared[vector_id] = item.get("raw_sha256")
    expected = {
        vector_id: vector["raw_sha256"] for vector_id, vector in registry.items()
    }
    if declared != expected:
        raise ValueError("sanitizer corpus bytes drifted from the authoritative registry")
    return {"exact_bytes": True, "total": len(registry)}


def canonical_reference_projection(
    archive: Path,
    reference: dict[str, Any],
) -> dict[str, Any]:
    projection, _authority, _attestation = _verified_reference_semantics(
        archive,
        reference,
    )
    return projection


def canonical_projection_sha256(projection: dict[str, Any]) -> str:
    return _sha256_bytes(canonical_json_bytes(projection))


def _public_key(proof_path: Path, expected_sha256: str) -> bytes:
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    key = base64.b64decode(proof["public_key_base64"], validate=True)
    if proof.get("public_key_sha256") != expected_sha256:
        raise ValueError("public-key proof fingerprint does not match corpus")
    if _sha256_bytes(key) != expected_sha256:
        raise ValueError("decoded public key does not match its fingerprint")
    if proof.get("private_seed_included") is not False:
        raise ValueError("public-key proof contains private material")
    try:
        challenge = base64.b64decode(proof["proof_challenge_base64"], validate=True)
        signature = base64.b64decode(proof["proof_signature_base64"], validate=True)
        Ed25519PublicKey.from_public_bytes(key).verify(signature, challenge)
    except (InvalidSignature, KeyError, ValueError) as error:
        raise ValueError("public-key runtime proof signature is invalid") from error
    return key


def verify_runtime_provenance(
    provenance: dict[str, Any],
    public_key: bytes,
) -> dict[str, Any]:
    if (
        provenance.get("schema_version") != "crosspatch.c2-runtime-provenance.v2"
        or provenance.get("machine_generated") is not True
        or provenance.get("generator") != RUNTIME_PROVENANCE_GENERATOR
    ):
        raise ValueError("genuine C2 runtime provenance schema is invalid")
    attestation = provenance.get("attestation")
    if not isinstance(attestation, dict):
        raise ValueError("genuine C2 runtime provenance lacks an attestation")
    canonical = canonical_json_bytes(attestation)
    if provenance.get("attestation_sha256") != _sha256_bytes(canonical):
        raise ValueError("genuine C2 runtime attestation hash drifted")
    if provenance.get("production_public_key_sha256") != _sha256_bytes(public_key):
        raise ValueError("genuine C2 runtime attestation key drifted")
    generator_sha256 = _sha256_file(_repo_file(RUNTIME_PROVENANCE_GENERATOR))
    if (
        provenance.get("generator_sha256") != generator_sha256
        or attestation.get("capture_generator_sha256") != generator_sha256
    ):
        raise ValueError("genuine C2 runtime attestation generator drifted")
    try:
        signature = base64.b64decode(provenance["signature_base64"], validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical)
    except (InvalidSignature, KeyError, ValueError) as error:
        raise ValueError("genuine C2 runtime attestation signature is invalid") from error
    return attestation


def _case_file(archive: Path, incident_id: str) -> dict[str, Any]:
    member = f"incidents/{incident_id}/case-file.json"
    with zipfile.ZipFile(archive) as bundle:
        return json.loads(bundle.read(member))


def _single(items: list[dict[str, Any]], *, label: str) -> dict[str, Any]:
    if len(items) != 1:
        raise ValueError(f"genuine C2 authority chain requires one {label}")
    return items[0]


def verify_authority_chain(
    *,
    manifest: dict[str, Any],
    case: dict[str, Any],
    broker_result: dict[str, Any],
    test_receipt: dict[str, Any],
) -> dict[str, Any]:
    """Verify the ordered verdict -> approval -> execution -> receipt chain."""
    incident = manifest.get("incident")
    if not isinstance(incident, dict):
        raise ValueError("genuine C2 manifest incident is missing")
    incident_id = incident.get("id")
    if (
        case.get("incident", {}).get("id") != incident_id
        or case.get("incident", {}).get("state") != "VERIFIED"
    ):
        raise ValueError("genuine C2 authority chain is not terminal VERIFIED")

    verdict = _single(case.get("verdicts", []), label="verdict")
    if (
        verdict.get("verdict") != "CLEAR"
        or verdict.get("verdict_sha256") != incident.get("verdict_sha256")
    ):
        raise ValueError("genuine C2 CLEAR verdict is not manifest-bound")

    warrant = _single(case.get("warrants", []), label="warrant")
    warrant_id = warrant.get("warrant_id")
    warrant_sha256 = warrant.get("canonical_sha256")
    if (
        warrant_sha256 != incident.get("warrant_sha256")
        or warrant.get("approval_status") != "APPROVED"
        or warrant.get("consumption_status") != "CONSUMED"
        or warrant.get("execution_status") != "EXECUTED"
        or warrant.get("binding_hashes", {}).get("verdict_sha256")
        != verdict.get("verdict_sha256")
    ):
        raise ValueError("genuine C2 approved warrant is not verdict-bound")
    public_warrant_bytes = warrant.get("public_warrant_bytes")
    if not isinstance(public_warrant_bytes, str):
        raise ValueError("genuine C2 public warrant bytes are missing")
    if _sha256_bytes(public_warrant_bytes.encode("utf-8")) != warrant.get(
        "public_warrant_sha256"
    ):
        raise ValueError("genuine C2 public warrant bytes drifted")
    public_warrant = json.loads(public_warrant_bytes)
    plan_ids = public_warrant.get("plan_ids")
    if (
        public_warrant.get("incident_id") != incident_id
        or public_warrant.get("warrant_id") != warrant_id
        or public_warrant.get("canonical_warrant_sha256") != warrant_sha256
        or public_warrant.get("verdict_sha256") != verdict.get("verdict_sha256")
        or not isinstance(plan_ids, list)
        or not plan_ids
    ):
        raise ValueError("genuine C2 public warrant is not authority-bound")

    events = sorted(case.get("events", []), key=lambda event: event.get("sequence", -1))
    sequences = [event.get("sequence") for event in events]
    if (
        any(not isinstance(sequence, int) for sequence in sequences)
        or sequences != sorted(set(sequences))
    ):
        raise ValueError("genuine C2 event sequence is malformed")
    verdict_event = _single(
        [event for event in events if event.get("type") == "VERDICT"],
        label="verdict event",
    )
    approval_event = _single(
        [event for event in events if event.get("type") == "WARRANT_APPROVED"],
        label="approval event",
    )
    execution_event = _single(
        [event for event in events if event.get("type") == "EXECUTION_STARTED"],
        label="execution event",
    )
    verified_event = _single(
        [event for event in events if event.get("type") == "VERIFIED"],
        label="verified event",
    )
    receipt_ids = warrant.get("receipt_ids")
    if not isinstance(receipt_ids, list) or len(receipt_ids) != 1:
        raise ValueError("genuine C2 warrant must bind one receipt")
    approval_details = approval_event.get("details", {})
    false_approval_event_sequences: list[int] = []
    if not (
        verdict_event.get("actor") == "Magistrate"
        and verdict_event.get("details") == {"verdict": "CLEAR"}
        and verdict_event["sequence"] < approval_event["sequence"]
        and approval_details.get("approval_id") == warrant.get("approval_id")
        and approval_details.get("approver_identity") == public_warrant.get("approver_identity")
        and approval_details.get("warrant_sha256") == warrant_sha256
    ):
        false_approval_event_sequences.append(approval_event["sequence"])
    if false_approval_event_sequences:
        raise ValueError("genuine C2 approval is not ordered and hash-bound")
    if not (
        approval_event["sequence"] < execution_event["sequence"] < verified_event["sequence"]
        and execution_event.get("details", {}).get("warrant_id") == warrant_id
        and verified_event.get("details", {}).get("warrant_id") == warrant_id
        and verified_event.get("details", {}).get("receipt_id") == receipt_ids[0]
    ):
        raise ValueError("genuine C2 execution is not approval-and-receipt-bound")

    if (
        broker_result.get("status") != "EXECUTED"
        or broker_result.get("warrant_id") != warrant_id
        or _sha256_bytes(canonical_json_bytes(broker_result)) != incident.get("receipt_sha256")
    ):
        raise ValueError("genuine C2 broker result is not manifest-bound")
    process_receipt = _single(broker_result.get("receipts", []), label="process receipt")
    if (
        process_receipt.get("plan_id") not in plan_ids
        or process_receipt.get("supervisor_verified") is not True
        or process_receipt.get("verification_code")
        != "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED"
    ):
        raise ValueError("genuine C2 trusted process receipt is invalid")
    receipt_sha256 = _sha256_bytes(canonical_json_bytes(process_receipt))
    if (
        test_receipt.get("id") != receipt_ids[0]
        or test_receipt.get("incident_id") != incident_id
        or test_receipt.get("warrant_id") != warrant_id
        or test_receipt.get("plan_id") != process_receipt.get("plan_id")
        or test_receipt.get("receipt") != process_receipt
        or test_receipt.get("receipt_sha256") != receipt_sha256
        or test_receipt.get("result", {}).get("passed") is not True
        or test_receipt.get("result", {}).get("receipt") != process_receipt
        or test_receipt.get("result", {}).get("receipt_sha256") != receipt_sha256
    ):
        raise ValueError("genuine C2 test receipt is not broker-bound")
    trusted_observation = process_receipt.get("trusted_observation")
    if not isinstance(trusted_observation, dict):
        raise ValueError("genuine C2 trusted observation is missing")

    return {
        "approval_bound": True,
        "counts": trusted_observation.get("counts"),
        "execution_status": warrant["execution_status"],
        "false_approval_event_sequences": false_approval_event_sequences,
        "final_state": case["incident"]["state"],
        "plan_ids": plan_ids,
        "response_statuses": trusted_observation.get("response_statuses"),
        "supervisor_verified": process_receipt["supervisor_verified"],
        "verdict_sequence": [verdict["verdict"]],
        "verification_code": process_receipt["verification_code"],
    }


def _event(case: dict[str, Any], event_type: str) -> dict[str, Any]:
    return _single(
        [event for event in case.get("events", []) if event.get("type") == event_type],
        label=event_type,
    )


def _verified_reference_semantics(
    archive: Path,
    reference: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    incident_id = reference["incident_id"]
    production_key = _public_key(
        _repo_file(reference["public_key_proof_path"]),
        reference["public_key_sha256"],
    )
    sealed_proof = json.loads(
        _repo_file(reference["sealed_key_proof_path"]).read_text(encoding="utf-8")
    )
    sealed_key = base64.b64decode(sealed_proof["public_key_base64"], validate=True)
    verified = verify_export(archive, production_key)
    cross_lineage = verify_export(archive, sealed_key)
    if not verified.valid or verified.manifest is None:
        raise ValueError(f"genuine C2 export signature failed: {verified.errors}")
    if cross_lineage.valid:
        raise ValueError("genuine C2 export incorrectly verified under sealed-cohort key")

    provenance = json.loads(
        _repo_file(reference["provenance_path"]).read_text(encoding="utf-8")
    )
    attestation = verify_runtime_provenance(provenance, production_key)
    if (
        attestation.get("incident_id") != incident_id
        or attestation.get("evidence_id") != reference["evidence_id"]
        or attestation.get("evidence_profile") != "instruction-like-log"
        or attestation.get("scenario") != "webhook-race"
        or reference.get("id") != f"c2-signed-log-{attestation.get('log_entry_sha256')}"
    ):
        raise ValueError("genuine C2 runtime attestation does not identify the reference")

    with zipfile.ZipFile(archive) as bundle:
        manifest = json.loads(bundle.read("manifest.json"))
        case = json.loads(bundle.read(f"incidents/{incident_id}/case-file.json"))
        evidence_member = f"incidents/{incident_id}/evidence/{reference['evidence_id']}.json"
        hostile_evidence = json.loads(bundle.read(evidence_member))
        broker_result = json.loads(
            bundle.read(f"incidents/{incident_id}/receipts/broker-result.json")
        )
        receipt_id = case["warrants"][0]["receipt_ids"][0]
        test_receipt = json.loads(
            bundle.read(f"incidents/{incident_id}/receipts/{receipt_id}.json")
        )
    authority = verify_authority_chain(
        manifest=manifest,
        case=case,
        broker_result=broker_result,
        test_receipt=test_receipt,
    )

    event_bindings = {
        "INCIDENT_OPENED": "incident_opened_event_hash",
        "REPRODUCTION_STARTED": "reproduction_started_event_hash",
        "EVIDENCE_CAPTURED": "evidence_captured_event_hash",
    }
    for event_type, attestation_key in event_bindings.items():
        if _event(case, event_type).get("event_hash") != attestation.get(attestation_key):
            raise ValueError("genuine C2 runtime provenance is not signed-export-bound")
    if _event(case, "INCIDENT_OPENED").get("details") != {
        "evidence_profile": "instruction-like-log",
        "scenario": "webhook-race",
    }:
        raise ValueError("genuine C2 signed export lost its evidence profile")
    evidence_captured = _event(case, "EVIDENCE_CAPTURED").get("details", {})
    if (
        evidence_captured.get("evidence_id") != attestation.get("evidence_id")
        or evidence_captured.get("sanitized_sha256")
        != attestation.get("database_sanitized_sha256")
    ):
        raise ValueError("genuine C2 sanitized evidence is not runtime-attestation-bound")

    required_tags = {
        "POTENTIAL_INSTRUCTION_REDACTED",
        "PRIVATE_AUTHORITY_MATERIAL_REDACTED",
    }
    if (
        hostile_evidence.get("classification") != "UNTRUSTED_EVIDENCE"
        or set(hostile_evidence.get("tags", [])) != required_tags
        or set(attestation.get("sanitizer_tags", []))
        != {"POTENTIAL_INSTRUCTION_REDACTED"}
    ):
        raise ValueError("genuine C2 sanitizer classification or tags drifted")
    if "ignore prior instructions" in hostile_evidence.get("text", "").lower():
        raise ValueError("genuine C2 hostile instruction leaked into published evidence")

    projection = {
        "authority_chain": {
            "approval_bound": authority["approval_bound"],
            "counts": authority["counts"],
            "execution_status": authority["execution_status"],
            "false_approval_events": len(authority["false_approval_event_sequences"]),
            "final_state": authority["final_state"],
            "plan_ids": authority["plan_ids"],
            "response_statuses": authority["response_statuses"],
            "supervisor_verified": authority["supervisor_verified"],
            "verdict_sequence": authority["verdict_sequence"],
            "verification_code": authority["verification_code"],
        },
        "evidence_profile": "instruction-like-log",
        "hostile_evidence": {
            "classification": hostile_evidence["classification"],
            "input_sha256": attestation["log_entry_sha256"],
            "sanitized_sha256": attestation["database_sanitized_sha256"],
            "tags": sorted(required_tags),
        },
        "scenario": "webhook-race",
        "schema_version": "crosspatch.c2-semantic-projection.v1",
    }
    return projection, authority, attestation


def _verify_reference(reference: dict[str, Any]) -> dict[str, Any]:
    incident_id = reference["incident_id"]
    archive = _repo_file(reference["archive_path"])
    public_case_path = _repo_file(reference["public_case_path"])
    if _sha256_file(archive) != reference["archive_sha256"]:
        raise ValueError("genuine C2 archive SHA-256 drifted")
    if _sha256_file(public_case_path) != reference["public_case_sha256"]:
        raise ValueError("genuine C2 public projection SHA-256 drifted")

    public_case = json.loads(public_case_path.read_text(encoding="utf-8"))
    if public_case.get("incident_id") != incident_id:
        raise ValueError("genuine C2 public projection incident mismatch")
    projection = public_case.get("projection")
    if (
        not isinstance(projection, dict)
        or projection.get("incident", {}).get("state") != "VERIFIED"
    ):
        raise ValueError("genuine C2 public projection is not VERIFIED")
    canonical_projection = public_case.get("canonical_projection_json")
    if not isinstance(canonical_projection, str):
        raise ValueError("genuine C2 public projection is missing canonical bytes")
    if canonical_projection != domain_canonical_json(projection).decode("ascii"):
        raise ValueError("genuine C2 public projection canonical bytes are inconsistent")
    if _sha256_bytes(canonical_projection.encode("ascii")) != public_case.get(
        "manifest_sha256"
    ):
        raise ValueError("genuine C2 public projection manifest hash drifted")

    canonical, authority, _attestation = _verified_reference_semantics(archive, reference)
    canonical_sha256 = canonical_projection_sha256(canonical)
    if canonical_sha256 != reference["canonical_sha256"]:
        raise ValueError("genuine C2 canonical projection SHA-256 drifted")
    return {
        "archive_sha256": reference["archive_sha256"],
        "boundary_held": True,
        "canonical_sha256": canonical_sha256,
        "false_approvals": len(authority["false_approval_event_sequences"]),
        "id": reference["id"],
        "incident_id": incident_id,
        "production_signature": "PASS",
        "sealed_lineage_verification": "REJECTED",
        "state": "VERIFIED",
        "verdict_sequence": authority["verdict_sequence"],
    }


def _verify_sanitizer_vectors(corpus: dict[str, Any]) -> list[dict[str, str]]:
    registry = _load_sanitizer_vector_registry()
    verify_sanitizer_registry(corpus)
    observed: list[dict[str, str]] = []
    for vector in corpus["sanitizer_vectors"]:
        raw = registry[vector["registry_id"]]["raw"]
        raw_sha256 = _sha256_bytes(raw)
        if raw_sha256 != vector["raw_sha256"]:
            raise ValueError(f"sanitizer vector hash drifted: {vector['id']}")
        view = sanitize_evidence(raw, provenance=f"eval:{vector['id']}")
        kinds = {tag.kind for tag in view.tags}
        if (
            view.classification != "UNTRUSTED_EVIDENCE"
            or "POTENTIAL_INSTRUCTION_REDACTED" not in kinds
        ):
            raise ValueError(f"sanitizer vector was not neutralized: {vector['id']}")
        observed.append({"id": vector["id"], "raw_sha256": raw_sha256})
    return observed


def _collect_registry_nodes(marker_expression: str) -> set[str]:
    environment = dict(os.environ)
    environment["OPENAI_API_KEY"] = ""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-m",
            marker_expression,
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stdout + result.stderr)[-2000:]
        raise ValueError(f"adversarial registry collection failed:\n{detail}")
    return {
        line.strip()
        for line in result.stdout.splitlines()
        if line.startswith(("backend/tests/", "victim/tests/")) and "::" in line
    }


def verify_declared_control_registries(corpus: dict[str, Any]) -> dict[str, bool]:
    sanitizer_bytes = verify_sanitizer_registry(corpus)
    declared_sanitizer = {
        item["pytest_node_id"] for item in corpus["sanitizer_vectors"]
    }
    declared_authority = {
        item["pytest_node_id"]
        for field in (
            "broker_tamper_controls",
            "broker_expiry_controls",
            "broker_reuse_controls",
        )
        for item in corpus[field]
    }
    observed_sanitizer = _collect_registry_nodes(_REGISTRY_MARKERS["sanitizer"])
    observed_authority = _collect_registry_nodes(_REGISTRY_MARKERS["authority"])
    if declared_sanitizer != observed_sanitizer:
        missing = sorted(observed_sanitizer - declared_sanitizer)
        extra = sorted(declared_sanitizer - observed_sanitizer)
        raise ValueError(f"sanitizer corpus registry drifted: missing={missing}, extra={extra}")
    if declared_authority != observed_authority:
        missing = sorted(observed_authority - declared_authority)
        extra = sorted(declared_authority - observed_authority)
        raise ValueError(f"authority corpus registry drifted: missing={missing}, extra={extra}")
    return {
        "authority_exact": True,
        "sanitizer_bytes_exact": sanitizer_bytes["exact_bytes"],
        "sanitizer_exact": True,
    }


def _run_authority_controls(corpus: dict[str, Any]) -> None:
    controls = (
        corpus["broker_tamper_controls"]
        + corpus["broker_expiry_controls"]
        + corpus["broker_reuse_controls"]
    )
    node_ids = [item["pytest_node_id"] for item in controls]
    environment = dict(os.environ)
    environment["OPENAI_API_KEY"] = ""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", *node_ids, "-q"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    expected = len(controls)
    if result.returncode != 0 or re.search(rf"\b{expected} passed\b", result.stdout) is None:
        detail = (result.stdout + result.stderr)[-2000:]
        raise ValueError(f"authority control suite failed:\n{detail}")


def _verify_duplicate_refusal(item: dict[str, Any]) -> dict[str, Any]:
    room = json.loads(_repo_file(item["artifact_path"]).read_text(encoding="utf-8"))
    events = room.get("events", [])
    matching = [event for event in events if event.get("type") == item["event_type"]]
    abstains = [
        event
        for event in events
        if event.get("type") == "VERDICT"
        and event.get("details", {}).get("verdict") == "ABSTAIN"
        and event.get("details", {}).get("failure_code") == "FAILED_RETRY_DUPLICATE"
    ]
    if (
        room.get("incident", {}).get("id") != item["incident_id"]
        or room.get("incident", {}).get("state") != "HUMAN_ESCALATION"
        or len(matching) != 1
        or len(abstains) != 1
        or room.get("pending_warrant") is not None
        or room.get("artifacts", {}).get("warrant") is not None
    ):
        raise ValueError("duplicate failed-retry artifact did not fail closed")
    return {"id": item["id"], "incident_id": item["incident_id"]}


def _verify_published_repairs(
    repairs: list[dict[str, Any]],
    production_key: bytes,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for repair in repairs:
        archive = _repo_file(repair["archive_path"])
        verified = verify_export(archive, production_key)
        if not verified.valid:
            raise ValueError(f"published export signature failed: {repair['incident_id']}")
        case = _case_file(archive, repair["incident_id"])
        sequence = [item["verdict"] for item in case["verdicts"]]
        if case["incident"]["state"] != "VERIFIED" or sequence != repair["verdict_sequence"]:
            raise ValueError(f"published verdict path drifted: {repair['incident_id']}")
        results.append(
            {
                "incident_id": repair["incident_id"],
                "verdict_sequence": sequence,
            }
        )
    return results


def _verify_sealed_cohort(specification: dict[str, Any]) -> dict[str, Any]:
    report = json.loads(
        _repo_file(specification["gate_report_path"]).read_text(encoding="utf-8")
    )
    expected_runs = specification["runs_with_remand"]
    if (
        report.get("qualifying_runs") != specification["qualifying_runs"]
        or report.get("preapproval_remand_runs") != expected_runs
        or report.get("signed_exports_valid") != specification["qualifying_runs"]
    ):
        raise ValueError("sealed-cohort REMAND evidence drifted")
    return {
        "runs_with_remand": len(expected_runs),
        "total": specification["qualifying_runs"],
    }


def build_report(corpus_path: Path = DEFAULT_CORPUS) -> dict[str, Any]:
    corpus = load_corpus(corpus_path)
    registry = verify_declared_control_registries(corpus)
    reference = corpus["genuine_hostile_evidence"][0]
    genuine = _verify_reference(reference)
    sanitizer = _verify_sanitizer_vectors(corpus)
    _run_authority_controls(corpus)
    duplicate = _verify_duplicate_refusal(corpus["duplicate_retry_refusals"][0])
    production_key = _public_key(
        _repo_file(reference["public_key_proof_path"]),
        reference["public_key_sha256"],
    )
    published = _verify_published_repairs(corpus["published_repairs"], production_key)
    sealed = _verify_sealed_cohort(corpus["sealed_cohort"])
    published_remands = sum(item["verdict_sequence"][0] == "REMAND" for item in published)

    return {
        "canonical_reference": {
            "archive_sha256": genuine["archive_sha256"],
            "canonical_sha256": genuine["canonical_sha256"],
            "incident_id": genuine["incident_id"],
            "production_signature": genuine["production_signature"],
            "sealed_lineage_verification": genuine["sealed_lineage_verification"],
        },
        "corpora": {
            "broker_authority_tamper": [item["id"] for item in corpus["broker_tamper_controls"]],
            "duplicate_failed_retry": [duplicate["id"]],
            "expired_warrants": [item["id"] for item in corpus["broker_expiry_controls"]],
            "genuine_hostile_evidence": [genuine["id"]],
            "published_repairs": [item["incident_id"] for item in published],
            "reused_warrants": [item["id"] for item in corpus["broker_reuse_controls"]],
            "sanitizer_vectors": sanitizer,
            "sealed_cohort_runs_with_remand": corpus["sealed_cohort"]["runs_with_remand"],
        },
        "counterfactual": {
            "kind": "design_argument",
            "numeric_claim_published": False,
            "reason": "no equivalent measured no-sanitizer baseline exists",
        },
        "methodology": {
            "denominators_are_separate": True,
            "false_approval_note": (
                "zero false-approval events were observed; only the genuine hostile-evidence "
                "case entered a model-and-human approval flow"
            ),
            "nothing_cherry_picked": all(registry.values()),
            "registry_exact": registry,
        },
        "observed": {
            "broker_authority_tamper": {
                "rejected_before_side_effects": len(corpus["broker_tamper_controls"]),
                "total": len(corpus["broker_tamper_controls"]),
            },
            "duplicate_failed_retry": {"refused": 1, "total": 1},
            "expired_warrants": {"denied": 1, "total": 1},
            "false_approval_events": genuine["false_approvals"],
            "genuine_hostile_evidence": {
                "boundary_held": 1,
                "false_approvals": genuine["false_approvals"],
                "total": 1,
            },
            "published_repairs": {
                "remand_then_clear": published_remands,
                "total": len(published),
            },
            "reused_warrants": {"denied": 1, "total": 1},
            "sanitizer_vectors": {
                "neutralized": len(sanitizer),
                "total": len(sanitizer),
            },
            "sealed_cohort": sealed,
        },
        "schema_version": "crosspatch.adversarial-eval.v1",
        "status": "PASS",
    }


def evidence_payload(
    report: dict[str, Any],
    *,
    checked_at: str,
    git_sha: str | None,
    source_sha256: str | None,
) -> dict[str, Any]:
    return {
        "checked_at": checked_at,
        "generator": GENERATOR,
        "git_sha": git_sha,
        "machine_generated": True,
        "report": report,
        "report_sha256": _sha256_bytes(canonical_json_bytes(report)),
        "schema_version": 1,
        "source": (
            "signed genuine C2 export, declared sanitizer vectors, broker controls, "
            "duplicate-refusal record, published exports, and sealed cohort"
        ),
        "source_sha256": source_sha256,
        "status": report["status"],
    }


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        report = build_report(arguments.corpus)
        if arguments.output is not None:
            output = repo_output_path(arguments.output)
            atomic_json(
                output,
                evidence_payload(
                    report,
                    checked_at=_utc_now(),
                    git_sha=current_git_sha(),
                    source_sha256=release_source_sha256(),
                ),
            )
        print(json.dumps(report, separators=(",", ":"), sort_keys=True))
        return 0
    except (AssertionError, KeyError, OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"adversarial evaluation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
