"""Sanitized, typed read models for model outputs and mutation warrants."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from typing import Any

from crosspatch.agents.schemas import CounselOutput, InspectorOutput, ProsecutorOutput
from crosspatch.broker.broker import BrokerResult, WarrantState
from crosspatch.broker.warrant import canonical_warrant_hash, parse_warrant_json
from crosspatch.db.models import (
    AgentRunRecord,
    ControlWarrantRecord,
    PatchCandidateRecord,
    TestRunRecord,
    TimelineEventRecord,
    WarrantRecord,
)
from crosspatch.domain.enums import Seat
from crosspatch.domain.hashing import canonical_json, sha256_hex
from crosspatch.evidence.sanitizer import sanitize_evidence
from crosspatch.runner.results import (
    ProcessReceipt,
    TrustedObservation,
    trusted_observation_digest,
)

_SPECIALIST_SEATS = frozenset({Seat.INSPECTOR.value, Seat.PROSECUTOR.value, Seat.COUNSEL.value})
_PUBLIC_EVENT_FIELDS: dict[str, frozenset[str]] = {
    "INCIDENT_OPENED": frozenset({"scenario", "evidence_profile"}),
    "REPRODUCTION_STARTED": frozenset({"scenario", "evidence_profile"}),
    "EVIDENCE_CAPTURED": frozenset({"evidence_id", "outcome", "sanitized_sha256"}),
    "REPRODUCTION_PASSED": frozenset({"evidence_id"}),
    "REPRODUCTION_INCONCLUSIVE": frozenset({"evidence_id"}),
    "ANALYSIS_STARTED": frozenset(),
    "RETRY_STARTED": frozenset(),
    "PATCH_REQUESTED": frozenset({"phase"}),
    "SEAT_STARTED": frozenset({"seat", "phase"}),
    "AGENT_OUTPUT_RECORDED": frozenset(
        {"seat", "phase", "effort", "output_sha256", "semantic_sha256"}
    ),
    "PATCH_PROPOSED": frozenset({"candidate_id", "patch_sha256"}),
    # A verdict event intentionally exposes the typed outcome, never the
    # Magistrate's analysis or required-change prose.
    "VERDICT": frozenset({"verdict", "remand_target", "reason", "failure_code"}),
    "REASONING_ESCALATED": frozenset({"seat", "effort", "escalation_count", "reason"}),
    "FAILED_RETRY_DUPLICATE": frozenset({"seat", "reason"}),
    "WARRANT_APPROVED": frozenset({"approval_id", "warrant_sha256", "approver_identity"}),
    "WARRANT_REJECTED": frozenset({"warrant_id", "warrant_sha256"}),
    "EXECUTION_STARTED": frozenset({"claim_id", "warrant_id"}),
    "TEST_FAILED": frozenset({"test_run_id", "warrant_id", "evidence_id"}),
    "VERIFIED": frozenset({"receipt_id", "warrant_id", "evidence_id"}),
    "EXECUTION_FAILED": frozenset({"warrant_id", "error_code"}),
    "BAILIFF_COMPLETED": frozenset({"warrant_id", "status"}),
    "REPAIR_CYCLE_FAILED": frozenset({"warrant_id", "error_code"}),
    "BACKGROUND_TASK_FAILED": frozenset({"operation", "failure_outcome"}),
    "BACKGROUND_TASK_ERROR_REPORTED": frozenset({"operation", "failure_outcome"}),
    "MODEL_METRICS_RECORDED": frozenset(
        {
            "seat",
            "model",
            "effort",
            "source",
            "response_id",
            "request_id",
            "latency_ms",
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "total_tokens",
            "uncached",
            "cost_usd",
            "cost_status",
            "schema_valid",
            "failure_reason",
            "pricing_source",
            "pricing_version",
        }
    ),
}


def published_event_details(event_type: str, value: dict[str, Any]) -> dict[str, Any]:
    """Return sanitized scalar fields explicitly declared for one event kind.

    The append-only private event remains complete. Unknown event types publish
    no details, so adding a new durable payload cannot silently widen the judge
    surface.
    """
    published: dict[str, Any] = {}
    for key in sorted(_PUBLIC_EVENT_FIELDS.get(event_type, frozenset())):
        item = value.get(key)
        if item is None:
            continue
        if isinstance(item, str):
            published[key] = _sanitize(
                item,
                field=f"timeline {event_type}.{key}",
            )[0]
        elif isinstance(item, (bool, int, float)):
            published[key] = item
    return published


def published_trusted_observation(
    result: dict[str, Any],
    *,
    expected_plan_id: str,
    expected_plan_sha256: str,
) -> dict[str, Any] | None:
    """Project only MAC-prebound typed observations from a persisted receipt."""
    has_receipt = "receipt" in result
    has_receipt_sha256 = "receipt_sha256" in result
    if not has_receipt and not has_receipt_sha256:
        return None
    if has_receipt != has_receipt_sha256:
        raise ValueError("persisted receipt and digest must be present together")
    receipt_value = result["receipt"]
    receipt_sha256 = result["receipt_sha256"]
    if not isinstance(receipt_value, dict) or not isinstance(receipt_sha256, str):
        raise ValueError("persisted receipt and digest must have valid types")
    if not hmac.compare_digest(sha256_hex(receipt_value), receipt_sha256):
        raise ValueError("persisted receipt digest mismatch")
    raw_observation = receipt_value.get("trusted_observation")
    raw_observation_sha256 = receipt_value.get("trusted_observation_sha256")
    if raw_observation is None and raw_observation_sha256 is None:
        try:
            receipt = ProcessReceipt.model_validate(receipt_value)
        except ValueError as error:
            raise ValueError("persisted receipt is invalid") from error
        if receipt.plan_id != expected_plan_id or not hmac.compare_digest(
            receipt.plan_sha256,
            expected_plan_sha256,
        ):
            raise ValueError("persisted receipt plan binding mismatch")
        return None
    if not isinstance(raw_observation, dict) or not isinstance(raw_observation_sha256, str):
        raise ValueError("trusted observation and digest must be present together")
    try:
        observation = TrustedObservation.model_validate(raw_observation)
    except ValueError as error:
        raise ValueError("trusted observation is invalid") from error
    expected_observation_sha256 = trusted_observation_digest(observation)
    if not hmac.compare_digest(
        expected_observation_sha256,
        raw_observation_sha256,
    ):
        raise ValueError("trusted observation digest mismatch")
    try:
        receipt = ProcessReceipt.model_validate(receipt_value)
    except ValueError as error:
        raise ValueError("persisted receipt is invalid") from error
    if receipt.plan_id != expected_plan_id or not hmac.compare_digest(
        receipt.plan_sha256,
        expected_plan_sha256,
    ):
        raise ValueError("persisted receipt plan binding mismatch")
    if (
        result.get("detail") != receipt.verification_code
        or result.get("passed") is not receipt.passed
    ):
        raise ValueError("persisted receipt result binding mismatch")
    return {
        "trusted_observation": observation.model_dump(mode="json"),
        "trusted_observation_sha256": raw_observation_sha256,
    }


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _sanitize(value: str, *, field: str) -> tuple[str, tuple[str, ...]]:
    sanitized = sanitize_evidence(
        value.encode("utf-8"),
        f"structured specialist output: {field}",
    )
    return sanitized.text, tuple(tag.kind for tag in sanitized.tags)


def _sanitize_many(values: tuple[str, ...], *, field: str) -> tuple[list[str], tuple[str, ...]]:
    cleaned: list[str] = []
    tags: set[str] = set()
    for value in values:
        text, value_tags = _sanitize(value, field=field)
        cleaned.append(text)
        tags.update(value_tags)
    return cleaned, tuple(sorted(tags))


def _common_summary(run: AgentRunRecord, *, kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "run_id": run.id,
        "seat": run.seat,
        "model": run.model,
        "effort": run.effort,
        "escalation_count": run.escalation_count,
        "phase": run.phase,
        "output_sha256": run.output_sha256,
        "semantic_sha256": run.semantic_sha256,
        "created_at": _aware_utc(run.created_at).isoformat(),
    }


def published_specialist_summaries(
    runs: tuple[AgentRunRecord, ...],
    candidates: tuple[PatchCandidateRecord, ...],
) -> list[dict[str, Any]]:
    """Return only schema-validated material fields; raw model prose is never emitted."""
    candidate_by_run = {candidate.agent_run_id: candidate for candidate in candidates}
    published: list[dict[str, Any]] = []
    for run in runs:
        if run.seat not in _SPECIALIST_SEATS or run.schema_status != "VALID":
            continue
        if run.seat == Seat.INSPECTOR.value:
            output = InspectorOutput.model_validate_json(run.output_json)
            evidence_ids, evidence_tags = _sanitize_many(
                output.evidence_ids,
                field="Inspector evidence_ids",
            )
            falsifiers, falsifier_tags = _sanitize_many(
                output.falsifiers,
                field="Inspector falsifiers",
            )
            published.append(
                {
                    **_common_summary(run, kind="INSPECTOR"),
                    "mechanism": output.mechanism.value,
                    "evidence_ids": evidence_ids,
                    "falsifiers": falsifiers,
                    "sanitization_tags": sorted(set(evidence_tags + falsifier_tags)),
                }
            )
            continue
        if run.seat == Seat.PROSECUTOR.value:
            output = ProsecutorOutput.model_validate_json(run.output_json).root
            counterexamples, counterexample_tags = _sanitize_many(
                output.counterexample_ids,
                field="Prosecutor counterexample_ids",
            )
            test_ids, test_tags = _sanitize_many(
                output.test_ids,
                field="Prosecutor test_ids",
            )
            evidence_ids, evidence_tags = _sanitize_many(
                output.evidence_ids,
                field="Prosecutor evidence_ids",
            )
            published.append(
                {
                    **_common_summary(run, kind="PROSECUTOR"),
                    "outcome": output.outcome,
                    "rival_mechanism": (
                        output.rival_mechanism.value
                        if output.outcome == "SUPPORTED_RIVAL"
                        else None
                    ),
                    "counterexample_ids": counterexamples,
                    "test_ids": test_ids,
                    "evidence_ids": evidence_ids,
                    "sanitization_tags": sorted(
                        set(counterexample_tags + test_tags + evidence_tags)
                    ),
                }
            )
            continue

        output = CounselOutput.model_validate_json(run.output_json)
        candidate = candidate_by_run.get(run.id)
        evidence_ids, evidence_tags = _sanitize_many(
            output.evidence_ids,
            field="Counsel evidence_ids",
        )
        defense, defense_tags = _sanitize(output.analysis, field="Counsel patch defense")
        intentions: list[dict[str, str]] = []
        intention_tags: set[str] = set()
        for intention in output.test_intentions:
            catalog_id, catalog_tags = _sanitize(
                intention.catalog_id,
                field="Counsel test intention catalog_id",
            )
            purpose, purpose_tags = _sanitize(
                intention.purpose,
                field="Counsel test intention purpose",
            )
            intention_tags.update(catalog_tags + purpose_tags)
            intentions.append({"catalog_id": catalog_id, "purpose": purpose})
        published.append(
            {
                **_common_summary(run, kind="COUNSEL"),
                "candidate_id": None if candidate is None else candidate.id,
                "patch_sha256": (
                    hashlib.sha256(output.normalized_diff.encode("utf-8")).hexdigest()
                    if candidate is None
                    else candidate.patch_sha256
                ),
                "patch_defense": defense,
                "evidence_ids": evidence_ids,
                "test_intentions": intentions,
                "sanitization_tags": sorted(
                    set(evidence_tags + defense_tags).union(intention_tags)
                ),
            }
        )
    return published


def published_warrant_history(
    controls: tuple[ControlWarrantRecord, ...],
    broker_records: tuple[WarrantRecord, ...],
    events: tuple[TimelineEventRecord, ...],
    test_runs: tuple[TestRunRecord, ...] = (),
) -> list[dict[str, Any]]:
    """Publish safe warrant bindings and status without nonce or approval secrets."""
    broker_by_id = {record.id: record for record in broker_records}
    receipt_ids: dict[str, list[str]] = {}
    for test_run in test_runs:
        warrant_id = test_run.result.get("warrant_id")
        if isinstance(warrant_id, str):
            receipt_ids.setdefault(warrant_id, []).append(test_run.id)
    for event in events:
        warrant_id = event.payload.get("warrant_id")
        if not isinstance(warrant_id, str):
            continue
        receipt_id = event.payload.get("receipt_id") or event.payload.get("test_run_id")
        if isinstance(receipt_id, str):
            values = receipt_ids.setdefault(warrant_id, [])
            if receipt_id not in values:
                values.append(receipt_id)

    published: list[dict[str, Any]] = []
    for control in controls:
        document = parse_warrant_json(bytes(control.canonical_document))
        if not hmac.compare_digest(canonical_warrant_hash(document), control.warrant_sha256):
            raise ValueError("published warrant hash disagrees with canonical bytes")
        broker = broker_by_id.get(control.id)
        execution_status = "NOT_EXECUTED"
        if broker is not None and broker.result_json is not None:
            result = BrokerResult.model_validate_json(broker.result_json)
            if result.warrant_id != control.id:
                raise ValueError("broker result belongs to a different warrant")
            execution_status = result.status.value
        elif broker is not None and broker.state == WarrantState.CONSUMING.value:
            execution_status = "IN_PROGRESS"
        nonce_sha256 = hashlib.sha256(document.nonce.encode("utf-8")).hexdigest()
        if broker is not None and not hmac.compare_digest(nonce_sha256, broker.nonce_sha256):
            raise ValueError("published warrant nonce digest disagrees with broker row")
        expires_at = _aware_utc(control.expires_at).isoformat()
        public_warrant = {
            "allowed_paths": list(document.allowed_paths),
            "approver_identity": document.approver_identity,
            "authority_snapshot_sha256": document.authority_snapshot_sha256,
            "base_sha": document.base_sha,
            "canonical_warrant_sha256": control.warrant_sha256,
            "environment_digest": document.environment_digest,
            "expires_at": expires_at,
            "format": "crosspatch-public-warrant-anatomy-v1",
            "incident_id": document.incident_id,
            "nonce_sha256": nonce_sha256,
            "patch_sha256": document.patch_sha256,
            "plan_ids": [plan.plan_id for plan in document.execution_plans],
            "repository_manifest_sha256": document.repository_manifest_sha256,
            "reviewed_evidence_manifest_sha256": (document.reviewed_evidence_manifest_sha256),
            "reviewed_timeline_head": document.reviewed_timeline_head,
            "runner_digest": document.runner_digest,
            "test_plan_sha256": document.test_plan_sha256,
            "verdict_sha256": document.verdict_sha256,
            "warrant_id": document.warrant_id,
        }
        public_warrant_bytes = canonical_json(public_warrant)
        published.append(
            {
                "warrant_id": control.id,
                "canonical_sha256": control.warrant_sha256,
                "public_warrant_bytes": public_warrant_bytes.decode("utf-8"),
                "public_warrant_sha256": hashlib.sha256(public_warrant_bytes).hexdigest(),
                "nonce_sha256": nonce_sha256,
                "binding_hashes": {
                    "authority_snapshot_sha256": document.authority_snapshot_sha256,
                    "base_sha": document.base_sha,
                    "environment_digest": document.environment_digest,
                    "patch_sha256": document.patch_sha256,
                    "repository_manifest_sha256": document.repository_manifest_sha256,
                    "reviewed_evidence_manifest_sha256": (
                        document.reviewed_evidence_manifest_sha256
                    ),
                    "reviewed_timeline_head": document.reviewed_timeline_head,
                    "runner_digest": document.runner_digest,
                    "test_plan_sha256": document.test_plan_sha256,
                    "verdict_sha256": document.verdict_sha256,
                },
                "approval_status": control.status,
                "approval_id": control.approval_id,
                "consumption_status": ("NOT_MATERIALIZED" if broker is None else broker.state),
                "execution_status": execution_status,
                "receipt_ids": receipt_ids.get(control.id, []),
                "created_at": _aware_utc(control.created_at).isoformat(),
                "expires_at": expires_at,
                "consumed_at": (
                    None
                    if broker is None or broker.nonce_consumed_at is None
                    else _aware_utc(broker.nonce_consumed_at).isoformat()
                ),
            }
        )
    return published


__all__ = [
    "published_event_details",
    "published_specialist_summaries",
    "published_trusted_observation",
    "published_warrant_history",
]
