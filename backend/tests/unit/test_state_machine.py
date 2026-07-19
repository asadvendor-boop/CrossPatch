from copy import deepcopy

import pytest
from crosspatch.domain.enums import IncidentState, RetryDisposition, Seat, Verdict
from crosspatch.domain.hashing import classify_retry, semantic_fingerprint
from crosspatch.domain.schemas import CounselOutput, ProsecutorOutput
from crosspatch.domain.state_machine import (
    Event,
    InvalidTransition,
    transition_incident,
    verdict_for_failure,
)
from pydantic import ValidationError

FAIL_CLOSED_REASONS = [
    "refusal",
    "cutoff",
    "truncated",
    "incomplete_response",
    "timeout",
    "network_failure",
    "invalid_schema",
    "missing_evidence_references",
    "sdk_exception",
    "guardrail_stop",
    "unknown_verdict",
]


@pytest.mark.parametrize("failure", FAIL_CLOSED_REASONS)
def test_every_model_failure_maps_to_abstain(failure):
    assert verdict_for_failure(failure) is Verdict.ABSTAIN


def test_unknown_failure_reason_also_fails_closed():
    assert verdict_for_failure("future-sdk-failure") is Verdict.ABSTAIN


def test_only_clear_can_enter_approval_pending():
    assert (
        transition_incident(IncidentState.REVIEWING, Event.verdict(Verdict.CLEAR))
        is IncidentState.APPROVAL_PENDING
    )

    non_clear_events = (
        Event.verdict(Verdict.REMAND, Seat.INSPECTOR),
        Event.verdict(Verdict.BLOCK),
        Event.verdict(Verdict.ABSTAIN),
    )
    for event in non_clear_events:
        assert (
            transition_incident(IncidentState.REVIEWING, event)
            is not IncidentState.APPROVAL_PENDING
        )


def test_verdict_outside_review_is_rejected():
    with pytest.raises(InvalidTransition):
        transition_incident(IncidentState.EVIDENCE_READY, Event.verdict(Verdict.CLEAR))


def test_untyped_or_malformed_authority_events_cannot_advance_state():
    with pytest.raises(InvalidTransition, match="typed verdict"):
        transition_incident(
            IncidentState.REVIEWING,
            Event(type="VERDICT", payload={"verdict": "CLEAR"}),
        )


def test_typed_human_revision_reopens_only_the_pending_approval_cycle():
    event = Event.revision_requested(
        warrant_id="war_revision_1",
        warrant_sha256="a" * 64,
        evidence_id="ev_revision_1",
    )
    assert (
        transition_incident(IncidentState.APPROVAL_PENDING, event)
        is IncidentState.PATCHING
    )
    with pytest.raises(InvalidTransition):
        transition_incident(IncidentState.VERIFIED, event)


def test_verified_is_terminal_for_every_state_changing_event():
    events = (
        Event(type="REPRODUCTION_STARTED"),
        Event(type="EVIDENCE_CAPTURED"),
        Event(type="REPRODUCTION_PASSED"),
        Event(type="REPRODUCTION_INCONCLUSIVE"),
        Event(type="ANALYSIS_STARTED"),
        Event(type="PATCH_REQUESTED"),
        Event(type="PATCH_PROPOSED"),
        Event.verdict(Verdict.CLEAR),
        Event.warrant_approved(
            approval_id="approval-terminal",
            warrant_sha256="a" * 64,
            approver_identity="operator-terminal",
        ),
        Event.warrant_expired(
            warrant_id="warrant-terminal",
            warrant_sha256="b" * 64,
        ),
        Event.revision_requested(
            warrant_id="warrant-terminal",
            warrant_sha256="c" * 64,
            evidence_id="evidence-terminal",
        ),
        Event.execution_started(
            claim_id="claim-terminal",
            warrant_id="warrant-terminal",
        ),
        Event(type="TEST_FAILED"),
        Event(type="RETRY_STARTED"),
        Event.verified(
            receipt_id="receipt-terminal",
            warrant_id="warrant-terminal",
        ),
        Event(type="BACKGROUND_TASK_FAILED"),
        Event.execution_failed(
            warrant_id="warrant-terminal",
            error_code="TERMINAL_STATE",
        ),
    )
    for event in events:
        with pytest.raises(InvalidTransition):
            transition_incident(IncidentState.VERIFIED, event)
    with pytest.raises(InvalidTransition, match="approval proof"):
        transition_incident(
            IncidentState.APPROVAL_PENDING,
            Event(type="WARRANT_APPROVED", payload={}),
        )


def test_remand_requires_a_valid_target_and_approval_requires_proof():
    with pytest.raises(ValueError, match="target"):
        Event.verdict(Verdict.REMAND)
    with pytest.raises(ValueError, match="target"):
        Event.verdict(Verdict.REMAND, Seat.BAILIFF)

    approved = Event.warrant_approved(
        approval_id="approval-1",
        warrant_sha256="a" * 64,
        approver_identity="operator-1",
    )
    assert transition_incident(IncidentState.APPROVAL_PENDING, approved) is IncidentState.APPROVED


def test_higher_effort_retry_with_same_inspector_semantics_is_rejected():
    first = semantic_fingerprint(
        Seat.INSPECTOR,
        {
            "mechanism": "check then insert",
            "evidence_ids": ["e2", "e1"],
            "falsifiers": ["unique index already active"],
            "analysis": "first explanation",
        },
    )
    retry = semantic_fingerprint(
        Seat.INSPECTOR,
        {
            "mechanism": "  CHECK   THEN INSERT ",
            "evidence_ids": ["e1", "e2"],
            "falsifiers": ["unique index already active"],
            "analysis": "a polished paraphrase",
            "request_id": "req-new",
            "timestamp": "2026-07-14T00:00:00Z",
        },
    )

    assert classify_retry(first, retry) is RetryDisposition.FAILED_RETRY_DUPLICATE


def test_mechanism_paraphrase_cannot_evade_duplicate_retry_detection():
    first = semantic_fingerprint(
        Seat.INSPECTOR,
        {"mechanism": "check then insert", "evidence_ids": ["e1"], "falsifiers": []},
    )
    paraphrase = semantic_fingerprint(
        Seat.INSPECTOR,
        {
            "mechanism": "insert only after checking",
            "evidence_ids": ["e1"],
            "falsifiers": [],
        },
    )

    assert classify_retry(first, paraphrase) is RetryDisposition.FAILED_RETRY_DUPLICATE


MATERIAL_OUTPUTS = {
    Seat.INSPECTOR: {
        "mechanism": "check then insert",
        "evidence_ids": ["e1"],
        "falsifiers": ["f1"],
    },
    Seat.PROSECUTOR: {
        "outcome": "SUPPORTED_RIVAL",
        "rival_mechanism": "worker retry",
        "counterexample_ids": ["ce1"],
        "test_ids": ["t1"],
    },
    Seat.COUNSEL: {
        "normalized_diff": "--- a/x\n+++ b/x\n@@\n-old\n+new\n",
        "test_intentions": [{"catalog_id": "race", "purpose": "prove exactly once"}],
    },
    Seat.MAGISTRATE: {
        "verdict": "REMAND",
        "finding_codes": ["MISSING_NEGATIVE_CONTROL"],
        "required_changes": [{"code": "ADD_TEST", "target": "Counsel"}],
        "remand_target": "Counsel",
    },
}


@pytest.mark.parametrize(
    "seat,changed_field,replacement",
    [
        (Seat.INSPECTOR, "mechanism", "late receipt insert"),
        (Seat.PROSECUTOR, "counterexample_ids", ["ce2"]),
        (Seat.COUNSEL, "normalized_diff", "--- a/x\n+++ b/x\n@@\n-old\n+other\n"),
        (Seat.MAGISTRATE, "finding_codes", ["UNSAFE_SCOPE"]),
    ],
)
def test_material_fields_change_seat_fingerprint(seat, changed_field, replacement):
    original = MATERIAL_OUTPUTS[seat]
    changed = deepcopy(original)
    changed[changed_field] = replacement

    assert semantic_fingerprint(seat, original) != semantic_fingerprint(seat, changed)


def test_prosecutor_schema_is_a_strict_discriminated_union():
    schema = ProsecutorOutput.model_json_schema()
    assert schema["type"] == "object"
    assert schema["properties"]["root"]["discriminator"]["propertyName"] == "outcome"

    parsed = ProsecutorOutput.model_validate(
        {
            "root": {
                "outcome": "NO_SUPPORTED_RIVAL",
                "counterexample_ids": ["no-supported-rival"],
                "test_ids": ["race-two-way"],
                "evidence_ids": ["ev-1"],
                "analysis": "No evidence-backed alternative survived.",
            }
        }
    )
    assert parsed.root.outcome == "NO_SUPPORTED_RIVAL"

    with pytest.raises(ValidationError):
        ProsecutorOutput.model_validate(
            {
                "root": {
                    "outcome": "NO_SUPPORTED_RIVAL",
                    "rival_mechanism": "forbidden on this branch",
                    "counterexample_ids": [],
                    "test_ids": [],
                    "analysis": "invalid",
                }
            }
        )


def test_counsel_schema_structurally_forbids_commands_and_test_source():
    schema = str(CounselOutput.model_json_schema()).lower()
    assert all(term not in schema for term in ("argv", "command", "test_code", "test_source"))

    with pytest.raises(ValidationError):
        CounselOutput.model_validate(
            {
                "normalized_diff": "--- a/x\n+++ b/x\n",
                "test_intentions": [],
                "argv": ["pytest"],
            }
        )
