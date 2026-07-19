"""Public, sanitized-only API data transfer objects."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from crosspatch.domain.enums import ScenarioId
from crosspatch.domain.hashing import canonical_json, sha256_hex
from crosspatch.publication_policy import is_forbidden_public_key
from crosspatch.runtime.scenarios import EvidenceProfile

_INCIDENT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SCENARIO_IDS = frozenset(get_args(ScenarioId))


class PublicModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class IncidentView(PublicModel):
    id: str = Field(pattern=_INCIDENT_PATTERN)
    title: str = Field(min_length=1, max_length=240)
    scenario: ScenarioId
    state: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    timeline_head: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    pending_warrant_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)


class IncidentCreate(PublicModel):
    scenario: str = Field(pattern=_IDENTIFIER_PATTERN)
    title: str | None = Field(default=None, min_length=1, max_length=240)
    evidence_profile: EvidenceProfile = "standard"


class PublishedVerdictRecordView(PublicModel):
    id: str = Field(pattern=_IDENTIFIER_PATTERN)
    incident_id: str = Field(pattern=_INCIDENT_PATTERN)
    verdict: Literal["CLEAR", "REMAND", "BLOCK", "ABSTAIN"]
    verdict_sha256: str = Field(pattern=_SHA256_PATTERN)
    source: Literal["Magistrate"]
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _aware_created_at(cls, value: datetime) -> datetime:
        return _require_aware_datetime(value)


class PublishedSeatSpendView(PublicModel):
    seat: Literal["Prosecutor", "Inspector", "Counsel", "Magistrate", "Bailiff"]
    effort: Literal["none", "low", "medium", "high", "xhigh"]
    escalation_count: int = Field(ge=0, le=2)
    cost_usd: float = Field(ge=0, allow_inf_nan=False)


class PublishedCaseSummaryView(PublicModel):
    incident_id: str = Field(pattern=_INCIDENT_PATTERN)
    title: str = Field(min_length=1, max_length=240)
    state: Literal["VERIFIED"]
    scenario: ScenarioId
    created_at: datetime
    updated_at: datetime
    revision: int = Field(ge=1)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    verdict_path: tuple[Literal["CLEAR", "REMAND", "BLOCK", "ABSTAIN"], ...] = Field(
        min_length=1
    )
    recorded_cost_usd: float = Field(ge=0, allow_inf_nan=False)
    duration_seconds: float = Field(ge=0, allow_inf_nan=False)
    evidence_to_verified_seconds: float | None = Field(
        default=None, ge=0, allow_inf_nan=False
    )
    human_gate_dwell_seconds: float | None = Field(
        default=None, ge=0, allow_inf_nan=False
    )
    execution_verification_seconds: float | None = Field(
        default=None, ge=0, allow_inf_nan=False
    )
    seat_spend: tuple[PublishedSeatSpendView, ...] = ()


class PublishedCaseListView(PublicModel):
    cases: tuple[PublishedCaseSummaryView, ...]


class PublishedCaseView(PublicModel):
    incident_id: str = Field(pattern=_INCIDENT_PATTERN)
    revision: int = Field(ge=1)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    projection: dict[str, Any]

    @model_validator(mode="after")
    def _validate_projection(self) -> PublishedCaseView:
        expected_keys = {
            "incident",
            "seats",
            "events",
            "verdicts",
            "specialist_summaries",
            "warrants",
            "artifacts",
            "pending_warrant",
        }
        if set(self.projection) != expected_keys:
            raise ValueError("published case projection schema mismatch")
        if sha256_hex(self.projection) != self.manifest_sha256:
            raise ValueError("published case manifest mismatch")
        incident = self.projection.get("incident")
        if not isinstance(incident, dict):
            raise ValueError("published case incident is malformed")
        if incident.get("id") != self.incident_id or incident.get("state") != "VERIFIED":
            raise ValueError("published case must be a matching VERIFIED snapshot")
        if incident.get("scenario") not in _SCENARIO_IDS:
            raise ValueError("published case scenario is not registered")
        if self.projection.get("pending_warrant") is not None:
            raise ValueError("published case cannot expose a pending warrant")
        events = self.projection.get("events")
        if not isinstance(events, list) or any(
            not isinstance(event, dict)
            or event.get("incident_id") != self.incident_id
            or event.get("published") is not True
            for event in events
        ):
            raise ValueError("published case events are malformed")
        artifacts = self.projection.get("artifacts")
        if not isinstance(artifacts, dict) or artifacts.get("warrant") is not None:
            raise ValueError("published case artifacts are malformed")
        evidence = artifacts.get("evidence")
        if not isinstance(evidence, list) or any(
            not isinstance(item, dict) or item.get("classification") != "UNTRUSTED_EVIDENCE"
            for item in evidence
        ):
            raise ValueError("published evidence is malformed")
        diff = artifacts.get("diff")
        if diff is not None and (
            not isinstance(diff, dict) or diff.get("classification") != "UNTRUSTED_EVIDENCE"
        ):
            raise ValueError("published diff is malformed")
        tests = artifacts.get("tests")
        if not isinstance(tests, list):
            raise ValueError("published tests are malformed")
        for test in tests:
            PublishedTestResultView.model_validate(test)
        warrants = self.projection.get("warrants")
        if not isinstance(warrants, list):
            raise ValueError("published warrant history is malformed")
        for warrant in warrants:
            validated = RoomWarrantHistoryView.model_validate(warrant)
            public_warrant = json.loads(validated.public_warrant_bytes)
            if public_warrant.get("incident_id") != self.incident_id:
                raise ValueError("published warrant must bind to the matching incident")
        _validate_public_json(self.projection)
        return self


class PublishedCaseDetailView(PublishedCaseView):
    display_title: str = Field(min_length=1, max_length=240)
    canonical_projection_json: str = Field(min_length=2, max_length=16_777_216)

    @model_validator(mode="after")
    def _validate_canonical_projection(self) -> PublishedCaseDetailView:
        encoded = self.canonical_projection_json.encode("utf-8")
        if hashlib.sha256(encoded).hexdigest() != self.manifest_sha256:
            raise ValueError("published canonical projection manifest mismatch")
        try:
            parsed = json.loads(self.canonical_projection_json)
        except (TypeError, ValueError) as error:
            raise ValueError("published canonical projection is malformed") from error
        if not isinstance(parsed, dict) or parsed != self.projection:
            raise ValueError("published canonical projection disagrees with projection")
        if canonical_json(parsed) != encoded or canonical_json(self.projection) != encoded:
            raise ValueError("published canonical projection bytes are not canonical")
        return self


class EvidenceView(PublicModel):
    classification: Literal["UNTRUSTED_EVIDENCE"] = "UNTRUSTED_EVIDENCE"
    id: str = Field(pattern=_IDENTIFIER_PATTERN)
    incident_id: str = Field(pattern=_INCIDENT_PATTERN)
    kind: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    provenance: str = Field(min_length=1, max_length=512)
    text: str
    sanitized_sha256: str = Field(pattern=_SHA256_PATTERN)
    tags: tuple[str, ...] = ()
    published: bool


class PublishedEvent(PublicModel):
    id: str = Field(pattern=_IDENTIFIER_PATTERN)
    incident_id: str = Field(pattern=_INCIDENT_PATTERN)
    sequence: int = Field(ge=1)
    type: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    actor: str = Field(pattern=_IDENTIFIER_PATTERN)
    summary: str = Field(max_length=16_384)
    details: dict[str, Any]
    event_hash: str = Field(pattern=_SHA256_PATTERN)
    created_at: datetime
    published: bool

    @field_validator("details")
    @classmethod
    def _details_are_public_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_public_json(value)
        return value


class WarrantView(PublicModel):
    id: str = Field(pattern=_IDENTIFIER_PATTERN)
    incident_id: str = Field(pattern=_INCIDENT_PATTERN)
    status: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    canonical_document: str = Field(min_length=2, max_length=1_048_576)
    warrant_sha256: str = Field(pattern=_SHA256_PATTERN)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def _aware_expiry(cls, value: datetime) -> datetime:
        return _require_aware_datetime(value)

    @model_validator(mode="after")
    def _document_matches_hash(self) -> WarrantView:
        actual = hashlib.sha256(self.canonical_document.encode("utf-8")).hexdigest()
        if actual != self.warrant_sha256:
            raise ValueError("canonical warrant document hash mismatch")
        return self


class WarrantDecisionRequest(PublicModel):
    confirmation: Literal["APPROVE", "REJECT"]
    warrant_sha256: str = Field(pattern=_SHA256_PATTERN)
    reason: str | None = Field(default=None, min_length=1, max_length=2_000)

    @model_validator(mode="after")
    def _approval_has_no_rejection_reason(self) -> WarrantDecisionRequest:
        if self.confirmation == "APPROVE" and self.reason is not None:
            raise ValueError("APPROVE cannot include a rejection reason")
        return self


class WarrantRevisionRequest(PublicModel):
    confirmation: Literal["REQUEST_REVISION"]
    warrant_sha256: str = Field(pattern=_SHA256_PATTERN)
    comment: str = Field(min_length=1, max_length=2_000)


class JudgeTokenRotateRequest(PublicModel):
    confirmation: Literal["ROTATE"]
    incident_id: str | None = Field(default=None, pattern=_INCIDENT_PATTERN)


class JudgeTokenRevokeRequest(PublicModel):
    confirmation: Literal["REVOKE"]


class JudgeTokenView(PublicModel):
    token: str = Field(min_length=32, max_length=1024)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def _aware_expiry(cls, value: datetime) -> datetime:
        return _require_aware_datetime(value)


class JudgeTokenMetadataView(PublicModel):
    token_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    expires_at: datetime
    revoked: bool
    created_at: datetime
    revoked_at: datetime | None = None

    @field_validator("expires_at", "created_at", "revoked_at")
    @classmethod
    def _aware_timestamps(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _require_aware_datetime(value)


class JudgeTokenListView(PublicModel):
    tokens: tuple[JudgeTokenMetadataView, ...]


class LiveTrialCredentialRotateRequest(PublicModel):
    confirmation: Literal["ROTATE"]


class LiveTrialCredentialRevokeRequest(PublicModel):
    confirmation: Literal["REVOKE"]


class LiveTrialCredentialView(PublicModel):
    token: str = Field(min_length=32, max_length=1024)
    subject: str = Field(pattern=_IDENTIFIER_PATTERN)
    expires_at: datetime
    global_budget_cap_usd: Decimal = Field(gt=0)

    @field_validator("expires_at")
    @classmethod
    def _aware_expiry(cls, value: datetime) -> datetime:
        return _require_aware_datetime(value)


class RoomIncidentView(PublicModel):
    id: str = Field(pattern=_INCIDENT_PATTERN)
    title: str = Field(min_length=1, max_length=240)
    state: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    severity: str = Field(min_length=1, max_length=32)
    scenario: ScenarioId
    base_sha: str = Field(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
    created_at: datetime
    updated_at: datetime


class RoomSeatView(PublicModel):
    name: Literal["Prosecutor", "Inspector", "Counsel", "Magistrate", "Bailiff"]
    role: str = Field(min_length=1, max_length=240)
    model: str = Field(min_length=1, max_length=64)
    tier_rationale: str = Field(min_length=1, max_length=240)
    effort: Literal["none", "low", "medium", "high", "xhigh"]
    escalation_count: int = Field(ge=0, le=2)
    state: Literal["idle", "working", "complete", "failed", "abstained"]


class RoomSpecialistSummaryBase(PublicModel):
    run_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    model: str = Field(min_length=1, max_length=64)
    effort: Literal["none", "low", "medium", "high", "xhigh"]
    escalation_count: int = Field(ge=0, le=2)
    phase: str = Field(min_length=1, max_length=64)
    output_sha256: str = Field(pattern=_SHA256_PATTERN)
    semantic_sha256: str = Field(pattern=_SHA256_PATTERN)
    created_at: datetime
    sanitization_tags: tuple[str, ...] = ()


class RoomInspectorSummaryView(RoomSpecialistSummaryBase):
    kind: Literal["INSPECTOR"]
    seat: Literal["Inspector"]
    mechanism: str = Field(min_length=1, max_length=128)
    evidence_ids: tuple[str, ...] = ()
    falsifiers: tuple[str, ...] = ()


class RoomProsecutorSummaryView(RoomSpecialistSummaryBase):
    kind: Literal["PROSECUTOR"]
    seat: Literal["Prosecutor"]
    outcome: Literal["SUPPORTED_RIVAL", "NO_SUPPORTED_RIVAL"]
    rival_mechanism: str | None = Field(default=None, max_length=128)
    counterexample_ids: tuple[str, ...] = ()
    test_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()


class RoomTestIntentionView(PublicModel):
    catalog_id: str = Field(min_length=1, max_length=256)
    purpose: str = Field(min_length=1, max_length=16_384)


class RoomCounselSummaryView(RoomSpecialistSummaryBase):
    kind: Literal["COUNSEL"]
    seat: Literal["Counsel"]
    candidate_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    patch_sha256: str = Field(pattern=_SHA256_PATTERN)
    patch_defense: str = Field(max_length=16_384)
    evidence_ids: tuple[str, ...] = ()
    test_intentions: tuple[RoomTestIntentionView, ...] = ()


RoomSpecialistSummaryView = Annotated[
    RoomInspectorSummaryView | RoomProsecutorSummaryView | RoomCounselSummaryView,
    Field(discriminator="kind"),
]


class RoomWarrantBindingHashesView(PublicModel):
    authority_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    base_sha: str = Field(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
    environment_digest: str = Field(pattern=_SHA256_PATTERN)
    patch_sha256: str = Field(pattern=_SHA256_PATTERN)
    repository_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    reviewed_evidence_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    reviewed_timeline_head: str = Field(pattern=_SHA256_PATTERN)
    runner_digest: str = Field(pattern=_SHA256_PATTERN)
    test_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    verdict_sha256: str = Field(pattern=_SHA256_PATTERN)


class RoomWarrantHistoryView(PublicModel):
    warrant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    canonical_sha256: str = Field(pattern=_SHA256_PATTERN)
    public_warrant_bytes: str = Field(min_length=2, max_length=65_536)
    public_warrant_sha256: str = Field(pattern=_SHA256_PATTERN)
    nonce_sha256: str = Field(pattern=_SHA256_PATTERN)
    binding_hashes: RoomWarrantBindingHashesView
    approval_status: Literal["PENDING_APPROVAL", "APPROVED", "REJECTED", "EXPIRED"]
    approval_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    consumption_status: Literal[
        "NOT_MATERIALIZED",
        "APPROVED",
        "CONSUMING",
        "CONSUMED",
        "REJECTED",
        "EXPIRED",
    ]
    execution_status: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    receipt_ids: tuple[str, ...] = ()
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None

    @model_validator(mode="after")
    def _validate_public_warrant_bytes(self) -> RoomWarrantHistoryView:
        encoded = self.public_warrant_bytes.encode("utf-8")
        if hashlib.sha256(encoded).hexdigest() != self.public_warrant_sha256:
            raise ValueError("public warrant anatomy hash mismatch")
        try:
            parsed = json.loads(self.public_warrant_bytes)
        except (TypeError, ValueError) as error:
            raise ValueError("public warrant anatomy is malformed") from error
        if not isinstance(parsed, dict) or canonical_json(parsed) != encoded:
            raise ValueError("public warrant anatomy bytes are not canonical")
        expected = {
            "authority_snapshot_sha256": self.binding_hashes.authority_snapshot_sha256,
            "base_sha": self.binding_hashes.base_sha,
            "canonical_warrant_sha256": self.canonical_sha256,
            "environment_digest": self.binding_hashes.environment_digest,
            "expires_at": self.expires_at.isoformat(),
            "nonce_sha256": self.nonce_sha256,
            "patch_sha256": self.binding_hashes.patch_sha256,
            "repository_manifest_sha256": (
                self.binding_hashes.repository_manifest_sha256
            ),
            "reviewed_evidence_manifest_sha256": (
                self.binding_hashes.reviewed_evidence_manifest_sha256
            ),
            "reviewed_timeline_head": self.binding_hashes.reviewed_timeline_head,
            "runner_digest": self.binding_hashes.runner_digest,
            "test_plan_sha256": self.binding_hashes.test_plan_sha256,
            "verdict_sha256": self.binding_hashes.verdict_sha256,
            "warrant_id": self.warrant_id,
        }
        expected_keys = {
            *expected,
            "allowed_paths",
            "approver_identity",
            "format",
            "incident_id",
            "plan_ids",
        }
        if set(parsed) != expected_keys or any(
            parsed.get(key) != value for key, value in expected.items()
        ):
            raise ValueError("public warrant anatomy disagrees with bound history")
        if parsed.get("format") != "crosspatch-public-warrant-anatomy-v1":
            raise ValueError("public warrant anatomy format mismatch")
        allowed_paths = parsed.get("allowed_paths")
        plan_ids = parsed.get("plan_ids")
        if (
            not isinstance(allowed_paths, list)
            or not allowed_paths
            or not all(isinstance(item, str) and item for item in allowed_paths)
            or not isinstance(plan_ids, list)
            or not plan_ids
            or not all(isinstance(item, str) and item for item in plan_ids)
            or not isinstance(parsed.get("approver_identity"), str)
        ):
            raise ValueError("public warrant anatomy annotations are malformed")
        _validate_public_json(parsed)
        return self


class RoomEvidenceView(PublicModel):
    classification: Literal["UNTRUSTED_EVIDENCE"] = "UNTRUSTED_EVIDENCE"
    id: str = Field(pattern=_IDENTIFIER_PATTERN)
    incident_id: str = Field(pattern=_INCIDENT_PATTERN)
    provenance: str = Field(min_length=1, max_length=512)
    kind: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    sanitized_sha256: str = Field(pattern=_SHA256_PATTERN)
    captured_at: datetime
    text: str
    tags: tuple[str, ...] = ()


class TrustedObservationCountsView(PublicModel):
    receipts: int = Field(ge=0, strict=True)
    jobs: int = Field(ge=0, strict=True)
    deliveries: int = Field(ge=0, strict=True)


class TrustedObservationView(PublicModel):
    counts: TrustedObservationCountsView
    response_statuses: tuple[
        Annotated[int, Field(ge=100, le=599, strict=True)], ...
    ] = Field(min_length=1, max_length=32)


class RoomTestView(PublicModel):
    id: str = Field(pattern=_IDENTIFIER_PATTERN)
    label: str = Field(min_length=1, max_length=240)
    state: Literal["pending", "running", "passed", "failed"]
    duration_ms: int | None = Field(default=None, ge=0)
    detail: str | None = Field(default=None, max_length=16_384)
    receipt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    trusted_observation: TrustedObservationView | None = None
    trusted_observation_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )

    @model_validator(mode="after")
    def _trusted_observation_digest_matches(self) -> RoomTestView:
        if (self.trusted_observation is None) != (
            self.trusted_observation_sha256 is None
        ):
            raise ValueError("trusted observation and digest must be present together")
        if self.trusted_observation is not None and not hmac.compare_digest(
            sha256_hex(self.trusted_observation.model_dump(mode="json")),
            self.trusted_observation_sha256 or "",
        ):
            raise ValueError("trusted observation digest mismatch")
        return self


class PublishedTestResultView(RoomTestView):
    plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    passed: bool | None = None
    warrant_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    evidence_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)


class RoomDiffView(PublicModel):
    classification: Literal["UNTRUSTED_EVIDENCE"] = "UNTRUSTED_EVIDENCE"
    incident_id: str = Field(pattern=_INCIDENT_PATTERN)
    candidate_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    patch_sha256: str = Field(pattern=_SHA256_PATTERN)
    text: str
    sanitized_sha256: str = Field(pattern=_SHA256_PATTERN)
    tags: tuple[str, ...] = ()
    created_at: datetime


class RoomArtifactsView(PublicModel):
    evidence: tuple[RoomEvidenceView, ...] = ()
    diff: RoomDiffView | None = None
    tests: tuple[RoomTestView, ...] = ()
    warrant: WarrantView | None = None


class IncidentRoomView(PublicModel):
    viewer_role: Literal["read_only", "operator", "approver", "live_trial"] = "read_only"
    incident: RoomIncidentView
    seats: tuple[RoomSeatView, ...] = Field(min_length=5, max_length=5)
    events: tuple[PublishedEvent, ...] = ()
    specialist_summaries: tuple[RoomSpecialistSummaryView, ...] = ()
    warrants: tuple[RoomWarrantHistoryView, ...] = ()
    artifacts: RoomArtifactsView
    pending_warrant: WarrantView | None = None


def _validate_public_json(value: Any, *, depth: int = 0) -> None:
    if depth > 16:
        raise ValueError("public event details exceed the nesting limit")
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError("public event detail keys must be strings")
            if is_forbidden_public_key(key):
                raise ValueError("public event details cannot contain private fields")
            _validate_public_json(nested, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _validate_public_json(nested, depth=depth + 1)
    elif value is None or isinstance(value, (str, int, float, bool)):
        try:
            json.dumps(value, allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError("public event details must be finite JSON") from error
    else:
        raise ValueError("public event details must be JSON")


def _require_aware_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("expiry must be timezone-aware")
    return value
