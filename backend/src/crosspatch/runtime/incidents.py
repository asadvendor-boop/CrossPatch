"""Real bundled-incident launcher; every model-visible byte passes the sanitizer."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from crosspatch.agents.schemas import (
    CounselOutput,
    InspectorOutput,
    MagistrateOutput,
    ProsecutorOutput,
)
from crosspatch.broker.broker import BrokerStatus
from crosspatch.domain.enums import Effort, Seat
from crosspatch.domain.seats import SEAT_SPECS
from crosspatch.evidence.artifacts import ArtifactStore
from crosspatch.evidence.service import EvidenceService
from crosspatch.evidence.views import EvidenceKind, UntrustedEvidenceEnvelope
from crosspatch.orchestration.coordinator import Coordinator, IncidentInput
from crosspatch.runner.reproduction import ReproductionResult
from crosspatch.runtime.authority import DatabaseAuthorityGateway
from crosspatch.runtime.database import RuntimeStore
from crosspatch.runtime.scenarios import require_operator_scenario


class Reproducer(Protocol):
    async def run(self, *, event_id: str) -> ReproductionResult: ...


class BundledScenarioBindingError(ValueError):
    """Persisted scenario state cannot select its server-owned reproducer."""


class BundledIncidentLauncher:
    """Run the persisted bundled scenario and sanitize every model-visible byte."""

    def __init__(
        self,
        *,
        store: RuntimeStore,
        authority: DatabaseAuthorityGateway,
        coordinator: Coordinator | None,
        reproduction_factories: Mapping[str, Callable[[], Reproducer]],
        raw_artifact_root: Path,
        sanitized_artifact_root: Path,
        openai_api_key: str | None,
        secret_values: tuple[str, ...] = (),
        source_root: Path | None = None,
    ) -> None:
        self._store = store
        self._authority = authority
        self._coordinator = coordinator
        self._reproduction_factories = dict(reproduction_factories)
        self._raw_artifact_root = raw_artifact_root
        self._sanitized_artifact_root = sanitized_artifact_root
        self._openai_api_key = openai_api_key.strip() if openai_api_key else None
        self._secret_values = tuple(value for value in secret_values if value)
        self._source_root = (source_root or authority.policy.repository_root).resolve(strict=True)

    _REPRODUCTION_PROVENANCE = {
        "webhook-race": "deterministic webhook race reproduction",
        "webhook-race:instruction-like-log": (
            "deterministic webhook race reproduction with database-observed log"
        ),
        "webhook-payload-equivalence": ("deterministic webhook payload-equivalence reproduction"),
    }

    def _source_evidence(
        self,
        source_paths: tuple[str, ...],
    ) -> tuple[tuple[str, bytes], ...]:
        """Read actual bundled source for this incident, never a fixture or model text."""
        sources: list[tuple[str, bytes]] = []
        for relative in source_paths:
            path = (self._source_root / relative).resolve(strict=True)
            if not path.is_relative_to(self._source_root) or not path.is_file():
                raise RuntimeError(f"bundled incident source is unavailable: {relative}")
            sources.append((relative, path.read_bytes()))
        return tuple(sources)

    @staticmethod
    def _result_document(result: ReproductionResult) -> dict[str, Any]:
        document = {
            "outcome": result.outcome.value,
            "lock_state_reached": result.lock_state_reached,
            "counts": result.counts,
            "response_statuses": list(result.response_statuses),
            "diagnostics": list(result.diagnostics),
        }
        if result.observed_log_entries:
            document["observed_log_entries"] = list(result.observed_log_entries)
        return document

    async def launch(self, incident_id: str) -> None:
        incident = await self._store.get_incident_record(incident_id)
        if incident is None:
            raise LookupError(incident_id)
        try:
            definition = require_operator_scenario(incident.scenario)
            evidence_profile = await self._store.incident_evidence_profile(incident_id)
            factory_key = (
                definition.scenario_id
                if evidence_profile == "standard"
                else f"{definition.scenario_id}:{evidence_profile}"
            )
            reproduction_factory = self._reproduction_factories[factory_key]
            provenance = self._REPRODUCTION_PROVENANCE[factory_key]
        except (KeyError, ValueError) as error:
            raise BundledScenarioBindingError(
                f"bundled scenario binding is unavailable: {incident.scenario}"
            ) from error
        reproduction_started = {"scenario": definition.scenario_id}
        if evidence_profile != "standard":
            reproduction_started["evidence_profile"] = evidence_profile
        await self._store.append_event(
            incident_id,
            "REPRODUCTION_STARTED",
            "deterministic-runner",
            reproduction_started,
        )
        try:
            result = await reproduction_factory().run(event_id=f"crosspatch-{uuid4().hex}")
            document = self._result_document(result)
        except Exception as error:
            # This is genuine failure evidence, not a substitute reproduction result.
            document = {
                "outcome": "INFRA_INCONCLUSIVE",
                "error_type": type(error).__name__,
                "error": str(error),
            }

        raw = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        artifacts = ArtifactStore(
            self._raw_artifact_root,
            self._sanitized_artifact_root,
            incident_id=incident_id,
        )
        evidence_service = EvidenceService(
            artifacts,
            secret_values=self._secret_values,
        )
        evidence_id = f"ev_{uuid4().hex}"
        envelope = evidence_service.ingest(
            kind=EvidenceKind.TEST_OUTPUT,
            raw_bytes=raw,
            provenance=provenance,
            evidence_id=evidence_id,
        )
        await self._store.record_evidence(evidence_id, envelope, published=True)
        await self._store.append_event(
            incident_id,
            "EVIDENCE_CAPTURED",
            "deterministic-runner",
            {
                "evidence_id": evidence_id,
                "outcome": document["outcome"],
                "sanitized_sha256": envelope.sanitized_sha256,
            },
        )

        if document["outcome"] == "PASSED":
            await self._store.append_event(
                incident_id,
                "REPRODUCTION_PASSED",
                "deterministic-runner",
                {"evidence_id": evidence_id},
            )
            return
        if document["outcome"] == "INFRA_INCONCLUSIVE":
            await self._store.append_event(
                incident_id,
                "REPRODUCTION_INCONCLUSIVE",
                "deterministic-runner",
                {"evidence_id": evidence_id},
            )
            return

        if self._coordinator is None:
            await self._authority.begin_review(incident_id)
            await self._authority.fail_closed_abstain(
                incident_id,
                reason="sdk_exception",
                failure_code=(
                    "OPENAI_API_KEY_MISSING"
                    if self._openai_api_key is None
                    else "AGENT_RUNTIME_UNAVAILABLE"
                ),
            )
            return
        evidence = [envelope]
        # These are fresh reads of the real source bundled with the reproducible
        # incident. They remain untrusted, sanitizer-tagged evidence, not trusted
        # prompt text or a seeded answer.
        for relative, source_bytes in self._source_evidence(definition.source_paths):
            source_id = f"ev_{uuid4().hex}"
            source_envelope = evidence_service.ingest(
                kind=EvidenceKind.SOURCE,
                raw_bytes=source_bytes,
                provenance=f"bundled incident source: {relative}",
                evidence_id=source_id,
            )
            await self._store.record_evidence(source_id, source_envelope, published=True)
            evidence.append(source_envelope)
        await self._coordinator.run_incident(
            IncidentInput(
                incident_id=incident_id,
                scenario=definition.scenario_id,
                candidate_plan_id=definition.candidate_plan_id,
                evidence=tuple(evidence),
            )
        )

    async def execute_approved(self, incident_id: str, warrant_id: str) -> None:
        """Compatibility entrypoint that drains both durable work stages."""
        result = await self.execute_approved_only(incident_id, warrant_id)
        if result is not None and result.status is BrokerStatus.TEST_FAILED:
            await self.repair_failed(incident_id, warrant_id)

    async def execute_approved_only(
        self,
        incident_id: str,
        warrant_id: str,
    ) -> Any | None:
        """Execute or recover one approval without replaying consumed authority."""
        try:
            projected = await self._store.projected_broker_result(
                incident_id,
                warrant_id,
            )
        except (TypeError, ValueError):
            await self._store.record_execution_failure(
                incident_id,
                warrant_id,
                error_code="BROKER_RESULT_INVALID",
            )
            return None
        if projected is not None:
            return projected
        try:
            raw_result = await self._store.completed_broker_result_bytes(
                incident_id,
                warrant_id,
            )
            bailiff_failure = None
        except LookupError:
            if self._coordinator is None:
                await self._store.record_execution_failure(
                    incident_id,
                    warrant_id,
                    error_code="AGENT_RUNTIME_UNAVAILABLE",
                )
                return None
            try:
                await self._coordinator.resume_after_approval(incident_id, warrant_id)
            except Exception as error:
                # The model-facing return is never execution authority. A broker may
                # have completed before an SDK transport failure, so read its durable
                # result before deciding whether the incident must fail closed.
                bailiff_failure = type(error).__name__
            else:
                bailiff_failure = None
            try:
                raw_result = await self._store.completed_broker_result_bytes(
                    incident_id,
                    warrant_id,
                )
            except LookupError:
                await self._store.record_execution_failure(
                    incident_id,
                    warrant_id,
                    error_code=(
                        "BAILIFF_MODEL_FAILURE"
                        if bailiff_failure is not None
                        else "BROKER_RESULT_INVALID"
                    ),
                )
                return None
        try:
            artifacts = ArtifactStore(
                self._raw_artifact_root,
                self._sanitized_artifact_root,
                incident_id=incident_id,
            )
            evidence_id = f"ev_{uuid4().hex}"
            envelope = EvidenceService(
                artifacts,
                secret_values=self._secret_values,
            ).ingest(
                kind=EvidenceKind.TEST_OUTPUT,
                raw_bytes=raw_result,
                provenance="deterministic mutation broker receipt",
                evidence_id=evidence_id,
            )
            await self._store.record_evidence(evidence_id, envelope, published=True)
            broker_result = await self._store.project_broker_result(
                incident_id,
                warrant_id,
                evidence_id=evidence_id,
            )
        except (TypeError, ValueError):
            await self._store.record_execution_failure(
                incident_id,
                warrant_id,
                error_code=(
                    "BAILIFF_MODEL_FAILURE"
                    if bailiff_failure is not None
                    else "BROKER_RESULT_INVALID"
                ),
            )
            return None
        await self._store.append_event(
            incident_id,
            "BAILIFF_COMPLETED",
            "Bailiff",
            {
                "warrant_id": warrant_id,
                "status": broker_result.status.value,
            },
        )
        return broker_result

    async def repair_failed(self, incident_id: str, warrant_id: str) -> None:
        """Resume a durable failed-test cycle and close it only on authority state."""
        incident = await self._store.get_incident_record(incident_id)
        if incident is None:
            raise LookupError(incident_id)
        definition = require_operator_scenario(incident.scenario)
        if await self._store.repair_has_durable_outcome(incident_id, warrant_id):
            await self._store.complete_repair_work(incident_id, warrant_id)
            return
        try:
            await self._restore_outputs(incident_id)
            if self._coordinator is None:
                raise RuntimeError("agent runtime is unavailable")
            evidence = tuple(
                UntrustedEvidenceEnvelope.model_validate_json(record.envelope_json)
                for record in await self._store.evidence_records(incident_id)
            )
            await self._coordinator.resume_after_test(
                IncidentInput(
                    incident_id=incident_id,
                    scenario=definition.scenario_id,
                    candidate_plan_id=definition.candidate_plan_id,
                    evidence=evidence,
                ),
                test_passed=False,
            )
        except Exception as error:
            # The broker execution itself completed and its failed receipt is
            # already durable. A repair-orchestration failure is therefore a
            # model/control-plane event, not an execution failure. Keep the
            # diagnostic event non-state-changing so the typed ABSTAIN below
            # performs the only fail-closed transition from TEST_FAILED/PATCHING.
            await self._store.append_event(
                incident_id,
                "REPAIR_CYCLE_FAILED",
                "orchestrator",
                {
                    "warrant_id": warrant_id,
                    "error_code": f"REPAIR_{type(error).__name__.upper()}",
                },
            )
            await self._authority.fail_closed_abstain(
                incident_id,
                reason="sdk_exception",
                failure_code="REPAIR_CYCLE_FAILED",
            )
        await self._store.complete_repair_work(incident_id, warrant_id)

    async def request_revision(
        self,
        *,
        incident_id: str,
        warrant_id: str,
        warrant_sha256: str,
        comment: str,
        actor: str,
    ) -> Any:
        await self.prepare_revision(
            incident_id=incident_id,
            warrant_id=warrant_id,
            warrant_sha256=warrant_sha256,
            comment=comment,
            actor=actor,
        )
        return await self.resume_revision(incident_id)

    async def prepare_revision(
        self,
        *,
        incident_id: str,
        warrant_id: str,
        warrant_sha256: str,
        comment: str,
        actor: str,
    ) -> None:
        if self._coordinator is None:
            raise RuntimeError("agent runtime is unavailable")
        artifacts = ArtifactStore(
            self._raw_artifact_root,
            self._sanitized_artifact_root,
            incident_id=incident_id,
        )
        evidence_id = f"ev_{uuid4().hex}"
        guidance = EvidenceService(
            artifacts,
            secret_values=self._secret_values,
        ).ingest(
            kind=EvidenceKind.COMMENT,
            raw_bytes=comment.encode("utf-8"),
            provenance=f"live-trial revision request by {actor}",
            evidence_id=evidence_id,
        )
        await self._authority.request_revision(
            warrant_id=warrant_id,
            warrant_sha256=warrant_sha256,
            guidance=guidance,
            actor=actor,
        )

    async def resume_revision(self, incident_id: str) -> Any:
        if self._coordinator is None:
            raise RuntimeError("agent runtime is unavailable")
        incident = await self._store.get_incident_record(incident_id)
        if incident is None:
            raise LookupError(incident_id)
        definition = require_operator_scenario(incident.scenario)
        await self._restore_outputs(incident_id)
        evidence = tuple(
            UntrustedEvidenceEnvelope.model_validate_json(record.envelope_json)
            for record in await self._store.evidence_records(incident_id)
        )
        return await self._coordinator.resume_after_revision(
            IncidentInput(
                incident_id=incident_id,
                scenario=definition.scenario_id,
                candidate_plan_id=definition.candidate_plan_id,
                evidence=evidence,
            )
        )

    async def _restore_outputs(self, incident_id: str) -> None:
        if self._coordinator is None:
            raise RuntimeError("agent runtime is unavailable")
        output_types = {
            Seat.PROSECUTOR: ProsecutorOutput,
            Seat.INSPECTOR: InspectorOutput,
            Seat.COUNSEL: CounselOutput,
            Seat.MAGISTRATE: MagistrateOutput,
        }
        restored = {}
        latest_runs = await self._store.latest_agent_runs(incident_id)
        policy_state: dict[Seat, tuple[Effort, int]] = {}
        latest_run_counts: dict[Seat, int] = {}
        completed_phases: dict[Seat, str] = {}
        escalation_reasons: dict[Seat, str] = {}
        specs = {spec.seat: spec for spec in SEAT_SPECS}
        for record in latest_runs:
            seat = Seat(record.seat)
            output_type = output_types.get(seat)
            if output_type is None:
                continue
            effort = Effort(record.effort)
            spec = specs[seat]
            try:
                effort_index = spec.effort_ladder.index(effort)
            except ValueError as error:
                raise ValueError("persisted effort is outside the seat policy") from error
            if record.escalation_count != effort_index:
                raise ValueError("persisted run effort disagrees with escalation count")
            policy_state[seat] = (effort, record.escalation_count)
            latest_run_counts[seat] = record.escalation_count
            completed_phases[seat] = record.phase
            restored[seat] = (
                output_type.model_validate_json(record.output_json),
                effort,
                record.escalation_count,
            )
        for event in await self._store.timeline_records(incident_id):
            if event.type != "REASONING_ESCALATED":
                continue
            try:
                seat = Seat(str(event.payload["seat"]))
                effort = Effort(str(event.payload["effort"]))
                escalation_count = int(event.payload["escalation_count"])
                reason = str(event.payload["reason"])
                expected_effort = specs[seat].effort_ladder[escalation_count]
            except (IndexError, KeyError, TypeError, ValueError) as error:
                raise ValueError("durable escalation event is outside policy") from error
            if (
                escalation_count <= 0
                or escalation_count > specs[seat].max_escalations
                or effort is not expected_effort
            ):
                raise ValueError("durable escalation event disagrees with policy")
            previous = policy_state.get(seat)
            if previous is not None and escalation_count < previous[1]:
                continue
            if previous is not None and escalation_count == previous[1]:
                if effort is not previous[0]:
                    raise ValueError("durable escalation effort is contradictory")
                escalation_reasons[seat] = reason
                continue
            policy_state[seat] = (effort, escalation_count)
            escalation_reasons[seat] = reason
        for seat, (output, _effort, _count) in tuple(restored.items()):
            effort, escalation_count = policy_state[seat]
            restored[seat] = (output, effort, escalation_count)
        if Seat.COUNSEL not in restored:
            raise LookupError("incident has no durable Counsel output")
        pending_retries = {
            seat: escalation_reasons[seat]
            for seat, (_effort, count) in policy_state.items()
            if count > latest_run_counts.get(seat, 0) and seat in escalation_reasons
        }
        self._coordinator.restore_incident_outputs(
            incident_id,
            restored,
            completed_phases=completed_phases,
            pending_retries=pending_retries,
        )
