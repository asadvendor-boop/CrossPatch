"""Concrete sanitized internal and published MCP read models."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from crosspatch.api.models import PublishedCaseView
from crosspatch.db.models import EvidenceRecord, PublishedCaseRecord, TestRunRecord
from crosspatch.domain.hashing import sha256_hex
from crosspatch.runner.catalog import ExecutionCatalog
from crosspatch.runtime.database import RuntimeStore, _published_evidence
from crosspatch.runtime.projection import published_trusted_observation


def _evidence_view(record: EvidenceRecord) -> dict[str, Any]:
    return _published_evidence(record)


def _test_result_view(record: TestRunRecord) -> dict[str, Any]:
    """Project broker evidence without its private full process receipt."""
    result = record.result if isinstance(record.result, dict) else {}
    public_result = {
        key: result[key]
        for key in (
            "warrant_id",
            "state",
            "passed",
            "duration_ms",
            "detail",
            "evidence_id",
            "receipt_sha256",
        )
        if key in result
    }
    trusted_observation = published_trusted_observation(
        result,
        expected_plan_id=record.plan_id,
        expected_plan_sha256=record.plan_sha256,
    )
    if trusted_observation is not None:
        public_result.update(trusted_observation)
    return {
        "incident_id": record.incident_id,
        "test_run_id": record.id,
        "plan_id": record.plan_id,
        "plan_sha256": record.plan_sha256,
        "result": public_result,
    }


class DatabaseEvidenceReader:
    def __init__(self, store: RuntimeStore) -> None:
        self._store = store

    async def list_incident_evidence(self, incident_id: str):
        return [
            _evidence_view(record)
            for record in await self._store.evidence_records(incident_id)
            if record.published
        ]

    async def _evidence(self, incident_id: str, evidence_id: str) -> EvidenceRecord:
        async with self._store.sessions() as session:
            record = await session.scalar(
                select(EvidenceRecord)
                .where(EvidenceRecord.id == evidence_id)
                .where(EvidenceRecord.incident_id == incident_id)
                .where(EvidenceRecord.published.is_(True))
            )
            if record is None:
                raise LookupError(evidence_id)
            return record

    async def get_sanitized_artifact(self, incident_id: str, evidence_id: str):
        return _evidence_view(await self._evidence(incident_id, evidence_id))

    async def search_source(self, incident_id: str, query: str):
        query = query.casefold().strip()
        if not query:
            return []
        return [
            _evidence_view(record)
            for record in await self._store.evidence_records(incident_id)
            if record.published
            and record.kind == "source"
            and query in record.sanitized_text.casefold()
        ][:50]

    async def get_source_blob(self, incident_id: str, source_id: str):
        record = await self._evidence(incident_id, source_id)
        if record.kind != "source":
            raise LookupError(source_id)
        return _evidence_view(record)

    async def list_test_catalog(self, incident_id: str):
        await self._store.get_incident_record(incident_id)
        return [
            {
                "incident_id": incident_id,
                "catalog_id": plan.plan_id,
                "plan_sha256": plan.sha256,
                "timeout_seconds": plan.timeout_seconds,
            }
            for plan in ExecutionCatalog.default().plans.values()
        ]

    async def get_test_result(self, incident_id: str, test_run_id: str):
        async with self._store.sessions() as session:
            record = await session.scalar(
                select(TestRunRecord)
                .where(TestRunRecord.id == test_run_id)
                .where(TestRunRecord.incident_id == incident_id)
            )
            if record is None:
                raise LookupError(test_run_id)
            return _test_result_view(record)

    async def get_incident_timeline(self, incident_id: str):
        projection = await self._store.read_projection(incident_id)
        if projection is None:
            raise LookupError(incident_id)
        return projection["events"]


class DatabaseCitationAuthority:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def contains_all(self, incident_id: str, evidence_ids: tuple[str, ...]) -> bool:
        if not evidence_ids or len(evidence_ids) != len(set(evidence_ids)):
            return False
        async with self._sessions() as session:
            found = frozenset(
                (
                    await session.scalars(
                        select(EvidenceRecord.id)
                        .where(EvidenceRecord.incident_id == incident_id)
                        .where(EvidenceRecord.id.in_(evidence_ids))
                        .where(EvidenceRecord.published.is_(True))
                    )
                ).all()
            )
        return found == frozenset(evidence_ids)


class DatabasePublishedCaseReader:
    """Read only the persisted public projection, never live authority tables."""

    def __init__(self, store: RuntimeStore) -> None:
        self._store = store

    async def _record(self, incident_id: str) -> PublishedCaseRecord:
        async with self._store.sessions() as session:
            record = await session.scalar(
                select(PublishedCaseRecord).where(
                    PublishedCaseRecord.incident_id == incident_id,
                    PublishedCaseRecord.published.is_(True),
                )
            )
            if record is None:
                raise LookupError(incident_id)
            return record

    @staticmethod
    def _public_case(record: PublishedCaseRecord) -> dict[str, Any]:
        projection = dict(record.projection)
        value = {
            "incident_id": record.incident_id,
            "revision": record.revision,
            "manifest_sha256": record.manifest_sha256,
            "projection": projection,
        }
        PublishedCaseView.model_validate(value)
        return value

    async def list_public_cases(self):
        async with self._store.sessions() as session:
            records = list(
                (
                    await session.scalars(
                        select(PublishedCaseRecord)
                        .where(PublishedCaseRecord.published.is_(True))
                        .order_by(PublishedCaseRecord.updated_at.desc())
                    )
                ).all()
            )
        return [self._public_case(record) for record in records]

    async def get_public_case(self, incident_id: str):
        return self._public_case(await self._record(incident_id))

    async def list_incidents(self):
        return [value["projection"]["incident"] for value in await self.list_public_cases()]

    async def get_case_file(self, incident_id: str):
        projection = (await self.get_public_case(incident_id))["projection"]
        return {"incident_id": incident_id, **projection}

    async def get_verdicts(self, incident_id: str):
        projection = (await self.get_public_case(incident_id))["projection"]
        return projection.get("verdicts", [])

    @staticmethod
    def _evidence(projection: dict[str, Any]) -> list[dict[str, Any]]:
        artifacts = projection.get("artifacts")
        if not isinstance(artifacts, dict):
            return []
        values = artifacts.get("evidence")
        if not isinstance(values, list):
            return []
        return [
            value
            for value in values
            if isinstance(value, dict) and value.get("classification") == "UNTRUSTED_EVIDENCE"
        ]

    async def search_evidence(self, incident_id: str, query: str):
        projection = (await self.get_public_case(incident_id))["projection"]
        query = query.casefold().strip()
        values = self._evidence(projection)
        return [
            value for value in values if query and query in str(value.get("text", "")).casefold()
        ][:50]

    async def get_sanitized_evidence(self, incident_id: str, evidence_id: str):
        projection = (await self.get_public_case(incident_id))["projection"]
        for value in self._evidence(projection):
            if value.get("evidence_id") == evidence_id:
                return value
        raise LookupError(evidence_id)

    async def get_warrant_log(self, incident_id: str):
        projection = (await self.get_public_case(incident_id))["projection"]
        return projection.get("warrants", [])

    async def verify_artifact_manifest(self, incident_id: str):
        record = await self._record(incident_id)
        projection = dict(record.projection)
        actual = sha256_hex(projection)
        PublishedCaseView.model_validate(
            {
                "incident_id": record.incident_id,
                "revision": record.revision,
                "manifest_sha256": actual,
                "projection": projection,
            }
        )
        return {
            "incident_id": incident_id,
            "valid": actual == record.manifest_sha256,
            "manifest_sha256": record.manifest_sha256,
        }

    async def get_summary(self, incident_id: str):
        projection = (await self.get_public_case(incident_id))["projection"]
        return projection["incident"]

    async def get_timeline(self, incident_id: str):
        projection = (await self.get_public_case(incident_id))["projection"]
        return projection.get("events", [])

    async def get_warrants(self, incident_id: str):
        return await self.get_warrant_log(incident_id)
