from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from crosspatch.db.models import TestRunRecord as DBTestRunRecord
from crosspatch.domain.enums import IncidentState
from crosspatch.mcp.auth import AuthConfig, AuthPolicy, TokenIssuer
from crosspatch.mcp.evidence_server import EVIDENCE_TOOL_ALLOWLIST, build_evidence_mcp
from crosspatch.runner.catalog import ExecutionCatalog
from crosspatch.runner.results import ProcessReceipt
from crosspatch.runtime.database import RuntimeDatabase, broker_receipt_result
from crosspatch.runtime.readers import DatabaseEvidenceReader

from backend.tests.contract._mcp_client import connected_mcp_client


@pytest_asyncio.fixture
async def runtime_database(tmp_path):
    database = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'evidence-mcp.db'}")
    await database.bootstrap()
    try:
        yield database
    finally:
        await database.close()


class EvidenceReader:
    async def list_incident_evidence(self, incident_id: str):
        return [{"incident_id": incident_id, "evidence_id": "ev-1"}]

    async def get_sanitized_artifact(self, incident_id: str, evidence_id: str):
        return {
            "classification": "UNTRUSTED_EVIDENCE",
            "incident_id": incident_id,
            "evidence_id": evidence_id,
            "text": "sanitized",
        }

    async def search_source(self, incident_id: str, query: str):
        return [{"incident_id": incident_id, "query": query, "source_id": "src-1"}]

    async def get_source_blob(self, incident_id: str, source_id: str):
        return {"incident_id": incident_id, "source_id": source_id, "text": "source"}

    async def list_test_catalog(self, incident_id: str):
        return [{"incident_id": incident_id, "catalog_id": "victim.contract"}]

    async def get_test_result(self, incident_id: str, test_run_id: str):
        return {"incident_id": incident_id, "test_run_id": test_run_id, "status": "PASSED"}

    async def get_incident_timeline(self, incident_id: str):
        return [{"incident_id": incident_id, "sequence": 1, "type": "EVIDENCE_CAPTURED"}]


def evidence_auth(
    now: datetime,
    *,
    incident_id: str = "inc-1",
) -> tuple[AuthPolicy, str]:
    config = AuthConfig(
        issuer="crosspatch-control",
        audience="crosspatch-evidence",
        zone="evidence",
        allowed_subjects=frozenset({"crosspatch-orchestrator"}),
        signing_secret=b"evidence-zone-test-secret-32-bytes!",
        allowed_hosts=frozenset({"evidence-mcp"}),
        allowed_origins=frozenset({"https://control.crosspatch.test"}),
        max_token_lifetime_seconds=300,
        incident_scoped=True,
    )
    token = TokenIssuer(config).issue(
        subject="crosspatch-orchestrator",
        jti="evidence-jti-1",
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
        incident_id=incident_id,
    )
    return AuthPolicy(config, clock=lambda: now), token


@pytest.mark.asyncio
async def test_evidence_mcp_streamable_http_exposes_exact_read_only_allowlist() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    auth, token = evidence_auth(now)
    surface = build_evidence_mcp(EvidenceReader(), auth=auth)

    async with connected_mcp_client(
        surface,
        token=token,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
    ) as client:
        result = await client.list_tools()

    assert tuple(tool.name for tool in result.tools) == (
        "list_incident_evidence",
        "get_sanitized_artifact",
        "search_source",
        "get_source_blob",
        "list_test_catalog",
        "get_test_result",
        "get_incident_timeline",
    )
    assert tuple(tool.name for tool in result.tools) == EVIDENCE_TOOL_ALLOWLIST
    assert all(tool.annotations and tool.annotations.readOnlyHint for tool in result.tools)
    assert not {"shell", "run_test", "approve_warrant", "execute_warrant"}.intersection(
        EVIDENCE_TOOL_ALLOWLIST
    )


@pytest.mark.asyncio
async def test_evidence_mcp_returns_only_incident_scoped_sanitized_dtos() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    auth, token = evidence_auth(now)
    surface = build_evidence_mcp(EvidenceReader(), auth=auth)

    async with connected_mcp_client(
        surface,
        token=token,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
    ) as client:
        result = await client.call_tool(
            "get_sanitized_artifact",
            {"incident_id": "inc-1", "evidence_id": "ev-1"},
        )

    assert result.isError is False
    rendered = "".join(getattr(item, "text", "") for item in result.content)
    assert "UNTRUSTED_EVIDENCE" in rendered
    assert '"kind": "mcp_result"' in rendered
    assert '"operation": "get_sanitized_artifact"' in rendered
    assert "inc-1" in rendered
    assert "raw_bytes" not in rendered
    assert "raw_path" not in rendered


@pytest.mark.asyncio
async def test_evidence_mcp_rejects_reader_output_from_another_incident() -> None:
    class CrossIncidentReader(EvidenceReader):
        async def get_sanitized_artifact(self, incident_id: str, evidence_id: str):
            return {
                "classification": "UNTRUSTED_EVIDENCE",
                "incident_id": "inc-other",
                "evidence_id": evidence_id,
                "text": "sanitized",
            }

    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    auth, token = evidence_auth(now)
    surface = build_evidence_mcp(CrossIncidentReader(), auth=auth)

    async with connected_mcp_client(
        surface,
        token=token,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
    ) as client:
        result = await client.call_tool(
            "get_sanitized_artifact",
            {"incident_id": "inc-1", "evidence_id": "ev-1"},
        )

    assert result.isError is True


@pytest.mark.asyncio
async def test_evidence_token_cannot_query_another_incident_before_reader_lookup() -> None:
    class TrackingReader(EvidenceReader):
        def __init__(self) -> None:
            self.lookups: list[str] = []

        async def list_incident_evidence(self, incident_id: str):
            self.lookups.append(incident_id)
            return await super().list_incident_evidence(incident_id)

    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    reader = TrackingReader()
    auth, token = evidence_auth(now, incident_id="inc-a")
    surface = build_evidence_mcp(reader, auth=auth)

    async with connected_mcp_client(
        surface,
        token=token,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
    ) as client:
        result = await client.call_tool(
            "list_incident_evidence",
            {"incident_id": "inc-b"},
        )

    assert result.isError is True
    assert reader.lookups == []


@pytest.mark.asyncio
async def test_real_persisted_broker_receipt_is_projected_without_private_receipt(
    runtime_database,
) -> None:
    incident_id = "inc-equivalence-persisted-receipt"
    await runtime_database.store.create_incident(
        incident_id=incident_id,
        title="Equivalent webhook retry rejected",
        scenario="webhook-payload-equivalence",
        state=IncidentState.OPEN,
        base_sha="1" * 40,
        repository_manifest_sha256="2" * 64,
        catalog_sha256="3" * 64,
        actor="operator-1",
    )
    plan = ExecutionCatalog.default().resolve("victim.payload-equivalence.candidate")
    observation = {
        "counts": {"receipts": 1, "jobs": 1, "deliveries": 1},
        "response_statuses": (202, 200, 409),
    }
    receipt = ProcessReceipt.for_test(
        plan=plan,
        trusted_observation=observation,
    )
    result_row = broker_receipt_result(
        receipt,
        warrant_id="war-persisted-receipt",
        evidence_id="ev-persisted-receipt",
    )
    private_values = {
        "raw_body_bytes": "RAW-EQUIVALENCE-BODY-MUST-NOT-CROSS",
        "webhook_signing_secret": "WEBHOOK-SIGNING-SECRET-MUST-NOT-CROSS",
        "raw_artifact_path": "/private/raw/equivalence.json",
        "approval_mac_key": "APPROVAL-MAC-KEY-MUST-NOT-CROSS",
        "candidate_context": "CANDIDATE-CONTEXT-MUST-NOT-CROSS",
        "raw_receipt": "RAW-RECEIPT-MUST-NOT-CROSS",
    }
    result_row.update(private_values)
    async with runtime_database.sessions() as session, session.begin():
        session.add(
            DBTestRunRecord(
                id="test-persisted-receipt",
                incident_id=incident_id,
                plan_id=plan.plan_id,
                plan_sha256=plan.sha256,
                result=result_row,
                created_at=datetime.now(UTC),
            )
        )

    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    auth, token = evidence_auth(now, incident_id=incident_id)
    surface = build_evidence_mcp(DatabaseEvidenceReader(runtime_database.store), auth=auth)
    async with connected_mcp_client(
        surface,
        token=token,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
    ) as client:
        result = await client.call_tool(
            "get_test_result",
            {"incident_id": incident_id, "test_run_id": "test-persisted-receipt"},
        )

    rendered = "".join(getattr(item, "text", "") for item in result.content)
    payload = json.loads(rendered)
    projected = payload["data"]
    projected_result = projected["result"]
    assert result.isError is False
    assert '"receipt_sha256"' in rendered
    assert '"receipt":' not in rendered
    assert receipt.verification_code in rendered
    assert plan.plan_id in rendered
    assert projected_result["trusted_observation"] == {
        "counts": {"receipts": 1, "jobs": 1, "deliveries": 1},
        "response_statuses": [202, 200, 409],
    }
    assert projected_result["trusted_observation_sha256"] == (receipt.trusted_observation_sha256)
    assert all(value not in rendered for value in private_values.values())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changed_field", "changed_value"),
    [
        pytest.param(
            "plan_id",
            "victim.duplicate-race.candidate",
            id="plan-id",
        ),
        pytest.param("plan_sha256", "0" * 64, id="plan-sha256"),
    ],
)
async def test_evidence_mcp_rejects_outer_plan_binding_that_differs_from_receipt(
    runtime_database,
    changed_field: str,
    changed_value: str,
) -> None:
    incident_id = f"inc-evidence-plan-mismatch-{changed_field}"
    await runtime_database.store.create_incident(
        incident_id=incident_id,
        title="Evidence plan binding",
        scenario="webhook-payload-equivalence",
        state=IncidentState.OPEN,
        base_sha="1" * 40,
        repository_manifest_sha256="2" * 64,
        catalog_sha256="3" * 64,
        actor="operator-1",
    )
    plan = ExecutionCatalog.default().resolve("victim.payload-equivalence.candidate")
    receipt = ProcessReceipt.for_test(
        plan=plan,
        trusted_observation={
            "counts": {"receipts": 1, "jobs": 1, "deliveries": 1},
            "response_statuses": (202, 200, 409),
        },
    )
    row_binding = {
        "plan_id": plan.plan_id,
        "plan_sha256": plan.sha256,
    }
    row_binding[changed_field] = changed_value
    async with runtime_database.sessions() as session, session.begin():
        session.add(
            DBTestRunRecord(
                id=f"test-evidence-plan-mismatch-{changed_field}",
                incident_id=incident_id,
                result=broker_receipt_result(
                    receipt,
                    warrant_id=f"war-evidence-plan-mismatch-{changed_field}",
                    evidence_id=f"ev-evidence-plan-mismatch-{changed_field}",
                ),
                created_at=datetime.now(UTC),
                **row_binding,
            )
        )

    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    auth, token = evidence_auth(now, incident_id=incident_id)
    surface = build_evidence_mcp(
        DatabaseEvidenceReader(runtime_database.store),
        auth=auth,
    )
    async with connected_mcp_client(
        surface,
        token=token,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
    ) as client:
        result = await client.call_tool(
            "get_test_result",
            {
                "incident_id": incident_id,
                "test_run_id": f"test-evidence-plan-mismatch-{changed_field}",
            },
        )

    assert result.isError is True
