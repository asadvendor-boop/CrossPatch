from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from crosspatch.domain.hashing import canonical_json, sha256_hex
from crosspatch.runner.catalog import CANDIDATE_PLAN_IDS, ExecutionCatalog
from crosspatch.runner.results import ProcessReceipt
from crosspatch.runner.runner_service import (
    RunnerServiceClient,
    RunnerServicePolicyViolation,
    build_runner_service_app,
    runner_receipt_mac,
)
from crosspatch.runner.supervisor import is_trusted_process_supervisor
from crosspatch.runner.worktree import PreparedWorkspace


def _workspace(tmp_path: Path) -> tuple[Path, Path, PreparedWorkspace]:
    workspaces_root = tmp_path / "workspaces"
    jobs_root = tmp_path / "jobs"
    workspace = workspaces_root / "war-123"
    job = jobs_root / "war-456"
    workspace.mkdir(parents=True)
    job.mkdir(parents=True)
    context = job / "candidate-context.json"
    context.write_text("{}", encoding="utf-8")
    return workspaces_root, jobs_root, PreparedWorkspace(root=workspace, context_path=context)


def test_legacy_receipt_round_trip_preserves_canonical_bytes_and_hash() -> None:
    old_bytes = (
        b'{"argv_sha256":"2222222222222222222222222222222222222222222222222222222222222222",'
        b'"candidate_executor_boot_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"candidate_executor_replacement_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
        b'"exit_code":0,"finished_at":"2026-07-01T00:00:01Z",'
        b'"job_provenance_sha256":"9999999999999999999999999999999999999999999999999999999999999999",'
        b'"plan_id":"legacy.plan",'
        b'"plan_sha256":"1111111111111111111111111111111111111111111111111111111111111111",'
        b'"runner_request_sha256":"6666666666666666666666666666666666666666666666666666666666666666",'
        b'"runner_service_identity_sha256":"7777777777777777777777777777777777777777777777777777777777777777",'
        b'"started_at":"2026-07-01T00:00:00Z","stderr_bytes":9,'
        b'"stderr_sha256":"4444444444444444444444444444444444444444444444444444444444444444",'
        b'"stderr_truncated":false,"stdout_bytes":7,'
        b'"stdout_sha256":"3333333333333333333333333333333333333333333333333333333333333333",'
        b'"stdout_truncated":false,"supervisor_verified":true,"timed_out":false,'
        b'"verification_code":"TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED",'
        b'"verification_sha256":"5555555555555555555555555555555555555555555555555555555555555555",'
        b'"workspace_provenance_sha256":"8888888888888888888888888888888888888888888888888888888888888888"}'
    )
    old_sha256 = "e11322c2005428048b7577e6b41e514cfd2caaf342aad70c71912477f8f333ed"

    receipt = ProcessReceipt.model_validate_json(old_bytes)
    receipt_json = receipt.model_dump(mode="json")

    assert b"trusted_observation" not in old_bytes
    assert canonical_json(receipt_json) == old_bytes
    assert sha256_hex(receipt_json) == old_sha256


def test_receipt_serializes_only_the_typed_trusted_observation() -> None:
    plan = ExecutionCatalog.default().resolve("victim.payload-equivalence.candidate")
    observation = {
        "counts": {"receipts": 2, "jobs": 3, "deliveries": 4},
        "response_statuses": [202, 200, 409],
    }
    receipt = ProcessReceipt.for_test(
        plan=plan,
        trusted_observation=observation,
    )

    rendered = receipt.model_dump(mode="json")
    assert rendered["trusted_observation"] == observation
    assert rendered["trusted_observation_sha256"] == sha256_hex(observation)


def test_receipt_requires_a_matching_observation_digest_pair() -> None:
    plan = ExecutionCatalog.default().resolve("victim.payload-equivalence.candidate")
    payload = ProcessReceipt.for_test(plan=plan).model_dump(mode="json")
    observation = {
        "counts": {"receipts": 2, "jobs": 3, "deliveries": 4},
        "response_statuses": [202, 200, 409],
    }

    with pytest.raises(ValueError, match="present together"):
        ProcessReceipt.model_validate(
            {**payload, "trusted_observation": observation}
        )
    with pytest.raises(ValueError, match="trusted observation digest"):
        ProcessReceipt.model_validate(
            {
                **payload,
                "trusted_observation": observation,
                "trusted_observation_sha256": "0" * 64,
            }
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("plan_id", sorted(CANDIDATE_PLAN_IDS))
async def test_runner_client_sends_only_opaque_keys_and_accepts_bound_receipt(
    tmp_path: Path,
    plan_id: str,
) -> None:
    workspaces_root, jobs_root, workspace = _workspace(tmp_path)
    plan = ExecutionCatalog.default().resolve(plan_id)
    token = "r" * 32
    captured: dict[str, object] = {}

    async def respond(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        captured["authorization"] = request.headers.get("authorization")
        captured["payload"] = payload
        receipt = ProcessReceipt.for_test(plan=plan)
        response = {
            "request_id": payload["request_id"],
            "plan_id": payload["plan_id"],
            "plan_sha256": payload["plan_sha256"],
            "request_sha256": sha256_hex(payload),
            "workspace_provenance_sha256": sha256_hex(
                {"key": payload["workspace_key"], "type": "candidate-workspace"}
            ),
            "job_provenance_sha256": sha256_hex(
                {"key": payload["job_key"], "type": "trusted-runner-job"}
            ),
            "receipt": receipt.model_dump(mode="json"),
            "service_pid": 7,
            "service_role": "trusted-runner",
            "service_uid": 10001,
        }
        response["receipt_mac_sha256"] = runner_receipt_mac(
            token,
            request=payload,
            response=response,
        )
        return httpx.Response(200, json=response)

    client = RunnerServiceClient(
        runner_url="http://runner:9020",
        auth_token=token,
        runner_uid=10001,
        workspaces_root=workspaces_root,
        jobs_root=jobs_root,
        transport=httpx.MockTransport(respond),
    )

    receipt = await client.run(workspace, plan)

    payload = captured["payload"]
    assert set(payload) == {
        "job_key",
        "plan_id",
        "plan_sha256",
        "request_id",
        "workspace_key",
    }
    assert payload["workspace_key"] == "war-123"
    assert payload["job_key"] == "war-456"
    assert payload["plan_id"] == plan.plan_id
    assert payload["plan_sha256"] == plan.sha256
    rendered = json.dumps(payload, sort_keys=True)
    assert str(workspaces_root) not in rendered
    assert str(jobs_root) not in rendered
    assert "candidate-context" not in rendered
    assert captured["authorization"] == f"Bearer {token}"
    assert receipt.passed is True
    assert receipt.runner_request_sha256 != "0" * 64
    assert receipt.runner_service_identity_sha256 != "0" * 64
    assert receipt.workspace_provenance_sha256 != "0" * 64
    assert receipt.job_provenance_sha256 != "0" * 64
    receipt_json = receipt.model_dump_json()
    assert "war-123" not in receipt_json
    assert "war-456" not in receipt_json
    assert is_trusted_process_supervisor(client) is True


@pytest.mark.asyncio
async def test_runner_client_rejects_receipt_with_invalid_mac(tmp_path: Path) -> None:
    workspaces_root, jobs_root, workspace = _workspace(tmp_path)
    plan = ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")

    async def respond(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        response = {
            "request_id": payload["request_id"],
            "plan_id": payload["plan_id"],
            "plan_sha256": payload["plan_sha256"],
            "request_sha256": sha256_hex(payload),
            "workspace_provenance_sha256": sha256_hex(
                {"key": payload["workspace_key"], "type": "candidate-workspace"}
            ),
            "job_provenance_sha256": sha256_hex(
                {"key": payload["job_key"], "type": "trusted-runner-job"}
            ),
            "receipt": ProcessReceipt.for_test(plan=plan).model_dump(mode="json"),
            "service_pid": 7,
            "service_role": "trusted-runner",
            "service_uid": 10001,
            "receipt_mac_sha256": "0" * 64,
        }
        return httpx.Response(200, json=response)

    client = RunnerServiceClient(
        runner_url="http://runner:9020",
        auth_token="r" * 32,
        runner_uid=10001,
        workspaces_root=workspaces_root,
        jobs_root=jobs_root,
        transport=httpx.MockTransport(respond),
    )

    with pytest.raises(RunnerServicePolicyViolation, match="receipt MAC"):
        await client.run(workspace, plan)


def test_runner_receipt_mac_binds_the_full_request_and_hash_only_provenance() -> None:
    token = "r" * 32
    request = {
        "job_key": "war-456",
        "plan_id": "victim.duplicate-race.candidate",
        "plan_sha256": "1" * 64,
        "request_id": "cpr-" + "2" * 32,
        "workspace_key": "war-123",
    }
    response = {
        "request_id": request["request_id"],
        "request_sha256": "3" * 64,
        "workspace_provenance_sha256": "4" * 64,
        "job_provenance_sha256": "5" * 64,
        "receipt": {
            "trusted_observation": {
                "counts": {"receipts": 2, "jobs": 3, "deliveries": 4},
                "response_statuses": [202, 200, 409],
            },
            "trusted_observation_sha256": "7" * 64,
        },
    }

    original = runner_receipt_mac(token, request=request, response=response)
    changed_request = {**request, "workspace_key": "war-124"}
    changed_provenance = {**response, "workspace_provenance_sha256": "6" * 64}
    changed_observation_digest = {
        **response,
        "receipt": {
            **response["receipt"],
            "trusted_observation_sha256": "8" * 64,
        },
    }

    assert runner_receipt_mac(
        token,
        request=changed_request,
        response=response,
    ) != original
    assert runner_receipt_mac(
        token,
        request=request,
        response=changed_provenance,
    ) != original
    assert runner_receipt_mac(
        token,
        request=request,
        response=changed_observation_digest,
    ) != original


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("plan_id", "plan_sha256"),
    [
        (
            ExecutionCatalog.default().resolve("victim.single-delivery").plan_id,
            ExecutionCatalog.default().resolve("victim.single-delivery").sha256,
        ),
        *[
            (plan_id, "0" * 64)
            for plan_id in sorted(CANDIDATE_PLAN_IDS)
        ],
    ],
)
async def test_runner_service_rejects_unbound_plan_before_workspace_or_supervisor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    plan_id: str,
    plan_sha256: str,
) -> None:
    workspaces_root, jobs_root, _workspace_value = _workspace(tmp_path)
    token = "r" * 32
    calls = 0

    def supervisor_factory():
        nonlocal calls
        calls += 1
        pytest.fail("invalid plan reached the trusted supervisor")

    monkeypatch.setattr("crosspatch.runner.runner_service.os.geteuid", lambda: 10001)
    app = build_runner_service_app(
        auth_token=token,
        workspaces_root=workspaces_root,
        jobs_root=jobs_root,
        supervisor_uid=10001,
        supervisor_factory=supervisor_factory,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://runner",
    ) as client:
        response = await client.post(
            "/v1/run",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "job_key": "missing-job",
                "plan_id": plan_id,
                "plan_sha256": plan_sha256,
                "request_id": "cpr-" + "1" * 32,
                "workspace_key": "missing-workspace",
            },
        )

    assert response.status_code == 409
    assert response.json()["detail"] == "trusted runner plan binding changed"
    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("plan_id", sorted(CANDIDATE_PLAN_IDS))
async def test_runner_service_dispatches_each_exact_candidate_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    plan_id: str,
) -> None:
    workspaces_root, jobs_root, _workspace_value = _workspace(tmp_path)
    token = "r" * 32
    captured = []
    observation = {
        "counts": {"receipts": 2, "jobs": 3, "deliveries": 4},
        "response_statuses": [202, 200, 409],
    }

    class RecordingSupervisor:
        async def run(self, workspace: PreparedWorkspace, plan):
            captured.append((workspace, plan))
            return ProcessReceipt.for_test(
                plan=plan,
                trusted_observation=observation,
            )

    monkeypatch.setattr("crosspatch.runner.runner_service.os.geteuid", lambda: 10001)
    monkeypatch.setattr(
        "crosspatch.runner.runner_service.is_trusted_process_supervisor",
        lambda _value: True,
    )
    app = build_runner_service_app(
        auth_token=token,
        workspaces_root=workspaces_root,
        jobs_root=jobs_root,
        supervisor_uid=10001,
        supervisor_factory=RecordingSupervisor,
    )
    plan = ExecutionCatalog.default().resolve(plan_id)
    request = {
        "job_key": "war-456",
        "plan_id": plan.plan_id,
        "plan_sha256": plan.sha256,
        "request_id": "cpr-" + "1" * 32,
        "workspace_key": "war-123",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://runner",
    ) as client:
        response = await client.post(
            "/v1/run",
            headers={"Authorization": f"Bearer {token}"},
            json=request,
        )

    assert response.status_code == 200
    assert len(captured) == 1
    assert captured[0][1] == plan
    payload = response.json()
    receipt_mac_sha256 = payload.pop("receipt_mac_sha256")
    assert payload["receipt"]["trusted_observation_sha256"] == sha256_hex(observation)
    assert receipt_mac_sha256 == runner_receipt_mac(
        token,
        request=request,
        response=payload,
    )


@pytest.mark.asyncio
async def test_runner_service_health_proves_trusted_service_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspaces_root, jobs_root, _workspace_value = _workspace(tmp_path)
    monkeypatch.setattr("crosspatch.runner.runner_service.os.geteuid", lambda: 10001)
    monkeypatch.setattr("crosspatch.runner.runner_service.os.getpid", lambda: 4242)
    app = build_runner_service_app(
        auth_token="r" * 32,
        workspaces_root=workspaces_root,
        jobs_root=jobs_root,
        supervisor_uid=10001,
        supervisor_factory=lambda: pytest.fail("health must not construct a supervisor"),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://runner",
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "candidate_plan_ids": sorted(CANDIDATE_PLAN_IDS),
        "pid": 4242,
        "service_role": "trusted-runner",
        "supervisor_uid": 10001,
    }
