"""Authenticated boundary for trusted candidate verification receipts.

The broker prepares and seals a disposable workspace.  This service is the
only production component that may combine the isolated candidate executor
with the external HTTP/PostgreSQL oracle.  Callers receive a receipt bound to
their exact request with a domain-separated HMAC.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
from collections.abc import Callable, Mapping
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from crosspatch.domain.hashing import canonical_json, sha256_hex
from crosspatch.runner.catalog import CANDIDATE_PLAN_IDS, ExecutionCatalog, ExecutionPlan
from crosspatch.runner.results import ProcessReceipt
from crosspatch.runner.secrets import (
    INSECURE_RUNNER_TOKEN,
    load_service_token,
)
from crosspatch.runner.supervisor import (
    _BROKER_SUPERVISOR_CAPABILITY,
    TrustedProcessSupervisor,
    is_trusted_process_supervisor,
)
from crosspatch.runner.worktree import PreparedWorkspace

_RECEIPT_MAC_DOMAIN = b"crosspatch-trusted-runner-receipt-v1\x00"


class RunnerServicePolicyViolation(ValueError):
    """Raised when a runner request or receipt crosses its fixed policy."""


class _RunnerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=r"^cpr-[0-9a-f]{32}$")
    workspace_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    job_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    plan_id: str
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class _RunnerResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=r"^cpr-[0-9a-f]{32}$")
    plan_id: str
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_provenance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    job_provenance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipt: ProcessReceipt
    service_pid: int = Field(ge=1)
    service_role: str = Field(pattern=r"^trusted-runner$")
    service_uid: int = Field(ge=1)
    receipt_mac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _required(environment: Mapping[str, str], key: str) -> str:
    value = environment.get(key, "")
    if not value or "\x00" in value:
        raise RunnerServicePolicyViolation(f"required runner setting is absent: {key}")
    return value


def _validate_token(value: str) -> str:
    if len(value.encode("utf-8")) < 32 or "\x00" in value:
        raise RunnerServicePolicyViolation("runner service token is invalid")
    return value


def _resolve_root(value: str | Path, *, label: str) -> Path:
    try:
        root = Path(value).resolve(strict=True)
    except OSError as error:
        raise RunnerServicePolicyViolation(f"{label} root is unavailable") from error
    if root.is_symlink() or not root.is_dir():
        raise RunnerServicePolicyViolation(f"{label} root is invalid")
    return root


def _opaque_child(root: Path, child: Path, *, label: str) -> str:
    try:
        resolved = child.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise RunnerServicePolicyViolation(f"{label} is outside its shared root") from error
    if len(relative.parts) != 1 or relative.parts[0] in {"", ".", ".."}:
        raise RunnerServicePolicyViolation(f"{label} key must be one path segment")
    if resolved.is_symlink() or not resolved.is_dir():
        raise RunnerServicePolicyViolation(f"{label} must be a real directory")
    return relative.parts[0]


def runner_receipt_mac(
    token: str,
    *,
    request: Mapping[str, object],
    response: Mapping[str, object],
) -> str:
    """Bind the receipt and hash-only provenance to the exact canonical request."""
    response_material = dict(response)
    response_material.pop("receipt_mac_sha256", None)
    material = {"request": dict(request), "response": response_material}
    return hmac.new(
        _validate_token(token).encode("utf-8"),
        _RECEIPT_MAC_DOMAIN + canonical_json(material),
        hashlib.sha256,
    ).hexdigest()


class RunnerServiceClient:
    """Broker-side fixed-plan client for the dedicated trusted runner service."""

    def __init__(
        self,
        *,
        runner_url: str,
        auth_token: str,
        runner_uid: int,
        workspaces_root: str | Path,
        jobs_root: str | Path,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not runner_url.startswith(("http://", "https://")):
            raise RunnerServicePolicyViolation("runner service URL must be HTTP(S)")
        self._runner_url = runner_url.rstrip("/")
        self._auth_token = _validate_token(auth_token)
        if runner_uid < 1:
            raise RunnerServicePolicyViolation("runner service UID must be positive")
        self._runner_uid = runner_uid
        self._workspaces_root = _resolve_root(workspaces_root, label="workspace")
        self._jobs_root = _resolve_root(jobs_root, label="job")
        self._transport = transport
        # Broker accepts only this concrete implementation or the in-process
        # trusted supervisor used by isolated unit tests.
        self._broker_capability = _BROKER_SUPERVISOR_CAPABILITY

    async def run(
        self,
        workspace: os.PathLike[str] | Path,
        plan: ExecutionPlan,
    ) -> ProcessReceipt:
        if plan.plan_id not in CANDIDATE_PLAN_IDS:
            raise RunnerServicePolicyViolation(
                "runner plan is not authorized for the trusted candidate sidecar"
            )
        expected = ExecutionCatalog.default().resolve(plan.plan_id)
        if not hmac.compare_digest(plan.sha256, expected.sha256):
            raise RunnerServicePolicyViolation(
                "runner plan differs from the immutable candidate catalog"
            )
        supplied_context = getattr(workspace, "context_path", None)
        if supplied_context is None:
            raise RunnerServicePolicyViolation("runner workspace omitted trusted context")
        workspace_path = Path(workspace)
        context_path = Path(supplied_context).resolve(strict=True)
        if context_path.name != "candidate-context.json":
            raise RunnerServicePolicyViolation("trusted context filename changed")
        workspace_key = _opaque_child(
            self._workspaces_root,
            workspace_path,
            label="workspace",
        )
        job_key = _opaque_child(self._jobs_root, context_path.parent, label="job")

        request_id = f"cpr-{secrets.token_hex(16)}"
        payload = {
            "job_key": job_key,
            "plan_id": plan.plan_id,
            "plan_sha256": plan.sha256,
            "request_id": request_id,
            "workspace_key": workspace_key,
        }
        try:
            async with httpx.AsyncClient(
                transport=self._transport,
                timeout=plan.timeout_seconds + 30,
            ) as client:
                response = await client.post(
                    f"{self._runner_url}/v1/run",
                    headers={"Authorization": f"Bearer {self._auth_token}"},
                    json=payload,
                )
            response.raise_for_status()
            parsed = _RunnerResponse.model_validate(response.json())
        except (httpx.HTTPError, OSError, ValueError, ValidationError) as error:
            raise RunnerServicePolicyViolation(
                "trusted runner returned an invalid response"
            ) from error

        response_binding = parsed.model_dump(
            mode="python", exclude={"receipt_mac_sha256"}
        )
        expected_mac = runner_receipt_mac(
            self._auth_token,
            request=payload,
            response=response_binding,
        )
        if not hmac.compare_digest(parsed.receipt_mac_sha256, expected_mac):
            raise RunnerServicePolicyViolation("trusted runner receipt MAC is invalid")
        expected_request_sha256 = sha256_hex(payload)
        expected_workspace_sha256 = sha256_hex(
            {"key": workspace_key, "type": "candidate-workspace"}
        )
        expected_job_sha256 = sha256_hex(
            {"key": job_key, "type": "trusted-runner-job"}
        )
        if (
            parsed.request_id != request_id
            or parsed.plan_id != plan.plan_id
            or not hmac.compare_digest(parsed.plan_sha256, plan.sha256)
            or not hmac.compare_digest(parsed.request_sha256, expected_request_sha256)
            or not hmac.compare_digest(
                parsed.workspace_provenance_sha256,
                expected_workspace_sha256,
            )
            or not hmac.compare_digest(
                parsed.job_provenance_sha256,
                expected_job_sha256,
            )
            or parsed.service_role != "trusted-runner"
            or parsed.service_uid != self._runner_uid
        ):
            raise RunnerServicePolicyViolation("trusted runner response binding changed")
        receipt = parsed.receipt
        if (
            receipt.plan_id != plan.plan_id
            or not hmac.compare_digest(receipt.plan_sha256, plan.sha256)
            or not hmac.compare_digest(receipt.argv_sha256, sha256_hex(plan.argv))
        ):
            raise RunnerServicePolicyViolation("trusted runner receipt plan binding changed")
        return receipt.model_copy(
            update={
                "runner_request_sha256": sha256_hex(
                    payload
                ),
                "runner_service_identity_sha256": sha256_hex(
                    {
                        "pid": parsed.service_pid,
                        "role": parsed.service_role,
                        "type": "trusted-runner-service",
                        "uid": parsed.service_uid,
                    }
                ),
                "workspace_provenance_sha256": parsed.workspace_provenance_sha256,
                "job_provenance_sha256": parsed.job_provenance_sha256,
            }
        )


def build_runner_service_client_from_environment(
    environment: Mapping[str, str] | None = None,
) -> RunnerServiceClient:
    values = dict(os.environ if environment is None else environment)
    return RunnerServiceClient(
        runner_url=_required(values, "CROSSPATCH_RUNNER_URL"),
        auth_token=load_service_token(
            values,
            "CROSSPATCH_RUNNER_TOKEN",
            insecure_values={INSECURE_RUNNER_TOKEN},
        ),
        runner_uid=int(_required(values, "CROSSPATCH_RUNNER_UID")),
        workspaces_root=_required(values, "CROSSPATCH_RUNNER_WORKSPACES_ROOT"),
        jobs_root=_required(values, "CROSSPATCH_RUNNER_JOBS_ROOT"),
    )


def build_runner_service_app(
    *,
    auth_token: str,
    workspaces_root: str | Path,
    jobs_root: str | Path,
    supervisor_uid: int,
    supervisor_factory: Callable[[], TrustedProcessSupervisor],
) -> FastAPI:
    token = _validate_token(auth_token)
    workspaces = _resolve_root(workspaces_root, label="workspace")
    jobs = _resolve_root(jobs_root, label="job")
    if supervisor_uid < 1 or os.geteuid() != supervisor_uid:
        raise RunnerServicePolicyViolation(
            "runner service is not running under the configured supervisor UID"
        )
    candidate_plans = {
        plan_id: ExecutionCatalog.default().resolve(plan_id)
        for plan_id in sorted(CANDIDATE_PLAN_IDS)
    }
    execution_lock = asyncio.Lock()
    app = FastAPI(title="CrossPatch trusted runner", docs_url=None, redoc_url=None)

    @app.get("/health")
    async def health() -> dict[str, object]:
        return {
            "candidate_plan_ids": sorted(candidate_plans),
            "pid": os.getpid(),
            "service_role": "trusted-runner",
            "supervisor_uid": supervisor_uid,
        }

    @app.post("/v1/run", response_model=_RunnerResponse)
    async def run(
        request: _RunnerRequest,
        authorization: str | None = Header(default=None),
    ) -> _RunnerResponse:
        expected_authorization = f"Bearer {token}"
        if authorization is None or not hmac.compare_digest(
            authorization, expected_authorization
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="trusted runner authentication failed",
            )
        plan = candidate_plans.get(request.plan_id)
        if plan is None or not hmac.compare_digest(
            request.plan_sha256, plan.sha256
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="trusted runner plan binding changed",
            )
        try:
            workspace = (workspaces / request.workspace_key).resolve(strict=True)
            job = (jobs / request.job_key).resolve(strict=True)
            workspace_key = _opaque_child(workspaces, workspace, label="workspace")
            job_key = _opaque_child(jobs, job, label="job")
            if workspace_key != request.workspace_key or job_key != request.job_key:
                raise RunnerServicePolicyViolation("runner key normalization changed")
            prepared = PreparedWorkspace(
                root=workspace,
                context_path=job / "candidate-context.json",
            )
            async with execution_lock:
                supervisor = supervisor_factory()
                if not is_trusted_process_supervisor(supervisor):
                    raise RunnerServicePolicyViolation(
                        "runner service factory returned an untrusted supervisor"
                    )
                receipt = await supervisor.run(prepared, plan)
        except (OSError, RunnerServicePolicyViolation) as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="trusted runner workspace policy failed",
            ) from error

        request_binding = request.model_dump(mode="python")
        response_binding: dict[str, object] = {
            "request_id": request.request_id,
            "plan_id": plan.plan_id,
            "plan_sha256": plan.sha256,
            "request_sha256": sha256_hex(request_binding),
            "workspace_provenance_sha256": sha256_hex(
                {"key": workspace_key, "type": "candidate-workspace"}
            ),
            "job_provenance_sha256": sha256_hex(
                {"key": job_key, "type": "trusted-runner-job"}
            ),
            "receipt": receipt,
            "service_pid": os.getpid(),
            "service_role": "trusted-runner",
            "service_uid": supervisor_uid,
        }
        return _RunnerResponse(
            **response_binding,
            receipt_mac_sha256=runner_receipt_mac(
                token,
                request=request_binding,
                response=response_binding,
            ),
        )

    return app


def create_app() -> FastAPI:
    """Uvicorn factory for the dedicated trusted runner container."""
    from crosspatch.runner.candidate_executor import (
        build_production_supervisor_from_environment,
    )

    values = dict(os.environ)
    try:
        supervisor_uid = int(_required(values, "CROSSPATCH_SUPERVISOR_UID"))
    except ValueError as error:
        raise RunnerServicePolicyViolation("supervisor UID must be an integer") from error
    workspaces_root = _required(values, "CROSSPATCH_RUNNER_WORKSPACES_ROOT")
    candidate_root = _required(values, "CROSSPATCH_CANDIDATE_WORKSPACES_ROOT")
    if _resolve_root(workspaces_root, label="workspace") != _resolve_root(
        candidate_root, label="candidate workspace"
    ):
        raise RunnerServicePolicyViolation(
            "runner and candidate-client workspace roots must match"
        )
    # Construct once at startup so UID, mounts, sockets, exact DB roles, RLS,
    # and least-privilege grants are attested before health can become green.
    build_production_supervisor_from_environment(values)
    return build_runner_service_app(
        auth_token=load_service_token(
            values,
            "CROSSPATCH_RUNNER_TOKEN",
            insecure_values={INSECURE_RUNNER_TOKEN},
        ),
        workspaces_root=workspaces_root,
        jobs_root=_required(values, "CROSSPATCH_RUNNER_JOBS_ROOT"),
        supervisor_uid=supervisor_uid,
        supervisor_factory=build_production_supervisor_from_environment,
    )
