"""Broker-side client for the isolated candidate execution sidecar."""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import hmac
import os
import secrets
import shutil
import stat
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import psycopg
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from crosspatch.runner.candidate_lifecycle import candidate_executor_boot_mac
from crosspatch.runner.catalog import CANDIDATE_PLAN_IDS, ExecutionCatalog, ExecutionPlan
from crosspatch.runner.secrets import (
    INSECURE_CANDIDATE_TOKEN,
    INSECURE_VICTIM_DATABASE_PASSWORDS,
    load_service_token,
    validate_release_database_url,
)
from crosspatch.runner.supervisor import (
    CandidateAttempt,
    PostgresHttpBlackBoxVerifier,
    TrustedProcessSupervisor,
)


class SidecarPolicyViolation(ValueError):
    """Raised before candidate code runs when sidecar policy is incomplete."""


class _SidecarResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: str
    runtime_id: str = Field(min_length=12, max_length=128)
    exit_code: int | None
    timed_out: bool
    started_at: object
    finished_at: object
    stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stderr_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stdout_bytes: int = Field(ge=0)
    stderr_bytes: int = Field(ge=0)
    executor_boot_id: str = Field(pattern=r"^cpb-[0-9a-f]{32}$")
    executor_boot_mac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class _SidecarHealth(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    boot_id: str = Field(pattern=r"^cpb-[0-9a-f]{32}$")
    boot_mac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_uid: int = Field(ge=1)
    service_role: str = Field(pattern=r"^candidate-executor$")


class SidecarCandidateExecutor:
    """Request a fixed plan from a separately privileged execution service.

    Only an opaque workspace key crosses the control API. The sidecar owns the
    read-only bind and PID namespace; it receives no oracle context or receipt
    authority.
    """

    pid_namespace_isolated = True
    workspace_read_only = True
    context_capability_absent = True
    external_receipt_authority = True

    def __init__(
        self,
        *,
        control_url: str,
        auth_token: str,
        shared_workspace_root: str | Path,
        handoff_workspace_root: str | Path,
        candidate_uid: int,
        control_socket: str | Path | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        lifecycle_timeout_seconds: float = 20,
    ) -> None:
        if not control_url.startswith(("http://", "https://")):
            raise SidecarPolicyViolation("candidate executor URL must be HTTP(S)")
        if len(auth_token) < 32 or "\x00" in auth_token:
            raise SidecarPolicyViolation("candidate executor token is invalid")
        if candidate_uid < 1:
            raise SidecarPolicyViolation("candidate UID must be positive")
        source_root = Path(shared_workspace_root).resolve(strict=True)
        handoff_root = Path(handoff_workspace_root).resolve(strict=True)
        if not source_root.is_dir() or source_root.is_symlink():
            raise SidecarPolicyViolation("shared workspace root is invalid")
        if not handoff_root.is_dir() or handoff_root.is_symlink():
            raise SidecarPolicyViolation("candidate handoff root is invalid")
        if source_root == handoff_root:
            raise SidecarPolicyViolation("candidate handoff must be a separate mount")
        self._control_url = control_url.rstrip("/")
        self._auth_token = auth_token
        self._shared_workspace_root = source_root
        self._handoff_workspace_root = handoff_root
        self._handoff_lock_path = handoff_root / ".execution.lock"
        self._handoff_lock_path.touch(mode=0o600, exist_ok=True)
        self._handoff_lock_path.chmod(0o600)
        self._execution_lock = asyncio.Lock()
        self._transport = transport
        self._control_socket: Path | None = None
        if control_socket is not None:
            path = Path(control_socket)
            try:
                metadata = path.lstat()
                parent = path.parent.resolve(strict=True)
            except OSError as error:
                raise SidecarPolicyViolation(
                    "candidate executor socket is unavailable"
                ) from error
            if (
                not path.is_absolute()
                or path.is_symlink()
                or path.parent != parent
                or not stat.S_ISSOCK(metadata.st_mode)
            ):
                raise SidecarPolicyViolation("candidate executor socket is unsafe")
            self._control_socket = path
        if not 0.01 <= lifecycle_timeout_seconds <= 120:
            raise SidecarPolicyViolation("candidate lifecycle timeout is invalid")
        self._lifecycle_timeout_seconds = lifecycle_timeout_seconds
        self.candidate_uid = candidate_uid

    def _request_transport(self) -> httpx.AsyncBaseTransport | None:
        if self._transport is not None:
            return self._transport
        if self._control_socket is not None:
            return httpx.AsyncHTTPTransport(uds=str(self._control_socket))
        return None

    def _validate_boot(self, health: _SidecarHealth) -> _SidecarHealth:
        expected = candidate_executor_boot_mac(
            self._auth_token,
            health.boot_id,
            self.candidate_uid,
        )
        if (
            health.candidate_uid != self.candidate_uid
            or health.service_role != "candidate-executor"
            or not hmac.compare_digest(health.boot_mac_sha256, expected)
        ):
            raise SidecarPolicyViolation("candidate executor boot identity is invalid")
        return health

    async def _health(self) -> _SidecarHealth:
        async with httpx.AsyncClient(
            transport=self._request_transport(), timeout=2
        ) as client:
            response = await client.get(f"{self._control_url}/health")
        response.raise_for_status()
        return self._validate_boot(_SidecarHealth.model_validate(response.json()))

    async def _wait_for_replacement(self, previous_boot_id: str) -> _SidecarHealth:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._lifecycle_timeout_seconds
        last_error: BaseException | None = None
        while loop.time() < deadline:
            try:
                health = await self._health()
                if health.boot_id != previous_boot_id:
                    return health
            except (httpx.HTTPError, ValueError, ValidationError) as error:
                last_error = error
            await asyncio.sleep(min(0.05, self._lifecycle_timeout_seconds / 5))
        raise SidecarPolicyViolation(
            "candidate executor replacement boot was not proven"
        ) from last_error

    def _source_workspace(self, workspace: Path) -> Path:
        resolved = Path(workspace).resolve(strict=True)
        try:
            relative = resolved.relative_to(self._shared_workspace_root)
        except ValueError as error:
            raise SidecarPolicyViolation(
                "candidate workspace is outside the shared workspace root"
            ) from error
        if len(relative.parts) != 1 or relative.parts[0] in {"", ".", ".."}:
            raise SidecarPolicyViolation("candidate workspace key must be one path segment")
        return resolved

    @staticmethod
    def _remove_handoff(path: Path) -> None:
        if not path.exists():
            return
        for directory, directory_names, filenames in os.walk(path, topdown=False):
            parent = Path(directory)
            parent.chmod(0o700)
            for name in filenames:
                (parent / name).chmod(0o600)
            for name in directory_names:
                (parent / name).chmod(0o700)
        shutil.rmtree(path)

    def _stage_workspace(self, source: Path, runtime_id: str) -> Path:
        for entry in self._handoff_workspace_root.iterdir():
            if entry == self._handoff_lock_path:
                continue
            if entry.is_symlink() or not entry.is_dir():
                raise SidecarPolicyViolation("candidate handoff root contains an unsafe entry")
            self._remove_handoff(entry)
        destination = self._handoff_workspace_root / runtime_id
        shutil.copytree(source, destination, symlinks=False)
        for directory, directory_names, filenames in os.walk(destination, topdown=False):
            parent = Path(directory)
            for name in filenames:
                child = parent / name
                metadata = child.lstat()
                if child.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                    raise SidecarPolicyViolation("candidate handoff contains a special file")
                child.chmod(0o555 if metadata.st_mode & 0o111 else 0o444)
            for name in directory_names:
                child = parent / name
                if child.is_symlink() or not child.is_dir():
                    raise SidecarPolicyViolation("candidate handoff contains a special directory")
                child.chmod(0o555)
        destination.chmod(0o555)
        return destination

    async def execute(
        self,
        workspace: Path,
        plan: ExecutionPlan,
        environment: dict[str, str],
    ) -> CandidateAttempt:
        if plan.plan_id not in CANDIDATE_PLAN_IDS:
            raise SidecarPolicyViolation(
                "plan is not authorized for the trusted candidate sidecar"
            )
        expected = ExecutionCatalog.default().resolve(plan.plan_id)
        if not hmac.compare_digest(expected.sha256, plan.sha256):
            raise SidecarPolicyViolation("candidate plan differs from the immutable catalog")
        if any(not key.startswith("CROSSPATCH_VERIFICATION_") for key in environment):
            raise SidecarPolicyViolation("candidate challenge contains a forbidden key")
        if "CROSSPATCH_CANDIDATE_CONTEXT" in environment or any(
            "candidate-context" in value for value in environment.values()
        ):
            raise SidecarPolicyViolation("candidate context capability is forbidden")

        source = self._source_workspace(workspace)
        runtime_id = f"cp-{secrets.token_hex(16)}"
        lock_file = self._handoff_lock_path.open("rb")
        staged: Path | None = None
        before: _SidecarHealth | None = None
        parsed: _SidecarResponse | None = None
        response_error: BaseException | None = None
        async with self._execution_lock:
            await asyncio.to_thread(fcntl.flock, lock_file.fileno(), fcntl.LOCK_EX)
            try:
                before = await self._health()
                staged = await asyncio.to_thread(
                    self._stage_workspace, source, runtime_id
                )
                payload = {
                    "environment": dict(sorted(environment.items())),
                    "plan_id": plan.plan_id,
                    "plan_sha256": plan.sha256,
                    "runtime_id": runtime_id,
                    "workspace_key": staged.name,
                }
                try:
                    async with httpx.AsyncClient(
                        transport=self._request_transport(),
                        timeout=plan.timeout_seconds + 15,
                    ) as client:
                        response = await client.post(
                            f"{self._control_url}/v1/execute",
                            headers={"Authorization": f"Bearer {self._auth_token}"},
                            json=payload,
                        )
                    response.raise_for_status()
                    parsed = _SidecarResponse.model_validate(response.json())
                except (httpx.HTTPError, ValueError, ValidationError) as error:
                    response_error = error
                if before is None:
                    raise SidecarPolicyViolation(
                        "candidate executor preflight boot was not proven"
                    )
                replacement = await self._wait_for_replacement(before.boot_id)
                if response_error is not None or parsed is None:
                    raise SidecarPolicyViolation(
                        "candidate sidecar returned an invalid receipt"
                    ) from response_error
                expected_response_boot_mac = candidate_executor_boot_mac(
                    self._auth_token,
                    parsed.executor_boot_id,
                    self.candidate_uid,
                )
                if (
                    parsed.executor_boot_id != before.boot_id
                    or not hmac.compare_digest(
                        parsed.executor_boot_mac_sha256,
                        expected_response_boot_mac,
                    )
                ):
                    raise SidecarPolicyViolation(
                        "candidate execution boot binding changed"
                    )
                if parsed.plan_id != plan.plan_id or parsed.runtime_id != runtime_id:
                    raise SidecarPolicyViolation(
                        "candidate sidecar response binding changed"
                    )
                return CandidateAttempt(
                    plan_id=parsed.plan_id,
                    candidate_uid=self.candidate_uid,
                    runtime_id=parsed.runtime_id,
                    pid_namespace_isolated=self.pid_namespace_isolated,
                    workspace_read_only=self.workspace_read_only,
                    context_capability_absent=self.context_capability_absent,
                    external_receipt_authority=self.external_receipt_authority,
                    exit_code=parsed.exit_code,
                    timed_out=parsed.timed_out,
                    started_at=parsed.started_at,
                    finished_at=parsed.finished_at,
                    stdout_sha256=parsed.stdout_sha256,
                    stderr_sha256=parsed.stderr_sha256,
                    stdout_bytes=parsed.stdout_bytes,
                    stderr_bytes=parsed.stderr_bytes,
                    teardown_verified=True,
                    executor_boot_sha256=hashlib.sha256(
                        before.boot_id.encode()
                    ).hexdigest(),
                    replacement_boot_sha256=hashlib.sha256(
                        replacement.boot_id.encode()
                    ).hexdigest(),
                )
            finally:
                if staged is not None:
                    await asyncio.to_thread(self._remove_handoff, staged)
                await asyncio.to_thread(
                    fcntl.flock, lock_file.fileno(), fcntl.LOCK_UN
                )
                lock_file.close()


def _required(environment: Mapping[str, str], key: str) -> str:
    value = environment.get(key, "")
    if not value or "\x00" in value:
        raise SidecarPolicyViolation(f"required production setting is absent: {key}")
    return value


def _verify_runner_database_boundary(oracle_url: str, worker_url: str) -> None:
    expected_identities = {
        oracle_url: "crosspatch_victim_oracle",
        worker_url: "crosspatch_victim_worker",
    }
    for database_url, expected_role in expected_identities.items():
        with psycopg.connect(database_url, autocommit=True) as connection:
            identity = connection.execute(
                """
                SELECT current_user, rolsuper, rolcreatedb, rolcreaterole,
                       rolinherit, rolreplication, rolbypassrls
                  FROM pg_roles WHERE rolname = current_user
                """
            ).fetchone()
        if identity != (
            expected_role,
            False,
            False,
            False,
            False,
            False,
            False,
        ):
            raise SidecarPolicyViolation(
                f"{expected_role} database role boundary is invalid"
            )
    with psycopg.connect(oracle_url, autocommit=True) as connection:
        oracle_privileges = connection.execute(
            """
            SELECT has_table_privilege(current_user, 'webhook_receipts', 'SELECT'),
                   has_table_privilege(current_user, 'webhook_receipts', 'DELETE'),
                   has_table_privilege(current_user, 'webhook_receipts', 'INSERT'),
                   has_table_privilege(current_user, 'outbox_jobs', 'UPDATE'),
                   has_table_privilege(current_user, 'deliveries', 'DELETE')
            """
        ).fetchone()
    if oracle_privileges != (True, True, False, False, True):
        raise SidecarPolicyViolation("oracle database privileges are invalid")
    with psycopg.connect(worker_url, autocommit=True) as connection:
        worker_privileges = connection.execute(
            """
            SELECT has_table_privilege(current_user, 'webhook_receipts', 'SELECT'),
                   has_table_privilege(current_user, 'webhook_receipts', 'INSERT'),
                   has_table_privilege(current_user, 'outbox_jobs', 'UPDATE'),
                   has_table_privilege(current_user, 'deliveries', 'INSERT'),
                   has_table_privilege(current_user, 'deliveries', 'DELETE')
            """
        ).fetchone()
    if worker_privileges != (True, False, True, True, False):
        raise SidecarPolicyViolation("worker database privileges are invalid")


def build_production_supervisor_from_environment(
    environment: Mapping[str, str] | None = None,
) -> TrustedProcessSupervisor:
    """Build the only broker-authorized production candidate path."""
    values = dict(os.environ if environment is None else environment)
    candidate_uid_value = _required(values, "CROSSPATCH_CANDIDATE_UID")
    supervisor_uid_value = _required(values, "CROSSPATCH_SUPERVISOR_UID")
    try:
        candidate_uid = int(candidate_uid_value)
        supervisor_uid = int(supervisor_uid_value)
    except ValueError as error:
        raise SidecarPolicyViolation(
            "candidate and supervisor UIDs must be integers"
        ) from error
    if candidate_uid == supervisor_uid:
        raise SidecarPolicyViolation("candidate and supervisor UIDs must differ")
    if os.geteuid() != supervisor_uid:
        raise SidecarPolicyViolation("runtime does not match the configured supervisor UID")

    auth_token = load_service_token(
        values,
        "CROSSPATCH_CANDIDATE_EXECUTOR_TOKEN",
        insecure_values={INSECURE_CANDIDATE_TOKEN},
    )
    # Validate release credentials before resolving transport or mount settings.
    # This keeps unsafe secrets fail-closed even when another setting is absent,
    # and avoids obscuring the credential violation behind a later startup error.
    database_url = validate_release_database_url(
        values,
        _required(values, "CROSSPATCH_TEST_DATABASE_URL"),
        label="oracle database",
        insecure_passwords=INSECURE_VICTIM_DATABASE_PASSWORDS,
    )
    worker_database_url = validate_release_database_url(
        values,
        _required(values, "CROSSPATCH_WORKER_DATABASE_URL"),
        label="worker database",
        insecure_passwords=INSECURE_VICTIM_DATABASE_PASSWORDS,
    )
    if urlsplit(database_url).username != "crosspatch_victim_oracle":
        raise SidecarPolicyViolation("oracle database username is invalid")
    if urlsplit(worker_database_url).username != "crosspatch_victim_worker":
        raise SidecarPolicyViolation("worker database username is invalid")
    control_url = _required(values, "CROSSPATCH_CANDIDATE_EXECUTOR_URL")
    control_socket = _required(values, "CROSSPATCH_CANDIDATE_EXECUTOR_SOCKET")
    target_url = _required(values, "CROSSPATCH_CANDIDATE_TARGET_URL")
    target_socket = _required(values, "CROSSPATCH_CANDIDATE_TARGET_SOCKET")
    workspaces_root = _required(values, "CROSSPATCH_CANDIDATE_WORKSPACES_ROOT")
    handoff_root = _required(values, "CROSSPATCH_CANDIDATE_HANDOFF_ROOT")
    _verify_runner_database_boundary(database_url, worker_database_url)
    executor = SidecarCandidateExecutor(
        control_url=control_url,
        auth_token=auth_token,
        shared_workspace_root=workspaces_root,
        handoff_workspace_root=handoff_root,
        candidate_uid=candidate_uid,
        control_socket=control_socket,
    )
    verifier = PostgresHttpBlackBoxVerifier(
        dsn=database_url,
        worker_dsn=worker_database_url,
        victim_url=target_url,
        victim_socket=target_socket,
    )
    return TrustedProcessSupervisor(
        executor=executor,
        verifier=verifier,
        supervisor_uid=supervisor_uid,
    )
