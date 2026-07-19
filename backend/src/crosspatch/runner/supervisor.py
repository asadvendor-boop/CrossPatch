"""Trusted success derivation outside the candidate process and UID.

Candidate exit status is diagnostic only. A receipt passes only when a trusted
black-box verifier derives the expected outcome from external observations and
the supervisor proves its pre-launch context is unchanged afterward.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
import stat
from datetime import datetime
from pathlib import Path
from typing import Protocol, TypeGuard

import httpx
import psycopg
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from crosspatch.domain.hashing import sha256_hex
from crosspatch.runner.candidate_context import (
    CandidateContextViolation,
    load_and_verify_candidate_context,
)
from crosspatch.runner.catalog import ExecutionPlan, OracleProfile
from crosspatch.runner.results import (
    ProcessReceipt,
    TrustedObservation,
    trusted_observation_digest,
    validate_trusted_observation_digest,
)

_MAX_SNAPSHOT_FILES = 50_000
_MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
_BROKER_SUPERVISOR_CAPABILITY = object()


class SupervisorPolicyViolation(ValueError):
    pass


class CandidateAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str
    candidate_uid: int = Field(ge=1)
    runtime_id: str = Field(min_length=12, max_length=128)
    pid_namespace_isolated: bool
    workspace_read_only: bool
    context_capability_absent: bool
    external_receipt_authority: bool
    exit_code: int | None
    timed_out: bool
    started_at: datetime
    finished_at: datetime
    stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stderr_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stdout_bytes: int = Field(ge=0)
    stderr_bytes: int = Field(ge=0)
    teardown_verified: bool
    executor_boot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replacement_boot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SupervisorChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    challenge_id: str = Field(min_length=1, max_length=128)
    environment: dict[str, str]

    @field_validator("environment")
    @classmethod
    def _environment_is_verifier_owned(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            if not key.startswith("CROSSPATCH_VERIFICATION_"):
                raise ValueError("verification environment keys require the fixed prefix")
            if not item or "\x00" in item:
                raise ValueError("verification environment values must be non-empty")
        return value


class BlackBoxVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    verified: bool
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,95}$")
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_observation: TrustedObservation | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    trusted_observation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def _trusted_observation_digest_matches(self) -> BlackBoxVerification:
        validate_trusted_observation_digest(
            self.trusted_observation,
            self.trusted_observation_sha256,
        )
        return self


class CandidateExecutor(Protocol):
    candidate_uid: int
    pid_namespace_isolated: bool
    workspace_read_only: bool
    context_capability_absent: bool
    external_receipt_authority: bool

    async def execute(
        self,
        workspace: Path,
        plan: ExecutionPlan,
        environment: dict[str, str],
    ) -> CandidateAttempt: ...


class TrustedBlackBoxVerifier(Protocol):
    async def prepare(self, plan: ExecutionPlan) -> SupervisorChallenge: ...

    async def verify(
        self,
        workspace: Path,
        plan: ExecutionPlan,
        challenge: SupervisorChallenge,
        attempt: CandidateAttempt,
    ) -> BlackBoxVerification: ...


class _ContextSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    device: int
    inode: int
    owner_uid: int
    mode: int
    size: int
    sha256: str


class _WorkspaceSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    file_count: int
    total_bytes: int
    manifest_sha256: str


def _snapshot_context(
    path: Path,
    *,
    candidate_uid: int,
    supervisor_uid: int,
) -> _ContextSnapshot:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise SupervisorPolicyViolation("candidate context must be a regular file")
    if metadata.st_uid == candidate_uid:
        raise SupervisorPolicyViolation("candidate context is owned by the candidate UID")
    if metadata.st_uid != supervisor_uid:
        raise SupervisorPolicyViolation("candidate context is not owned by the supervisor UID")
    if stat.S_IMODE(metadata.st_mode) != 0o400:
        raise SupervisorPolicyViolation("candidate context must have exact mode 0400")
    value = path.read_bytes()
    after = path.lstat()
    if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        raise SupervisorPolicyViolation("candidate context changed while being snapshotted")
    return _ContextSnapshot(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
        size=metadata.st_size,
        sha256=hashlib.sha256(value).hexdigest(),
    )


def _snapshot_workspace(root: Path) -> _WorkspaceSnapshot:
    """Hash a regular-file-only tree without trusting candidate-owned output."""
    if root.is_symlink() or not root.is_dir():
        raise SupervisorPolicyViolation("candidate workspace must be a real directory")
    records: list[dict[str, object]] = []
    file_count = 0
    total_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if path.is_symlink():
            raise SupervisorPolicyViolation("candidate workspace contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            records.append(
                {
                    "kind": "directory",
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "path": relative,
                }
            )
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise SupervisorPolicyViolation("candidate workspace contains a special file")
        file_count += 1
        total_bytes += metadata.st_size
        if file_count > _MAX_SNAPSHOT_FILES or total_bytes > _MAX_SNAPSHOT_BYTES:
            raise SupervisorPolicyViolation("candidate workspace exceeds snapshot limits")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
            opened = os.fstat(source.fileno())
        after = path.lstat()
        identity = (metadata.st_dev, metadata.st_ino, metadata.st_size)
        if identity != (opened.st_dev, opened.st_ino, opened.st_size) or identity != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise SupervisorPolicyViolation("candidate workspace changed during snapshot")
        records.append(
            {
                "kind": "file",
                "mode": stat.S_IMODE(metadata.st_mode),
                "path": relative,
                "sha256": digest.hexdigest(),
                "size": metadata.st_size,
            }
        )
    return _WorkspaceSnapshot(
        file_count=file_count,
        total_bytes=total_bytes,
        manifest_sha256=sha256_hex(records),
    )


class TrustedProcessSupervisor:
    """Turn an untrusted candidate attempt into a trusted process receipt."""

    trusted_supervisor = True

    def __init__(
        self,
        *,
        executor: CandidateExecutor,
        verifier: TrustedBlackBoxVerifier,
        supervisor_uid: int | None = None,
    ) -> None:
        self._executor = executor
        self._verifier = verifier
        self._supervisor_uid = os.geteuid() if supervisor_uid is None else supervisor_uid
        if executor.candidate_uid == self._supervisor_uid:
            raise SupervisorPolicyViolation(
                "production candidate execution requires a distinct UID"
            )
        required_isolation = {
            "context capability absent": executor.context_capability_absent,
            "external receipt authority": executor.external_receipt_authority,
            "isolated PID namespace": executor.pid_namespace_isolated,
            "read-only workspace": executor.workspace_read_only,
        }
        missing = tuple(name for name, enabled in required_isolation.items() if not enabled)
        if missing:
            raise SupervisorPolicyViolation(
                f"candidate executor lacks required isolation: {', '.join(missing)}"
            )
        self._broker_capability = _BROKER_SUPERVISOR_CAPABILITY

    async def run(
        self,
        workspace: os.PathLike[str] | Path,
        plan: ExecutionPlan,
    ) -> ProcessReceipt:
        supplied_context = getattr(workspace, "context_path", None)
        workspace = Path(workspace).resolve(strict=True)
        context_path = (
            Path(supplied_context).resolve(strict=True)
            if supplied_context is not None
            else workspace.parent / "candidate-context.json"
        )
        before = _snapshot_context(
            context_path,
            candidate_uid=self._executor.candidate_uid,
            supervisor_uid=self._supervisor_uid,
        )
        try:
            load_and_verify_candidate_context(context_path, expected_root=workspace)
        except CandidateContextViolation as error:
            raise SupervisorPolicyViolation("candidate context validation failed") from error
        workspace_before = _snapshot_workspace(workspace)
        challenge = await self._verifier.prepare(plan)
        environment = dict(challenge.environment)
        attempt = await self._executor.execute(workspace, plan, environment)

        context_changed = False
        workspace_changed = False
        try:
            after = _snapshot_context(
                context_path,
                candidate_uid=self._executor.candidate_uid,
                supervisor_uid=self._supervisor_uid,
            )
            context_changed = before != after
            load_and_verify_candidate_context(context_path, expected_root=workspace)
        except (OSError, SupervisorPolicyViolation):
            context_changed = True
        except CandidateContextViolation:
            context_changed = True
        try:
            workspace_changed = workspace_before != _snapshot_workspace(workspace)
        except (OSError, SupervisorPolicyViolation):
            workspace_changed = True

        verification = await self._verifier.verify(
            workspace,
            plan,
            challenge,
            attempt,
        )
        isolation_matches = (
            attempt.pid_namespace_isolated == self._executor.pid_namespace_isolated
            and attempt.workspace_read_only == self._executor.workspace_read_only
            and attempt.context_capability_absent == self._executor.context_capability_absent
            and attempt.external_receipt_authority == self._executor.external_receipt_authority
        )
        if attempt.candidate_uid != self._executor.candidate_uid or not isolation_matches:
            code = "CANDIDATE_IDENTITY_CHANGED"
            verified = False
        elif (
            not attempt.teardown_verified
            or attempt.executor_boot_sha256 == "0" * 64
            or attempt.replacement_boot_sha256 == "0" * 64
            or hmac.compare_digest(
                attempt.executor_boot_sha256,
                attempt.replacement_boot_sha256,
            )
        ):
            code = "CANDIDATE_TEARDOWN_UNPROVEN"
            verified = False
        elif context_changed:
            code = "CANDIDATE_CONTEXT_CHANGED"
            verified = False
        elif workspace_changed:
            code = "CANDIDATE_WORKSPACE_CHANGED"
            verified = False
        elif attempt.timed_out or attempt.exit_code != 0:
            code = "CANDIDATE_PROCESS_FAILED"
            verified = False
        elif not verification.verified:
            code = verification.code
            verified = False
        else:
            code = verification.code
            verified = True

        verification_material: dict[str, object] = {
            "attempt": attempt,
            "challenge_id": challenge.challenge_id,
            "context_before": before,
            "context_unchanged": not context_changed,
            "runtime_id": attempt.runtime_id,
            "teardown_verified": attempt.teardown_verified,
            "workspace_before": workspace_before,
            "workspace_unchanged": not workspace_changed,
            "observation_sha256": verification.observation_sha256,
            "plan_sha256": plan.sha256,
            "verified": verified,
            "verification_code": code,
        }
        if verification.trusted_observation_sha256 is not None:
            verification_material["trusted_observation_sha256"] = (
                verification.trusted_observation_sha256
            )
        verification_sha256 = sha256_hex(verification_material)
        return ProcessReceipt(
            plan_id=plan.plan_id,
            plan_sha256=plan.sha256,
            argv_sha256=sha256_hex(plan.argv),
            exit_code=attempt.exit_code,
            timed_out=attempt.timed_out,
            started_at=attempt.started_at,
            finished_at=attempt.finished_at,
            stdout_sha256=attempt.stdout_sha256,
            stderr_sha256=attempt.stderr_sha256,
            stdout_bytes=attempt.stdout_bytes,
            stderr_bytes=attempt.stderr_bytes,
            supervisor_verified=verified,
            verification_code=code,
            verification_sha256=verification_sha256,
            trusted_observation=verification.trusted_observation,
            trusted_observation_sha256=verification.trusted_observation_sha256,
            candidate_executor_boot_sha256=attempt.executor_boot_sha256,
            candidate_executor_replacement_sha256=attempt.replacement_boot_sha256,
        )


def is_trusted_process_supervisor(value: object) -> TypeGuard[TrustedProcessSupervisor]:
    """Accept only concrete local or authenticated remote trusted runners."""
    from crosspatch.runner.runner_service import RunnerServiceClient

    return (
        isinstance(value, (TrustedProcessSupervisor, RunnerServiceClient))
        and getattr(value, "_broker_capability", None) is _BROKER_SUPERVISOR_CAPABILITY
    )


class PostgresCountBlackBoxVerifier:
    """Derive race success from trusted direct database observations.

    The database DSN never enters the candidate challenge. The candidate gets
    only a fresh event identifier and must produce the externally observable
    invariant through its separately provisioned runtime credential.
    """

    def __init__(self, *, dsn: str, provider: str = "acme-pay") -> None:
        if not dsn:
            raise ValueError("trusted verifier database DSN is required")
        self._dsn = dsn
        self._provider = provider

    def _clear(self, event_id: str) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as connection:
            connection.execute(
                "DELETE FROM deliveries WHERE provider = %s AND event_id = %s",
                (self._provider, event_id),
            )
            connection.execute(
                "DELETE FROM outbox_jobs WHERE provider = %s AND event_id = %s",
                (self._provider, event_id),
            )
            connection.execute(
                "DELETE FROM webhook_receipts WHERE provider = %s AND event_id = %s",
                (self._provider, event_id),
            )

    async def prepare(self, plan: ExecutionPlan) -> SupervisorChallenge:
        if plan.expected_counts is None:
            raise SupervisorPolicyViolation("black-box plan omitted expected counts")
        event_id = f"cpv-{secrets.token_hex(16)}"
        await asyncio.to_thread(self._clear, event_id)
        return SupervisorChallenge(
            challenge_id=event_id,
            environment={"CROSSPATCH_VERIFICATION_EVENT_ID": event_id},
        )

    def _counts(self, event_id: str) -> tuple[int, int, int]:
        with psycopg.connect(self._dsn, autocommit=True) as connection:
            values = []
            for query in (
                "SELECT count(*) FROM webhook_receipts "
                "WHERE provider = %s AND event_id = %s",
                "SELECT count(*) FROM outbox_jobs "
                "WHERE provider = %s AND event_id = %s",
                "SELECT count(*) FROM deliveries "
                "WHERE provider = %s AND event_id = %s",
            ):
                row = connection.execute(
                    query,
                    (self._provider, event_id),
                ).fetchone()
                if row is None:
                    raise RuntimeError("trusted count query returned no row")
                values.append(int(row[0]))
        return values[0], values[1], values[2]

    async def verify(
        self,
        workspace: Path,
        plan: ExecutionPlan,
        challenge: SupervisorChallenge,
        attempt: CandidateAttempt,
    ) -> BlackBoxVerification:
        del workspace, attempt
        observed = await asyncio.to_thread(self._counts, challenge.challenge_id)
        expected = plan.expected_counts
        verified = expected is not None and observed == expected
        return BlackBoxVerification(
            verified=verified,
            code=(
                "TRUSTED_DATABASE_INVARIANT_MATCHED"
                if verified
                else "TRUSTED_DATABASE_INVARIANT_MISMATCH"
            ),
            observation_sha256=sha256_hex(
                {
                    "challenge_id": challenge.challenge_id,
                    "expected": expected,
                    "observed": observed,
                    "provider": self._provider,
                    "source": "trusted-supervisor-postgres",
                }
            ),
        )


class PostgresHttpBlackBoxVerifier(PostgresCountBlackBoxVerifier):
    """Exercise the candidate over HTTP and derive success from trusted PostgreSQL.

    The candidate receives neither the random event identifier nor any oracle
    path before the request arrives. The verifier runs outside the candidate
    UID/PID namespace and never consumes candidate stdout as authorization.
    """

    def __init__(
        self,
        *,
        dsn: str,
        worker_dsn: str | None = None,
        victim_url: str,
        victim_socket: str | Path | None = None,
        provider: str = "acme-pay",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(dsn=dsn, provider=provider)
        if not victim_url.startswith(("http://", "https://")):
            raise ValueError("trusted verifier victim URL must be HTTP(S)")
        self._victim_url = victim_url.rstrip("/")
        self._worker_dsn = worker_dsn or dsn
        socket_value = None if victim_socket is None else str(victim_socket)
        if socket_value is not None and "\x00" in socket_value:
            raise ValueError("trusted verifier Unix socket is invalid")
        self._victim_socket = None if socket_value is None else Path(socket_value)
        if self._victim_socket is not None and not self._victim_socket.is_absolute():
            raise ValueError("trusted verifier Unix socket must be absolute")
        self._transport = transport
        self._exercise_task: asyncio.Task[object] | None = None
        self._exercise_profile: OracleProfile | None = None

    def _http_transport(self) -> httpx.AsyncBaseTransport | None:
        if self._transport is not None:
            return self._transport
        if self._victim_socket is None:
            return None
        return httpx.AsyncHTTPTransport(uds=str(self._victim_socket))

    async def _wait_until_ready(self) -> None:
        deadline = asyncio.get_running_loop().time() + 10
        async with httpx.AsyncClient(
            transport=self._http_transport(), timeout=0.5
        ) as client:
            while True:
                try:
                    response = await client.get(f"{self._victim_url}/health")
                    if response.status_code == 200:
                        return
                except httpx.HTTPError:
                    pass
                if asyncio.get_running_loop().time() >= deadline:
                    raise TimeoutError("candidate HTTP service did not become ready")
                await asyncio.sleep(0.05)

    async def _exercise_race(self, event_id: str, signing_secret: str) -> object:
        from victim.db import Database
        from victim.worker import DeliveryWorker

        from crosspatch.runner.reproduction import RaceReproducer

        await self._wait_until_ready()
        database = Database(self._dsn)
        worker_database = Database(self._worker_dsn)
        return await RaceReproducer(
            database=database,
            signing_secret=signing_secret,
            victim_url=self._victim_url,
            victim_socket=self._victim_socket,
            transport=self._transport,
            drain_jobs=DeliveryWorker(worker_database).drain,
            minimum_blocked_inserts=1,
        ).run(event_id=event_id)

    async def _exercise_payload_equivalence(
        self,
        event_id: str,
        signing_secret: str,
    ) -> object:
        from victim.db import Database
        from victim.worker import DeliveryWorker

        from crosspatch.runner.reproduction import PayloadEquivalenceReproducer

        await self._wait_until_ready()
        database = Database(self._dsn)
        worker_database = Database(self._worker_dsn)
        return await PayloadEquivalenceReproducer(
            database=database,
            signing_secret=signing_secret,
            victim_url=self._victim_url,
            victim_socket=self._victim_socket,
            transport=self._transport,
            drain_jobs=DeliveryWorker(worker_database).drain,
        ).run(event_id=event_id)

    async def prepare(self, plan: ExecutionPlan) -> SupervisorChallenge:
        if plan.expected_counts is None:
            raise SupervisorPolicyViolation("black-box plan omitted expected counts")
        if self._exercise_task is not None:
            raise SupervisorPolicyViolation("HTTP verifier cannot be reused concurrently")
        if plan.oracle_profile is OracleProfile.DUPLICATE_RACE:
            exercise = self._exercise_race
        elif plan.oracle_profile is OracleProfile.PAYLOAD_EQUIVALENCE:
            if plan.expected_statuses is None:
                raise SupervisorPolicyViolation(
                    "payload-equivalence oracle omitted expected HTTP statuses"
                )
            exercise = self._exercise_payload_equivalence
        else:
            raise SupervisorPolicyViolation("candidate plan has no trusted HTTP oracle")
        event_id = f"cpv-{secrets.token_hex(16)}"
        signing_secret = secrets.token_urlsafe(48)
        await asyncio.to_thread(self._clear, event_id)
        self._exercise_profile = plan.oracle_profile
        self._exercise_task = asyncio.create_task(
            exercise(event_id, signing_secret)
        )
        # Scope and signing material are consumed by the trusted sidecar parent;
        # only the fresh attempt secret reaches the candidate child.
        return SupervisorChallenge(
            challenge_id=event_id,
            environment={
                "CROSSPATCH_VERIFICATION_SCOPE_EVENT_ID": event_id,
                "CROSSPATCH_VERIFICATION_SCOPE_PROVIDER": self._provider,
                "CROSSPATCH_VERIFICATION_SIGNING_SECRET": signing_secret,
            },
        )

    async def verify(
        self,
        workspace: Path,
        plan: ExecutionPlan,
        challenge: SupervisorChallenge,
        attempt: CandidateAttempt,
    ) -> BlackBoxVerification:
        del workspace, attempt
        task = self._exercise_task
        prepared_profile = self._exercise_profile
        self._exercise_task = None
        self._exercise_profile = None
        failure: str | None = None
        result = None
        if task is None:
            failure = "exercise-not-started"
        else:
            try:
                result = await asyncio.wait_for(task, timeout=15)
            except BaseException as error:
                failure = type(error).__name__
        observed = await asyncio.to_thread(self._counts, challenge.challenge_id)
        observed_is_typed = (
            isinstance(observed, tuple)
            and len(observed) == 3
            and all(type(count) is int and count >= 0 for count in observed)
        )
        expected = plan.expected_counts
        result_counts = None
        result_statuses = None
        lock_state_reached = False
        if result is not None:
            result_counts = tuple(
                int(result.counts[name]) for name in ("receipts", "jobs", "deliveries")
            )
            result_statuses = tuple(result.response_statuses)
            lock_state_reached = bool(result.lock_state_reached)
        common_invariant = (
            failure is None
            and expected is not None
            and observed_is_typed
            and observed == expected
            and result_counts == expected
            and prepared_profile is plan.oracle_profile
        )
        if plan.oracle_profile is OracleProfile.DUPLICATE_RACE:
            profile_invariant = (
                lock_state_reached
                and result_statuses is not None
                and all(status in {200, 202} for status in result_statuses)
            )
        elif plan.oracle_profile is OracleProfile.PAYLOAD_EQUIVALENCE:
            profile_invariant = (
                lock_state_reached
                and plan.expected_statuses is not None
                and result_statuses == plan.expected_statuses
            )
        else:
            profile_invariant = False
        verified = (
            common_invariant
            and profile_invariant
        )
        trusted_observation = None
        trusted_observation_sha256 = None
        if (
            observed_is_typed
            and result_statuses
            and all(type(status) is int and 100 <= status <= 599 for status in result_statuses)
        ):
            trusted_observation = TrustedObservation(
                counts={
                    "receipts": observed[0],
                    "jobs": observed[1],
                    "deliveries": observed[2],
                },
                response_statuses=result_statuses,
            )
            trusted_observation_sha256 = trusted_observation_digest(
                trusted_observation
            )
        return BlackBoxVerification(
            verified=verified,
            code=(
                "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED"
                if verified
                else "TRUSTED_HTTP_POSTGRES_INVARIANT_MISMATCH"
            ),
            observation_sha256=sha256_hex(
                {
                    "challenge_id": challenge.challenge_id,
                    "expected": expected,
                    "expected_http_statuses": plan.expected_statuses,
                    "failure": failure,
                    "http_statuses": result_statuses,
                    "lock_state_reached": lock_state_reached,
                    "oracle_profile": (
                        plan.oracle_profile.value
                        if plan.oracle_profile is not None
                        else None
                    ),
                    "observed": observed,
                    "prepared_oracle_profile": (
                        prepared_profile.value
                        if prepared_profile is not None
                        else None
                    ),
                    "reported_counts": result_counts,
                    "source": "trusted-supervisor-http-postgres",
                }
            ),
            trusted_observation=trusted_observation,
            trusted_observation_sha256=trusted_observation_sha256,
        )
