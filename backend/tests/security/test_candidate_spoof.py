from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest
from crosspatch.domain.hashing import byte_sha256
from crosspatch.runner.catalog import ExecutionCatalog, ExecutionPlan
from crosspatch.runner.supervisor import (
    BlackBoxVerification,
    CandidateAttempt,
    PostgresHttpBlackBoxVerifier,
    SupervisorChallenge,
    TrustedProcessSupervisor,
)

REPOSITORY_ROOT = Path(__file__).parents[3]
PYTHON_IMAGE = (
    "python:3.13.7-slim-bookworm@"
    "sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d"
)
POSTGRES_IMAGE = (
    "postgres:16-bookworm@"
    "sha256:da788743d2060767375896de4d646f7576f5911461444b372616f19ea61db2ec"
)
RUNNER_IMAGE = "crosspatch-runner:local"
VALID_CANDIDATE_PATCH = b"""--- a/victim/src/victim/db.py
+++ b/victim/src/victim/db.py
@@ -68,21 +68,32 @@
\x20
     def accept_vulnerable(self, event: WebhookEvent) -> IngestDisposition:
         with self.connect() as connection, connection.transaction():
-            existing = connection.execute(
+            inserted = connection.execute(
                 \"\"\"
-                SELECT payload_sha256
-                  FROM webhook_receipts
-                 WHERE provider = %s AND event_id = %s
+                INSERT INTO webhook_receipts (provider, event_id, payload_sha256)
+                VALUES (%s, %s, %s)
+                ON CONFLICT (provider, event_id) DO NOTHING
+                RETURNING payload_sha256
                 \"\"\",
-                (event.provider, event.event_id),
+                (event.provider, event.event_id, event.payload_sha256),
             ).fetchone()
-            if existing is not None:
+            if inserted is None:
+                existing = connection.execute(
+                    \"\"\"
+                    SELECT payload_sha256
+                      FROM webhook_receipts
+                     WHERE provider = %s AND event_id = %s
+                    \"\"\",
+                    (event.provider, event.event_id),
+                ).fetchone()
+                if existing is None:
+                    raise RuntimeError(\"conflicting webhook receipt disappeared\")
                 if existing[\"payload_sha256\"].strip() != event.payload_sha256:
                     return IngestDisposition.PAYLOAD_MISMATCH
                 return IngestDisposition.DUPLICATE
\x20
-            # Deliberately vulnerable ordering: two transactions can both pass
-            # the check and enqueue work before either publishes its receipt.
+            # Receipt ownership is acquired before work is enqueued. A concurrent
+            # duplicate blocks at the unique key and cannot create a second job.
             connection.execute(
                 \"\"\"
                 INSERT INTO outbox_jobs (provider, event_id, payload, payload_sha256)
@@ -95,14 +106,6 @@
                     event.payload_sha256,
                 ),
             )
-            connection.execute(
-                \"\"\"
-                INSERT INTO webhook_receipts (provider, event_id, payload_sha256)
-                VALUES (%s, %s, %s)
-                ON CONFLICT (provider, event_id) DO NOTHING
-                \"\"\",
-                (event.provider, event.event_id, event.payload_sha256),
-            )
             return IngestDisposition.ACCEPTED
\x20
     def counts(self, *, provider: str, event_id: str | None = None) -> dict[str, int]:
"""


def _docker_binary() -> str:
    native = Path("/opt/homebrew/bin/docker")
    value = str(native) if native.is_file() else shutil.which("docker")
    if value is None:
        pytest.skip("Docker is required for the candidate-isolation regression")
    return value


class DockerCandidateExecutor:
    """Test implementation of the production sidecar isolation contract."""

    candidate_uid = 10002
    pid_namespace_isolated = True
    workspace_read_only = True
    context_capability_absent = True
    external_receipt_authority = True

    def __init__(
        self,
        *,
        image: str = PYTHON_IMAGE,
        network: str = "none",
        fixed_environment: dict[str, str] | None = None,
        extra_mounts: tuple[tuple[Path, str], ...] = (),
        published_ports: tuple[tuple[int, int], ...] = (),
    ) -> None:
        self._docker = _docker_binary()
        self._image = image
        self._network = network
        self._fixed_environment = dict(fixed_environment or {})
        self._extra_mounts = extra_mounts
        self._published_ports = published_ports
        self.last_command: tuple[str, ...] = ()
        self.last_stdout = b""
        self.last_stderr = b""

    async def execute(
        self,
        workspace: Path,
        plan: ExecutionPlan,
        environment: dict[str, str],
    ) -> CandidateAttempt:
        challenge = dict(environment)
        signing_secret = challenge.pop(
            "CROSSPATCH_VERIFICATION_SIGNING_SECRET", None
        )
        challenge.pop("CROSSPATCH_VERIFICATION_SCOPE_EVENT_ID", None)
        challenge.pop("CROSSPATCH_VERIFICATION_SCOPE_PROVIDER", None)
        merged_environment = {
            "CROSSPATCH_CANDIDATE_UID": str(self.candidate_uid),
            "CROSSPATCH_EXECUTOR_PID": "2147483647",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            **self._fixed_environment,
        }
        if signing_secret is not None:
            merged_environment["CROSSPATCH_CANDIDATE_WEBHOOK_SECRET"] = signing_secret
        if set(merged_environment) & set(challenge):
            raise RuntimeError("verifier challenge cannot replace sidecar configuration")
        merged_environment.update(challenge)
        forbidden = "CROSSPATCH_CANDIDATE_CONTEXT"
        if forbidden in merged_environment or any(
            "candidate-context" in value for value in merged_environment.values()
        ):
            raise RuntimeError("candidate context capability must not enter the sidecar")

        runtime_id = f"crosspatch-candidate-{secrets.token_hex(12)}"
        command = [
            self._docker,
            "run",
            "--rm",
            "--name",
            runtime_id,
            "--network",
            self._network,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--pids-limit",
            "128",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "--user",
            f"{self.candidate_uid}:{self.candidate_uid}",
            "--volume",
            f"{workspace}:/workspace:ro",
            "--workdir",
            "/workspace",
        ]
        if self._network != "none":
            command.extend(("--add-host", "host.docker.internal:host-gateway"))
        for host_port, container_port in self._published_ports:
            command.extend(("--publish", f"127.0.0.1:{host_port}:{container_port}"))
        for source, target in self._extra_mounts:
            resolved = source.resolve(strict=True)
            rendered = f"{resolved}:{target}:ro"
            if "candidate-context" in rendered or "docker.sock" in rendered:
                raise RuntimeError("forbidden candidate mount")
            command.extend(("--volume", rendered))
        for key, value in sorted(merged_environment.items()):
            command.extend(("--env", f"{key}={value}"))
        command.extend(("--entrypoint", plan.argv[0], self._image, *plan.argv[1:]))
        self.last_command = tuple(command)

        started = datetime.now(UTC)
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        timed_out = False
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=plan.timeout_seconds + 10
            )
        except TimeoutError:
            timed_out = True
            await asyncio.create_subprocess_exec(
                self._docker,
                "rm",
                "-f",
                runtime_id,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            process.kill()
            stdout, stderr = await process.communicate()
        finished = datetime.now(UTC)
        self.last_stdout = stdout
        self.last_stderr = stderr
        return CandidateAttempt(
            plan_id=plan.plan_id,
            candidate_uid=self.candidate_uid,
            runtime_id=runtime_id,
            pid_namespace_isolated=self.pid_namespace_isolated,
            workspace_read_only=self.workspace_read_only,
            context_capability_absent=self.context_capability_absent,
            external_receipt_authority=self.external_receipt_authority,
            exit_code=process.returncode,
            timed_out=timed_out,
            started_at=started,
            finished_at=finished,
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr).hexdigest(),
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            teardown_verified=True,
            executor_boot_sha256=hashlib.sha256(runtime_id.encode()).hexdigest(),
            replacement_boot_sha256=hashlib.sha256(
                f"{runtime_id}:destroyed".encode()
            ).hexdigest(),
        )


class RejectingBlackBoxVerifier:
    async def prepare(self, plan: ExecutionPlan) -> SupervisorChallenge:
        del plan
        return SupervisorChallenge(challenge_id="challenge-no-observation", environment={})

    async def verify(
        self,
        workspace: Path,
        plan: ExecutionPlan,
        challenge: SupervisorChallenge,
        attempt: CandidateAttempt,
    ) -> BlackBoxVerification:
        del workspace, plan, challenge, attempt
        return BlackBoxVerification(
            verified=False,
            code="BLACK_BOX_OUTCOME_MISSING",
            observation_sha256="0" * 64,
        )


def _write_context(
    workspace: Path,
    *,
    relative_path: str,
    base_sha256: str,
    patch_bytes: bytes,
) -> Path:
    candidate_sha256 = byte_sha256((workspace / relative_path).read_bytes())
    context = workspace.parent / "candidate-context.json"
    context.write_text(
        json.dumps(
            {
                "allowed_paths": [relative_path],
                "base_file_sha256": {relative_path: base_sha256},
                "base_sha": "a" * 40,
                "candidate_file_sha256": {relative_path: candidate_sha256},
                "candidate_root": str(workspace.resolve()),
                "format": "crosspatch-candidate-context-v1",
                "patch_sha256": byte_sha256(patch_bytes),
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    context.chmod(0o400)
    return context


def _job(root: Path, candidate_source: str) -> tuple[Path, ExecutionPlan]:
    job = root / "job"
    workspace = job / "workspace"
    workspace.mkdir(parents=True)
    source = workspace / "candidate.py"
    source.write_text(candidate_source, encoding="utf-8")
    _write_context(
        workspace,
        relative_path="candidate.py",
        base_sha256=byte_sha256(b"original candidate bytes"),
        patch_bytes=b"non-empty approved patch",
    )
    return workspace, ExecutionPlan(
        plan_id="victim.duplicate-race.candidate",
        argv=("/usr/local/bin/python", "-c", "import candidate"),
        timeout_seconds=10,
        expected_counts=(1, 1, 1),
    )


@pytest.fixture
def docker_job_root() -> Iterator[Path]:
    root = Path.cwd() / ".crosspatch" / "supervisor-tests" / secrets.token_hex(12)
    root.mkdir(mode=0o700, parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


@dataclass(frozen=True, slots=True)
class PostgresRuntime:
    host_dsn: str
    candidate_dsn: str
    network: str


def _postgres_runtime_addresses(
    *, name: str, network: str, password: str, host_port: int
) -> PostgresRuntime:
    return PostgresRuntime(
        host_dsn=(
            f"postgresql://crosspatch:{password}@127.0.0.1:{host_port}/crosspatch"
        ),
        candidate_dsn=(
            f"postgresql://crosspatch:{password}@{name}:5432/crosspatch"
        ),
        network=network,
    )


def test_candidate_database_address_uses_isolated_container_network() -> None:
    runtime = _postgres_runtime_addresses(
        name="crosspatch-p0-postgres-regression",
        network="crosspatch-p0-network-regression",
        password="test-password",
        host_port=54321,
    )

    assert runtime.network == "crosspatch-p0-network-regression"
    assert "@127.0.0.1:54321/crosspatch" in runtime.host_dsn
    assert "@crosspatch-p0-postgres-regression:5432/crosspatch" in runtime.candidate_dsn
    assert "host.docker.internal" not in runtime.candidate_dsn


@pytest.fixture
def postgres_runtime() -> Iterator[PostgresRuntime]:
    docker = _docker_binary()
    name = f"crosspatch-p0-postgres-{secrets.token_hex(8)}"
    network = f"crosspatch-p0-network-{secrets.token_hex(8)}"
    password = secrets.token_hex(16)
    subprocess.run(
        [docker, "network", "create", network],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        subprocess.run(
            [
                docker,
                "run",
                "--detach",
                "--rm",
                "--name",
                name,
                "--network",
                network,
                "--env",
                "POSTGRES_DB=crosspatch",
                "--env",
                "POSTGRES_USER=crosspatch",
                "--env",
                f"POSTGRES_PASSWORD={password}",
                "--publish",
                "127.0.0.1::5432",
                POSTGRES_IMAGE,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        try:
            port_output = subprocess.run(
                [docker, "port", name, "5432/tcp"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            port = int(port_output.rsplit(":", 1)[1])
            runtime = _postgres_runtime_addresses(
                name=name,
                network=network,
                password=password,
                host_port=port,
            )
            deadline = time.monotonic() + 45
            while True:
                try:
                    with psycopg.connect(
                        runtime.host_dsn, connect_timeout=1, autocommit=True
                    ) as connection:
                        connection.execute("SELECT 1")
                    break
                except psycopg.Error:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.25)
            schema = (REPOSITORY_ROOT / "infra/postgres/victim-init.sql").read_text(
                encoding="utf-8"
            )
            with psycopg.connect(runtime.host_dsn, autocommit=True) as connection:
                connection.execute(schema)
            yield runtime
        finally:
            subprocess.run(
                [docker, "rm", "--force", name],
                check=False,
                capture_output=True,
            )
    finally:
        subprocess.run(
            [docker, "network", "rm", network],
            check=False,
            capture_output=True,
        )


def _free_tcp_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _patched_candidate_workspace(root: Path) -> Path:
    job = root / "positive"
    workspace = job / "workspace"
    for relative in ("backend/src", "victim/src", "infra/postgres"):
        source = REPOSITORY_ROOT / relative
        shutil.copytree(source, workspace / relative)
    baseline = (REPOSITORY_ROOT / "victim/src/victim/db.py").read_bytes()
    subprocess.run(
        ["git", "apply", "--no-index", "--whitespace=nowarn", "-"],
        cwd=workspace,
        input=VALID_CANDIDATE_PATCH,
        check=True,
        capture_output=True,
    )
    _write_context(
        workspace,
        relative_path="victim/src/victim/db.py",
        base_sha256=byte_sha256(baseline),
        patch_bytes=VALID_CANDIDATE_PATCH,
    )
    return workspace


@pytest.mark.asyncio
async def test_import_time_zero_exit_and_forged_stdout_cannot_spoof_success(
    docker_job_root: Path,
):
    source = """import json
import os
print(json.dumps({"supervisor_verified": True, "passed": True, "exit_code": 0}), flush=True)
os._exit(0)
"""
    workspace, plan = _job(docker_job_root, source)
    supervisor = TrustedProcessSupervisor(
        executor=DockerCandidateExecutor(),
        verifier=RejectingBlackBoxVerifier(),
        supervisor_uid=os.geteuid(),
    )

    receipt = await supervisor.run(workspace, plan)

    assert receipt.exit_code == 0, "regression must exercise the zero-exit spoof"
    assert receipt.stdout_bytes > 0, "regression must exercise forged receipt output"
    assert receipt.supervisor_verified is False
    assert receipt.passed is False
    assert receipt.verification_code == "BLACK_BOX_OUTCOME_MISSING"


@pytest.mark.asyncio
async def test_candidate_has_no_context_source_write_or_receipt_capability(
    docker_job_root: Path,
):
    source = """import json
import os
from pathlib import Path
assert "CROSSPATCH_CANDIDATE_CONTEXT" not in os.environ
for guessed in (Path("/candidate-context.json"), Path("/workspace/../candidate-context.json")):
    try:
        guessed.read_bytes()
    except (FileNotFoundError, PermissionError, OSError):
        pass
    else:
        raise AssertionError("candidate context became visible")
candidate = Path("/workspace/candidate.py")
before = candidate.read_bytes()
try:
    candidate.write_text("forged source", encoding="utf-8")
except OSError:
    pass
else:
    raise AssertionError("candidate workspace is writable")
assert candidate.read_bytes() == before
print(json.dumps({"verification_code": "TRUSTED_DATABASE_INVARIANT_MATCHED"}), flush=True)
"""
    workspace, plan = _job(docker_job_root, source)
    context = workspace.parent / "candidate-context.json"
    context_before = context.read_bytes()
    source_before = (workspace / "candidate.py").read_bytes()
    executor = DockerCandidateExecutor()
    supervisor = TrustedProcessSupervisor(
        executor=executor,
        verifier=RejectingBlackBoxVerifier(),
        supervisor_uid=os.geteuid(),
    )

    receipt = await supervisor.run(workspace, plan)

    rendered = " ".join(executor.last_command)
    assert f"{workspace}:/workspace:ro" in executor.last_command
    assert "candidate-context" not in rendered
    assert "docker.sock" not in rendered
    assert context.stat().st_mode & 0o777 == 0o400
    assert context.read_bytes() == context_before
    assert (workspace / "candidate.py").read_bytes() == source_before
    assert receipt.exit_code == 0, executor.last_stderr.decode("utf-8", "replace")
    assert receipt.stdout_bytes > 0
    assert receipt.supervisor_verified is False
    assert receipt.passed is False
    assert receipt.verification_code == "BLACK_BOX_OUTCOME_MISSING"


@pytest.mark.asyncio
async def test_real_patched_candidate_passes_trusted_external_http_and_postgres_oracle(
    docker_job_root: Path,
    postgres_runtime: PostgresRuntime,
):
    workspace = _patched_candidate_workspace(docker_job_root)
    candidate_port = _free_tcp_port()
    service_driver = (
        REPOSITORY_ROOT
        / "backend/tests/security/fixtures/candidate_tcp_driver.py"
    )
    plan = ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
    executor = DockerCandidateExecutor(
        image=RUNNER_IMAGE,
        network=postgres_runtime.network,
        fixed_environment={
            "CROSSPATCH_CANDIDATE_DATABASE_URL": postgres_runtime.candidate_dsn,
            "CROSSPATCH_CANDIDATE_PORT": "8001",
            "CROSSPATCH_CANDIDATE_RUN_SECONDS": "7",
            "CROSSPATCH_CANDIDATE_WORKSPACE": "/workspace",
            "PYTHONPATH": "/workspace/backend/src:/workspace/victim/src",
        },
        extra_mounts=((service_driver, "/opt/crosspatch/candidate_service.py"),),
        published_ports=((candidate_port, 8001),),
    )
    verifier = PostgresHttpBlackBoxVerifier(
        dsn=postgres_runtime.host_dsn,
        victim_url=f"http://127.0.0.1:{candidate_port}",
    )
    supervisor = TrustedProcessSupervisor(
        executor=executor,
        verifier=verifier,
        supervisor_uid=os.geteuid(),
    )

    receipt = await supervisor.run(workspace, plan)

    rendered = " ".join(executor.last_command)
    assert f"{workspace}:/workspace:ro" in executor.last_command
    assert "candidate-context" not in rendered
    assert "docker.sock" not in rendered
    assert receipt.exit_code == 0, executor.last_stderr.decode("utf-8", "replace")
    assert receipt.supervisor_verified is True
    assert receipt.passed is True
    assert receipt.verification_code == "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED"
