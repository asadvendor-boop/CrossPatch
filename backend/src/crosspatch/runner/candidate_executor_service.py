"""Control service for the pre-provisioned candidate execution container."""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import hmac
import os
import signal
import socket
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.background import BackgroundTask
from starlette.responses import JSONResponse

from crosspatch.runner.candidate_lifecycle import (
    candidate_executor_boot_mac,
    new_candidate_executor_boot_id,
)
from crosspatch.runner.catalog import CANDIDATE_PLAN_IDS, ExecutionCatalog, ExecutionPlan
from crosspatch.runner.process import _apply_child_limits
from crosspatch.runner.secrets import (
    INSECURE_CANDIDATE_TOKEN,
    INSECURE_VICTIM_DATABASE_PASSWORDS,
    load_service_token,
    validate_release_database_url,
)

_MAX_OUTPUT_BYTES = 2 * 1024 * 1024
_CANDIDATE_RUNTIME_GID = 10004


class _ExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_id: str = Field(pattern=r"^cp-[0-9a-f]{32}$")
    workspace_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    environment: dict[str, str]

    @field_validator("environment")
    @classmethod
    def _validate_environment(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            if (
                not key.startswith("CROSSPATCH_VERIFICATION_")
                or not item
                or "\x00" in item
                or "CANDIDATE_CONTEXT" in key
                or "candidate-context" in item.casefold()
            ):
                raise ValueError("candidate challenge environment is unsafe")
        return value


class _ExecutionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str
    runtime_id: str
    exit_code: int | None
    timed_out: bool
    started_at: datetime
    finished_at: datetime
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    executor_boot_id: str = Field(pattern=r"^cpb-[0-9a-f]{32}$")
    executor_boot_mac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class _HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    boot_id: str = Field(pattern=r"^cpb-[0-9a-f]{32}$")
    boot_mac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_uid: int = Field(ge=1)
    service_role: str = Field(pattern=r"^candidate-executor$")


def _required(environment: dict[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value or "\x00" in value:
        raise RuntimeError(f"{name} is required")
    return value


def _resolve_candidate_plan_binding(
    plan_id: str,
    plan_sha256: str,
) -> ExecutionPlan:
    """Resolve only an exact server-owned candidate plan binding."""
    if plan_id not in CANDIDATE_PLAN_IDS:
        raise ValueError("candidate execution plan binding changed")
    plan = ExecutionCatalog.default().resolve(plan_id)
    if not hmac.compare_digest(plan_sha256, plan.sha256):
        raise ValueError("candidate execution plan binding changed")
    return plan


def _read_output(path: str) -> tuple[str, int]:
    value = Path(path).read_bytes()
    return hashlib.sha256(value).hexdigest(), len(value)


def _candidate_environment(
    *,
    database_url: str,
    workspace: Path,
    candidate_app_socket: Path,
    candidate_socket_fd: int,
    candidate_uid: int,
    executor_uid: int,
    executor_pid: int,
    run_seconds: float,
    challenge: dict[str, str],
) -> dict[str, str]:
    """Build the minimal child environment from immutable runtime paths."""
    ephemeral_secret = challenge.get("CROSSPATCH_VERIFICATION_SIGNING_SECRET", "")
    if (
        len(ephemeral_secret.encode("utf-8")) < 32
        or "\x00" in ephemeral_secret
        or any(character.isspace() for character in ephemeral_secret)
    ):
        raise RuntimeError("candidate attempt signing secret is invalid")
    forwarded = {
        key: value
        for key, value in challenge.items()
        if key
        not in {
            "CROSSPATCH_VERIFICATION_SCOPE_EVENT_ID",
            "CROSSPATCH_VERIFICATION_SCOPE_PROVIDER",
            "CROSSPATCH_VERIFICATION_SIGNING_SECRET",
        }
    }
    environment = {
        "CI": "1",
        "CROSSPATCH_CANDIDATE_DATABASE_URL": database_url,
        "CROSSPATCH_CANDIDATE_APP_SOCKET": str(candidate_app_socket),
        "CROSSPATCH_CANDIDATE_RUN_SECONDS": str(run_seconds),
        "CROSSPATCH_CANDIDATE_SOCKET_FD": str(candidate_socket_fd),
        "CROSSPATCH_CANDIDATE_UID": str(candidate_uid),
        "CROSSPATCH_CANDIDATE_WEBHOOK_SECRET": ephemeral_secret,
        "CROSSPATCH_CANDIDATE_WORKSPACE": str(workspace),
        "CROSSPATCH_EXECUTOR_UID": str(executor_uid),
        "CROSSPATCH_EXECUTOR_PID": str(executor_pid),
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": "/opt/crosspatch/venv/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        # The runner image copies this package tree as root-owned, read-only
        # input. Never import trusted runtime support from the candidate mount.
        "PYTHONPATH": "/opt/crosspatch/src",
    }
    environment.update(forwarded)
    return environment


def _database_identity(database_url: str) -> tuple[object, ...] | None:
    with psycopg.connect(database_url, autocommit=True) as connection:
        return connection.execute(
            """
            SELECT current_user, rolsuper, rolcreatedb, rolcreaterole,
                   rolinherit, rolreplication, rolbypassrls
              FROM pg_roles WHERE rolname = current_user
            """
        ).fetchone()


def _verify_candidate_database_boundary(candidate_url: str, scope_url: str) -> None:
    if _database_identity(candidate_url) != (
        "crosspatch_victim_candidate",
        False,
        False,
        False,
        False,
        False,
        False,
    ):
        raise RuntimeError("candidate database role boundary is invalid")
    if _database_identity(scope_url) != (
        "crosspatch_victim_scope",
        False,
        False,
        False,
        False,
        False,
        False,
    ):
        raise RuntimeError("candidate scope role boundary is invalid")
    with psycopg.connect(candidate_url, autocommit=True) as connection:
        privileges = connection.execute(
            """
            SELECT has_table_privilege(current_user, 'webhook_receipts', 'SELECT'),
                   has_table_privilege(current_user, 'webhook_receipts', 'INSERT'),
                   has_table_privilege(current_user, 'webhook_receipts', 'UPDATE'),
                   has_table_privilege(current_user, 'outbox_jobs', 'INSERT'),
                   has_table_privilege(current_user, 'deliveries', 'INSERT'),
                   (SELECT relrowsecurity AND relforcerowsecurity
                      FROM pg_class WHERE oid = 'webhook_receipts'::regclass),
                   (SELECT relrowsecurity AND relforcerowsecurity
                      FROM pg_class WHERE oid = 'outbox_jobs'::regclass)
            """
        ).fetchone()
    if privileges != (True, True, False, True, False, True, True):
        raise RuntimeError("candidate database privileges are invalid")
    with psycopg.connect(scope_url, autocommit=True) as connection:
        scope_privileges = connection.execute(
            """
            SELECT has_table_privilege(current_user, 'webhook_receipts', 'SELECT'),
                   has_table_privilege(current_user, 'candidate_scope_bindings', 'SELECT'),
                   has_function_privilege(
                       current_user,
                       'crosspatch_bind_candidate_scope(text,text,text,timestamptz)',
                       'EXECUTE'
                   ),
                   has_function_privilege(
                       current_user,
                       'crosspatch_clear_candidate_scope(text)',
                       'EXECUTE'
                   )
            """
        ).fetchone()
    if scope_privileges != (False, False, True, True):
        raise RuntimeError("candidate scope privileges are invalid")


def _bind_candidate_scope(
    scope_url: str,
    *,
    provider: str,
    event_id: str,
    runtime_id: str,
    expires_at: datetime,
) -> None:
    with psycopg.connect(scope_url, autocommit=True) as connection:
        connection.execute(
            "SELECT crosspatch_bind_candidate_scope(%s, %s, %s, %s)",
            (provider, event_id, runtime_id, expires_at),
        )


def _clear_candidate_scope(scope_url: str, runtime_id: str) -> None:
    with psycopg.connect(scope_url, autocommit=True) as connection:
        connection.execute(
            "SELECT crosspatch_clear_candidate_scope(%s)",
            (runtime_id,),
        )


def _open_candidate_listener(path: Path) -> socket.socket:
    try:
        parent = path.parent.resolve(strict=True)
        parent_metadata = parent.lstat()
    except OSError as error:
        raise RuntimeError("candidate socket parent is unavailable") from error
    if (
        not path.is_absolute()
        or path.parent != parent
        or parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or parent_metadata.st_gid != _CANDIDATE_RUNTIME_GID
        or stat.S_IMODE(parent_metadata.st_mode) != 0o2770
    ):
        raise RuntimeError("candidate socket parent policy changed")
    try:
        path_metadata = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if (
            not stat.S_ISSOCK(path_metadata.st_mode)
            or path_metadata.st_uid != os.geteuid()
            or path_metadata.st_gid != _CANDIDATE_RUNTIME_GID
            or stat.S_IMODE(path_metadata.st_mode) != 0o660
        ):
            raise RuntimeError("candidate socket path is occupied by an untrusted entry")
        path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        path.chmod(0o660)
        metadata = path.lstat()
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != _CANDIDATE_RUNTIME_GID
            or stat.S_IMODE(metadata.st_mode) != 0o660
        ):
            raise RuntimeError("candidate socket metadata policy changed after bind")
        listener.listen(128)
        listener.set_inheritable(True)
        return listener
    except BaseException:
        listener.close()
        path.unlink(missing_ok=True)
        raise


def _set_no_new_privileges() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "failed to set no_new_privs")


def _drop_capability_sets() -> None:
    class _CapabilityHeader(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class _CapabilityData(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    header = _CapabilityHeader(0x20080522, 0)
    data = (_CapabilityData * 2)()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), "failed to clear candidate capabilities")


def _drop_candidate_identity(*, candidate_uid: int, candidate_gid: int) -> None:
    """Irreversibly demote the child before any model-authored import."""
    os.setgroups([])
    os.setresgid(candidate_gid, candidate_gid, candidate_gid)
    os.setresuid(candidate_uid, candidate_uid, candidate_uid)
    _drop_capability_sets()
    _set_no_new_privileges()
    if (
        os.getresuid() != (candidate_uid, candidate_uid, candidate_uid)
        or os.getresgid() != (candidate_gid, candidate_gid, candidate_gid)
        or os.getgroups()
    ):
        raise RuntimeError("candidate child privilege drop did not become irreversible")


def _prepare_candidate_process(
    candidate_uid: int,
    candidate_gid: int,
    timeout_seconds: int,
) -> None:
    _drop_candidate_identity(candidate_uid=candidate_uid, candidate_gid=candidate_gid)
    _apply_child_limits(timeout_seconds, _MAX_OUTPUT_BYTES)


def _candidate_process_ids(candidate_uid: int) -> tuple[int, ...]:
    result: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status_text = (entry / "status").read_text(encoding="ascii")
        except (OSError, UnicodeError):
            continue
        uid_line = next(
            (line for line in status_text.splitlines() if line.startswith("Uid:")),
            "",
        )
        fields = uid_line.split()
        if len(fields) >= 3 and int(fields[1]) == candidate_uid:
            result.append(int(entry.name))
    return tuple(sorted(result))


async def _kill_candidate_processes(candidate_uid: int) -> None:
    for _attempt in range(50):
        process_ids = _candidate_process_ids(candidate_uid)
        if not process_ids:
            return
        for process_id in process_ids:
            try:
                os.kill(process_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
        await asyncio.sleep(0.02)


def create_app() -> FastAPI:
    configuration = dict(os.environ)
    token = load_service_token(
        configuration,
        "CROSSPATCH_CANDIDATE_EXECUTOR_TOKEN",
        insecure_values={INSECURE_CANDIDATE_TOKEN},
    )
    executor_uid = int(_required(configuration, "CROSSPATCH_EXECUTOR_UID"))
    candidate_uid = int(_required(configuration, "CROSSPATCH_CANDIDATE_UID"))
    candidate_gid = int(_required(configuration, "CROSSPATCH_CANDIDATE_GID"))
    if min(executor_uid, candidate_uid, candidate_gid) < 1:
        raise RuntimeError("candidate executor identities must be positive")
    if os.geteuid() != executor_uid:
        raise RuntimeError("candidate executor is not running under its trusted UID")
    if executor_uid == candidate_uid:
        raise RuntimeError("candidate child UID must differ from the executor UID")
    workspace_root = Path(
        _required(configuration, "CROSSPATCH_CANDIDATE_WORKSPACES_ROOT")
    ).resolve(strict=True)
    if workspace_root.is_symlink() or not workspace_root.is_dir():
        raise RuntimeError("candidate workspace mount is unavailable")
    database_url = validate_release_database_url(
        configuration,
        _required(configuration, "CROSSPATCH_CANDIDATE_DATABASE_URL"),
        label="candidate database",
        insecure_passwords=INSECURE_VICTIM_DATABASE_PASSWORDS,
    )
    scope_database_url = validate_release_database_url(
        configuration,
        _required(configuration, "CROSSPATCH_CANDIDATE_SCOPE_DATABASE_URL"),
        label="candidate scope database",
        insecure_passwords=INSECURE_VICTIM_DATABASE_PASSWORDS,
    )
    if urlsplit(database_url).username != "crosspatch_victim_candidate":
        raise RuntimeError("candidate database username is invalid")
    if urlsplit(scope_database_url).username != "crosspatch_victim_scope":
        raise RuntimeError("candidate scope database username is invalid")
    _verify_candidate_database_boundary(database_url, scope_database_url)
    candidate_app_socket = Path(
        _required(configuration, "CROSSPATCH_CANDIDATE_APP_SOCKET")
    )
    run_seconds = float(configuration.get("CROSSPATCH_CANDIDATE_RUN_SECONDS", "12"))
    if not candidate_app_socket.is_absolute() or not 2 <= run_seconds <= 120:
        raise RuntimeError("candidate executor service bounds are invalid")
    execution_lock = asyncio.Lock()
    boot_id = new_candidate_executor_boot_id()
    boot_mac = candidate_executor_boot_mac(token, boot_id, candidate_uid)
    app = FastAPI(title="CrossPatch candidate executor", docs_url=None, redoc_url=None)

    @app.get("/health", response_model=_HealthResponse)
    async def health() -> _HealthResponse:
        return _HealthResponse(
            boot_id=boot_id,
            boot_mac_sha256=boot_mac,
            candidate_uid=candidate_uid,
            service_role="candidate-executor",
        )

    async def terminate_after_response() -> None:
        await asyncio.sleep(0.05)
        os.kill(os.getpid(), signal.SIGTERM)

    @app.exception_handler(Exception)
    async def fail_closed_after_internal_error(
        _request: Request,
        _error: Exception,
    ) -> JSONResponse:
        return JSONResponse(
            {"detail": "candidate execution failed closed"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            background=BackgroundTask(terminate_after_response),
        )

    @app.post("/v1/execute", response_model=None)
    async def execute(
        request: _ExecutionRequest,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        expected_authorization = f"Bearer {token}"
        if authorization is None or not hmac.compare_digest(
            authorization, expected_authorization
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="candidate executor authentication failed",
            )
        try:
            plan = _resolve_candidate_plan_binding(
                request.plan_id,
                request.plan_sha256,
            )
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="candidate execution plan binding changed",
            ) from error
        workspace = (workspace_root / request.workspace_key).resolve(strict=True)
        try:
            relative = workspace.relative_to(workspace_root)
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="candidate workspace escaped its mount",
            ) from error
        metadata = workspace.lstat()
        if (
            len(relative.parts) != 1
            or workspace.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_mode & 0o222
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="candidate workspace is not a sealed directory",
            )
        visible_entries = {entry.name for entry in workspace_root.iterdir()}
        if visible_entries != {request.workspace_key, ".execution.lock"}:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="candidate handoff contains a sibling workspace",
            )
        scope_provider = request.environment.get(
            "CROSSPATCH_VERIFICATION_SCOPE_PROVIDER", ""
        )
        scope_event_id = request.environment.get(
            "CROSSPATCH_VERIFICATION_SCOPE_EVENT_ID", ""
        )
        if not scope_provider or not scope_event_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="candidate database scope is absent",
            )

        stdout_fd, stdout_name = tempfile.mkstemp(prefix="candidate-stdout-", dir="/tmp")
        stderr_fd, stderr_name = tempfile.mkstemp(prefix="candidate-stderr-", dir="/tmp")
        os.fchmod(stdout_fd, 0o600)
        os.fchmod(stderr_fd, 0o600)
        process: asyncio.subprocess.Process | None = None
        candidate_listener: socket.socket | None = None
        scope_bound = False
        timed_out = False
        started_at = datetime.now(UTC)
        try:
            async with execution_lock:
                await asyncio.to_thread(
                    _bind_candidate_scope,
                    scope_database_url,
                    provider=scope_provider,
                    event_id=scope_event_id,
                    runtime_id=request.runtime_id,
                    expires_at=datetime.now(UTC)
                    + timedelta(seconds=plan.timeout_seconds + 30),
                )
                scope_bound = True
                candidate_listener = _open_candidate_listener(candidate_app_socket)
                environment = _candidate_environment(
                    database_url=database_url,
                    workspace=workspace,
                    candidate_app_socket=candidate_app_socket,
                    candidate_socket_fd=candidate_listener.fileno(),
                    candidate_uid=candidate_uid,
                    executor_uid=executor_uid,
                    executor_pid=os.getpid(),
                    run_seconds=run_seconds,
                    challenge=request.environment,
                )
                with os.fdopen(stdout_fd, "wb", closefd=True) as stdout_file, os.fdopen(
                    stderr_fd, "wb", closefd=True
                ) as stderr_file:
                    process = await asyncio.create_subprocess_exec(
                        *plan.argv,
                        cwd=workspace,
                        env=environment,
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        close_fds=True,
                        pass_fds=(candidate_listener.fileno(),),
                        start_new_session=True,
                        preexec_fn=lambda: _prepare_candidate_process(
                            candidate_uid,
                            candidate_gid,
                            plan.timeout_seconds,
                        ),
                    )
                    try:
                        await asyncio.wait_for(process.wait(), timeout=plan.timeout_seconds)
                    except TimeoutError:
                        timed_out = True
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        await process.wait()
                    finally:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        await _kill_candidate_processes(candidate_uid)
            finished_at = datetime.now(UTC)
            stdout_sha256, stdout_bytes = _read_output(stdout_name)
            stderr_sha256, stderr_bytes = _read_output(stderr_name)
            response = _ExecutionResponse(
                plan_id=plan.plan_id,
                runtime_id=request.runtime_id,
                exit_code=process.returncode if process is not None else None,
                timed_out=timed_out,
                started_at=started_at,
                finished_at=finished_at,
                stdout_sha256=stdout_sha256,
                stderr_sha256=stderr_sha256,
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
                executor_boot_id=boot_id,
                executor_boot_mac_sha256=boot_mac,
            )
            return JSONResponse(
                response.model_dump(mode="json"),
                background=BackgroundTask(terminate_after_response),
            )
        finally:
            try:
                if scope_bound:
                    await asyncio.to_thread(
                        _clear_candidate_scope,
                        scope_database_url,
                        request.runtime_id,
                    )
            finally:
                if candidate_listener is not None:
                    candidate_listener.close()
                candidate_app_socket.unlink(missing_ok=True)
                Path(stdout_name).unlink(missing_ok=True)
                Path(stderr_name).unlink(missing_ok=True)

    return app
