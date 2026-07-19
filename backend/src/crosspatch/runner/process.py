"""Fixed-argv subprocess execution with a clean environment and group cleanup."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import resource
import signal
import stat
import sys
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from crosspatch.domain.hashing import sha256_hex
from crosspatch.runner.catalog import CANDIDATE_PLAN_IDS, ExecutionPlan
from crosspatch.runner.results import ProcessReceipt

_ALLOWED_RUNTIME_ENV = frozenset(
    {
        "CROSSPATCH_TEST_DATABASE_URL",
        "CROSSPATCH_VICTIM_URL",
        "CROSSPATCH_VICTIM_WEBHOOK_SECRET",
    }
)


class Catalog(Protocol):
    def resolve(self, plan_id: str) -> ExecutionPlan: ...


class RunnerPolicyViolation(ValueError):
    pass


def _apply_child_limits(timeout_seconds: int, max_output_bytes: int) -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_output_bytes, max_output_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    # RLIMIT_NPROC is per real user on macOS, where the local test runner
    # shares the developer account with unrelated processes. The production
    # runner is Linux and has its own UID/PID namespace, so enforce it there.
    if sys.platform.startswith("linux") and hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    resource.setrlimit(
        resource.RLIMIT_CPU,
        (max(1, timeout_seconds), max(2, timeout_seconds + 1)),
    )
    if sys.platform.startswith("linux") and hasattr(resource, "RLIMIT_AS"):
        gibibyte = 1024 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (gibibyte, gibibyte))


class FixedProcessRunner:
    # Direct subprocess exit is diagnostic only and cannot be injected into
    # the mutation broker as a success authority.
    trusted_supervisor = False
    def __init__(
        self,
        *,
        catalog: Catalog,
        runtime_environment: Mapping[str, str] | None = None,
        max_output_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        supplied = dict(runtime_environment or {})
        unknown = set(supplied) - _ALLOWED_RUNTIME_ENV
        if unknown:
            raise RunnerPolicyViolation(f"runtime environment contains forbidden keys: {unknown}")
        self._catalog = catalog
        self._runtime_environment = supplied
        self._max_output_bytes = max_output_bytes

    def _validate_plan(self, plan: ExecutionPlan) -> None:
        try:
            expected = self._catalog.resolve(plan.plan_id)
        except LookupError as error:
            raise RunnerPolicyViolation("plan is absent from the immutable catalog") from error
        if not hmac.compare_digest(expected.sha256, plan.sha256):
            raise RunnerPolicyViolation("argv or settings differ from the immutable catalog")
        if plan.plan_id in CANDIDATE_PLAN_IDS:
            raise RunnerPolicyViolation(
                "candidate plan requires the trusted candidate sidecar"
            )
        executable = Path(plan.argv[0])
        if not executable.is_absolute():
            raise RunnerPolicyViolation("catalog executable must be absolute")
        try:
            metadata = executable.stat()
        except OSError as error:
            raise RunnerPolicyViolation("catalog executable is unavailable") from error
        if not stat.S_ISREG(metadata.st_mode) or not os.access(executable, os.X_OK):
            raise RunnerPolicyViolation("catalog executable is not an executable regular file")
        if plan.working_directory != "/workspace":
            raise RunnerPolicyViolation("catalog working directory must be /workspace")

    def _environment(self, workspace: Path, plan: ExecutionPlan) -> dict[str, str]:
        home = workspace.parent / ".crosspatch-home"
        home.mkdir(mode=0o700, exist_ok=True)
        environment = {
            "CI": "1",
            "HOME": str(home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_COLOR": "1",
            "PATH": "/opt/crosspatch/venv/bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": f"{workspace}/backend/src:{workspace}/victim/src",
            "PYTEST_ADDOPTS": "-p no:cacheprovider",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "NPM_CONFIG_IGNORE_SCRIPTS": "true",
            "npm_config_ignore_scripts": "true",
        }
        environment.update(self._runtime_environment)
        return environment

    async def run(self, workspace: Path, plan: ExecutionPlan) -> ProcessReceipt:
        workspace = Path(workspace).resolve(strict=True)
        if not workspace.is_dir() or workspace.is_symlink():
            raise RunnerPolicyViolation("workspace must be a real directory")
        self._validate_plan(plan)
        environment = self._environment(workspace, plan)
        stdout_fd, stdout_name = tempfile.mkstemp(prefix="stdout-", dir=workspace.parent)
        stderr_fd, stderr_name = tempfile.mkstemp(prefix="stderr-", dir=workspace.parent)
        os.fchmod(stdout_fd, 0o600)
        os.fchmod(stderr_fd, 0o600)
        started_at = datetime.now(UTC)
        timed_out = False
        process: asyncio.subprocess.Process | None = None
        try:
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
                    start_new_session=True,
                    preexec_fn=lambda: _apply_child_limits(
                        plan.timeout_seconds, self._max_output_bytes
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
                    # A test can exit while leaving descendants. They share the
                    # new process group and are killed before the receipt returns.
                    if not timed_out:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
            finished_at = datetime.now(UTC)
            stdout = Path(stdout_name).read_bytes()
            stderr = Path(stderr_name).read_bytes()
            return ProcessReceipt(
                plan_id=plan.plan_id,
                plan_sha256=plan.sha256,
                argv_sha256=sha256_hex(plan.argv),
                exit_code=process.returncode if process is not None else None,
                timed_out=timed_out,
                started_at=started_at,
                finished_at=finished_at,
                stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                stderr_sha256=hashlib.sha256(stderr).hexdigest(),
                stdout_bytes=len(stdout),
                stderr_bytes=len(stderr),
                stdout_truncated=len(stdout) >= self._max_output_bytes,
                stderr_truncated=len(stderr) >= self._max_output_bytes,
                supervisor_verified=False,
                verification_code="UNSUPERVISED_PROCESS_EXIT",
                verification_sha256="0" * 64,
            )
        finally:
            Path(stdout_name).unlink(missing_ok=True)
            Path(stderr_name).unlink(missing_ok=True)
