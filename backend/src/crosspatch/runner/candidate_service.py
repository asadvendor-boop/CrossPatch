"""Root-owned sidecar entrypoint for candidate HTTP behavior.

This driver is mounted outside the candidate workspace. It starts candidate
code as a service but emits no authoritative receipt; the external supervisor
derives success from HTTP and PostgreSQL observations.
"""

from __future__ import annotations

import asyncio
import os
import socket
import stat
import sys
from pathlib import Path

import uvicorn

_ZERO_CAPABILITY_FIELDS = ("CapEff", "CapPrm", "CapInh", "CapAmb")


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or "\x00" in value:
        raise RuntimeError(f"{name} is required")
    return value


def _validate_linux_sandbox_status(
    status_text: str,
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    """Prove the candidate cannot retain or regain executor authority."""
    fields: dict[str, str] = {}
    for line in status_text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key] = value.strip()
    try:
        uids = tuple(int(value) for value in fields["Uid"].split())
        gids = tuple(int(value) for value in fields["Gid"].split())
        capabilities = tuple(
            int(fields[name], 16) for name in _ZERO_CAPABILITY_FIELDS
        )
    except (KeyError, ValueError) as error:
        raise RuntimeError("candidate sandbox status is incomplete") from error
    groups = tuple(int(value) for value in fields.get("Groups", "").split())
    if uids != (expected_uid,) * 4 or gids != (expected_gid,) * 4:
        raise RuntimeError("candidate retained a privileged real or saved identity")
    # Some container runtimes repeat the primary unprivileged GID in Groups.
    # No other supplementary identity is acceptable.
    if any(group != expected_gid for group in groups) or any(capabilities):
        raise RuntimeError("candidate retained supplementary groups or capabilities")
    if fields.get("NoNewPrivs") != "1":
        raise RuntimeError("candidate can still acquire privileges across exec")


def _validate_candidate_listener(
    listener: socket.socket,
    *,
    socket_path: Path,
) -> None:
    """Verify the exact inherited endpoint without granting path traversal.

    The trusted executor validates filesystem ownership and permissions before
    demoting the child. The candidate intentionally cannot traverse that
    setgid directory, so this process validates the inherited descriptor and
    exact Unix-domain binding only.
    """
    if (
        not socket_path.is_absolute()
        or listener.family != socket.AF_UNIX
        or listener.type & socket.SOCK_STREAM == 0
        or Path(listener.getsockname()) != socket_path
        or not stat.S_ISSOCK(os.fstat(listener.fileno()).st_mode)
    ):
        raise RuntimeError("candidate service listener binding is invalid")


async def serve() -> int:
    expected_uid = int(_required("CROSSPATCH_CANDIDATE_UID"))
    expected_gid = expected_uid
    executor_uid = int(_required("CROSSPATCH_EXECUTOR_UID"))
    executor_pid = int(_required("CROSSPATCH_EXECUTOR_PID"))
    if expected_uid < 1 or os.geteuid() != expected_uid:
        raise RuntimeError("candidate service did not enter the dedicated candidate UID")
    if executor_uid < 1 or executor_uid == expected_uid:
        raise RuntimeError("candidate service executor UID boundary is invalid")
    if executor_pid < 1 or os.getpid() == executor_pid:
        raise RuntimeError("candidate service did not cross the executor PID boundary")
    try:
        process_status = Path("/proc/self/status").read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise RuntimeError("candidate sandbox status is unavailable") from error
    _validate_linux_sandbox_status(
        process_status,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    workspace = Path(_required("CROSSPATCH_CANDIDATE_WORKSPACE")).resolve(strict=True)
    if workspace.is_symlink() or not workspace.is_dir():
        raise RuntimeError("candidate workspace must be a real directory")
    candidate_source = workspace / "victim" / "src"
    if not candidate_source.is_dir():
        raise RuntimeError("candidate victim source is unavailable")
    # uvicorn and this driver are imported before candidate source enters the
    # module search path. Only the victim package is intentionally untrusted.
    sys.path.insert(0, str(candidate_source))
    from victim.app import create_app
    from victim.db import Database

    database = Database(_required("CROSSPATCH_CANDIDATE_DATABASE_URL"))
    secret = _required("CROSSPATCH_CANDIDATE_WEBHOOK_SECRET")
    candidate_app_socket = Path(_required("CROSSPATCH_CANDIDATE_APP_SOCKET"))
    listener_fd = int(_required("CROSSPATCH_CANDIDATE_SOCKET_FD"))
    run_seconds = float(os.environ.get("CROSSPATCH_CANDIDATE_RUN_SECONDS", "30"))
    if listener_fd < 3 or not 2 <= run_seconds <= 120:
        raise RuntimeError("candidate service bounds are invalid")
    listener = socket.socket(fileno=listener_fd)
    _validate_candidate_listener(listener, socket_path=candidate_app_socket)
    listener.set_inheritable(False)

    server = uvicorn.Server(
        uvicorn.Config(
            create_app(database=database, signing_secret=secret),
            access_log=False,
            log_level="warning",
        )
    )

    async def stop_at_deadline() -> None:
        await asyncio.sleep(run_seconds)
        server.should_exit = True

    deadline = asyncio.create_task(stop_at_deadline())
    try:
        await server.serve(sockets=[listener])
    finally:
        deadline.cancel()
        await asyncio.gather(deadline, return_exceptions=True)
        listener.close()
    return 0 if server.started else 1


if __name__ == "__main__":  # pragma: no cover - executed in the sidecar
    raise SystemExit(asyncio.run(serve()))
