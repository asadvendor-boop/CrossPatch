#!/opt/crosspatch/venv/bin/python
"""Root bootstrap for the capability-bounded candidate executor."""

from __future__ import annotations

import ctypes
import os
import socket
import stat
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path

EXECUTOR_UID = 10003
EXECUTOR_GID = 10003
RUNTIME_GROUP_GID = 10004
RUNTIME_ROOT = Path("/run/crosspatch")
CONTROL_DIRECTORY = RUNTIME_ROOT / "control"
CONTROL_SOCKET = CONTROL_DIRECTORY / "executor.sock"

_CAP_KILL = 5
_CAP_SETGID = 6
_CAP_SETUID = 7
REQUIRED_CAPABILITY_MASK = sum(
    1 << capability for capability in (_CAP_KILL, _CAP_SETGID, _CAP_SETUID)
)
_LINUX_CAPABILITY_VERSION_3 = 0x20080522
_PR_SET_KEEPCAPS = 8
_PR_SET_NO_NEW_PRIVS = 38
_TRUSTED_PACKAGE_ROOT = Path("/opt/crosspatch/src")


class _CapabilityHeader(ctypes.Structure):
    _fields_ = (("version", ctypes.c_uint32), ("pid", ctypes.c_int))


class _CapabilityData(ctypes.Structure):
    _fields_ = (
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    )


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def _prctl(option: int, argument: int) -> None:
    result = _libc().prctl(option, argument, 0, 0, 0)
    if result != 0:
        raise OSError(ctypes.get_errno(), f"prctl({option}) failed")


def _set_keep_capabilities(enabled: bool) -> None:
    _prctl(_PR_SET_KEEPCAPS, int(enabled))


def _set_no_new_privileges() -> None:
    _prctl(_PR_SET_NO_NEW_PRIVS, 1)


def _set_executor_capabilities() -> None:
    header = _CapabilityHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapabilityData * 2)()
    data[0] = _CapabilityData(
        effective=REQUIRED_CAPABILITY_MASK,
        permitted=REQUIRED_CAPABILITY_MASK,
        inheritable=0,
    )
    if _libc().capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), "failed to retain executor capabilities")


def _status_fields(status_text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in status_text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key] = value.strip()
    return fields


def _identity(fields: Mapping[str, str], name: str) -> tuple[int, ...]:
    values = tuple(int(value) for value in fields[name].split())
    if len(values) != 4:
        raise ValueError(f"{name} must expose four Linux identities")
    return values


def _capability(fields: Mapping[str, str], name: str) -> int:
    return int(fields[name], 16)


def _validate_root_status(status_text: str) -> None:
    fields = _status_fields(status_text)
    try:
        valid = (
            _identity(fields, "Uid") == (0, 0, 0, 0)
            and _identity(fields, "Gid") == (0, 0, 0, 0)
            and _capability(fields, "CapEff") == REQUIRED_CAPABILITY_MASK
            and _capability(fields, "CapPrm") == REQUIRED_CAPABILITY_MASK
            and _capability(fields, "CapBnd") == REQUIRED_CAPABILITY_MASK
            and _capability(fields, "CapInh") == 0
            and _capability(fields, "CapAmb") == 0
            and int(fields["NoNewPrivs"]) == 0
        )
    except (KeyError, ValueError) as error:
        raise RuntimeError("root process status is incomplete") from error
    if not valid:
        raise RuntimeError("root process status violates the bootstrap policy")


def _validate_executor_status(status_text: str) -> None:
    fields = _status_fields(status_text)
    try:
        groups = tuple(int(value) for value in fields.get("Groups", "").split())
        valid = (
            _identity(fields, "Uid") == (EXECUTOR_UID,) * 4
            and _identity(fields, "Gid") == (EXECUTOR_GID,) * 4
            and groups == (RUNTIME_GROUP_GID,)
            and _capability(fields, "CapEff") == REQUIRED_CAPABILITY_MASK
            and _capability(fields, "CapPrm") == REQUIRED_CAPABILITY_MASK
            and _capability(fields, "CapBnd") == REQUIRED_CAPABILITY_MASK
            and _capability(fields, "CapInh") == 0
            and _capability(fields, "CapAmb") == 0
            and int(fields["NoNewPrivs"]) == 1
        )
    except (KeyError, ValueError) as error:
        raise RuntimeError("executor process status is incomplete") from error
    if not valid:
        raise RuntimeError("executor process status violates the demotion policy")


def _read_status() -> str:
    try:
        return Path("/proc/self/status").read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise RuntimeError("Linux process status is unavailable") from error


def _assert_root_start() -> None:
    _validate_root_status(_read_status())


def _assert_executor_status() -> None:
    _validate_executor_status(_read_status())


def _require_real_directory(path: Path) -> None:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"runtime path is not a real directory: {path}")


def _validate_runtime_root(path: Path) -> None:
    _require_real_directory(path)
    metadata = path.lstat()
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        raise RuntimeError("candidate runtime root ownership changed")


def _clean_directory(directory: Path) -> None:
    for entry in directory.iterdir():
        if stat.S_ISDIR(entry.lstat().st_mode):
            raise RuntimeError(f"nested runtime directory is forbidden: {entry}")
        entry.unlink()


def _filesystem_ids() -> tuple[int, int]:
    fields = _status_fields(_read_status())
    try:
        return _identity(fields, "Uid")[3], _identity(fields, "Gid")[3]
    except (KeyError, ValueError) as error:
        raise RuntimeError("filesystem identities are unavailable") from error


@contextmanager
def _executor_filesystem_identity() -> Iterator[None]:
    libc = _libc()
    previous_gid = libc.setfsgid(RUNTIME_GROUP_GID)
    previous_uid = libc.setfsuid(EXECUTOR_UID)
    try:
        if _filesystem_ids() != (EXECUTOR_UID, RUNTIME_GROUP_GID):
            raise RuntimeError("failed to enter executor filesystem identity")
        yield
    finally:
        libc.setfsuid(previous_uid)
        libc.setfsgid(previous_gid)
        if _filesystem_ids() != (previous_uid, previous_gid):
            raise RuntimeError("failed to restore root filesystem identity")


def _create_executor_directory(path: Path) -> None:
    with _executor_filesystem_identity():
        path.mkdir(mode=0o770)
        path.chmod(0o2770)
        metadata = path.lstat()
        if (
            metadata.st_uid != EXECUTOR_UID
            or metadata.st_gid != RUNTIME_GROUP_GID
            or stat.S_IMODE(metadata.st_mode) != 0o2770
        ):
            raise RuntimeError("executor runtime directory ownership changed")


def _prepare_runtime(runtime_root: Path = RUNTIME_ROOT) -> None:
    runtime_root.mkdir(mode=0o755, parents=True, exist_ok=True)
    _validate_runtime_root(runtime_root)
    # CAP_CHOWN is intentionally absent. Retain root-group access only during
    # bootstrap and use filesystem IDs to create final 10003:10004 children.
    os.setgroups([0, RUNTIME_GROUP_GID])
    runtime_root.chmod(0o770)
    try:
        for directory in (runtime_root / "control", runtime_root / "app"):
            if directory.exists():
                _require_real_directory(directory)
                _clean_directory(directory)
                directory.rmdir()
            _create_executor_directory(directory)
    finally:
        runtime_root.chmod(0o755)


def _demote_executor() -> None:
    os.setgroups([RUNTIME_GROUP_GID])
    _set_keep_capabilities(True)
    os.setresgid(EXECUTOR_GID, EXECUTOR_GID, EXECUTOR_GID)
    os.setresuid(EXECUTOR_UID, EXECUTOR_UID, EXECUTOR_UID)
    _set_executor_capabilities()
    _set_keep_capabilities(False)


def _validate_control_parent(path: Path) -> None:
    if path != CONTROL_SOCKET or path.parent != CONTROL_DIRECTORY:
        raise RuntimeError("candidate executor control socket path changed")
    metadata = path.parent.lstat()
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != EXECUTOR_UID
        or metadata.st_gid != RUNTIME_GROUP_GID
        or stat.S_IMODE(metadata.st_mode) != 0o2770
    ):
        raise RuntimeError("candidate executor control directory policy changed")


def _open_control_socket(path: Path) -> socket.socket:
    _validate_control_parent(path)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != EXECUTOR_UID:
            raise RuntimeError("candidate executor control socket path is occupied")
        path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        listener.listen(128)
        listener.set_inheritable(False)
        metadata = path.lstat()
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != EXECUTOR_UID
            or metadata.st_gid != RUNTIME_GROUP_GID
            or stat.S_IMODE(metadata.st_mode) != 0o660
        ):
            raise RuntimeError("candidate executor control socket policy changed")
        return listener
    except BaseException:
        listener.close()
        path.unlink(missing_ok=True)
        raise


def _remove_owned_socket(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.geteuid():
        path.unlink()


def _run_uvicorn(environment: Mapping[str, str]) -> int:
    configured_socket = environment.get("CROSSPATCH_CANDIDATE_EXECUTOR_SOCKET", "")
    if configured_socket != str(CONTROL_SOCKET):
        raise RuntimeError("CROSSPATCH_CANDIDATE_EXECUTOR_SOCKET must use the fixed UDS")
    if _TRUSTED_PACKAGE_ROOT.is_dir():
        sys.path.insert(0, str(_TRUSTED_PACKAGE_ROOT))
    import uvicorn

    listener = _open_control_socket(CONTROL_SOCKET)
    server = uvicorn.Server(
        uvicorn.Config(
            "crosspatch.runner.candidate_executor_service:create_app",
            factory=True,
            access_log=False,
            log_level="info",
        )
    )
    try:
        server.run(sockets=[listener])
        return 0 if server.started else 1
    finally:
        listener.close()
        _remove_owned_socket(CONTROL_SOCKET)


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if arguments:
        raise RuntimeError("candidate executor entrypoint accepts no arguments")
    values = dict(os.environ if environment is None else environment)
    _assert_root_start()
    _prepare_runtime()
    os.umask(0o117)
    _demote_executor()
    _set_no_new_privileges()
    _assert_executor_status()
    return _run_uvicorn(values)


if __name__ == "__main__":
    raise SystemExit(main())
