#!/usr/bin/env python3
"""Create and validate operational PostgreSQL backups without shell redirection."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SANITIZED_ARCHIVE = "sanitized-artifacts.tar"
MANIFEST_AUTHENTICATOR = "manifest.hmac"
ALLOWED_MEMBERS = {
    "database.dump",
    "compose-config.json",
    "metadata.json",
    "manifest.json",
    MANIFEST_AUTHENTICATOR,
    SANITIZED_ARCHIVE,
}
RESTORE_PROJECT = re.compile(r"crosspatch-restore-[0-9a-f]{12}\Z")


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def manifest_authentication_key() -> bytes:
    configured = os.environ.get("CROSSPATCH_BACKUP_AUTH_KEY_FILE", "").strip()
    if not configured:
        raise RuntimeError("CROSSPATCH_BACKUP_AUTH_KEY_FILE is required")
    path = Path(configured)
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("backup authentication key must be a regular non-symlink file")
    if path.stat().st_mode & 0o077:
        raise RuntimeError("backup authentication key must be owner-only (mode 0600)")
    encoded = path.read_bytes().strip()
    if len(encoded) > 4096:
        raise RuntimeError("backup authentication key file is unexpectedly large")
    try:
        key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise RuntimeError("backup authentication key must be valid base64") from error
    if len(key) < 32:
        raise RuntimeError("backup authentication key must decode to at least 32 bytes")
    return key


def run(argv: list[str], *, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        argv,
        cwd=ROOT,
        input=input_bytes,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace")[-4000:]
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(argv)}\n{detail}")
    return result.stdout


def git_sha() -> str:
    return run(["git", "rev-parse", "HEAD"]).decode().strip()


def add_bytes(archive: tarfile.TarFile, name: str, value: bytes) -> None:
    information = tarfile.TarInfo(name)
    information.size = len(value)
    information.mode = 0o600
    information.mtime = int(datetime.now(UTC).timestamp())
    archive.addfile(information, io.BytesIO(value))


def validate_sanitized_archive(value: bytes) -> None:
    total_size = 0
    with tarfile.open(fileobj=io.BytesIO(value), mode="r:") as archive:
        for member in archive.getmembers():
            relative = PurePosixPath(member.name)
            if (
                relative.is_absolute()
                or not relative.parts
                or relative.parts[0] != "sanitized"
                or any(part in {"", ".", ".."} for part in relative.parts)
                or not (member.isfile() or member.isdir())
                or member.issym()
                or member.islnk()
            ):
                raise RuntimeError(f"unsafe sanitized artifact member: {member.name}")
            total_size += member.size
            if total_size > 512_000_000:
                raise RuntimeError("sanitized artifact archive exceeds the restore limit")


def backup(output_dir: Path) -> Path:
    authentication_key = manifest_authentication_key()
    database = run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "postgres",
            "pg_dump",
            "--username=crosspatch",
            "--dbname=crosspatch",
            "--format=custom",
            "--no-owner",
        ]
    )
    compose = run(["docker", "compose", "config", "--no-interpolate", "--format", "json"])
    sanitized = run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            (
                "import sys,tarfile; from pathlib import Path; "
                "root=Path('/var/lib/crosspatch/artifacts/sanitized'); "
                "archive=tarfile.open(fileobj=sys.stdout.buffer,mode='w|'); "
                "info=tarfile.TarInfo('sanitized'); "
                "info.type=tarfile.DIRTYPE; info.mode=448; "
                "archive.add(root,arcname='sanitized',recursive=True) "
                "if root.is_dir() else archive.addfile(info); archive.close()"
            ),
        ]
    )
    validate_sanitized_archive(sanitized)
    metadata = (
        json.dumps(
            {
                "schema_version": 1,
                "created_at": now(),
                "git_sha": git_sha(),
                "source": ("docker compose PostgreSQL custom dump plus sanitized artifact volume"),
                "contains_secrets": False,
                "handling": "sensitive operational backup; encrypt and store off-host",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    files = {
        "database.dump": database,
        "compose-config.json": compose,
        "metadata.json": metadata,
        SANITIZED_ARCHIVE: sanitized,
    }
    manifest = (
        json.dumps(
            {
                "schema_version": 1,
                "files": {
                    name: {"sha256": digest(value), "bytes": len(value)}
                    for name, value in sorted(files.items())
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    files["manifest.json"] = manifest
    files[MANIFEST_AUTHENTICATOR] = (
        hmac.new(authentication_key, manifest, hashlib.sha256).hexdigest().encode() + b"\n"
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    final = output_dir / f"crosspatch-{timestamp}.tar.gz"
    with tempfile.NamedTemporaryFile(dir=output_dir, prefix=".crosspatch-", delete=False) as temp:
        temporary = Path(temp.name)
    try:
        with tarfile.open(temporary, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for name, value in sorted(files.items()):
                add_bytes(archive, name, value)
        os.chmod(temporary, 0o600)
        os.replace(temporary, final)
    finally:
        temporary.unlink(missing_ok=True)
    (final.with_suffix(final.suffix + ".sha256")).write_text(
        f"{digest(final.read_bytes())}  {final.name}\n", encoding="utf-8"
    )
    return final


def read_archive(path: Path) -> dict[str, bytes]:
    authentication_key = manifest_authentication_key()
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("backup must be a regular file")
    result: dict[str, bytes] = {}
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)) or set(names) != ALLOWED_MEMBERS:
            raise RuntimeError("backup contains missing, duplicate, or unexpected members")
        for member in members:
            if not member.isfile() or member.issym() or member.islnk() or member.size > 512_000_000:
                raise RuntimeError(f"unsafe backup member: {member.name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise RuntimeError(f"backup member is unreadable: {member.name}")
            result[member.name] = stream.read()
    expected_authenticator = hmac.new(
        authentication_key,
        result["manifest.json"],
        hashlib.sha256,
    ).hexdigest()
    supplied_authenticator = (
        result[MANIFEST_AUTHENTICATOR].decode("ascii", errors="replace").strip()
    )
    if not hmac.compare_digest(expected_authenticator, supplied_authenticator):
        raise RuntimeError("backup manifest authentication failed")
    manifest = json.loads(result["manifest.json"])
    expected = manifest.get("files", {})
    for name in ALLOWED_MEMBERS - {"manifest.json", MANIFEST_AUTHENTICATOR}:
        record = expected.get(name, {})
        if record.get("sha256") != digest(result[name]) or record.get("bytes") != len(result[name]):
            raise RuntimeError(f"backup hash/length mismatch: {name}")
    validate_sanitized_archive(result[SANITIZED_ARCHIVE])
    return result


def require_isolated_restore_target() -> str:
    if os.environ.get("CROSSPATCH_RESTORE_CONFIRM") != "RESTORE":
        raise RuntimeError("set CROSSPATCH_RESTORE_CONFIRM=RESTORE for the isolated target")
    if os.environ.get("CROSSPATCH_RESTORE_TARGET") != "isolated-nonproduction":
        raise RuntimeError(
            "set CROSSPATCH_RESTORE_TARGET=isolated-nonproduction for a disposable target"
        )
    project = os.environ.get("CROSSPATCH_RESTORE_PROJECT", "")
    if RESTORE_PROJECT.fullmatch(project) is None:
        raise RuntimeError(
            "CROSSPATCH_RESTORE_PROJECT must match crosspatch-restore-<12 lowercase hex>"
        )
    if os.environ.get("COMPOSE_PROJECT_NAME") != project:
        raise RuntimeError("COMPOSE_PROJECT_NAME must exactly match CROSSPATCH_RESTORE_PROJECT")
    if os.environ.get("CROSSPATCH_RELEASE_MODE", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }:
        raise RuntimeError("restore is forbidden against a release-mode Compose project")
    return project


def restore(path: Path) -> None:
    require_isolated_restore_target()
    files = read_archive(path)
    # The target is contractually disposable and non-production. Reset its
    # migrated schema before replay so pg_restore never depends on drop order
    # for foreign keys that reference primary-key indexes.
    run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "postgres",
            "psql",
            "--username=crosspatch",
            "--dbname=crosspatch",
            "--set=ON_ERROR_STOP=1",
            "--command",
            "DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        ]
    )
    run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "postgres",
            "pg_restore",
            "--username=crosspatch",
            "--dbname=crosspatch",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--exit-on-error",
        ],
        input_bytes=files["database.dump"],
    )
    run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            (
                "import sys,tarfile; "
                "archive=tarfile.open(fileobj=sys.stdin.buffer,mode='r|'); "
                "archive.extractall(path='/var/lib/crosspatch/artifacts',filter='data')"
            ),
        ],
        input_bytes=files[SANITIZED_ARCHIVE],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(os.environ.get("CROSSPATCH_BACKUP_DIR", ROOT / "backups")),
    )
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("archive", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.operation == "backup":
            print(backup(arguments.output_dir))
        else:
            restore(arguments.archive)
            print("restore completed; run ./scripts/verify-release.sh --strict")
    except (RuntimeError, OSError, tarfile.TarError, json.JSONDecodeError) as error:
        print(f"{arguments.operation} failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
