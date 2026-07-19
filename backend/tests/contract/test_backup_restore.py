from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import io
import json
import os
import sys
import tarfile
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _load_script() -> ModuleType:
    path = ROOT / "scripts" / "backup_restore.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_backup_restore_contract", path
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _sanitized_archive() -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as archive:
        directory = tarfile.TarInfo("sanitized")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
    return stream.getvalue()


def _write_authenticated_archive(
    module: ModuleType,
    path: Path,
    key: bytes,
    *,
    authenticate: bytes | None = None,
) -> None:
    files = {
        "database.dump": b"database",
        "compose-config.json": b"{}\n",
        "metadata.json": b"{}\n",
        module.SANITIZED_ARCHIVE: _sanitized_archive(),
    }
    manifest = (
        json.dumps(
            {
                "schema_version": 1,
                "files": {
                    name: {"sha256": module.digest(value), "bytes": len(value)}
                    for name, value in sorted(files.items())
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    files["manifest.json"] = manifest
    files[module.MANIFEST_AUTHENTICATOR] = (
        hmac.new(key, authenticate if authenticate is not None else manifest, hashlib.sha256)
        .hexdigest()
        .encode()
        + b"\n"
    )
    with tarfile.open(path, "w:gz") as archive:
        for name, value in sorted(files.items()):
            module.add_bytes(archive, name, value)


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        ({}, "CROSSPATCH_RESTORE_CONFIRM"),
        (
            {
                "CROSSPATCH_RESTORE_CONFIRM": "RESTORE",
                "CROSSPATCH_RESTORE_TARGET": "isolated-nonproduction",
                "CROSSPATCH_RESTORE_PROJECT": "crosspatch",
                "COMPOSE_PROJECT_NAME": "crosspatch",
            },
            "crosspatch-restore",
        ),
        (
            {
                "CROSSPATCH_RESTORE_CONFIRM": "RESTORE",
                "CROSSPATCH_RESTORE_TARGET": "isolated-nonproduction",
                "CROSSPATCH_RESTORE_PROJECT": "crosspatch-restore-a1b2c3d4e5f6",
                "COMPOSE_PROJECT_NAME": "crosspatch-production",
            },
            "COMPOSE_PROJECT_NAME",
        ),
        (
            {
                "CROSSPATCH_RESTORE_CONFIRM": "RESTORE",
                "CROSSPATCH_RESTORE_TARGET": "isolated-nonproduction",
                "CROSSPATCH_RESTORE_PROJECT": "crosspatch-restore-a1b2c3d4e5f6",
                "COMPOSE_PROJECT_NAME": "crosspatch-restore-a1b2c3d4e5f6",
                "CROSSPATCH_RELEASE_MODE": "1",
            },
            "release-mode",
        ),
    ],
)
def test_restore_refuses_unisolated_targets_before_reading_archive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment: dict[str, str],
    message: str,
) -> None:
    module = _load_script()
    for name in (
        "COMPOSE_PROJECT_NAME",
        "CROSSPATCH_RELEASE_MODE",
        "CROSSPATCH_RESTORE_CONFIRM",
        "CROSSPATCH_RESTORE_PROJECT",
        "CROSSPATCH_RESTORE_TARGET",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        module,
        "read_archive",
        lambda _path: (_ for _ in ()).throw(AssertionError("archive was read")),
    )

    with pytest.raises(RuntimeError, match=message):
        module.restore(tmp_path / "backup.tar.gz")


def test_restore_uses_only_the_explicit_disposable_project(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_script()
    project = "crosspatch-restore-a1b2c3d4e5f6"
    monkeypatch.setenv("CROSSPATCH_RESTORE_CONFIRM", "RESTORE")
    monkeypatch.setenv("CROSSPATCH_RESTORE_TARGET", "isolated-nonproduction")
    monkeypatch.setenv("CROSSPATCH_RESTORE_PROJECT", project)
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", project)
    monkeypatch.delenv("CROSSPATCH_RELEASE_MODE", raising=False)
    monkeypatch.setattr(
        module,
        "read_archive",
        lambda _path: {
            "database.dump": b"database",
            module.SANITIZED_ARCHIVE: b"sanitized",
        },
    )
    commands: list[tuple[list[str], bytes | None]] = []

    def fake_run(argv: list[str], *, input_bytes: bytes | None = None) -> bytes:
        commands.append((argv, input_bytes))
        assert module.os.environ["COMPOSE_PROJECT_NAME"] == project
        return b""

    monkeypatch.setattr(module, "run", fake_run)

    module.restore(tmp_path / "backup.tar.gz")

    assert len(commands) == 3
    assert all(command[:3] == ["docker", "compose", "exec"] for command, _ in commands)
    assert commands[0][0][-2:] == [
        "--command",
        "DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
    ]
    assert commands[0][1] is None
    assert commands[1][1] == b"database"
    assert commands[2][1] == b"sanitized"


def test_backup_manifest_is_authenticated_before_restore_input_is_trusted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_script()
    key = b"k" * 48
    key_path = tmp_path / "backup-auth.key"
    key_path.write_bytes(base64.b64encode(key) + b"\n")
    key_path.chmod(0o600)
    monkeypatch.setenv("CROSSPATCH_BACKUP_AUTH_KEY_FILE", str(key_path))

    valid = tmp_path / "valid.tar.gz"
    _write_authenticated_archive(module, valid, key)
    assert module.read_archive(valid)["database.dump"] == b"database"

    unauthenticated = tmp_path / "unauthenticated.tar.gz"
    _write_authenticated_archive(
        module,
        unauthenticated,
        key,
        authenticate=b"a different manifest\n",
    )
    with pytest.raises(RuntimeError, match="manifest authentication failed"):
        module.read_archive(unauthenticated)


def test_backup_authentication_key_must_be_owner_only_and_unpredictable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_script()
    key_path = tmp_path / "backup-auth.key"
    key_path.write_bytes(base64.b64encode(b"short") + b"\n")
    key_path.chmod(0o600)
    monkeypatch.setenv("CROSSPATCH_BACKUP_AUTH_KEY_FILE", str(key_path))
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        module.manifest_authentication_key()

    key_path.write_bytes(base64.b64encode(os.urandom(48)) + b"\n")
    key_path.chmod(0o640)
    with pytest.raises(RuntimeError, match="owner-only"):
        module.manifest_authentication_key()
