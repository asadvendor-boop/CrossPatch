"""Strict runtime configuration and judge-token lifecycle."""

from __future__ import annotations

import fcntl
import os
import secrets
import stat
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_JUDGE_TOKEN_EXPIRY = datetime(2026, 8, 13, 7, tzinfo=UTC)
DEFAULT_JUDGE_TOKEN_EXPIRY = datetime(2026, 9, 1, 7, tzinfo=UTC)

_DEFAULT_JUDGE_TOKEN_FILE = Path(".crosspatch/secrets/judge-token")
_DEFAULT_OPERATOR_TOKEN_FILE = Path(".crosspatch/secrets/operator-token")
_DEFAULT_APPROVER_TOKEN_FILE = Path(".crosspatch/secrets/approver-token")
_DEFAULT_APPROVER_CSRF_FILE = Path(".crosspatch/secrets/approver-csrf-token")
_DEFAULT_APPROVER_STEP_UP_FILE = Path(".crosspatch/secrets/approver-step-up-token")
_DEFAULT_EVIDENCE_SIGNING_FILE = Path(".crosspatch/secrets/evidence-mcp-signing-secret")
_DEFAULT_BROKER_SIGNING_FILE = Path(".crosspatch/secrets/broker-mcp-signing-secret")
_DEFAULT_JUDGE_SIGNING_FILE = Path(".crosspatch/secrets/judge-mcp-signing-secret")
_DEFAULT_APPROVAL_MAC_FILE = Path(".crosspatch/secrets/approval-mac-key")
_DEFAULT_EXPORT_SIGNING_FILE = Path(".crosspatch/secrets/export-signing-seed")
_DEFAULT_VICTIM_WEBHOOK_FILE = Path(".crosspatch/secrets/victim-webhook-secret")
_JUDGE_TOKEN_BYTES = 48
_TOKEN_BOOTSTRAP_LOCK = threading.Lock()


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def validate_judge_token_expiry(value: datetime) -> datetime:
    """Normalize a judge-token expiry to UTC and enforce the hosted judge window."""
    minimum = _utc_text(MIN_JUDGE_TOKEN_EXPIRY)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"judge token expiry must be timezone-aware and at or after {minimum}")

    normalized = value.astimezone(UTC)
    if normalized < MIN_JUDGE_TOKEN_EXPIRY:
        raise ValueError(f"judge token expiry must be at or after {minimum}")
    return normalized


def _read_existing_token(path: Path) -> str:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"runtime token path must be a regular file: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        path.chmod(0o600)
    token = path.read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError(f"runtime token file is empty: {path}")
    return token


@contextmanager
def _token_bootstrap_file_lock(path: Path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    lock_path = path.with_name(f".{path.name}.lock")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _publish_token_atomically(path: Path, token: str) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as token_file:
            descriptor = None
            token_file.write(f"{token}\n")
            token_file.flush()
            os.fsync(token_file.fileno())
        os.replace(temporary, path)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _load_or_create_judge_token_at(path: Path) -> SecretStr:
    with _TOKEN_BOOTSTRAP_LOCK, _token_bootstrap_file_lock(path):
        try:
            return SecretStr(_read_existing_token(path))
        except FileNotFoundError:
            pass

        candidate = secrets.token_urlsafe(_JUDGE_TOKEN_BYTES)
        _publish_token_atomically(path, candidate)
        return SecretStr(_read_existing_token(path))


def _load_or_create_judge_token() -> SecretStr:
    return _load_or_create_judge_token_at(_DEFAULT_JUDGE_TOKEN_FILE)


def _secret_factory(path: Path):
    return lambda: _load_or_create_judge_token_at(path)


class Settings(BaseSettings):
    """Validated settings loaded from environment variables or a local `.env` file."""

    model_config = SettingsConfigDict(
        env_prefix="CROSSPATCH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )

    openai_api_key: SecretStr | None = Field(default=None, validation_alias="OPENAI_API_KEY")
    openai_api: Literal["responses"] = "responses"
    judge_token: SecretStr = Field(default_factory=_load_or_create_judge_token)
    judge_token_expires_at: datetime = DEFAULT_JUDGE_TOKEN_EXPIRY
    database_url: str = "postgresql+asyncpg://crosspatch:crosspatch@127.0.0.1:5432/crosspatch"
    repository_root: Path = Path(".")
    allowed_origins: str = "http://127.0.0.1:3000,http://localhost:3000"
    operator_token: SecretStr = Field(
        default_factory=_secret_factory(_DEFAULT_OPERATOR_TOKEN_FILE)
    )
    approver_token: SecretStr = Field(
        default_factory=_secret_factory(_DEFAULT_APPROVER_TOKEN_FILE)
    )
    approver_csrf_token: SecretStr = Field(
        default_factory=_secret_factory(_DEFAULT_APPROVER_CSRF_FILE)
    )
    approver_step_up_token: SecretStr = Field(
        default_factory=_secret_factory(_DEFAULT_APPROVER_STEP_UP_FILE)
    )
    api_token_expires_at: datetime = DEFAULT_JUDGE_TOKEN_EXPIRY
    approver_step_up_expires_at: datetime = DEFAULT_JUDGE_TOKEN_EXPIRY
    evidence_mcp_signing_secret: SecretStr = Field(
        default_factory=_secret_factory(_DEFAULT_EVIDENCE_SIGNING_FILE)
    )
    broker_mcp_signing_secret: SecretStr = Field(
        default_factory=_secret_factory(_DEFAULT_BROKER_SIGNING_FILE)
    )
    judge_mcp_signing_secret: SecretStr = Field(
        default_factory=_secret_factory(_DEFAULT_JUDGE_SIGNING_FILE)
    )
    approval_mac_key: SecretStr = Field(
        default_factory=_secret_factory(_DEFAULT_APPROVAL_MAC_FILE)
    )
    export_signing_seed: SecretStr = Field(
        default_factory=_secret_factory(_DEFAULT_EXPORT_SIGNING_FILE)
    )
    victim_webhook_secret: SecretStr = Field(
        default_factory=_secret_factory(_DEFAULT_VICTIM_WEBHOOK_FILE)
    )
    victim_database_url: str = (
        "postgresql://crosspatch_victim:crosspatch_victim@127.0.0.1:5432/crosspatch_victim"
    )
    victim_url: str = "http://127.0.0.1:8001"
    evidence_mcp_url: str = "http://127.0.0.1:8101/mcp"
    broker_mcp_url: str = "http://127.0.0.1:8102/mcp"
    evidence_mcp_host: str = "127.0.0.1:8101"
    judge_mcp_host: str = "127.0.0.1:8103"
    broker_mcp_host: str = "127.0.0.1:8102"
    control_origin: str = "http://127.0.0.1:8000"
    public_origin: str = "http://127.0.0.1:3000"
    raw_artifact_root: Path = Path(".crosspatch/artifacts/raw")
    sanitized_artifact_root: Path = Path(".crosspatch/artifacts/sanitized")
    session_database_path: Path = Path(".crosspatch/sessions/agents.sqlite")
    repository_id: str = "crosspatch"
    approval_mac_key_id: str = "approval-v1"
    runner_digest: str | None = None
    environment_digest: str | None = None

    @field_validator("judge_token")
    @classmethod
    def _validate_judge_token(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("judge token must not be blank")
        return value

    _validate_judge_expiry = field_validator("judge_token_expires_at")(
        validate_judge_token_expiry
    )
    _validate_api_expiry = field_validator("api_token_expires_at")(
        validate_judge_token_expiry
    )
    _validate_step_up_expiry = field_validator("approver_step_up_expires_at")(
        validate_judge_token_expiry
    )

    @field_validator("runner_digest", "environment_digest")
    @classmethod
    def _validate_optional_digest(cls, value: str | None) -> str | None:
        if value is not None and (
            len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError("runtime digests must be lowercase SHA-256")
        return value
