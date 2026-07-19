"""Fail-closed loading for runner-bound bearer tokens."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Set
from pathlib import Path
from urllib.parse import unquote, urlsplit

INSECURE_RUNNER_TOKEN = "crosspatch-local-runner-service-token-32chars"
INSECURE_CANDIDATE_TOKEN = "crosspatch-local-sidecar-token-32chars"
INSECURE_VICTIM_DATABASE_PASSWORD = "crosspatch-victim-local-only"
INSECURE_VICTIM_DATABASE_PASSWORDS = frozenset(
    {
        INSECURE_VICTIM_DATABASE_PASSWORD,
        "crosspatch-victim-app-local-only",
        "crosspatch-victim-candidate-local-only",
        "crosspatch-victim-worker-local-only",
        "crosspatch-victim-oracle-local-only",
        "crosspatch-victim-scope-local-only",
    }
)
INSECURE_VICTIM_WEBHOOK_SECRET = "crosspatch-local-webhook-secret-change-me"
_TRUE = frozenset({"1", "true", "yes"})
_FALSE = frozenset({"0", "false", "no", ""})


class RunnerSecretViolation(ValueError):
    """Raised when a runner token source is absent, ambiguous, or unsafe."""


def _release_mode(environment: Mapping[str, str]) -> bool:
    value = environment.get("CROSSPATCH_RELEASE_MODE", "0").strip().casefold()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise RunnerSecretViolation("CROSSPATCH_RELEASE_MODE must be a boolean value")


def _read_private_token(path_value: str) -> str:
    path = Path(path_value)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RunnerSecretViolation("runner token file is unavailable") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise RunnerSecretViolation("runner token file must be a regular file")
    if metadata.st_uid != os.geteuid():
        raise RunnerSecretViolation("runner token file must be owned by the service UID")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise RunnerSecretViolation("runner token file must have exact mode 0600")
    if metadata.st_size > 4096:
        raise RunnerSecretViolation("runner token file is oversized")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RunnerSecretViolation("runner token file cannot be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        original_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_size,
        )
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_uid,
            stat.S_IMODE(opened.st_mode),
            opened.st_size,
        )
        if original_identity != opened_identity or not stat.S_ISREG(opened.st_mode):
            raise RunnerSecretViolation("runner token file changed while being opened")
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            raw = source.read(4097)
            after = os.fstat(source.fileno())
        if len(raw) > 4096:
            raise RunnerSecretViolation("runner token file is oversized")
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            stat.S_IMODE(after.st_mode),
            after.st_size,
        )
        if after_identity != opened_identity or after.st_mtime_ns != opened.st_mtime_ns:
            raise RunnerSecretViolation("runner token file changed while being read")
        rendered = raw.decode("utf-8")
    except UnicodeError as error:
        raise RunnerSecretViolation("runner token file is not strict UTF-8") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    value = rendered.removesuffix("\n")
    if rendered not in {value, f"{value}\n"}:
        raise RunnerSecretViolation("runner token file has non-canonical whitespace")
    return value


def load_service_token(
    environment: Mapping[str, str],
    name: str,
    *,
    insecure_values: Set[str] = frozenset(),
) -> str:
    """Load one token from an environment value or an owned mode-0600 file."""
    direct = environment.get(name, "")
    file_value = environment.get(f"{name}_FILE", "")
    if bool(direct) == bool(file_value):
        raise RunnerSecretViolation(
            f"exactly one of {name} or {name}_FILE must be configured"
        )
    value = direct if direct else _read_private_token(file_value)
    if "\x00" in value or any(character.isspace() for character in value):
        raise RunnerSecretViolation("runner token contains forbidden whitespace")
    if len(value.encode("utf-8")) < 32:
        raise RunnerSecretViolation("runner token must contain at least 32 bytes")
    if _release_mode(environment) and (
        value in insecure_values or len(set(value)) < 12
    ):
        raise RunnerSecretViolation(
            "release mode requires a random token and rejects source defaults"
        )
    return value


def validate_release_secret(
    environment: Mapping[str, str],
    value: str,
    *,
    label: str,
    insecure_values: Set[str] = frozenset(),
) -> str:
    """Reject development credentials before a release-mode service starts."""
    if not _release_mode(environment):
        return value
    encoded = value.encode("utf-8")
    if (
        value in insecure_values
        or "\x00" in value
        or any(character.isspace() for character in value)
        or len(encoded) < 24
        or len(set(value)) < 12
    ):
        raise RunnerSecretViolation(
            f"release mode requires a random {label} and rejects source defaults"
        )
    return value


def validate_release_database_url(
    environment: Mapping[str, str],
    value: str,
    *,
    label: str,
    insecure_passwords: Set[str] = frozenset(),
) -> str:
    """Require a non-default, high-entropy PostgreSQL password in release mode."""
    if not _release_mode(environment):
        return value
    try:
        parsed = urlsplit(value)
        password = unquote(parsed.password or "")
    except (UnicodeError, ValueError) as error:
        raise RunnerSecretViolation(
            f"release mode requires a valid {label} URL"
        ) from error
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname:
        raise RunnerSecretViolation(f"release mode requires a PostgreSQL {label} URL")
    validate_release_secret(
        environment,
        password,
        label=f"{label} password",
        insecure_values=insecure_passwords,
    )
    return value
