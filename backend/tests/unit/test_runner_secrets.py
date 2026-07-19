from __future__ import annotations

import secrets
from pathlib import Path

import crosspatch.runner.secrets as runner_secrets
import pytest
from crosspatch.runner.candidate_executor_service import create_app as create_candidate_app
from crosspatch.runner.runner_service import create_app as create_runner_app
from crosspatch.runner.secrets import (
    INSECURE_CANDIDATE_TOKEN,
    INSECURE_RUNNER_TOKEN,
    RunnerSecretViolation,
    load_service_token,
)

_RANDOM_SECRET = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4P5q6R7s8T9u0"


def _candidate_environment(tmp_path: Path) -> dict[str, str]:
    return {
        "CROSSPATCH_RELEASE_MODE": "1",
        "CROSSPATCH_CANDIDATE_DATABASE_URL": (
            "postgresql://crosspatch_victim_candidate:strong-DB-pass-A1b2C3d4E5f6@db/crosspatch"
        ),
        "CROSSPATCH_CANDIDATE_SCOPE_DATABASE_URL": (
            "postgresql://crosspatch_victim_scope:scope-DB-pass-Q1w2E3r4T5y6@db/crosspatch"
        ),
        "CROSSPATCH_CANDIDATE_APP_SOCKET": "/run/crosspatch/control/candidate.sock",
        "CROSSPATCH_CANDIDATE_EXECUTOR_TOKEN": _RANDOM_SECRET,
        "CROSSPATCH_CANDIDATE_GID": "10002",
        "CROSSPATCH_CANDIDATE_UID": "10002",
        "CROSSPATCH_CANDIDATE_WORKSPACES_ROOT": str(tmp_path),
        "CROSSPATCH_EXECUTOR_UID": "10003",
    }


def _runner_environment(tmp_path: Path) -> dict[str, str]:
    workspaces = tmp_path / "workspaces"
    handoff = tmp_path / "handoff"
    jobs = tmp_path / "jobs"
    workspaces.mkdir()
    handoff.mkdir()
    jobs.mkdir()
    return {
        "CROSSPATCH_RELEASE_MODE": "1",
        "CROSSPATCH_CANDIDATE_EXECUTOR_TOKEN": _RANDOM_SECRET,
        "CROSSPATCH_CANDIDATE_EXECUTOR_URL": "http://candidate-executor:9010",
        "CROSSPATCH_CANDIDATE_TARGET_URL": "http://candidate-executor:8002",
        "CROSSPATCH_CANDIDATE_UID": "10002",
        "CROSSPATCH_CANDIDATE_HANDOFF_ROOT": str(handoff),
        "CROSSPATCH_CANDIDATE_WORKSPACES_ROOT": str(workspaces),
        "CROSSPATCH_RUNNER_JOBS_ROOT": str(jobs),
        "CROSSPATCH_RUNNER_TOKEN": _RANDOM_SECRET,
        "CROSSPATCH_RUNNER_WORKSPACES_ROOT": str(workspaces),
        "CROSSPATCH_SUPERVISOR_UID": "10001",
        "CROSSPATCH_TEST_DATABASE_URL": (
            "postgresql://crosspatch_victim_oracle:strong-DB-pass-A1b2C3d4E5f6@db/crosspatch"
        ),
        "CROSSPATCH_WORKER_DATABASE_URL": (
            "postgresql://crosspatch_victim_worker:other-DB-pass-Z9y8X7w6V5u4@db/crosspatch"
        ),
    }


def test_service_token_can_come_from_exact_mode_0600_owned_file(tmp_path: Path) -> None:
    token_file = tmp_path / "runner.token"
    token_file.write_text(f"{secrets.token_urlsafe(48)}\n", encoding="ascii")
    token_file.chmod(0o600)

    value = load_service_token(
        {"CROSSPATCH_RUNNER_TOKEN_FILE": str(token_file)},
        "CROSSPATCH_RUNNER_TOKEN",
        insecure_values={INSECURE_RUNNER_TOKEN},
    )

    assert len(value) >= 32


def test_service_token_file_rejects_broad_permissions(tmp_path: Path) -> None:
    token_file = tmp_path / "runner.token"
    token_file.write_text(secrets.token_urlsafe(48), encoding="ascii")
    token_file.chmod(0o644)

    with pytest.raises(RunnerSecretViolation, match="0600"):
        load_service_token(
            {"CROSSPATCH_RUNNER_TOKEN_FILE": str(token_file)},
            "CROSSPATCH_RUNNER_TOKEN",
            insecure_values={INSECURE_RUNNER_TOKEN},
        )


def test_service_token_file_rejects_a_symlink_at_the_configured_path(
    tmp_path: Path,
) -> None:
    target = tmp_path / "runner-target.token"
    target.write_text(f"{secrets.token_urlsafe(48)}\n", encoding="ascii")
    target.chmod(0o600)
    configured = tmp_path / "runner.token"
    configured.symlink_to(target)

    with pytest.raises(RunnerSecretViolation, match="regular file"):
        load_service_token(
            {"CROSSPATCH_RUNNER_TOKEN_FILE": str(configured)},
            "CROSSPATCH_RUNNER_TOKEN",
            insecure_values={INSECURE_RUNNER_TOKEN},
        )


def test_service_token_file_rejects_inode_replacement_between_lstat_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = tmp_path / "runner.token"
    configured.write_text(f"{secrets.token_urlsafe(48)}\n", encoding="ascii")
    configured.chmod(0o600)
    replacement = tmp_path / "replacement.token"
    replacement.write_text(f"{secrets.token_urlsafe(48)}\n", encoding="ascii")
    replacement.chmod(0o600)
    original = tmp_path / "original.token"
    real_open = runner_secrets.os.open
    swapped = False

    def swapping_open(path: str | bytes, flags: int, mode: int = 0o777) -> int:
        nonlocal swapped
        if not swapped and Path(path) == configured:
            configured.replace(original)
            replacement.replace(configured)
            swapped = True
        return real_open(path, flags, mode)

    monkeypatch.setattr(runner_secrets.os, "open", swapping_open)

    with pytest.raises(RunnerSecretViolation, match="changed while being opened"):
        load_service_token(
            {"CROSSPATCH_RUNNER_TOKEN_FILE": str(configured)},
            "CROSSPATCH_RUNNER_TOKEN",
            insecure_values={INSECURE_RUNNER_TOKEN},
        )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CROSSPATCH_RUNNER_TOKEN", INSECURE_RUNNER_TOKEN),
        ("CROSSPATCH_CANDIDATE_EXECUTOR_TOKEN", INSECURE_CANDIDATE_TOKEN),
        ("CROSSPATCH_RUNNER_TOKEN", "r" * 64),
    ],
)
def test_release_mode_rejects_source_defaults_and_low_entropy_tokens(
    name: str,
    value: str,
) -> None:
    with pytest.raises(RunnerSecretViolation, match="release"):
        load_service_token(
            {name: value, "CROSSPATCH_RELEASE_MODE": "1"},
            name,
            insecure_values={value},
        )


def test_release_mode_accepts_a_random_service_token() -> None:
    value = secrets.token_urlsafe(48)
    assert (
        load_service_token(
            {"CROSSPATCH_RUNNER_TOKEN": value, "CROSSPATCH_RELEASE_MODE": "1"},
            "CROSSPATCH_RUNNER_TOKEN",
            insecure_values={INSECURE_RUNNER_TOKEN},
        )
        == value
    )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (
            "CROSSPATCH_CANDIDATE_DATABASE_URL",
            "postgresql://crosspatch_victim:crosspatch-victim-local-only@db/crosspatch",
        ),
        (
            "CROSSPATCH_CANDIDATE_SCOPE_DATABASE_URL",
            "postgresql://crosspatch_victim_scope:crosspatch-victim-scope-local-only@db/crosspatch",
        ),
    ],
)
def test_candidate_service_release_startup_rejects_unsafe_runtime_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    environment = _candidate_environment(tmp_path)
    environment[name] = value
    for key, item in environment.items():
        monkeypatch.setenv(key, item)
    monkeypatch.setattr(
        "crosspatch.runner.candidate_executor_service.os.geteuid", lambda: 10003
    )

    with pytest.raises(RunnerSecretViolation, match="release"):
        create_candidate_app()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (
            "CROSSPATCH_TEST_DATABASE_URL",
            "postgresql://crosspatch_victim:crosspatch-victim-local-only@db/crosspatch",
        ),
        (
            "CROSSPATCH_WORKER_DATABASE_URL",
            "postgresql://crosspatch_victim_worker:crosspatch-victim-worker-local-only@db/crosspatch",
        ),
    ],
)
def test_runner_service_release_startup_rejects_unsafe_oracle_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    environment = _runner_environment(tmp_path)
    environment[name] = value
    for key, item in environment.items():
        monkeypatch.setenv(key, item)
    monkeypatch.setattr("crosspatch.runner.runner_service.os.geteuid", lambda: 10001)

    with pytest.raises(RunnerSecretViolation, match="release"):
        create_runner_app()
