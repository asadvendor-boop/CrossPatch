from __future__ import annotations

import hashlib
import secrets

import pytest
from crosspatch.runtime import factories
from crosspatch.runtime.migrate import migrate


@pytest.mark.parametrize(
    ("loader", "name", "environment", "value"),
    [
        (
            factories._token,
            "operator.token",
            "CROSSPATCH_OPERATOR_TOKEN",
            "crosspatch-local-operator-token-change-me",
        ),
        (
            factories._material,
            "approval-mac.key",
            "CROSSPATCH_APPROVAL_MAC_KEY",
            "crosspatch-local-approval-mac-key-change-me",
        ),
    ],
)
def test_release_mode_rejects_checked_in_control_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    loader,
    name: str,
    environment: str,
    value: str,
) -> None:
    monkeypatch.setenv("CROSSPATCH_RELEASE_MODE", "1")
    monkeypatch.setenv("CROSSPATCH_STATE_ROOT", str(tmp_path))
    monkeypatch.setenv(environment, value)

    with pytest.raises(ValueError, match="release mode"):
        loader(name, environment)


@pytest.mark.parametrize(
    ("loader", "name", "environment"),
    [
        (factories._token, "reader.token", "CROSSPATCH_READER_TOKEN"),
        (
            factories._material,
            "judge-mcp-signing.key",
            "CROSSPATCH_JUDGE_MCP_SIGNING_SECRET",
        ),
    ],
)
def test_release_mode_requires_explicit_control_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    loader,
    name: str,
    environment: str,
) -> None:
    monkeypatch.setenv("CROSSPATCH_RELEASE_MODE", "1")
    monkeypatch.setenv("CROSSPATCH_STATE_ROOT", str(tmp_path))
    monkeypatch.delenv(environment, raising=False)

    with pytest.raises(ValueError, match=environment):
        loader(name, environment)


def test_release_mode_rejects_local_control_database_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CROSSPATCH_RELEASE_MODE", "1")
    monkeypatch.setenv(
        "CROSSPATCH_DATABASE_URL",
        (
            "postgresql+asyncpg://crosspatch:crosspatch-local-only@"
            "postgres:5432/crosspatch"
        ),
    )

    with pytest.raises(ValueError, match="release mode"):
        factories._database()


@pytest.mark.asyncio
async def test_release_mode_rejects_local_migration_role_passwords() -> None:
    with pytest.raises(RuntimeError, match="release mode"):
        await migrate(
            {
                "CROSSPATCH_RELEASE_MODE": "1",
                "CROSSPATCH_DATABASE_URL": (
                    "postgresql+asyncpg://crosspatch:crosspatch-local-only@"
                    "postgres:5432/crosspatch"
                ),
                "CROSSPATCH_API_POSTGRES_PASSWORD": "crosspatch-local-api-db-change-me",
                "CROSSPATCH_BROKER_POSTGRES_PASSWORD": (
                    "crosspatch-local-broker-db-change-me"
                ),
                "CROSSPATCH_EVIDENCE_POSTGRES_PASSWORD": (
                    "crosspatch-local-evidence-db-change-me"
                ),
                "CROSSPATCH_JUDGE_POSTGRES_PASSWORD": (
                    "crosspatch-local-judge-db-change-me"
                ),
            }
        )


def test_local_mode_still_generates_a_persistent_private_reader_token(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("CROSSPATCH_RELEASE_MODE", "0")
    monkeypatch.setenv("CROSSPATCH_STATE_ROOT", str(tmp_path))
    monkeypatch.delenv("CROSSPATCH_READER_TOKEN", raising=False)

    first = factories._token("reader.token", "CROSSPATCH_READER_TOKEN")
    second = factories._token("reader.token", "CROSSPATCH_READER_TOKEN")

    assert first == second
    assert len(first) >= 32
    assert (tmp_path / "secrets" / "reader.token").stat().st_mode & 0o777 == 0o600


def test_release_mode_accepts_explicit_random_credentials_and_asyncpg_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = secrets.token_urlsafe(48)
    password = secrets.token_urlsafe(32)
    monkeypatch.setenv("CROSSPATCH_RELEASE_MODE", "1")
    monkeypatch.setenv("CROSSPATCH_READER_TOKEN", token)
    monkeypatch.setenv(
        "CROSSPATCH_DATABASE_URL",
        f"postgresql+asyncpg://crosspatch:{password}@postgres:5432/crosspatch",
    )

    assert factories._token("reader.token", "CROSSPATCH_READER_TOKEN") == token
    assert factories._database().database_url.startswith("postgresql+asyncpg://")


@pytest.mark.parametrize(
    "value",
    [
        "0" * 64,
        hashlib.sha256(b"crosspatch-runner-dev").hexdigest(),
    ],
)
def test_release_mode_rejects_placeholder_warrant_digests(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("CROSSPATCH_RELEASE_MODE", "1")
    monkeypatch.setenv("CROSSPATCH_RUNNER_DIGEST", value)

    with pytest.raises(ValueError, match="release mode"):
        factories._bound_digest(
            "CROSSPATCH_RUNNER_DIGEST",
            hashlib.sha256(b"crosspatch-runner-dev").hexdigest(),
        )


def test_bound_digest_requires_exact_lowercase_sha256(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CROSSPATCH_RELEASE_MODE", "0")
    monkeypatch.setenv("CROSSPATCH_RUNNER_DIGEST", "not-a-digest")

    with pytest.raises(ValueError, match="64 lowercase hexadecimal"):
        factories._bound_digest("CROSSPATCH_RUNNER_DIGEST", "0" * 64)
