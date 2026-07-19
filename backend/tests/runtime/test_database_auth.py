from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from crosspatch.api.dependencies import Role
from crosspatch.db.models import ApiPrincipalRecord
from crosspatch.domain.enums import IncidentState
from crosspatch.mcp.auth import AuthConfig, TokenIssuer
from crosspatch.runtime.auth import (
    ApiCredential,
    DatabaseJudgeTokenRegistry,
    DatabaseTokenAuthenticator,
    JudgeTokenRepository,
)
from crosspatch.runtime.database import RuntimeDatabase
from sqlalchemy import select


@pytest_asyncio.fixture
async def database(tmp_path):
    runtime = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'runtime.db'}")
    await runtime.bootstrap()
    try:
        yield runtime
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_persistent_api_auth_reenumerates_real_incidents_without_wildcards(database) -> None:
    expires_at = datetime(2026, 9, 1, 7, tzinfo=UTC)
    credential = ApiCredential(
        token="operator-token-" "value-with-at-least-32-characters",
        subject="operator-1",
        role=Role.OPERATOR,
        expires_at=expires_at,
    )
    authenticator = DatabaseTokenAuthenticator(database.sessions, (credential,))
    await authenticator.provision()

    await database.store.create_incident(
        incident_id="inc-runtime-1",
        title="Webhook duplicate delivery",
        scenario="webhook-race",
        state=IncidentState.OPEN,
        base_sha="1" * 40,
        repository_manifest_sha256="2" * 64,
        catalog_sha256="3" * 64,
        actor="operator-1",
    )

    principal = await authenticator.authenticate(credential.token)
    assert principal is not None
    assert principal.incident_ids == frozenset({"inc-runtime-1"})
    assert "*" not in principal.incident_ids

    restarted = DatabaseTokenAuthenticator(database.sessions, (credential,))
    restarted_principal = await restarted.authenticate(credential.token)
    assert restarted_principal == principal

    async with database.sessions() as session:
        record = await session.scalar(select(ApiPrincipalRecord))
    assert record is not None
    assert record.bearer_sha256 == hashlib.sha256(credential.token.encode()).hexdigest()
    assert credential.token not in repr(record)


@pytest.mark.asyncio
async def test_api_credential_provisioning_preserves_durable_revocation(database) -> None:
    credential = ApiCredential(
        token="revoked-operator-" "token-value-with-at-least-32-characters",
        subject="revoked-operator",
        role=Role.OPERATOR,
        expires_at=datetime(2026, 9, 1, 7, tzinfo=UTC),
    )
    authenticator = DatabaseTokenAuthenticator(database.sessions, (credential,))
    await authenticator.provision()
    async with database.sessions() as session, session.begin():
        record = await session.get(ApiPrincipalRecord, credential.subject)
        assert record is not None
        record.revoked = True

    await authenticator.provision()

    async with database.sessions() as session:
        record = await session.get(ApiPrincipalRecord, credential.subject)
        assert record is not None
        assert record.revoked is True
    assert await authenticator.authenticate(credential.token) is None


@pytest.mark.asyncio
async def test_read_only_judge_credential_is_granted_new_incidents(database) -> None:
    credential = ApiCredential(
        token="reader-token-" "value-with-at-least-32-characters",
        subject="judge-reader-1",
        role=Role.READ_ONLY,
        expires_at=datetime(2026, 9, 1, 7, tzinfo=UTC),
    )
    authenticator = DatabaseTokenAuthenticator(database.sessions, (credential,))
    await authenticator.provision()

    await database.store.create_incident(
        incident_id="inc-reader-grant-1",
        title="Judge read access",
        scenario="webhook-race",
        state=IncidentState.OPEN,
        base_sha="1" * 40,
        repository_manifest_sha256="2" * 64,
        catalog_sha256="3" * 64,
        actor="operator-1",
    )

    principal = await authenticator.authenticate(credential.token)
    assert principal is not None
    assert principal.role is Role.READ_ONLY
    assert principal.incident_ids == frozenset({"inc-reader-grant-1"})


@pytest.mark.asyncio
async def test_judge_registry_shares_only_digest_expiry_and_revocation(database) -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    expires_at = datetime(2026, 9, 1, 7, tzinfo=UTC)
    config = AuthConfig(
        issuer="crosspatch-control",
        audience="crosspatch-judge",
        zone="judge",
        allowed_subjects=frozenset({"judge-client"}),
        signing_secret=b"judge-runtime-signing-secret-32-bytes",
        allowed_hosts=frozenset({"judge-mcp"}),
        allowed_origins=frozenset({"https://crosspatch.test"}),
        max_token_lifetime_seconds=None,
    )
    token = TokenIssuer(config).issue(
        subject="judge-client",
        jti="judge-runtime-jti-1",
        issued_at=now,
        expires_at=expires_at,
    )
    repository = JudgeTokenRepository(database.sessions)
    await repository.register(
        token,
        jti="judge-runtime-jti-1",
        expires_at=expires_at,
        actor="approver-1",
    )

    registry = DatabaseJudgeTokenRegistry(database.sync_url, clock=lambda: now)
    assert registry.is_active(token)
    assert token not in repr(registry)
    assert registry.active_count == 1

    await repository.revoke_by_token_id("judge-runtime-jti-1", actor="approver-1")
    assert not registry.is_active(token)


@pytest.mark.asyncio
async def test_judge_token_metadata_and_actor_audit_survive_restart(database) -> None:
    token = "judge-token-value-that-is-never-returned-by-metadata"
    token_id = "judge-runtime-jti-audited"
    expires_at = datetime(2026, 9, 1, 7, tzinfo=UTC)
    repository = JudgeTokenRepository(database.sessions)

    await repository.register(
        token,
        jti=token_id,
        expires_at=expires_at,
        actor="approver-issuer",
    )
    issued = await repository.list_tokens()
    assert len(issued) == 1
    assert issued[0].token_id == token_id
    assert issued[0].expires_at == expires_at
    assert issued[0].revoked is False
    assert token not in repr(issued)

    revoked = await repository.revoke_by_token_id(
        token_id,
        actor="approver-revoker",
    )
    assert revoked is not None and revoked.revoked is True
    assert revoked.revoked_at is not None

    restarted = JudgeTokenRepository(database.sessions)
    persisted = await restarted.list_tokens()
    audit = await restarted.audit_events()
    assert persisted == (revoked,)
    assert [(event.action, event.token_id, event.actor) for event in audit] == [
        ("ISSUED", token_id, "approver-issuer"),
        ("REVOKED", token_id, "approver-revoker"),
    ]
