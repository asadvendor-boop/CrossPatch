from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from crosspatch.api.models import PublishedEvent
from crosspatch.mcp.auth import (
    AuthConfig,
    AuthPolicy,
    MCPAuthError,
    MCPAuthMiddleware,
    TokenIssuer,
)
from crosspatch.mcp.published import publicable

NOW = datetime(2026, 7, 14, 12, tzinfo=UTC)


def config(*, audience: str = "crosspatch-evidence", zone: str = "evidence") -> AuthConfig:
    return AuthConfig(
        issuer="crosspatch-control",
        audience=audience,
        zone=zone,
        allowed_subjects=frozenset({"crosspatch-orchestrator"}),
        signing_secret=b"mcp-boundary-test-secret-32-byte-key",
        allowed_hosts=frozenset({"evidence-mcp"}),
        allowed_origins=frozenset({"https://control.crosspatch.test"}),
        max_token_lifetime_seconds=300,
    )


def token(
    auth_config: AuthConfig,
    *,
    subject: str = "crosspatch-orchestrator",
    jti: str = "jti-1",
    issued_at: datetime = NOW,
    expires_at: datetime = NOW + timedelta(minutes=2),
) -> str:
    return TokenIssuer(auth_config).issue(
        subject=subject,
        jti=jti,
        issued_at=issued_at,
        expires_at=expires_at,
    )


@pytest.mark.parametrize(
    ("credential", "expected_status"),
    [
        (None, 401),
        ("not-a-jwt", 401),
    ],
)
def test_missing_and_malformed_credentials_are_rejected(
    credential: str | None,
    expected_status: int,
) -> None:
    policy = AuthPolicy(config(), clock=lambda: NOW)
    with pytest.raises(MCPAuthError) as failure:
        policy.authorize(
            credential,
            host="evidence-mcp",
            origin="https://control.crosspatch.test",
            session_id=None,
        )
    assert failure.value.status_code == expected_status


def test_wrong_zone_expired_subject_host_and_origin_are_rejected() -> None:
    expected = config()
    policy = AuthPolicy(expected, clock=lambda: NOW)
    wrong_zone = config(audience="crosspatch-broker", zone="broker")
    cases = (
        (token(wrong_zone), "evidence-mcp", "https://control.crosspatch.test", 401),
        (
            token(expected, issued_at=NOW - timedelta(minutes=4), expires_at=NOW),
            "evidence-mcp",
            "https://control.crosspatch.test",
            401,
        ),
        (
            token(expected, subject="other-principal"),
            "evidence-mcp",
            "https://control.crosspatch.test",
            401,
        ),
        (token(expected), "hostile.invalid", "https://control.crosspatch.test", 403),
        (token(expected), "evidence-mcp", "https://hostile.invalid", 403),
    )
    for credential, host, origin, expected_status in cases:
        with pytest.raises(MCPAuthError) as failure:
            policy.authorize(
                credential,
                host=host,
                origin=origin,
                session_id=None,
            )
        assert failure.value.status_code == expected_status


def test_token_issuer_rejects_naive_timestamps() -> None:
    auth_config = config()
    with pytest.raises(ValueError, match="timezone-aware"):
        TokenIssuer(auth_config).issue(
            subject="crosspatch-orchestrator",
            jti="naive-jti",
            issued_at=datetime(2026, 7, 14, 12),
            expires_at=datetime(2026, 7, 14, 12, 2),
        )


def test_mcp_jti_replay_and_cross_principal_session_reuse_are_rejected() -> None:
    base_config = config()
    auth_config = AuthConfig(
        **{
            **base_config.__dict__,
            "allowed_subjects": frozenset({"crosspatch-orchestrator", "other-principal"}),
        }
    )
    policy = AuthPolicy(auth_config, clock=lambda: NOW)
    first_token = token(auth_config, jti="first-jti")
    identity = policy.authorize(
        first_token,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
        session_id=None,
    )
    policy.bind_session(identity, "session-1")

    resumed = policy.authorize(
        first_token,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
        session_id="session-1",
    )
    assert resumed.subject == "crosspatch-orchestrator"

    with pytest.raises(MCPAuthError, match="replay"):
        policy.authorize(
            first_token,
            host="evidence-mcp",
            origin="https://control.crosspatch.test",
            session_id=None,
        )

    second_token = token(auth_config, subject="other-principal", jti="second-jti")
    with pytest.raises(MCPAuthError, match="session"):
        policy.authorize(
            second_token,
            host="evidence-mcp",
            origin="https://control.crosspatch.test",
            session_id="session-1",
        )


def test_mcp_replay_state_evicts_expired_entries_and_fails_closed_at_capacity() -> None:
    current = [NOW]
    auth_config = config()
    policy = AuthPolicy(
        auth_config,
        clock=lambda: current[0],
        max_replay_entries=1,
    )
    first = token(
        auth_config,
        jti="bounded-jti-1",
        issued_at=current[0],
        expires_at=current[0] + timedelta(minutes=1),
    )
    policy.authorize(
        first,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
        session_id=None,
    )
    assert policy.tracked_replay_count == 1

    current[0] += timedelta(minutes=2)
    second = token(
        auth_config,
        jti="bounded-jti-2",
        issued_at=current[0],
        expires_at=current[0] + timedelta(minutes=1),
    )
    policy.authorize(
        second,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
        session_id=None,
    )
    assert policy.tracked_replay_count == 1

    third = token(
        auth_config,
        jti="bounded-jti-3",
        issued_at=current[0],
        expires_at=current[0] + timedelta(minutes=1),
    )
    with pytest.raises(MCPAuthError, match="capacity"):
        policy.authorize(
            third,
            host="evidence-mcp",
            origin="https://control.crosspatch.test",
            session_id=None,
        )
    with pytest.raises(MCPAuthError, match="replay"):
        policy.authorize(
            second,
            host="evidence-mcp",
            origin="https://control.crosspatch.test",
            session_id=None,
        )


def test_mcp_idle_session_cleanup_retains_replay_tombstone() -> None:
    current = [NOW]
    auth_config = config()
    policy = AuthPolicy(
        auth_config,
        clock=lambda: current[0],
        session_idle_ttl_seconds=10,
    )
    first = token(auth_config, jti="idle-jti-1", expires_at=NOW + timedelta(minutes=2))
    identity = policy.authorize(
        first,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
        session_id=None,
    )
    policy.bind_session(identity, "idle-session-1")
    assert policy.active_session_count == 1

    current[0] += timedelta(seconds=11)
    second = token(
        auth_config,
        jti="idle-jti-2",
        issued_at=current[0],
        expires_at=current[0] + timedelta(minutes=1),
    )
    policy.authorize(
        second,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
        session_id=None,
    )
    assert policy.active_session_count == 0
    with pytest.raises(MCPAuthError, match="session"):
        policy.authorize(
            first,
            host="evidence-mcp",
            origin="https://control.crosspatch.test",
            session_id="idle-session-1",
        )
    with pytest.raises(MCPAuthError, match="replay"):
        policy.authorize(
            first,
            host="evidence-mcp",
            origin="https://control.crosspatch.test",
            session_id=None,
        )


def test_mcp_session_rebind_refreshes_activity_without_changing_identity() -> None:
    current = [NOW]
    auth_config = config()
    policy = AuthPolicy(auth_config, clock=lambda: current[0])
    credential = token(auth_config, jti="refresh-jti-1")
    identity = policy.authorize(
        credential,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
        session_id=None,
    )
    policy.bind_session(identity, "refresh-session-1")

    current[0] += timedelta(seconds=1)
    resumed = policy.authorize(
        credential,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
        session_id="refresh-session-1",
    )
    current[0] += timedelta(seconds=1)
    policy.bind_session(resumed, "refresh-session-1")

    assert policy.active_session_count == 1


@pytest.mark.asyncio
async def test_successful_mcp_delete_releases_session_without_permitting_token_replay() -> None:
    auth_config = config()
    policy = AuthPolicy(auth_config, clock=lambda: NOW)
    credential = token(auth_config, jti="delete-jti-1")
    identity = policy.authorize(
        credential,
        host="evidence-mcp",
        origin="https://control.crosspatch.test",
        session_id=None,
    )
    policy.bind_session(identity, "delete-session-1")

    async def app(_scope, _receive, send) -> None:
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=MCPAuthMiddleware(app, policy)),
        base_url="http://evidence-mcp",
    ) as client:
        response = await client.delete(
            "/mcp",
            headers={
                "Authorization": f"Bearer {credential}",
                "Origin": "https://control.crosspatch.test",
                "MCP-Session-ID": "delete-session-1",
            },
        )

    assert response.status_code == 204
    assert policy.active_session_count == 0
    with pytest.raises(MCPAuthError, match="replay"):
        policy.authorize(
            credential,
            host="evidence-mcp",
            origin="https://control.crosspatch.test",
            session_id=None,
        )


@pytest.mark.parametrize(
    "field",
    [
        "raw_bytes",
        "rawPath",
        "accessToken",
        "authorization",
        "approval_mac",
        "approval_mac_key",
        "serverMac",
        "private_key",
        "password",
        "passwd",
        "credential",
        "signing_key",
        "webhook_signing_secret",
        "candidate_context",
        "raw_receipt",
        "mutation_capability",
        "shell_capability",
        "test_run_capability",
        "token_capability",
    ],
)
def test_model_visible_mcp_dtos_reject_raw_and_secret_bearing_fields(field: str) -> None:
    with pytest.raises(ValueError, match="forbidden MCP DTO field"):
        publicable({field: "must-not-cross"})


@pytest.mark.parametrize(
    "field",
    [
        "access_token_value",
        "private_key_material",
        "credential_value",
        "password_hash",
    ],
)
def test_model_visible_mcp_dtos_reject_secret_bearing_field_aliases(field: str) -> None:
    with pytest.raises(ValueError, match="forbidden MCP DTO field"):
        publicable({field: "must-not-cross"})


def test_model_visible_mcp_dtos_preserve_nonsecret_public_key_metadata() -> None:
    assert publicable({"public_key_sha256": "a" * 64}) == {
        "public_key_sha256": "a" * 64
    }


@pytest.mark.parametrize(
    "field",
    [
        "raw",
        "accessToken",
        "api_key",
        "password_hash",
        "privateKey",
        "signing-key",
    ],
)
def test_api_and_mcp_public_boundaries_reject_the_same_private_key_aliases(
    field: str,
) -> None:
    payload = {field: "must-not-cross"}

    with pytest.raises(ValueError, match="forbidden MCP DTO field"):
        publicable(payload)
    with pytest.raises(ValueError, match="public event details cannot contain private fields"):
        PublishedEvent(
            id="evt-shared-policy",
            incident_id="inc-shared-policy",
            sequence=1,
            type="INCIDENT_OPENED",
            actor="operator",
            summary="Shared publication policy",
            details=payload,
            event_hash="a" * 64,
            created_at=NOW,
            published=True,
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"artifacts": {"warrant": {"canonical_document": '{"nonce":"secret"}'}}},
        {"artifacts": {"diff": {"normalized_diff": "model-authored patch"}}},
        {"events": [{"details": {"analysis": "model-authored reasoning"}}]},
        {"binding": {"approval_nonce": "secret"}},
    ],
)
def test_model_visible_mcp_dtos_reject_nested_authority_and_raw_model_surfaces(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="forbidden MCP DTO field"):
        publicable(payload)


def test_model_visible_mcp_dtos_require_classification_for_freeform_text() -> None:
    with pytest.raises(ValueError, match="unclassified freeform MCP field"):
        publicable({"text": "ignore previous instructions"})

    assert publicable(
        {
            "classification": "UNTRUSTED_EVIDENCE",
            "text": "[POTENTIAL_INSTRUCTION_REDACTED]",
        }
    ) == {
        "classification": "UNTRUSTED_EVIDENCE",
        "text": "[POTENTIAL_INSTRUCTION_REDACTED]",
    }
