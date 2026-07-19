from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from crosspatch.mcp.auth import AuthConfig, AuthPolicy, TokenIssuer
from crosspatch.mcp.broker_server import build_broker_mcp

from backend.tests.contract._mcp_client import connected_mcp_client


class Broker:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def execute_warrant(self, warrant_id: str):
        self.calls.append(warrant_id)
        return {"warrant_id": warrant_id, "status": "VERIFIED"}


def broker_auth(now: datetime) -> tuple[AuthPolicy, str]:
    config = AuthConfig(
        issuer="crosspatch-control",
        audience="crosspatch-broker",
        zone="broker",
        allowed_subjects=frozenset({"Bailiff"}),
        signing_secret=b"broker-zone-test-secret-32-byte-key",
        allowed_hosts=frozenset({"broker-mcp"}),
        allowed_origins=frozenset({"https://control.crosspatch.test"}),
        max_token_lifetime_seconds=300,
    )
    token = TokenIssuer(config).issue(
        subject="Bailiff",
        jti="broker-jti-1",
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
    )
    return AuthPolicy(config, clock=lambda: now), token


@pytest.mark.asyncio
async def test_broker_mcp_exposes_exactly_execute_warrant() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    auth, token = broker_auth(now)
    broker = Broker()
    surface = build_broker_mcp(broker, auth=auth)

    async with connected_mcp_client(
        surface,
        token=token,
        host="broker-mcp",
        origin="https://control.crosspatch.test",
    ) as client:
        tools = await client.list_tools()
        response = await client.call_tool("execute_warrant", {"id": "warrant-1"})

    assert [tool.name for tool in tools.tools] == ["execute_warrant"]
    assert response.isError is False
    rendered = "".join(getattr(item, "text", "") for item in response.content)
    assert "UNTRUSTED_EVIDENCE" in rendered
    assert '"operation": "execute_warrant"' in rendered
    assert broker.calls == ["warrant-1"]


def test_broker_builder_rejects_non_bailiff_auth_policy() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    config = AuthConfig(
        issuer="crosspatch-control",
        audience="crosspatch-broker",
        zone="broker",
        allowed_subjects=frozenset({"crosspatch-orchestrator"}),
        signing_secret=b"broker-zone-test-secret-32-byte-key",
        allowed_hosts=frozenset({"broker-mcp"}),
        allowed_origins=frozenset({"https://control.crosspatch.test"}),
    )
    with pytest.raises(ValueError, match="Bailiff"):
        build_broker_mcp(Broker(), auth=AuthPolicy(config, clock=lambda: now))
