from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from crosspatch.mcp.auth import (
    AuthConfig,
    AuthPolicy,
    JudgeToken,
    JudgeTokenRegistry,
    MCPAuthError,
    TokenIssuer,
)
from crosspatch.mcp.judge_server import (
    JUDGE_RESOURCE_ALLOWLIST,
    JUDGE_TOOL_ALLOWLIST,
    build_judge_mcp,
)
from mcp.shared.exceptions import McpError

from backend.tests.contract._mcp_client import connected_mcp_client


class PublishedReader:
    def __init__(self) -> None:
        self.state = {"published_revision": 7, "rows": ["inc-1"]}

    async def list_incidents(self):
        return [{"incident_id": "inc-1", "state": "VERIFIED"}]

    async def get_case_file(self, incident_id: str):
        return {"incident_id": incident_id, "manifest_sha256": "a" * 64}

    async def get_verdicts(self, incident_id: str):
        return [{"incident_id": incident_id, "verdict": "CLEAR"}]

    async def search_evidence(self, incident_id: str, query: str):
        return [{"incident_id": incident_id, "query": query, "evidence_id": "ev-1"}]

    async def get_sanitized_evidence(self, incident_id: str, evidence_id: str):
        return {
            "classification": "UNTRUSTED_EVIDENCE",
            "incident_id": incident_id,
            "evidence_id": evidence_id,
            "text": "sanitized",
        }

    async def get_warrant_log(self, incident_id: str):
        return [{"incident_id": incident_id, "warrant_id": "w-1", "status": "CONSUMED"}]

    async def verify_artifact_manifest(self, incident_id: str):
        return {"incident_id": incident_id, "valid": True}

    async def get_summary(self, incident_id: str):
        return {"incident_id": incident_id, "state": "VERIFIED"}

    async def get_timeline(self, incident_id: str):
        return [{"incident_id": incident_id, "sequence": 1}]

    async def get_warrants(self, incident_id: str):
        return [{"incident_id": incident_id, "warrant_id": "w-1"}]


def judge_auth(now: datetime) -> tuple[AuthPolicy, str, JudgeTokenRegistry]:
    config = AuthConfig(
        issuer="crosspatch-control",
        audience="crosspatch-judge",
        zone="judge",
        allowed_subjects=frozenset({"judge-client"}),
        signing_secret=b"judge-zone-test-secret-32-byte-key!",
        allowed_hosts=frozenset({"judge-mcp"}),
        allowed_origins=frozenset({"https://demo.crosspatch.test"}),
        max_token_lifetime_seconds=None,
        incident_scoped=True,
    )
    expires_at = datetime(2026, 9, 1, 7, tzinfo=UTC)
    token = TokenIssuer(config).issue(
        subject="judge-client",
        jti="judge-jti-1",
        issued_at=now,
        expires_at=expires_at,
        incident_id="inc-1",
    )
    registry = JudgeTokenRegistry(clock=lambda: now)
    registry.register(token, expires_at=expires_at)
    return (
        AuthPolicy(
            config,
            clock=lambda: now,
            judge_tokens=registry,
            allow_registered_token_reuse=True,
        ),
        token,
        registry,
    )


def published_browse_auth(now: datetime) -> tuple[AuthPolicy, str, JudgeTokenRegistry]:
    config = AuthConfig(
        issuer="crosspatch-control",
        audience="crosspatch-judge",
        zone="judge",
        allowed_subjects=frozenset({"judge-client"}),
        signing_secret=b"judge-zone-test-secret-32-byte-key!",
        allowed_hosts=frozenset({"judge-mcp"}),
        allowed_origins=frozenset({"https://demo.crosspatch.test"}),
        max_token_lifetime_seconds=None,
        incident_scoped=False,
    )
    expires_at = datetime(2026, 9, 1, 7, tzinfo=UTC)
    token = TokenIssuer(config).issue(
        subject="judge-client",
        jti="judge-published-browse-jti-1",
        issued_at=now,
        expires_at=expires_at,
    )
    registry = JudgeTokenRegistry(clock=lambda: now)
    registry.register(token, expires_at=expires_at)
    return (
        AuthPolicy(
            config,
            clock=lambda: now,
            judge_tokens=registry,
            allow_registered_token_reuse=True,
        ),
        token,
        registry,
    )


@pytest.mark.asyncio
async def test_published_browse_judge_lists_and_reads_two_published_cases() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    auth, token, _registry = published_browse_auth(now)

    class TwoPublishedCases(PublishedReader):
        async def list_incidents(self):
            return [
                {"incident_id": "inc-1", "state": "VERIFIED"},
                {"incident_id": "inc-2", "state": "VERIFIED"},
            ]

        async def get_case_file(self, incident_id: str):
            if incident_id == "inc-inflight":
                raise LookupError(incident_id)
            return await super().get_case_file(incident_id)

    surface = build_judge_mcp(TwoPublishedCases(), auth=auth)
    async with connected_mcp_client(
        surface,
        token=token,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
    ) as client:
        listed = await client.call_tool("list_incidents", {})
        rendered = "".join(getattr(item, "text", "") for item in listed.content)
        assert "inc-1" in rendered
        assert "inc-2" in rendered

        first = await client.call_tool("get_case_file", {"incident_id": "inc-1"})
        second = await client.call_tool("get_case_file", {"incident_id": "inc-2"})
        assert first.isError is False
        assert second.isError is False
        unpublished = await client.call_tool(
            "get_case_file", {"incident_id": "inc-inflight"}
        )
        assert unpublished.isError is True


@pytest.mark.asyncio
async def test_judge_mcp_reads_only_published_payload_equivalence_projection() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    auth, token, _registry = published_browse_auth(now)

    class PayloadEquivalenceReader(PublishedReader):
        async def list_incidents(self):
            return [
                {
                    "incident_id": "inc-equivalence-published",
                    "scenario": "webhook-payload-equivalence",
                    "state": "VERIFIED",
                }
            ]

        async def get_case_file(self, incident_id: str):
            if incident_id != "inc-equivalence-published":
                raise LookupError(incident_id)
            return {
                "incident_id": incident_id,
                "incident": {
                    "id": incident_id,
                    "scenario": "webhook-payload-equivalence",
                    "state": "VERIFIED",
                },
                "artifacts": {
                    "evidence": [
                        {
                            "classification": "UNTRUSTED_EVIDENCE",
                            "incident_id": incident_id,
                            "evidence_id": "ev-equivalence-published",
                            "text": "statuses=202,200,409 counts=1,1,1",
                        }
                    ],
                    "tests": [
                        {
                            "label": "victim.payload-equivalence.candidate",
                            "state": "passed",
                            "receipt_sha256": "a" * 64,
                            "trusted_observation": {
                                "counts": {
                                    "receipts": 1,
                                    "jobs": 1,
                                    "deliveries": 1,
                                },
                                "response_statuses": [202, 200, 409],
                            },
                            "trusted_observation_sha256": "b" * 64,
                        }
                    ],
                },
            }

    surface = build_judge_mcp(PayloadEquivalenceReader(), auth=auth)
    async with connected_mcp_client(
        surface,
        token=token,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
    ) as client:
        published = await client.call_tool(
            "get_case_file",
            {"incident_id": "inc-equivalence-published"},
        )
        unpublished = await client.call_tool(
            "get_case_file",
            {"incident_id": "inc-equivalence-unpublished"},
        )

    rendered = "".join(getattr(item, "text", "") for item in published.content)
    payload = json.loads(rendered)
    projected_test = payload["data"]["artifacts"]["tests"][0]
    assert published.isError is False
    assert unpublished.isError is True
    assert "webhook-payload-equivalence" in rendered
    assert "victim.payload-equivalence.candidate" in rendered
    assert projected_test["trusted_observation"] == {
        "counts": {"receipts": 1, "jobs": 1, "deliveries": 1},
        "response_statuses": [202, 200, 409],
    }
    assert projected_test["state"] == "passed"
    assert all(
        marker not in rendered
        for marker in (
            "raw_body_bytes",
            "webhook_signing_secret",
            "raw_artifact_path",
            "approval_mac_key",
            "candidate_context",
            "raw_receipt",
        )
    )


@pytest.mark.asyncio
async def test_incident_scoped_judge_lists_and_reads_only_its_authorized_case() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    config = AuthConfig(
        issuer="crosspatch-control",
        audience="crosspatch-judge",
        zone="judge",
        allowed_subjects=frozenset({"judge-client"}),
        signing_secret=b"judge-zone-test-secret-32-byte-key!",
        allowed_hosts=frozenset({"judge-mcp"}),
        allowed_origins=frozenset({"https://demo.crosspatch.test"}),
        max_token_lifetime_seconds=None,
        incident_scoped=True,
    )
    expires_at = datetime(2026, 9, 1, 7, tzinfo=UTC)
    token = TokenIssuer(config).issue(
        subject="judge-client",
        jti="judge-scoped-jti-1",
        issued_at=now,
        expires_at=expires_at,
        incident_id="inc-1",
    )
    registry = JudgeTokenRegistry(clock=lambda: now)
    registry.register(token, expires_at=expires_at)
    auth = AuthPolicy(
        config,
        clock=lambda: now,
        judge_tokens=registry,
        allow_registered_token_reuse=True,
    )

    class TwoIncidentReader(PublishedReader):
        def __init__(self) -> None:
            super().__init__()
            self.case_reads: list[str] = []
            self.summary_reads: list[str] = []

        async def list_incidents(self):
            return [
                {"incident_id": "inc-1", "state": "VERIFIED"},
                {"incident_id": "inc-2", "state": "VERIFIED"},
            ]

        async def get_case_file(self, incident_id: str):
            self.case_reads.append(incident_id)
            return await super().get_case_file(incident_id)

        async def get_summary(self, incident_id: str):
            self.summary_reads.append(incident_id)
            return await super().get_summary(incident_id)

    reader = TwoIncidentReader()
    surface = build_judge_mcp(reader, auth=auth)

    async with connected_mcp_client(
        surface,
        token=token,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
    ) as client:
        listed = await client.call_tool("list_incidents", {})
        rendered = "".join(getattr(item, "text", "") for item in listed.content)
        assert "inc-1" in rendered
        assert "inc-2" not in rendered

        denied_tool = await client.call_tool("get_case_file", {"incident_id": "inc-2"})
        assert denied_tool.isError is True
        assert reader.case_reads == []

        with pytest.raises(McpError):
            await client.read_resource("crosspatch://incidents/inc-2/summary")
        assert reader.summary_reads == []


def test_judge_mcp_requires_reusable_registered_bearer_sessions() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    reusable, _token, registry = judge_auth(now)
    one_shot = AuthPolicy(reusable.config, clock=lambda: now, judge_tokens=registry)

    with pytest.raises(ValueError, match="reusable registered bearer"):
        build_judge_mcp(PublishedReader(), auth=one_shot)
    with pytest.raises(ValueError, match="revocable token registry"):
        AuthPolicy(
            reusable.config,
            clock=lambda: now,
            allow_registered_token_reuse=True,
        )

    evidence_config = AuthConfig(
        **{
            **reusable.config.__dict__,
            "audience": "crosspatch-evidence",
            "zone": "evidence",
        }
    )
    with pytest.raises(ValueError, match="judge trust zone"):
        AuthPolicy(
            evidence_config,
            clock=lambda: now,
            judge_tokens=registry,
            allow_registered_token_reuse=True,
        )


def test_registered_judge_bearer_survives_lost_initialize_and_disconnect() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    policy, credential, _registry = judge_auth(now)

    lost = policy.authorize(
        credential,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
        session_id=None,
    )
    assert lost.subject == "judge-client"

    first = policy.authorize(
        credential,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
        session_id=None,
    )
    policy.bind_session(first, "judge-session-1")

    parallel = policy.authorize(
        credential,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
        session_id=None,
    )
    policy.bind_session(parallel, "judge-session-parallel")
    assert policy.authorize(
        credential,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
        session_id="judge-session-parallel",
    ).subject == "judge-client"

    policy.release_session("judge-session-1")

    replacement = policy.authorize(
        credential,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
        session_id=None,
    )
    policy.bind_session(replacement, "judge-session-2")
    assert policy.authorize(
        credential,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
        session_id="judge-session-2",
    ).subject == "judge-client"
    with pytest.raises(MCPAuthError, match="session"):
        policy.authorize(
            credential,
            host="judge-mcp",
            origin="https://demo.crosspatch.test",
            session_id="judge-session-1",
        )


def test_registered_judge_bearer_reconnects_after_idle_and_obeys_revocation() -> None:
    current = [datetime(2026, 7, 14, 12, tzinfo=UTC)]
    config = AuthConfig(
        issuer="crosspatch-control",
        audience="crosspatch-judge",
        zone="judge",
        allowed_subjects=frozenset({"judge-client"}),
        signing_secret=b"judge-zone-test-secret-32-byte-key!",
        allowed_hosts=frozenset({"judge-mcp"}),
        allowed_origins=frozenset({"https://demo.crosspatch.test"}),
        max_token_lifetime_seconds=None,
    )
    expires_at = datetime(2026, 9, 1, 7, tzinfo=UTC)
    credential = TokenIssuer(config).issue(
        subject="judge-client",
        jti="judge-persistent-jti-1",
        issued_at=current[0],
        expires_at=expires_at,
    )
    registry = JudgeTokenRegistry(clock=lambda: current[0])
    registry.register(credential, expires_at=expires_at)
    policy = AuthPolicy(
        config,
        clock=lambda: current[0],
        judge_tokens=registry,
        allow_registered_token_reuse=True,
        session_idle_ttl_seconds=10,
    )
    identity = policy.authorize(
        credential,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
        session_id=None,
    )
    policy.bind_session(identity, "judge-idle-session")

    current[0] += timedelta(seconds=11)
    assert policy.active_session_count == 0
    replacement = policy.authorize(
        credential,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
        session_id=None,
    )
    policy.bind_session(replacement, "judge-reconnected-session")

    registry.revoke(credential)
    with pytest.raises(MCPAuthError, match="revoked"):
        policy.authorize(
            credential,
            host="judge-mcp",
            origin="https://demo.crosspatch.test",
            session_id="judge-reconnected-session",
        )


def test_judge_token_rejects_expiry_before_required_availability() -> None:
    with pytest.raises(ValueError, match="2026-08-13T07:00:00Z"):
        JudgeToken(expires_at="2026-08-13T06:59:59Z")


def test_judge_token_registry_hashes_tokens_and_rotates_with_overlap() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    registry = JudgeTokenRegistry(clock=lambda: now)
    expiry = datetime(2026, 9, 1, 7, tzinfo=UTC)
    first = "first-judge-token-secret"
    second = "second-judge-token-secret"
    registry.register(first, expires_at=expiry)
    registry.rotate(second, expires_at=expiry)

    assert registry.is_active(first)
    assert registry.is_active(second)
    assert first not in repr(registry)
    assert second not in repr(registry)
    assert registry.active_count == 2

    registry.revoke(first)
    assert not registry.is_active(first)
    assert registry.is_active(second)


@pytest.mark.asyncio
async def test_judge_mcp_has_exact_read_only_tools_and_four_resources() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    auth, token, _ = judge_auth(now)
    surface = build_judge_mcp(PublishedReader(), auth=auth)

    async with connected_mcp_client(
        surface,
        token=token,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
    ) as client:
        tools = await client.list_tools()
        templates = await client.list_resource_templates()

    assert tuple(tool.name for tool in tools.tools) == (
        "list_incidents",
        "get_case_file",
        "get_verdicts",
        "search_evidence",
        "get_sanitized_evidence",
        "get_warrant_log",
        "verify_artifact_manifest",
    )
    assert tuple(tool.name for tool in tools.tools) == JUDGE_TOOL_ALLOWLIST
    assert all(tool.annotations and tool.annotations.readOnlyHint for tool in tools.tools)
    assert tuple(str(template.uriTemplate) for template in templates.resourceTemplates) == (
        "crosspatch://incidents/{id}/summary",
        "crosspatch://incidents/{id}/timeline",
        "crosspatch://incidents/{id}/verdicts",
        "crosspatch://incidents/{id}/warrants",
    )
    assert tuple(str(template.uriTemplate) for template in templates.resourceTemplates) == (
        JUDGE_RESOURCE_ALLOWLIST
    )
    assert set(JUDGE_TOOL_ALLOWLIST).isdisjoint(
        {"approve_warrant", "execute_warrant", "run_test", "shell"}
    )
    assert all("raw" not in uri for uri in JUDGE_RESOURCE_ALLOWLIST)


@pytest.mark.asyncio
async def test_judge_bearer_reconnects_after_clean_streamable_http_disconnect() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    auth, credential, _registry = judge_auth(now)
    surface = build_judge_mcp(PublishedReader(), auth=auth)

    async with surface.inner_app.router.lifespan_context(surface.inner_app):
        for _attempt in range(2):
            async with connected_mcp_client(
                surface,
                token=credential,
                host="judge-mcp",
                origin="https://demo.crosspatch.test",
                manage_lifespan=False,
            ) as client:
                result = await client.list_tools()
                assert tuple(tool.name for tool in result.tools) == JUDGE_TOOL_ALLOWLIST


@pytest.mark.asyncio
async def test_all_judge_operations_are_observably_read_only() -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    auth, token, _ = judge_auth(now)
    reader = PublishedReader()
    before = deepcopy(reader.state)
    surface = build_judge_mcp(reader, auth=auth)

    async with connected_mcp_client(
        surface,
        token=token,
        host="judge-mcp",
        origin="https://demo.crosspatch.test",
    ) as client:
        calls = (
            ("list_incidents", {}),
            ("get_case_file", {"incident_id": "inc-1"}),
            ("get_verdicts", {"incident_id": "inc-1"}),
            ("search_evidence", {"incident_id": "inc-1", "query": "race"}),
            (
                "get_sanitized_evidence",
                {"incident_id": "inc-1", "evidence_id": "ev-1"},
            ),
            ("get_warrant_log", {"incident_id": "inc-1"}),
            ("verify_artifact_manifest", {"incident_id": "inc-1"}),
        )
        for name, arguments in calls:
            result = await client.call_tool(name, arguments)
            assert result.isError is False
            rendered = "".join(getattr(item, "text", "") for item in result.content)
            assert "UNTRUSTED_EVIDENCE" in rendered
            assert '"kind": "mcp_result"' in rendered
        for suffix in ("summary", "timeline", "verdicts", "warrants"):
            resource = await client.read_resource(f"crosspatch://incidents/inc-1/{suffix}")
            assert resource.contents
            assert "UNTRUSTED_EVIDENCE" in resource.contents[0].text

    assert reader.state == before
